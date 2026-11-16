use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A transport that never carries data: the pool only needs the type.
#[derive(Debug)]
struct Dummy;

impl AsyncRead for Dummy {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Dummy {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Transport for Dummy {}

fn idle_stream() -> Box<dyn Transport> {
    Box::new(Dummy)
}

fn key(authority: &str) -> PoolKey {
    PoolKey::new(authority, ConnectionIdentity::default())
}

fn take_http1(pool: &Pool, authority: &str) -> Http1Idle {
    match pool.take(&key(authority)) {
        Some(IdleConnection::Http1(idle)) => idle,
        None => panic!("expected an idle connection"),
    }
}

fn pool(max_idle: usize, idle_timeout: Duration) -> Pool {
    Pool::new(PoolConfig {
        max_idle_per_authority: max_idle,
        idle_timeout,
        ..PoolConfig::default()
    })
}

#[test]
fn production_pool_defaults_are_bounded() {
    let config = PoolConfig::default();
    assert_eq!(config.max_in_flight_per_authority, Some(64));
    assert_eq!(config.max_in_flight_total, Some(512));
}

#[test]
fn an_empty_pool_has_nothing_to_reuse() {
    let pool = pool(2, Duration::from_secs(60));
    assert!(pool.take(&key("example:443")).is_none());
    assert_eq!(pool.idle_count(&key("example:443")), 0);
}

#[test]
fn a_returned_connection_is_reused_with_its_buffered_bytes() {
    let pool = pool(2, Duration::from_secs(60));
    let mut buffered = BytesMut::new();
    buffered.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
    pool.put(
        &key("example:443"),
        idle_stream(),
        buffered,
        Some(51_234),
        None,
    );

    let idle = take_http1(&pool, "example:443");
    assert_eq!(idle.local_port, Some(51_234));
    assert_eq!(&idle.buffered[..], b"HTTP/1.1 200 OK\r\n");
    assert_eq!(pool.idle_count(&key("example:443")), 0, "take removes it");
}

#[test]
fn authorities_do_not_share_connections() {
    let pool = pool(2, Duration::from_secs(60));
    pool.put(&key("a:443"), idle_stream(), BytesMut::new(), None, None);
    assert!(pool.take(&key("b:443")).is_none());
    assert!(pool.take(&key("a:443")).is_some());
}

#[test]
fn the_idle_cap_evicts_the_oldest() {
    let pool = pool(2, Duration::from_secs(60));
    for port in 1..=5u16 {
        pool.put(
            &key("example:443"),
            idle_stream(),
            BytesMut::new(),
            Some(port),
            None,
        );
    }
    assert_eq!(pool.idle_count(&key("example:443")), 2);
    assert_eq!(take_http1(&pool, "example:443").local_port, Some(5));
    assert_eq!(take_http1(&pool, "example:443").local_port, Some(4));
    assert!(pool.take(&key("example:443")).is_none());
}

#[test]
fn a_stale_connection_is_discarded_rather_than_reused() {
    let pool = pool(2, Duration::from_millis(1));
    pool.put(
        &key("example:443"),
        idle_stream(),
        BytesMut::new(),
        None,
        None,
    );
    std::thread::sleep(Duration::from_millis(5));
    assert!(
        pool.take(&key("example:443")).is_none(),
        "an expired connection must not be handed out"
    );
}

#[test]
fn a_candidate_the_caller_cannot_drive_is_left_in_place() {
    let pool = pool(2, Duration::from_secs(60));
    pool.put(
        &key("example:443"),
        idle_stream(),
        BytesMut::new(),
        None,
        None,
    );
    assert!(
        pool.take_matching(&key("example:443"), |protocol| protocol != Protocol::Http1)
            .is_none(),
        "an HTTP/1.1 socket must not be handed to a caller that wants HTTP/2"
    );
    assert_eq!(
        pool.idle_count(&key("example:443")),
        1,
        "the rejected candidate must remain available to a compatible request"
    );
}

/// Same authority, same pool, two runtimes: the second runtime must not
/// receive the first one's socket, whose I/O registration died with it.
#[test]
fn a_connection_is_never_handed_to_a_different_runtime() {
    let pool = pool(2, Duration::from_secs(60));
    let first = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("first runtime");
    first.block_on(async {
        pool.put(
            &key("example:443"),
            idle_stream(),
            BytesMut::new(),
            None,
            None,
        );
        assert_eq!(pool.idle_count(&key("example:443")), 1);
    });

    let second = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("second runtime");
    let taken = second.block_on(async { pool.take(&key("example:443")).is_some() });
    assert!(!taken, "a foreign runtime must not inherit this socket");
    assert_eq!(
        pool.idle_count(&key("example:443")),
        0,
        "the discarded candidate must leave the pool"
    );
}

#[test]
fn a_zero_cap_disables_pooling() {
    let pool = pool(0, Duration::from_secs(60));
    pool.put(
        &key("example:443"),
        idle_stream(),
        BytesMut::new(),
        None,
        None,
    );
    assert_eq!(pool.idle_count(&key("example:443")), 0);
}

#[test]
fn max_idle_total_evicts_globally_oldest_across_authorities() {
    let pool = Pool::new(PoolConfig {
        max_idle_per_authority: 4,
        max_idle_total: 3,
        idle_timeout: Duration::from_secs(60),
        max_in_flight_per_authority: None,
        max_in_flight_total: None,
    });

    for (host, port) in [
        ("a:443", 1),
        ("b:443", 2),
        ("c:443", 3),
        ("d:443", 4),
        ("e:443", 5),
    ] {
        pool.put(&key(host), idle_stream(), BytesMut::new(), Some(port), None);
    }

    assert_eq!(pool.total_idle_count(), 3);
    assert_eq!(pool.idle_count(&key("a:443")), 0);
    assert_eq!(pool.idle_count(&key("b:443")), 0);
    assert_eq!(pool.idle_count(&key("c:443")), 1);
    assert_eq!(pool.idle_count(&key("d:443")), 1);
    assert_eq!(pool.idle_count(&key("e:443")), 1);
}

#[test]
fn synchronous_reap_evicts_expired_connections_across_keys() {
    let pool = pool(4, Duration::from_millis(5));
    pool.put(&key("a:443"), idle_stream(), BytesMut::new(), None, None);
    pool.put(&key("b:443"), idle_stream(), BytesMut::new(), None, None);
    std::thread::sleep(Duration::from_millis(12));

    let evicted = pool.reap();
    assert_eq!(evicted, 2);
    assert_eq!(pool.total_idle_count(), 0);
    assert_eq!(pool.reap(), 0);
}

#[tokio::test]
async fn background_reaper_evicts_expired_connections_and_stops_on_pool_drop() {
    let pool = Pool::new(PoolConfig {
        max_idle_per_authority: 4,
        max_idle_total: 16,
        max_in_flight_per_authority: None,
        max_in_flight_total: None,
        idle_timeout: Duration::from_millis(20),
    });
    let weak = Arc::downgrade(&pool.inner);
    pool.put(&key("a:443"), idle_stream(), BytesMut::new(), None, None);
    assert_eq!(pool.idle_count(&key("a:443")), 1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while pool.idle_count(&key("a:443")) > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "background reaper did not evict idle entry before deadline"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    drop(pool);
    assert!(
        weak.strong_count() == 0,
        "background reaper must hold Weak and never keep PoolInner alive"
    );
}

#[tokio::test]
async fn max_in_flight_per_authority_bounds_concurrency() {
    let pool = Pool::new(PoolConfig {
        max_in_flight_per_authority: Some(2),
        ..PoolConfig::default()
    });
    let p1 = pool
        .acquire_in_flight("api.example:443")
        .await
        .expect("permit 1")
        .expect("bounded");
    let _p2 = pool
        .acquire_in_flight("api.example:443")
        .await
        .expect("permit 2")
        .expect("bounded");

    let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
    let pool_clone = pool.clone();
    let waiter = tokio::spawn(async move {
        let _p3 = pool_clone
            .acquire_in_flight("api.example:443")
            .await
            .expect("permit 3");
        let _ = ready_tx.send(());
    });

    tokio::task::yield_now().await;
    assert!(
        matches!(
            ready_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "third concurrent exchange must wait while two permits are held"
    );

    drop(p1);
    waiter.await.expect("waiter finished");

    let zero_pool = Pool::new(PoolConfig {
        max_in_flight_per_authority: Some(0),
        ..PoolConfig::default()
    });
    assert!(
        zero_pool
            .acquire_in_flight("api.example:443")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn max_in_flight_total_bounds_all_authorities_together() {
    let pool = Pool::new(PoolConfig {
        max_in_flight_per_authority: Some(4),
        max_in_flight_total: Some(1),
        ..PoolConfig::default()
    });
    let held = pool
        .acquire_in_flight("a.example:443")
        .await
        .expect("first authority")
        .expect("bounded");
    let wait = tokio::time::timeout(
        Duration::from_millis(20),
        pool.acquire_in_flight("b.example:443"),
    )
    .await;
    assert!(wait.is_err(), "the global cap must block another authority");
    drop(held);
    assert!(
        pool.acquire_in_flight("b.example:443")
            .await
            .expect("after release")
            .is_some()
    );
}

#[cfg(feature = "http2")]
#[tokio::test]
async fn shared_h2_session_bounds_concurrent_permits_and_evicts_on_goaway() {
    use netune_http2::CLIENT_PREFACE;
    use netune_http2::frame::{
        FRAME_HEADER_LEN, FRAME_SETTINGS, FRAME_WINDOW_UPDATE, Frame, FrameHeader,
        SETTING_MAX_CONCURRENT_STREAMS,
    };
    use netune_http2::{H2ClientConnection, H2Fingerprint};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_io, mut socket) = tokio::io::duplex(8192);
    let (goaway_tx, goaway_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let mut preface = [0u8; CLIENT_PREFACE.len()];
        socket.read_exact(&mut preface).await.expect("preface");

        let mut hdr = [0u8; FRAME_HEADER_LEN];
        socket.read_exact(&mut hdr).await.expect("settings hdr");
        let frame = FrameHeader::parse(&hdr).expect("parse");
        let mut payload = vec![0u8; frame.length as usize];
        socket
            .read_exact(&mut payload)
            .await
            .expect("settings payload");

        socket
            .write_all(&Frame::settings(false, vec![(SETTING_MAX_CONCURRENT_STREAMS, 2)]).encode())
            .await
            .expect("server settings");

        loop {
            socket.read_exact(&mut hdr).await.expect("hdr");
            let f = FrameHeader::parse(&hdr).expect("parse");
            let mut p = vec![0u8; f.length as usize];
            socket.read_exact(&mut p).await.expect("payload");
            match f.frame_type {
                FRAME_WINDOW_UPDATE => continue,
                FRAME_SETTINGS => break,
                other => panic!("unexpected frame {other}"),
            }
        }
        socket
            .write_all(&Frame::settings(true, Vec::new()).encode())
            .await
            .expect("ack");

        goaway_rx.await.expect("trigger goaway");
        socket
            .write_all(&Frame::goaway(0, 0, bytes::Bytes::new()).encode())
            .await
            .expect("goaway");
        let mut buf = [0u8; 8];
        let _ = socket.read(&mut buf).await;
    });

    let boxed: Box<dyn Transport> = Box::new(client_io);
    let session = H2ClientConnection::handshake(boxed, H2Fingerprint::chrome())
        .await
        .expect("handshake")
        .into_session();

    let pool = pool(4, Duration::from_secs(60));
    let k = key("h2.example:443");
    pool.register_http2(&k, session, Some(1234), None);
    assert_eq!(pool.idle_count(&k), 1);

    let c1 = pool.checkout_http2(&k).expect("permit 1");
    assert_eq!(pool.idle_count(&k), 0, "busy session is no longer idle");
    let c2 = pool.checkout_http2(&k).expect("permit 2");
    assert!(pool.checkout_http2(&k).is_none(), "max streams = 2 reached");

    drop(c1);
    let c3 = pool.checkout_http2(&k).expect("slot freed on permit drop");
    drop(c2);
    drop(c3);
    assert_eq!(pool.idle_count(&k), 1);

    let _ = goaway_tx.send(());
    server.await.expect("server");
    assert!(pool.checkout_http2(&k).is_none());
    assert_eq!(pool.idle_count(&k), 0);
}
