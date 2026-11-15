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

fn idle_stream() -> Box<dyn Transport> {
    Box::new(Dummy)
}

fn key(authority: &str) -> PoolKey {
    PoolKey::new(authority, ConnectionIdentity::default())
}

fn take_http1(pool: &Pool, authority: &str) -> Http1Idle {
    match pool.take(&key(authority)) {
        Some(IdleConnection::Http1(idle)) => idle,
        #[cfg(feature = "http2")]
        Some(IdleConnection::Http2(_)) => panic!("expected an HTTP/1.1 connection"),
        None => panic!("expected an idle connection"),
    }
}

fn pool(max_idle: usize, idle_timeout: Duration) -> Pool {
    Pool::new(PoolConfig {
        max_idle_per_authority: max_idle,
        idle_timeout,
    })
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
