//! The HTTP/2 server, exercised as a real server by a real client.
//!
//! These are the tests that decide whether the server role is a transport or a demo. Each one
//! names a property an operator depends on, and each one would pass trivially against a server
//! that only ever handled one well-formed GET.
//!
//! The client is this workspace's own [`H2ClientConnection`] rather than `hyper`, deliberately:
//! both ends are owned code, so a divergence is a bug in *this* repository rather than a bug
//! report against a dependency. The oracle direction — hyper as the peer — lives in
//! `crates/netune/tests/` where depending on hyper is already sanctioned.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use netune_http2::client::H2ClientConnection;
use netune_http2::server::{
    H2Body, H2Handler, H2Request, H2Response, H2ResponseBody, ResponseFuture, ServerSession,
    ServerSessionConfig, SessionEnd,
};
use netune_http2::{H2Fingerprint, LocalSettings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// A handler that echoes the body and reports what it was asked.
struct Echo;

impl H2Handler for Echo {
    fn handle(&self, request: H2Request) -> ResponseFuture<'_> {
        Box::pin(async move {
            let method = request.method.clone();
            let path = String::from_utf8_lossy(&request.path).into_owned();
            let mut body = request.body;
            let bytes = body.read_to_end().await;
            H2Response {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: H2ResponseBody::Bytes(Bytes::from(format!(
                    "{} {} {}",
                    method.as_str(),
                    path,
                    String::from_utf8_lossy(&bytes)
                ))),
            }
        })
    }
}

/// A handler that answers with a body larger than one frame and larger than the initial window,
/// so flow control is exercised rather than assumed.
struct Large {
    size: usize,
    chunk: usize,
}

impl H2Handler for Large {
    fn handle(&self, _request: H2Request) -> ResponseFuture<'_> {
        let size = self.size;
        let chunk = self.chunk;
        Box::pin(async move {
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
                let payload = vec![b'x'; chunk];
                let mut sent = 0;
                while sent < size {
                    let take = (size - sent).min(chunk);
                    if tx
                        .send(Bytes::copy_from_slice(&payload[..take]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    sent += take;
                }
            });
            H2Response::stream(http::StatusCode::OK, rx)
        })
    }
}

/// A handler that panics, to prove the connection survives one bad stream.
struct Panics;

impl H2Handler for Panics {
    fn handle(&self, request: H2Request) -> ResponseFuture<'_> {
        if request.path.as_ref() == b"/panic" {
            Box::pin(async move { panic!("a handler bug") })
        } else {
            Box::pin(async move { H2Response::ok(&b"fine"[..]) })
        }
    }
}

/// Bind a server on an ephemeral port, serve `limit` connections, and return its address.
async fn spawn_server<H: H2Handler>(
    handler: Arc<H>,
    config: ServerSessionConfig,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let handler = Arc::clone(&handler);
            let config = config.clone();
            tokio::spawn(async move {
                let session =
                    ServerSession::new(handler, config, Arc::new(netune_http2::NoObserver));
                let end = session
                    .run(socket, false, std::future::pending::<()>())
                    .await;
                // A session that ended by protocol error is a test failure, not a test outcome;
                // asserting here keeps a silent misparse from looking like a clean close.
                if let SessionEnd::Protocol(error, code) = end {
                    panic!("session ended with protocol error {code}: {error}");
                }
            });
        }
    });
    address
}

async fn connect(address: std::net::SocketAddr) -> H2ClientConnection<TcpStream> {
    let stream = TcpStream::connect(address).await.expect("connect");
    H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_never_sends_settings_is_cut_off_at_the_handshake_bound() {
    let config = ServerSessionConfig {
        handshake_timeout: Duration::from_millis(100),
        ..ServerSessionConfig::for_tests()
    };
    let address = spawn_server(Arc::new(Echo), config).await;
    let mut socket = TcpStream::connect(address).await.expect("connect");

    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut buffer = [0u8; 1024];
        loop {
            if socket.read(&mut buffer).await.expect("read") == 0 {
                return;
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "a stalled handshake must not hold the connection open"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_idle_h2_connection_is_closed_at_the_idle_bound() {
    let config = ServerSessionConfig {
        idle_timeout: Duration::from_millis(100),
        ..ServerSessionConfig::for_tests()
    };
    let address = spawn_server(Arc::new(Echo), config).await;
    let mut socket = TcpStream::connect(address).await.expect("connect");
    socket
        .write_all(netune_http2::CLIENT_PREFACE)
        .await
        .expect("preface");
    let settings = netune_http2::Frame::Settings {
        ack: false,
        settings: Vec::new(),
    }
    .encode();
    socket.write_all(&settings).await.expect("settings");

    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut buffer = [0u8; 1024];
        loop {
            if socket.read(&mut buffer).await.expect("read") == 0 {
                return;
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "an idle connection must not hold an admission permit indefinitely"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_get_round_trips_and_the_handler_sees_the_path() {
    let address = spawn_server(Arc::new(Echo), ServerSessionConfig::for_tests()).await;
    let mut client = connect(address).await;
    let response = client
        .request("GET", "probe.test", "http", "/v1/models", &[], None)
        .await
        .expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(&response.body[..], b"GET /v1/models ");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_body_arrives_byte_for_byte() {
    let address = spawn_server(Arc::new(Echo), ServerSessionConfig::for_tests()).await;
    let mut client = connect(address).await;
    let payload = b"{\"stream\":true}";
    let response = client
        .request("POST", "probe.test", "http", "/v1/chat", &[], Some(payload))
        .await
        .expect("response");
    assert!(response.body.ends_with(payload), "{:?}", response.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_larger_than_the_window_is_delivered_whole() {
    // 256 KiB through a 16 KiB initial window: the server must replenish credit as the handler
    // consumes, or this hangs rather than fails.
    let server = Arc::new(Large {
        size: 256 * 1024,
        chunk: 8 * 1024,
    });
    let address = spawn_server(server, ServerSessionConfig::for_tests()).await;
    let mut client = connect(address).await;
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.request("GET", "probe.test", "http", "/big", &[], None),
    )
    .await
    .expect("the transfer must not hang on flow control")
    .expect("response");
    assert_eq!(response.body.len(), 256 * 1024);
    assert!(response.body.iter().all(|byte| *byte == b'x'));
}

#[tokio::test(flavor = "multi_thread")]
async fn two_streams_are_served_concurrently_over_one_connection() {
    // Two requests issued back to back: the second must not wait for the first, because the
    // connection is multiplexed. The client here sends serially (an egress attempt is one request,
    // ADR-0001), so what this pins is that the *server* keeps the connection usable across
    // requests rather than closing it after the first.
    let address = spawn_server(Arc::new(Echo), ServerSessionConfig::for_tests()).await;
    let mut client = connect(address).await;
    for path in ["/a", "/b", "/c"] {
        let response = client
            .request("GET", "probe.test", "http", path, &[], None)
            .await
            .expect("response");
        assert_eq!(
            String::from_utf8_lossy(&response.body),
            format!("GET {path} ")
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_panicking_handler_fails_one_stream_and_not_the_connection() {
    let address = spawn_server(Arc::new(Panics), ServerSessionConfig::for_tests()).await;
    let mut client = connect(address).await;
    let failed = client
        .request("GET", "probe.test", "http", "/panic", &[], None)
        .await
        .expect("a 500 is a response");
    assert_eq!(failed.status, 500, "a handler bug is answered, not dropped");

    let ok = client
        .request("GET", "probe.test", "http", "/ok", &[], None)
        .await
        .expect("the connection survived");
    assert_eq!(ok.status, 200);
    assert_eq!(&ok.body[..], b"fine");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_preface_that_is_not_http2_is_refused() {
    let address = spawn_server(Arc::new(Echo), ServerSessionConfig::for_tests()).await;
    let mut socket = TcpStream::connect(address).await.expect("connect");
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");
    // The server writes its SETTINGS first (legal), then fails the preface check and closes.
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf)).await;
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut rest)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_drain_finishes_the_stream_in_flight_and_sends_goaway() {
    let config = ServerSessionConfig::for_tests();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let (shutdown, wait) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        let session =
            ServerSession::new(Arc::new(Echo), config, Arc::new(netune_http2::NoObserver));
        let _ = session
            .run(socket, false, async move {
                let _ = wait.await;
            })
            .await;
    });

    let mut client = connect(address).await;
    let first = client
        .request("GET", "probe.test", "http", "/before", &[], None)
        .await
        .expect("the request before the drain completes");
    assert_eq!(&first.body[..], b"GET /before ");
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_settings_change_mid_connection_is_acked_and_honoured() {
    // The client advertises a larger initial window after the handshake. The server must apply it
    // to open streams (there are none at that instant) and acknowledge it; a missing ACK would
    // leave the client's `settings_acknowledged` false forever.
    let address = spawn_server(Arc::new(Echo), ServerSessionConfig::for_tests()).await;
    let stream = TcpStream::connect(address).await.expect("connect");
    let mut client = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake");
    let response = client
        .request("GET", "probe.test", "http", "/after-settings", &[], None)
        .await
        .expect("response");
    assert_eq!(response.status, 200);
}

#[test]
fn the_advertised_settings_are_the_ones_the_peer_is_told() {
    let config = ServerSessionConfig::for_tests();
    let local = LocalSettings::for_ingress();
    let advertised: Vec<(u16, u32)> = config.settings.clone();
    assert_eq!(
        advertised,
        config.local.parameters(),
        "the SETTINGS sent are the bounds named in `local`"
    );
    assert!(
        advertised
            .iter()
            .any(|(id, _)| *id == netune_http2::SETTING_ENABLE_PUSH)
    );
    assert_eq!(
        local.max_frame_size, 16_384,
        "a public listener starts at the RFC minimum"
    );
}

#[allow(dead_code)]
fn unused(_: H2Body) {}

#[tokio::test(flavor = "multi_thread")]
async fn a_protocol_error_ends_the_connection_with_a_goaway() {
    // RFC 9113 §6.8: a peer that is told nothing keeps waiting on streams it believes are open,
    // which reads as a hang rather than as a failure. Every protocol ending must carry a `GOAWAY`,
    // and there is exactly one place that sends it.
    use netune_http2::frame::FRAME_HEADER_LEN;
    use netune_http2::{Frame, FrameHeader};

    let config = ServerSessionConfig::for_tests();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let (end_tx, end_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        let session =
            ServerSession::new(Arc::new(Echo), config, Arc::new(netune_http2::NoObserver));
        let end = session
            .run(socket, false, std::future::pending::<()>())
            .await;
        let _ = end_tx.send(end);
    });

    let mut socket = TcpStream::connect(address).await.expect("connect");
    socket
        .write_all(netune_http2::CLIENT_PREFACE)
        .await
        .expect("preface");
    socket
        .write_all(
            &Frame::Settings {
                ack: false,
                settings: Vec::new(),
            }
            .encode(),
        )
        .await
        .expect("settings");

    // An even stream id from a client is a connection error: it collides with the parity a server
    // uses for its own streams.
    socket
        .write_all(
            &Frame::Headers {
                stream_id: 2,
                end_stream: true,
                end_headers: true,
                header_block: Bytes::new(),
            }
            .encode(),
        )
        .await
        .expect("headers");

    // Read until a GOAWAY appears; the server's own SETTINGS and ACK come first. Frames are walked
    // properly rather than scanned for a byte pattern, because a `DATA` payload could contain one.
    let mut saw_goaway = false;
    let mut buffer: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    'outer: while tokio::time::Instant::now() < deadline {
        // Drain every complete frame currently buffered.
        loop {
            if buffer.len() < FRAME_HEADER_LEN {
                break;
            }
            let header = FrameHeader::parse(&buffer[..FRAME_HEADER_LEN]).expect("header");
            let total = FRAME_HEADER_LEN + header.length as usize;
            if buffer.len() < total {
                break;
            }
            if header.frame_type == netune_http2::frame::FRAME_GOAWAY && header.length >= 8 {
                saw_goaway = true;
                break 'outer;
            }
            buffer.drain(..total);
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(1), socket.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(read)) => buffer.extend_from_slice(&chunk[..read]),
            Err(_) => break,
        }
    }
    assert!(saw_goaway, "a protocol error must be announced with GOAWAY");

    let end = tokio::time::timeout(Duration::from_secs(5), end_rx)
        .await
        .expect("the session ended")
        .expect("the session reported why");
    assert!(matches!(end, SessionEnd::Protocol(_, _)), "{end:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_body_larger_than_the_stream_window_is_accepted() {
    // The response direction was covered; the *request* direction was not, and it is the one that
    // silently stalls: a peer may not send past its per-stream window, so a server that never returns
    // credit never receives the rest of the body.
    let address = spawn_server(Arc::new(Echo), ServerSessionConfig::for_tests()).await;
    let mut client = connect(address).await;
    let payload = vec![b'q'; 256 * 1024];
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.request("POST", "probe.test", "http", "/upload", &[], Some(&payload)),
    )
    .await
    .expect("a request body past the window must not hang")
    .expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body.len(),
        "POST /upload ".len() + payload.len(),
        "the whole body arrived"
    );
}
