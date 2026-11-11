//! What a production HTTP/1.1 origin must do, proven over a real loopback socket.
//!
//! Every test here names a property an operator depends on and a naive transport gets wrong. They are
//! separate from `ingress.rs` because they are about *correctness under a real client's behaviour*
//! rather than about framing, and a failure here is a failure an operator would see in production
//! rather than a failure a conformance suite would see.

#![allow(clippy::expect_used, clippy::unwrap_used)]
mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
#[cfg(feature = "http2")]
use netune_server::ServedProtocol;
use netune_server::{
    CollectingObserver, Handler, HandlerFuture, IncomingRequest, RequestBody, Response, Server,
    ServerConfig,
};
use netune_trace::DiagnosticCode;
use tokio::io::AsyncReadExt;

use support::{read_until, response_complete, server_with};

/// Run `server` until `body` resolves, then drain it.
async fn with_server<F, Fut>(server: Server, body: F)
where
    F: FnOnce(std::net::SocketAddr) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let address = server.local_addr();
    let (shutdown, wait) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = wait.await;
            })
            .await;
    });
    body(address).await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("the server drained within the deadline")
        .expect("the serving task did not panic");
}

/// A handler that streams three chunks and then ends.
struct Streams;

impl Handler for Streams {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        _body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tokio::spawn(async move {
                for word in ["alpha", "-", "omega"] {
                    if tx.send(Bytes::from_static(word.as_bytes())).await.is_err() {
                        return;
                    }
                }
            });
            Response::stream(http::StatusCode::OK, rx)
        })
    }
}

/// A handler that panics on one path and answers on the other, so containment is observable from both
/// sides.
struct SometimesPanics;

impl Handler for SometimesPanics {
    fn handle<'a>(&'a self, request: IncomingRequest, _body: RequestBody<'a>) -> HandlerFuture<'a> {
        let panic = request.target_str() == Some("/panic");
        Box::pin(async move {
            if panic {
                panic!("a handler bug");
            }
            Response::ok(&b"answered"[..])
        })
    }
}

/// A handler that records whether it was called at all.
struct Counts {
    calls: Arc<AtomicUsize>,
}

impl Handler for Counts {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        _body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Response::ok(&b"called"[..]) })
    }
}

/// A handler that reads the body and echoes it, so a `100-continue` exchange is observable end to end.
struct ReadsBody;

impl Handler for ReadsBody {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        mut body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            let bytes = body.read_to_end().await.unwrap_or_default();
            Response::ok(bytes)
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streaming_response_reaches_the_peer_chunk_by_chunk() {
    let server = server_with(ServerConfig::for_tests(), Arc::new(Streams)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /stream HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("closed")
            .expect("read");

        let text = String::from_utf8_lossy(&collected);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(
            text.to_lowercase().contains("transfer-encoding: chunked"),
            "a stream is chunk-framed, not close-delimited: {text}"
        );
        let body = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("a head terminator in {text:?}"))
            .1;
        assert_eq!(
            body, "5\r\nalpha\r\n1\r\n-\r\n5\r\nomega\r\n0\r\n\r\n",
            "{body:?}"
        );

        // The honest proof: our own client-role decoder accepts it.
        let mut reader = netune_http1::Http1Reader::new(support::ScriptedIo::from_slices(&[
            collected.as_slice(),
        ]));
        let head = reader
            .read_response_head(&http::Method::GET)
            .await
            .expect("a conforming chunked response parses");
        assert_eq!(head.body, netune_http1::BodyKind::Chunked);
        let decoded = reader.read_body_to_end().await.expect("body");
        assert_eq!(&decoded[..], b"alpha-omega");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streaming_response_to_head_carries_no_body_and_no_chunks() {
    let server = server_with(ServerConfig::for_tests(), Arc::new(Streams)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"HEAD /stream HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("closed")
            .expect("read");
        let text = String::from_utf8_lossy(&collected);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(
            !text.contains("alpha"),
            "a HEAD response must not carry the body it describes: {text}"
        );
        assert!(
            !text.contains("0\r\n\r\n"),
            "and must not terminate a body it never started: {text}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_panicking_handler_answers_500_and_keeps_the_listener_serving() {
    let observer = Arc::new(CollectingObserver::default());
    let config = ServerConfig::for_tests().with_trace_sink(Arc::clone(&observer) as _);
    let server = server_with(config, Arc::new(SometimesPanics)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /panic HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("the connection closed after the panic")
            .expect("read");
        let text = String::from_utf8_lossy(&collected);
        assert!(
            text.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
            "a handler crash is a status line, not a reset socket: {text}"
        );
        assert!(
            !text.contains("a handler bug"),
            "the panic message must not leak to the peer: {text}"
        );

        // And the listener is still serving.
        let mut second = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        second
            .write_all(b"GET /ok HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let response = read_until(&mut second, response_complete).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200 OK"),
            "{:?}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"answered"));
    })
    .await;

    let traces = observer.take();
    assert!(!traces.is_empty(), "the connections were traced");
    let panic = traces
        .iter()
        .flat_map(|trace| trace.diagnostics.iter())
        .find(|record| record.code == DiagnosticCode::SERVER_HANDLER_PANIC)
        .expect("the panic is classified in the diagnostic table");
    assert!(
        panic.message.contains("a handler bug"),
        "the panic message is evidence: {panic:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn expect_100_continue_is_answered_before_the_body_is_sent() {
    // A client that sends `Expect: 100-continue` and waits must be told to proceed. A server that
    // stays silent makes every large upload pay the client's timeout.
    let server = server_with(ServerConfig::for_tests(), Arc::new(ReadsBody)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(
                b"POST /upload HTTP/1.1\r\nHost: probe\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n",
            )
            .await
            .expect("write");

        // The interim response must arrive before the body does.
        let interim = read_until(&mut stream, |bytes| bytes.windows(4).any(|w| w == b"\r\n\r\n")).await;
        let text = String::from_utf8_lossy(&interim);
        assert!(
            text.starts_with("HTTP/1.1 100 Continue\r\n"),
            "the peer must be told to proceed: {text}"
        );

        stream.write_all(b"hello").await.expect("body");
        let response = read_until(&mut stream, response_complete).await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.ends_with("hello"), "the body still arrives: {text}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_without_host_never_reaches_the_handler() {
    // RFC 9112 §3.2 makes `Host` mandatory for HTTP/1.1. A listener that routed it anyway would be
    // routable to different origins by two different hops.
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with(
        ServerConfig::for_tests(),
        Arc::new(Counts {
            calls: Arc::clone(&calls),
        }),
    )
    .await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /admin HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("closed")
            .expect("read");
        let text = String::from_utf8_lossy(&collected);
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "no handler ran");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_host_headers_never_reach_the_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with(
        ServerConfig::for_tests(),
        Arc::new(Counts {
            calls: Arc::clone(&calls),
        }),
    )
    .await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(
                b"GET /admin HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write");
        let response = read_until(&mut stream, response_complete).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400 Bad Request"),
            "{:?}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reuse_quota_closes_the_connection_with_an_announcement() {
    // Keep-alive is not a promise of indefinite reuse: after the quota the last response carries
    // `Connection: close`, which is how a configuration rollout drains.
    let config = ServerConfig::for_tests().with_max_requests_per_connection(2);
    let (handler, count) = support::Counting::new(Duration::ZERO);
    let server = server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let mut announced = false;
        for _ in 0..2 {
            stream
                .write_all(b"GET /ping HTTP/1.1\r\nHost: probe\r\n\r\n")
                .await
                .expect("write");
            let response = read_until(&mut stream, response_complete).await;
            if String::from_utf8_lossy(&response)
                .to_lowercase()
                .contains("connection: close")
            {
                announced = true;
            }
        }
        assert!(announced, "the last response announces the close");
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "and no third request is served"
        );
    })
    .await;
}

#[cfg(feature = "http2")]
#[tokio::test(flavor = "multi_thread")]
async fn an_http2_prior_knowledge_connection_is_served_and_reported_as_h2() {
    // The listener distinguishes the protocols from the first bytes, so a client that opens with the
    // preface gets HTTP/2 rather than a 400.
    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = ServerConfig::for_tests().with_trace_sink(Arc::clone(&observer) as _);
    let (handler, _count) = support::Counting::new(Duration::ZERO);
    let server = server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let mut client = netune_http2::client::H2ClientConnection::handshake(
            stream,
            netune_http2::H2Fingerprint::chrome(),
        )
        .await
        .expect("an h2 preface is recognised as HTTP/2");
        let response = client
            .request("GET", "probe.test", "http", "/ping", &[], None)
            .await
            .expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(&response.body[..], b"counted");
    })
    .await;

    let protocols: Vec<ServedProtocol> =
        observer.take().iter().map(|trace| trace.protocol).collect();
    assert_eq!(
        protocols,
        vec![ServedProtocol::Http2],
        "the trace names the protocol that was served"
    );
}

#[cfg(feature = "http2")]
#[tokio::test(flavor = "multi_thread")]
async fn http2_is_refused_when_the_listener_does_not_offer_it() {
    let config = ServerConfig::for_tests().with_protocols(netune_server::Protocols::HTTP1);
    let (handler, count) = support::Counting::new(Duration::ZERO);
    let server = server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(netune_http2::CLIENT_PREFACE)
            .await
            .expect("preface");
        let mut collected = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected)).await;
        let text = String::from_utf8_lossy(&collected);
        assert!(
            text.contains("505"),
            "a protocol the listener does not offer is refused, not downgraded: {text}"
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handler_body_ceiling_is_available_to_the_application() {
    struct Limited;

    impl Handler for Limited {
        fn handle<'a>(
            &'a self,
            _request: IncomingRequest,
            mut body: RequestBody<'a>,
        ) -> HandlerFuture<'a> {
            Box::pin(async move {
                match body.read_to_end_within(4).await {
                    Ok(bytes) => Response::ok(bytes),
                    Err(_) => Response::content_too_large(),
                }
            })
        }
    }

    let server = server_with(ServerConfig::for_tests(), Arc::new(Limited)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"POST /x HTTP/1.1\r\nHost: p\r\nContent-Length: 9\r\nConnection: close\r\n\r\n123456789")
            .await
            .expect("write");
        let response = read_until(&mut stream, response_complete).await;
        assert!(
            response.starts_with(b"HTTP/1.1 413"),
            "{:?}",
            String::from_utf8_lossy(&response)
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_10_peer_that_opted_in_is_told_the_connection_stays_open() {
    // HTTP/1.0 persistence is opt-in on *both* sides. A server that honours the request but never
    // announces it leaves the client closing anyway, so the keep-alive it asked for costs a round
    // trip for nothing.
    let (handler, count) = support::Counting::new(Duration::ZERO);
    let server = server_with(ServerConfig::for_tests(), Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /ping HTTP/1.0\r\nHost: probe\r\nConnection: keep-alive\r\n\r\n")
            .await
            .expect("write");
        let first = read_until(&mut stream, response_complete).await;
        let text = String::from_utf8_lossy(&first).to_lowercase();
        assert!(text.starts_with("http/1.1 200 ok"), "{text}");
        assert!(
            text.contains("connection: keep-alive"),
            "the announcement is what makes a 1.0 client reuse the socket: {text}"
        );

        // And it really is reusable.
        stream
            .write_all(b"GET /ping HTTP/1.0\r\nHost: probe\r\nConnection: keep-alive\r\n\r\n")
            .await
            .expect("write");
        let second = read_until(&mut stream, response_complete).await;
        assert!(second.starts_with(b"HTTP/1.1 200 OK"));
        assert_eq!(count.load(Ordering::SeqCst), 2);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_10_peer_that_did_not_opt_in_is_closed_without_the_announcement() {
    let (handler, _count) = support::Counting::new(Duration::ZERO);
    let server = server_with(ServerConfig::for_tests(), Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /ping HTTP/1.0\r\nHost: probe\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("the connection closed, as 1.0 requires")
            .expect("read");
        let text = String::from_utf8_lossy(&collected).to_lowercase();
        assert!(
            !text.contains("keep-alive"),
            "a 1.0 peer that did not opt in must not be told it may reuse: {text}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_request_is_recorded_with_a_real_error_code() {
    // A validation rejection used to be recorded as code `0`, which is not a code: an aggregate
    // filtering on `Error` would have counted it as "unspecified" instead of as a protocol refusal.
    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = ServerConfig::for_tests().with_trace_sink(Arc::clone(&observer) as _);
    let (handler, _count) = support::Counting::new(Duration::ZERO);
    let server = server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /a b HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected)).await;
        assert!(String::from_utf8_lossy(&collected).starts_with("HTTP/1.1 400"));
    })
    .await;

    let traces = observer.take();
    assert_eq!(traces.len(), 1);
    let codes: Vec<u32> = traces[0]
        .log
        .iter()
        .filter(|event| event.kind == netune_trace::EventKind::Error)
        .map(|event| event.a)
        .collect();
    assert_eq!(
        codes,
        vec![netune_trace::DiagnosticCode::SERVER_PROTOCOL.raw()],
        "a malformed request line is a protocol refusal, and it is classified"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_duplicate_host_is_answered_and_recorded_as_an_invalid_request() {
    // The other side of the same coin: a request the codec accepts and the transport refuses. It must
    // still be a status line, and it must still be a real code.
    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = ServerConfig::for_tests().with_trace_sink(Arc::clone(&observer) as _);
    let (handler, _count) = support::Counting::new(Duration::ZERO);
    let server = server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(
                b"GET /x HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write");
        let mut collected = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected)).await;
        assert!(String::from_utf8_lossy(&collected).starts_with("HTTP/1.1 400"));
    })
    .await;

    let codes: Vec<u32> = observer.take()[0]
        .log
        .iter()
        .filter(|event| event.kind == netune_trace::EventKind::Error)
        .map(|event| event.a)
        .collect();
    assert_eq!(
        codes,
        vec![netune_trace::DiagnosticCode::SERVER_INVALID_REQUEST.raw()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_request_that_is_rejected_is_answered_as_a_head_response() {
    // A rejection must be written with the request's own method: answering `HEAD` with a body would
    // shift the next response on a connection the peer might still reuse.
    let (handler, _count) = support::Counting::new(Duration::ZERO);
    let server = server_with(ServerConfig::for_tests(), Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        // No `Host`, so it is rejected — and it is a HEAD.
        stream
            .write_all(b"HEAD /x HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected)).await;
        let text = String::from_utf8_lossy(&collected);
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert!(
            text.ends_with("\r\n\r\n"),
            "a HEAD response is its head: {text:?}"
        );
    })
    .await;
}

#[cfg(feature = "http2")]
#[tokio::test(flavor = "multi_thread")]
async fn an_http2_only_listener_refuses_http11_instead_of_serving_it() {
    // The mirror of the h2 refusal. Without it, an `HTTP2`-only listener served HTTP/1.1 requests it
    // never advertised — the downgrade `INV-SERVER-09` forbids, through the door nobody checked.
    let config = ServerConfig::for_tests().with_protocols(netune_server::Protocols::HTTP2);
    let (handler, count) = support::Counting::new(Duration::ZERO);
    let server = server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /ping HTTP/1.1\r\nHost: probe\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected)).await;
        let text = String::from_utf8_lossy(&collected);
        assert!(
            text.contains("505"),
            "an HTTP/1.1 request to an h2-only listener is refused: {text:?}"
        );
        assert_eq!(count.load(Ordering::SeqCst), 0, "no handler ran");
    })
    .await;
}

#[cfg(feature = "http2")]
#[tokio::test(flavor = "multi_thread")]
async fn an_http2_listener_serves_h2_when_it_is_the_only_protocol() {
    let config = ServerConfig::for_tests().with_protocols(netune_server::Protocols::HTTP2);
    let (handler, count) = support::Counting::new(Duration::ZERO);
    let server = server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let mut client = netune_http2::client::H2ClientConnection::handshake(
            stream,
            netune_http2::H2Fingerprint::chrome(),
        )
        .await
        .expect("h2 on an h2-only listener");
        let response = client
            .request("GET", "probe.test", "http", "/ping", &[], None)
            .await
            .expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    })
    .await;
}

#[cfg(feature = "http2")]
#[tokio::test(flavor = "multi_thread")]
async fn a_shutdown_drains_an_in_flight_http2_stream() {
    // INV-SERVER-06 for the multiplexed protocol. A session that was never told to drain would be
    // aborted by the deadline instead of finishing the response it had already promised.
    let (handler, count) = support::Counting::new(Duration::from_millis(300));
    let server = server_with(ServerConfig::for_tests(), Arc::new(handler)).await;
    let address = server.local_addr();
    let (shutdown, wait) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = wait.await;
            })
            .await;
    });

    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let mut client = netune_http2::client::H2ClientConnection::handshake(
        stream,
        netune_http2::H2Fingerprint::chrome(),
    )
    .await
    .expect("handshake");
    let request = tokio::spawn(async move {
        client
            .request("GET", "probe.test", "http", "/slow", &[], None)
            .await
    });

    // Let the request reach the handler, then drain.
    tokio::time::sleep(Duration::from_millis(60)).await;
    let _ = shutdown.send(());

    let response = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .expect("the in-flight stream is finished during the drain")
        .expect("the request task did not panic")
        .expect("the response arrives");
    assert_eq!(response.status, 200);
    assert_eq!(&response.body[..], b"counted");
    assert_eq!(count.load(Ordering::SeqCst), 1);

    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("the drain finished")
        .expect("no panic");
}

#[cfg(feature = "http2")]
#[tokio::test(flavor = "multi_thread")]
async fn an_http2_handler_timeout_is_recorded_on_its_own_stream() {
    // The defect this pins: a stream-0 `Error` is copied by `split_multiplexed` into *every* sub-log,
    // so one slow handler would have made an unrelated fast stream derive as failed. The assertion is
    // therefore about the *absence* of a stream-0 error as much as its presence.
    struct SlowOnOnePath;

    impl Handler for SlowOnOnePath {
        fn handle<'a>(
            &'a self,
            request: IncomingRequest,
            _body: RequestBody<'a>,
        ) -> HandlerFuture<'a> {
            let slow = request
                .target_str()
                .is_some_and(|target| target.ends_with("/slow"));
            Box::pin(async move {
                if slow {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Response::ok(&b"fast"[..])
            })
        }
    }

    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = ServerConfig::for_tests()
        .with_handler_timeout(Duration::from_millis(150))
        .with_trace_sink(Arc::clone(&observer) as _);
    let server = server_with(config, Arc::new(SlowOnOnePath)).await;
    with_server(server, |address| async move {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let mut client = netune_http2::client::H2ClientConnection::handshake(
            stream,
            netune_http2::H2Fingerprint::chrome(),
        )
        .await
        .expect("handshake");
        // Two streams on one connection: the slow one times out, the fast one must not be affected.
        // The client serialises requests (an egress attempt is one request, ADR-0001), so the fast one
        // is issued second and its success is what proves the connection survived.
        let slow = client
            .request("GET", "probe.test", "http", "/slow", &[], None)
            .await
            .expect("the timeout is answered, not dropped");
        assert_eq!(slow.status, 500);
        let fast = client
            .request("GET", "probe.test", "http", "/fast", &[], None)
            .await
            .expect("the connection survived the timeout");
        assert_eq!(fast.status, 200);
        assert_eq!(&fast.body[..], b"fast");
    })
    .await;

    let traces = observer.take();
    let trace = traces.first().expect("one connection traced");
    let timeouts: Vec<(u32, u32)> = trace
        .log
        .iter()
        .filter(|event| event.kind == netune_trace::EventKind::Error)
        .map(|event| (event.stream, event.a))
        .collect();
    assert!(
        timeouts.iter().all(|(stream, _)| *stream != 0),
        "a per-stream failure must never be recorded at stream 0: {timeouts:?}"
    );
    assert!(
        timeouts.iter().any(|(_, code)| {
            *code == netune_trace::DiagnosticCode::SERVER_HANDLER_TIMEOUT.raw()
        }),
        "the timeout is classified: {timeouts:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connect_request_is_refused_rather_than_answered_as_if_a_tunnel_opened() {
    // A 2xx to `CONNECT` means "the tunnel is open and every byte from here is for the peer". This
    // transport never dials a peer (`INV-SERVER-01`), so it cannot open one: answering 2xx would send
    // the client's tunnel bytes into the HTTP parser, which reads as a protocol error after the client
    // has already committed. `501` is the only answer that is true.
    let (handler, count) = support::Counting::new(Duration::ZERO);
    let server = server_with(ServerConfig::for_tests(), Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected)).await;
        let text = String::from_utf8_lossy(&collected);
        assert!(
            text.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
            "a tunnel this transport cannot open is refused: {text:?}"
        );
        assert!(
            !text.starts_with("HTTP/1.1 2"),
            "a 2xx would tell the client its bytes are being relayed: {text:?}"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "the handler is not asked to fake a tunnel"
        );
    })
    .await;
}

#[cfg(feature = "http2")]
#[tokio::test(flavor = "multi_thread")]
async fn an_http2_connect_is_refused_too() {
    // The same rule, on the protocol that spells the method differently. RFC 9113 §8.5 makes an
    // extended `CONNECT` a tunnel request as well, and RFC 8441's `:protocol` variant is not
    // implemented at all, so every `CONNECT` is one this transport cannot honour.
    let (handler, count) = support::Counting::new(Duration::ZERO);
    let server = server_with(ServerConfig::for_tests(), Arc::new(handler)).await;
    with_server(server, |address| async move {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let mut client = netune_http2::client::H2ClientConnection::handshake(
            stream,
            netune_http2::H2Fingerprint::chrome(),
        )
        .await
        .expect("handshake");
        let response = client
            .request("CONNECT", "example.com:443", "https", "", &[], None)
            .await
            .expect("the refusal is a response");
        assert_eq!(
            response.status, 501,
            "a tunnel this transport cannot open is refused on both protocols"
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
    })
    .await;
}
