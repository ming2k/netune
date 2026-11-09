//! End-to-end ingress behaviour over a real loopback socket.
//!
//! These are the tests that decide whether `netune-server` is a transport or a demo.
//! Each one names a property an operator depends on, and each one would pass trivially
//! against a server that only ever handled one well-formed request.

#![allow(clippy::expect_used, clippy::unwrap_used)]
mod support;

use std::sync::Arc;
use std::time::Duration;

use netune_server::{Server, ServerConfig};
use support::{Counting, Echo, Fixed, IgnoresBody, exchange, read_until, response_complete};

/// Run `server` until `body` completes, then drain it.
///
/// A helper so every test drains the same way: a test that forgets to shut a server
/// down leaks a task and passes for the wrong reason.
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
    // The drain returns once every connection task has ended; a hang here is a real
    // bug and should fail the test rather than block the suite.
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("the server drained within the deadline")
        .expect("the serving task did not panic");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_body_is_echoed_byte_for_byte() {
    let server = support::echo_server().await;
    with_server(server, |address| async move {
        let response = exchange(
            address,
            b"POST /echo HTTP/1.1\r\nHost: probe\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            response_complete,
        )
        .await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.ends_with("hello"), "the body is echoed: {text}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_method_and_target_reach_the_handler_unmodified() {
    let server = support::echo_server().await;
    with_server(server, |address| async move {
        let response = exchange(
            address,
            b"DELETE /v1/items/42?force=1 HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n",
            response_complete,
        )
        .await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("x-method: DELETE"), "{text}");
        assert!(
            text.contains("x-target: /v1/items/42?force=1"),
            "the query string survives: {text}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_connection_serves_several_requests() {
    let (handler, count) = Counting::new(Duration::ZERO);
    let server = support::server_with(ServerConfig::for_tests(), Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        for _ in 0..3 {
            stream
                .write_all(b"GET /ping HTTP/1.1\r\nHost: probe\r\n\r\n")
                .await
                .expect("write");
            let response = read_until(&mut stream, response_complete).await;
            assert!(
                response.starts_with(b"HTTP/1.1 200 OK"),
                "{}",
                String::from_utf8_lossy(&response)
            );
        }
        drop(stream);
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "three requests on one connection reach the handler three times"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_close_request_closes_the_connection_after_the_response() {
    let server = support::echo_server().await;
    with_server(server, |address| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /bye HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("the server closed the connection")
            .expect("read");
        let text = String::from_utf8_lossy(&collected);
        assert!(
            text.to_lowercase().contains("connection: close"),
            "the response announces the close: {text}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ignored_body_is_drained_so_the_connection_stays_usable() {
    // The handler never reads the 5-byte body. The transport must consume it before
    // the next request, or the next request's head would be read out of this body.
    let server = support::server_with(ServerConfig::for_tests(), Arc::new(IgnoresBody)).await;
    with_server(server, |address| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"POST /a HTTP/1.1\r\nHost: probe\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .expect("write");
        let first = read_until(&mut stream, response_complete).await;
        assert!(
            String::from_utf8_lossy(&first).ends_with("ignored"),
            "{}",
            String::from_utf8_lossy(&first)
        );

        stream
            .write_all(b"GET /b HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let second = read_until(&mut stream, response_complete).await;
        assert!(
            second.starts_with(b"HTTP/1.1 200 OK"),
            "the second request was answered: {}",
            String::from_utf8_lossy(&second)
        );
        let mut rest = Vec::new();
        let _ = stream.read(&mut rest).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunked_request_body_is_decoded() {
    let server = support::echo_server().await;
    with_server(server, |address| async move {
        let response = exchange(
            address,
            b"POST /chunked HTTP/1.1\r\nHost: probe\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n",
            response_complete,
        )
        .await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.ends_with("hello!"), "chunks are reassembled: {text}");
    })
    .await;
}

/// A handler that declares chunked framing must produce a message a chunked *decoder*
/// accepts. This is the regression guard for the framing mismatch that once let a chunked
/// head go out with raw bytes under it.
/// A real keep-alive connection serving two requests must yield two per-exchange
/// derivations, each with its own handler span — and a single `derive_ingress` over the
/// whole connection must refuse rather than describe only the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_two_request_connection_yields_two_exchanges_from_the_real_transport() {
    use netune_trace::{
        Reason, Validity, derive_ingress, derive_ingress_exchanges, exchange_count,
    };

    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = ServerConfig::for_tests().with_trace_sink(Arc::clone(&observer) as _);
    let (handler, count) = Counting::new(Duration::from_millis(5));
    let server = support::server_with(config, Arc::new(handler)).await;

    with_server(server, |address| async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        for _ in 0..2 {
            stream
                .write_all(b"GET /twice HTTP/1.1\r\nHost: probe\r\n\r\n")
                .await
                .expect("write");
            let response = read_until(&mut stream, response_complete).await;
            assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        }
        drop(stream);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    })
    .await;

    let ingress = observer
        .take()
        .into_iter()
        .next()
        .expect("the connection was traced");
    assert_eq!(ingress.exchanges, 2, "the transport counted two exchanges");
    assert_eq!(exchange_count(&ingress.log), 2);

    let trace = netune_trace::RequestTrace {
        id: netune_trace::TraceId::new("two"),
        attempt: netune_trace::AttemptRef {
            round: 0,
            turn: 0,
            attempt: 0,
        },
        endpoint: netune_trace::EndpointRef {
            provider: String::new(),
            model: String::new(),
            authority: address_string(),
        },
        connection: netune_trace::ConnectionInfo::default(),
        identity: netune_trace::ConnectionIdentity::default(),
        schema_version: netune_trace::TRACE_SCHEMA_VERSION,
        fidelity: netune_trace::Fidelity::l1(),
        log: ingress.log,
    };

    // A single derivation must refuse: one set of spans cannot describe two requests.
    let whole = derive_ingress(&trace);
    assert_eq!(whole.handler_us.value(), None);
    assert_eq!(
        whole.handler_us.validity(),
        Validity::NotEstimable(Reason::MultipleExchanges)
    );

    // The per-exchange view must describe both, each with a measured handler span.
    let exchanges = derive_ingress_exchanges(&trace);
    assert_eq!(exchanges.len(), 2);
    for (index, exchange) in exchanges.iter().enumerate() {
        assert!(
            exchange.handler_us.is_measured(),
            "exchange {index} has a measured handler span: {:?}",
            exchange.handler_us.validity()
        );
        assert_eq!(exchange.status.value(), Some(200));
        assert!(
            exchange.request_read_us.is_measured(),
            "exchange {index} has its own read span: {:?}",
            exchange.request_read_us.validity()
        );
    }
}

fn address_string() -> String {
    "127.0.0.1:0".to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunked_response_from_the_orchestrator_is_correctly_framed() {
    struct Chunked;

    impl netune_server::Handler for Chunked {
        fn handle<'a>(
            &'a self,
            _request: netune_server::IncomingRequest,
            _body: netune_server::RequestBody<'a>,
        ) -> netune_server::HandlerFuture<'a> {
            Box::pin(async move {
                let mut response = netune_server::Response::ok(&b"hello world"[..]);
                response.head = response.head.with_chunked_body();
                response
            })
        }
    }

    let server = support::server_with(ServerConfig::for_tests(), Arc::new(Chunked)).await;
    with_server(server, |address| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /chunked HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("closed")
            .expect("read");

        let text = String::from_utf8_lossy(&collected);
        let body = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("a head terminator in {text:?}"))
            .1;
        assert!(
            body.starts_with("b\r\nhello world\r\n"),
            "the body is chunk-framed, not raw: {body:?}"
        );
        assert!(
            body.ends_with("0\r\n\r\n"),
            "the body is terminated: {body:?}"
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
        assert_eq!(&decoded[..], b"hello world");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_no_content_status_carries_no_body() {
    let server = support::server_with(
        ServerConfig::for_tests(),
        Arc::new(Fixed {
            status: http::StatusCode::NO_CONTENT,
            body: bytes::Bytes::from_static(b"must not appear"),
        }),
    )
    .await;
    with_server(server, |address| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /none HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("closed")
            .expect("read");
        let text = String::from_utf8_lossy(&collected);
        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"), "{text}");
        assert!(!text.contains("must not appear"), "{text}");
        assert!(!text.to_lowercase().contains("content-length"), "{text}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_connection_is_shed_when_the_cap_is_reached() {
    // One permit, held by a connection that never finishes its head. The second
    // connection must be closed rather than queued.
    let config = ServerConfig::for_tests()
        .with_max_connections(1)
        .with_head_timeout(Duration::from_secs(30));
    let (handler, count) = Counting::new(Duration::ZERO);
    let server = support::server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut first = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        // An incomplete head: the first connection holds its permit.
        first
            .write_all(b"GET /slow HTTP/1.1\r\n")
            .await
            .expect("write");

        // Give the accept loop a moment to admit the first connection.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut second = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        second
            .write_all(b"GET /shed HTTP/1.1\r\nHost: probe\r\n\r\n")
            .await
            .expect("write");
        let mut buffer = [0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buffer))
            .await
            .expect("the shed connection must not hang");

        // The shed is a close, and which close the kernel picks depends on whether our
        // unread request bytes are still buffered: a clean `FIN` when the peer's data
        // has been drained, a `RST` when it has not. Both are the same fact — the
        // connection ended immediately, with no response and no work done — so the test
        // asserts that fact rather than an implementation detail of the TCP stack.
        match read {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(read) => panic!(
                "a shed connection must not be answered, got {read} bytes: {}",
                String::from_utf8_lossy(&buffer[..read])
            ),
            Err(error) => panic!("unexpected read error: {error}"),
        }
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "neither connection reached the handler"
        );
        drop(first);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_never_finishes_its_head_is_closed_at_the_deadline() {
    let config = ServerConfig::for_tests().with_head_timeout(Duration::from_millis(200));
    let (handler, count) = Counting::new(Duration::ZERO);
    let server = support::server_with(config, Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        // A head that never terminates: the slow-loris shape.
        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: probe\r\n")
            .await
            .expect("write");
        let mut collected = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("the server must close the connection at the deadline");
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a peer that never produced a head never reaches the handler"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_smuggling_shape_is_refused_before_the_handler() {
    let (handler, count) = Counting::new(Duration::ZERO);
    let server = support::server_with(ServerConfig::for_tests(), Arc::new(handler)).await;
    with_server(server, |address| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // CL.TE
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(
                b"POST /smuggle HTTP/1.1\r\nHost: probe\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            )
            .await
            .expect("write");
        let mut collected = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
            .await
            .expect("the connection is closed on a framing violation");
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a smuggling shape never reaches application code"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_drains_an_in_flight_request_instead_of_cutting_it() {
    // The handler takes 300 ms; shutdown arrives while it is running. The response
    // must still arrive, and the drain must not return before it does.
    let config = ServerConfig::for_tests().with_drain_timeout(Duration::from_secs(5));
    let (handler, count) = Counting::new(Duration::from_millis(300));
    let server = support::server_with(config, Arc::new(handler)).await;
    let address = server.local_addr();

    let (shutdown, wait) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = wait.await;
            })
            .await;
    });

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");

    // Let the request reach the handler, then shut down.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown.send(());

    let mut collected = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut collected))
        .await
        .expect("the in-flight response is delivered during the drain")
        .expect("read");
    assert!(
        String::from_utf8_lossy(&collected).ends_with("counted"),
        "the drain let the handler finish: {}",
        String::from_utf8_lossy(&collected)
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("the drain finished")
        .expect("no panic");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bind_refuses_an_unusable_configuration_before_taking_a_port() {
    let error = Server::bind(
        "127.0.0.1:0",
        ServerConfig::for_tests().with_max_connections(0),
        Arc::new(Echo),
    )
    .await
    .expect_err("a zero connection cap is refused");
    assert!(
        format!("{error}").contains("max_connections"),
        "the reason names the field: {error}"
    );
}
