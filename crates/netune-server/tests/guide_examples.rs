#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Compile-and-run guard for `docs/how-to/serve-http.md`.
//!
//! The guide shows code that must stay true to the real API. Every snippet below is
//! transcribed from it (modulo the port, which the guide fixes and a test cannot) and
//! *executed*, so a guide that drifts from the API fails CI instead of lying to readers.
//!
//! The guide's claims about ingress timings are asserted too: a table of readings that
//! nothing verifies would be prose, not documentation.

use std::sync::Arc;
use std::time::Duration;

use netune_server::{
    Handler, HandlerFuture, IncomingRequest, Limits, RequestBody, Response, Server, ServerConfig,
};
use netune_trace::derive_ingress;

// -- 1. Write a handler (verbatim from the guide) -----------------------------

struct Echo;

impl Handler for Echo {
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

// -- 4. Collect the trace (verbatim, modulo printing) -------------------------

/// The guide's observer, as the crate ships it: one finished connection, one trace.
///
/// The guide tells a consumer to install an observer; this is that type, used the way the
/// guide uses it. What it receives is a complete `IngressTrace`, so `derive_ingress` can be
/// called on it directly rather than on something the consumer reassembled.
type Collecting = netune_server::CollectingObserver;

/// The guide's `Response::ok(bytes)` path, end to end.
#[tokio::test(flavor = "multi_thread")]
async fn the_guide_handler_echoes_a_body() {
    let server = Server::bind("127.0.0.1:0", ServerConfig::for_tests(), Arc::new(Echo))
        .await
        .expect("bind");
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
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: guide\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
        .expect("write");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("the server closes after `Connection: close`")
        .expect("read");
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.ends_with("hello"), "{text}");

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("drained")
        .expect("no panic");
}

/// The guide's config chain must be the real one, and it must bind.
#[tokio::test(flavor = "multi_thread")]
async fn the_guide_configuration_chain_binds() {
    let config = ServerConfig::default()
        .with_limits(Limits::for_ingress())
        .with_max_connections(256)
        .with_head_timeout(Duration::from_secs(10))
        .with_body_timeout(Duration::from_secs(60))
        .with_handler_timeout(Duration::from_secs(120))
        .with_drain_timeout(Duration::from_secs(30))
        .with_trace_sink(Arc::new(Collecting::default()));

    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("the documented configuration binds");
    assert_ne!(server.local_addr().port(), 0, "a real port was assigned");
}

/// Every reading in the guide's table is measured for a real exchange.
///
/// This is what makes the table documentation rather than a claim: each span named in the
/// guide is asserted to be present, and the two the guide says must be distinguishable —
/// slow client versus slow handler — are read from separate fields.
#[tokio::test(flavor = "multi_thread")]
async fn the_guide_timing_table_describes_a_real_exchange() {
    let sink = Arc::new(Collecting::default());
    let config = ServerConfig::for_tests().with_trace_sink(Arc::clone(&sink) as _);
    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("bind");
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
        .write_all(b"POST /timed HTTP/1.1\r\nHost: guide\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
        .await
        .expect("write");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "served");

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("drained")
        .expect("no panic");

    // The trace the guide promises: complete, and directly derivable.
    let ingress = sink
        .take()
        .into_iter()
        .next()
        .expect("the observer received one finished connection");
    assert!(ingress.exchanges >= 1);
    let log = ingress.log;

    let trace = netune_trace::RequestTrace {
        meta: netune_trace::TraceMeta::new(
            netune_trace::TraceId::new("guide"),
            netune_trace::Direction::Ingress,
        ),
        attempt: netune_trace::AttemptRef {
            round: 0,
            turn: 0,
            attempt: 0,
        },
        endpoint: netune_trace::EndpointRef {
            provider: String::new(),
            model: String::new(),
            authority: address.to_string(),
        },
        connection: netune_trace::ConnectionInfo::default(),
        identity: netune_trace::ConnectionIdentity::default(),
        schema_version: netune_trace::TRACE_SCHEMA_VERSION,
        fidelity: netune_trace::Fidelity::l1(),
        log,
        diagnostics: netune_trace::DiagnosticTable::default(),
    };

    // The guide's inline example, exercised.
    let derived = derive_ingress(&trace);
    let handler = derived
        .handler_us
        .value()
        .expect("the guide promises `handler_us`");
    let read = derived
        .request_read_us
        .value()
        .expect("the guide promises `request_read_us`");
    let _ = (handler, read);

    for (name, reading) in [
        ("request_read_us", derived.request_read_us),
        ("handler_us", derived.handler_us),
        ("write_start_us", derived.write_start_us),
        ("write_us", derived.write_us),
        ("response_write_us", derived.response_write_us),
        ("ingress_e2e_us", derived.ingress_e2e_us),
    ] {
        assert!(
            reading.is_measured(),
            "the guide's table claims `{name}` is derivable: {:?}",
            reading.validity()
        );
    }
}

/// The guide's "a body you do not read is drained for you" claim.
#[tokio::test(flavor = "multi_thread")]
async fn the_guide_claim_about_unread_bodies_holds() {
    struct Ignores;

    impl Handler for Ignores {
        fn handle<'a>(
            &'a self,
            _request: IncomingRequest,
            _body: RequestBody<'a>,
        ) -> HandlerFuture<'a> {
            Box::pin(async move { Response::ok(&b"done"[..]) })
        }
    }

    let server = Server::bind("127.0.0.1:0", ServerConfig::for_tests(), Arc::new(Ignores))
        .await
        .expect("bind");
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
    // A body the handler never reads, then a second request on the same connection.
    stream
        .write_all(b"POST /a HTTP/1.1\r\nHost: guide\r\nContent-Length: 5\r\n\r\nhello")
        .await
        .expect("write");
    let mut first = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await.expect("read");
        first.extend_from_slice(&buffer[..read]);
        if first.ends_with(b"done") {
            break;
        }
    }
    stream
        .write_all(b"GET /b HTTP/1.1\r\nHost: guide\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut second = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut second)).await;
    assert!(
        second.starts_with(b"HTTP/1.1 200 OK"),
        "the unread body was drained and the connection stayed usable: {}",
        String::from_utf8_lossy(&second)
    );

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("drained")
        .expect("no panic");
}
