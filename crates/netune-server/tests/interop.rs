//! The workspace's two orchestrators, in one test.
//!
//! `netune` (egress) and `netune-server` (ingress) must not depend on each other in
//! production (`[INV-SERVER-01]`), which means neither crate's own suite can prove
//! they interoperate. This suite is where that proof lives: it depends on both as a
//! dev-dependency, so neither has to.
//!
//! What is being proven is not "HTTP works" — `hyper` already believes that. It is that
//! **one request produces a client trace and a server trace that both derive**,
//! anchored on their own origins, so a stack operator can tell a slow handler from a
//! slow link because both ends are ours ([INV-TRACE-01], [INV-SERVER-02]).

#![allow(clippy::expect_used, clippy::unwrap_used)]
mod support;

use std::sync::Arc;
use std::time::Duration;

use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TraceConfig};
use netune_server::{Server, ServerConfig};
use netune_trace::{TraceCollector, TracePropagation, derive, derive_ingress};

/// Serve `server` in the background, returning its address, a shutdown trigger and the
/// serving task.
fn spawn(
    server: Server,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let address = server.local_addr();
    let (shutdown, wait) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = wait.await;
            })
            .await;
    });
    (address, shutdown, handle)
}

fn client() -> Client<TcpConnector> {
    Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn our_client_and_our_server_complete_a_request() {
    let server = support::echo_server().await;
    let (address, shutdown, handle) = spawn(server);

    let target = Target::plain(format!("127.0.0.1:{}", address.port()));
    let head =
        RequestHead::new(http::Method::POST, "/echo").with_header("content-type", "text/plain");
    let recorder = TraceCollector::start(1024);

    let mut response = client()
        .send_traced(&target, recorder, head, None)
        .await
        .expect("the request completes against our own server");
    assert_eq!(response.head.status, http::StatusCode::OK);
    assert_eq!(
        response
            .head
            .headers
            .get("x-method")
            .map(|value| value.to_str().unwrap()),
        Some("POST"),
        "the server's handler saw the method we sent"
    );
    let body = response.body.read_to_end().await.expect("body");
    assert_eq!(&body[..], b"", "an empty request body echoes back empty");
    drop(response);

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("drained")
        .expect("no panic");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_propagated_trace_id_joins_the_client_and_server_records() {
    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = ServerConfig::for_tests()
        .with_trace_sink(Arc::clone(&observer) as _)
        .with_trace_propagation(TracePropagation::Header("x-netune-request-id"));
    let server = support::server_with(config, Arc::new(support::Echo)).await;
    let (address, shutdown, handle) = spawn(server);

    let target = Target::plain(format!("127.0.0.1:{}", address.port()));
    let head = RequestHead::new(http::Method::GET, "/joined");
    let mut response = client()
        .request_traced(
            &target,
            head,
            None,
            TraceConfig::new(1024)
                .with_propagation(TracePropagation::Header("x-netune-request-id")),
        )
        .await
        .expect("request");
    let body = response.body.read_to_end().await.expect("body");
    assert!(body.is_empty());
    let client_trace = response.body.trace().expect("client trace");
    drop(response);

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("drained")
        .expect("no panic");

    let traces = observer.take();
    assert_eq!(traces.len(), 1, "the listener traced the connection");
    assert_eq!(
        client_trace.meta.id, traces[0].meta.id,
        "the propagated id is the same on both ends"
    );
    assert_eq!(traces[0].diagnostics.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_survives_the_round_trip_between_our_two_orchestrators() {
    let server = support::echo_server().await;
    let (address, shutdown, handle) = spawn(server);

    let target = Target::plain(format!("127.0.0.1:{}", address.port()));
    let payload = r#"{"messages":[{"role":"user","content":"hello"}]}"#;
    let head = RequestHead::new(http::Method::POST, "/v1/echo")
        .with_header("content-type", "application/json");
    let recorder = TraceCollector::start(1024);

    let mut response = client()
        .send_traced(
            &target,
            recorder,
            head,
            Some(bytes::Bytes::from_static(payload.as_bytes())),
        )
        .await
        .expect("request");
    let mut body = Vec::new();
    while let Some(chunk) = response.body.next_chunk().await.expect("chunk") {
        body.extend_from_slice(&chunk);
    }
    assert_eq!(
        String::from_utf8_lossy(&body),
        payload,
        "the body crossed both orchestrators byte for byte"
    );
    drop(response);

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("drained")
        .expect("no panic");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_egress_trace_derives_a_measured_ttfb() {
    let server = support::echo_server().await;
    let (address, shutdown, handle) = spawn(server);

    let target = Target::plain(format!("127.0.0.1:{}", address.port()));
    let head = RequestHead::new(http::Method::GET, "/trace");
    let recorder = TraceCollector::start(1024);

    let mut response = client()
        .send_traced(&target, recorder, head, None)
        .await
        .expect("request");
    let _ = response.body.read_to_end().await.expect("body");
    let trace = response.body.trace().expect("the trace is complete");
    drop(response);

    let derived = derive(&trace);
    assert!(
        derived.ttfb_us.is_measured(),
        "a real loopback exchange measures a TTFB: {:?}",
        derived.ttfb_us.validity()
    );
    assert!(
        derived.tcp_us.is_measured(),
        "the connection was not pooled, so its establishment is measured"
    );

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("drained")
        .expect("no panic");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ingress_trace_from_a_real_exchange_derives_every_phase() {
    // The server is given a sink; the exchange is performed by our own client; the
    // events the transport actually recorded are then derived. Nothing here asks a
    // handler to report its own numbers — the point is that the transport's record is
    // sufficient.
    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = ServerConfig::for_tests().with_trace_sink(Arc::clone(&observer) as _);
    let server = support::server_with(config, Arc::new(support::Echo)).await;
    let (address, shutdown, handle) = spawn(server);

    let target = Target::plain(format!("127.0.0.1:{}", address.port()));
    let head = RequestHead::new(http::Method::POST, "/measured");
    let recorder = TraceCollector::start(1024);

    let mut response = client()
        .send_traced(&target, recorder, head, None)
        .await
        .expect("request");
    let _ = response.body.read_to_end().await.expect("body");
    drop(response);

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("drained")
        .expect("no panic");

    let traces = observer.take();
    assert_eq!(traces.len(), 1, "one finished connection, one trace");
    let ingress = traces.into_iter().next().expect("the trace");
    assert!(ingress.exchanges >= 1, "the exchange completed");
    assert!(
        !ingress.log.is_empty(),
        "the transport recorded the connection's events"
    );
    let log = ingress.log;

    let trace = netune_trace::RequestTrace {
        meta: netune_trace::TraceMeta::new(
            netune_trace::TraceId::new("ingress"),
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

    let derived = derive_ingress(&trace);
    assert_eq!(
        derived.status.value(),
        Some(200),
        "the handler's status is a recorded fact"
    );
    assert!(
        derived.ingress_e2e_us.is_measured(),
        "accept → response is measured: {:?}",
        derived.ingress_e2e_us.validity()
    );
    assert!(
        derived.handler_us.is_measured(),
        "the handler span is measured: {:?}",
        derived.handler_us.validity()
    );
    assert!(
        derived.request_us.is_measured(),
        "the request read is measured: {:?}",
        derived.request_us.validity()
    );
    assert!(
        derived.write_us.is_measured(),
        "the response write is measured: {:?}",
        derived.write_us.validity()
    );
}

/// Neither orchestrator may depend on the other in production.
///
/// The manifests are read directly because they are what a reviewer reads, and a wrong
/// dependency fails here at the same moment it is added rather than one CI stage later.
/// `netune-server` legitimately lists `netune` under `[dev-dependencies]`, which is the
/// one place the dependency is allowed to exist and the reason this suite can run at
/// all.
#[test]
fn neither_orchestrator_depends_on_the_other_in_production() {
    let egress = include_str!("../../netune/Cargo.toml");
    let ingress = include_str!("../../netune-server/Cargo.toml");

    assert!(
        !egress.contains("netune-server"),
        "`netune` must not depend on the ingress orchestrator, not even as a dev-dependency ([INV-SERVER-01])"
    );

    let production = ingress
        .split("[dev-dependencies]")
        .next()
        .expect("a manifest before its dev section");
    assert!(
        !production.contains("netune = {") && !production.contains("\"../netune\""),
        "`netune-server` must not depend on the egress orchestrator in production ([INV-SERVER-01])"
    );
    assert!(
        ingress.contains("[dev-dependencies]") && ingress.contains("../netune"),
        "the interop suite is the one sanctioned place that dependency exists"
    );
}

#[test]
fn the_shared_leaves_are_the_only_shared_dependencies() {
    let ingress = include_str!("../../netune-server/Cargo.toml");
    let production = ingress
        .split("[dev-dependencies]")
        .next()
        .expect("a manifest before its dev section");
    for leaf in ["netune-http1", "netune-http2", "netune-trace", "netune-io"] {
        assert!(
            production.contains(leaf),
            "`netune-server` must draw on the shared leaf `{leaf}`"
        );
    }
    // WebSocket ingress is a separate, later decision (ADR-0011, ADR-0012), and the probe
    // links none of the stack. A codec leaf appearing here before its decision would be
    // scope creep in a manifest, and the checker below is what makes that a failing test
    // rather than a review note.
    assert!(!production.contains("netune-ws"));
    assert!(!production.contains("netune-probe"));
}

/// The response head this crate exposes is the codec's own type, not a copy.
#[test]
fn the_response_head_is_the_codecs_own_type() {
    let built = netune_server::ResponseHead::new(http::StatusCode::IM_A_TEAPOT);
    let as_codec: netune_http1::ResponseHead = built;
    assert_eq!(as_codec.status, http::StatusCode::IM_A_TEAPOT);
}
