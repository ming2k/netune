//! The request-level seam, driven from the outside.
//!
//! These tests hold one claim to account: a `Client` over a `Mock` runs the
//! same client code a real connection does. Redirects, decoding, bounds and
//! the trace are exercised here without a socket, and the last tests put the
//! mock and the real wire behind the same client.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write as _;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use netune::mock::{Matcher, Mock, MockResponse};
use netune::{
    BodyState, Client, ClientConfig, Fault, FaultConnector, FaultScript, Pool, RequestHead, Target,
    TcpConnector, TraceConfig,
};
use netune_trace::{DiagnosticCode, EventKind, Fidelity, derive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn client(mock: &Mock) -> Client {
    Client::with_transport(mock.clone(), ClientConfig::default())
}

fn client_with(mock: &Mock, config: ClientConfig) -> Client {
    Client::with_transport(mock.clone(), config)
}

fn target() -> Target {
    Target::plain("api.example:80")
}

async fn get(client: &Client, target: &Target, path: &str) -> (StatusCode, Bytes) {
    let mut response = client
        .request(target, RequestHead::new(Method::GET, path), None)
        .await
        .expect("request");
    let body = response.body.read_to_end().await.expect("body");
    (response.head.status, body)
}

#[tokio::test]
async fn inv_exchange_01_a_mocked_route_answers_and_records_the_call() {
    let mock = Mock::new();
    mock.on(Matcher::get("/health"))
        .reply(MockResponse::ok("up"));
    let client = client(&mock);

    let (status, body) = get(&client, &target(), "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"up");

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].authority, "api.example:80");
    assert_eq!(calls[0].target, "/health");
    assert!(
        calls[0].headers.contains_key("user-agent"),
        "the transport sees the request after the client's own headers were added"
    );
    assert_eq!(mock.hits(&Matcher::get("/health")), 1);
    assert_eq!(mock.hits(&Matcher::post("/health")), 0);
}

#[tokio::test]
async fn one_shot_replies_script_a_sequence_before_the_standing_reply() {
    let mock = Mock::new();
    mock.on(Matcher::post("/jobs"))
        .reply_once(MockResponse::new(StatusCode::SERVICE_UNAVAILABLE))
        .reply_once(MockResponse::new(StatusCode::TOO_MANY_REQUESTS))
        .reply(MockResponse::new(StatusCode::CREATED));
    let client = client(&mock);

    let mut statuses = Vec::new();
    for _ in 0..4 {
        let response = client
            .request(&target(), RequestHead::new(Method::POST, "/jobs"), "{}")
            .await
            .expect("request");
        statuses.push(response.head.status.as_u16());
    }
    assert_eq!(statuses, [503, 429, 201, 201]);
    assert_eq!(mock.calls()[0].body.as_ref(), b"{}");
}

#[tokio::test]
async fn a_reply_can_be_computed_from_the_request() {
    let mock = Mock::new();
    mock.on(Matcher::any().path_prefix("/echo/"))
        .reply_with(|request| MockResponse::ok(request.target.clone()));
    let client = client(&mock);
    let (_, body) = get(&client, &target(), "/echo/abc").await;
    assert_eq!(body.as_ref(), b"/echo/abc");
}

#[tokio::test]
async fn an_unmatched_request_fails_with_evidence_instead_of_reaching_anything() {
    let mock = Mock::new();
    let client = client(&mock);
    let error = client
        .request(&target(), RequestHead::new(Method::GET, "/nope"), None)
        .await
        .expect_err("no route");
    assert!(error.to_string().contains("no route matches GET /nope"));
    assert!(error.trace().diagnostics.last_error().is_some());
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn a_mocked_redirect_is_followed_and_credentials_stay_on_the_origin() {
    let mock = Mock::new();
    mock.on(Matcher::get("/start").authority("api.example:80"))
        .reply(MockResponse::redirect(
            StatusCode::FOUND,
            "http://elsewhere.example/landed",
        ));
    mock.on(Matcher::get("/landed").authority("elsewhere.example:80"))
        .reply(MockResponse::ok("landed"));
    let client = client(&mock);

    let head = RequestHead::new(Method::GET, "/start").with_header("authorization", "secret");
    let mut response = client
        .request(&target(), head, None)
        .await
        .expect("request");
    assert_eq!(
        response.body.read_to_end().await.expect("body").as_ref(),
        b"landed"
    );

    let calls = mock.calls();
    assert_eq!(calls.len(), 2, "one call per hop");
    assert!(calls[0].headers.contains_key("authorization"));
    assert!(
        !calls[1].headers.contains_key("authorization"),
        "credentials never follow a redirect off the original origin"
    );
}

#[tokio::test]
async fn a_mocked_encoded_body_is_decoded_by_the_client() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"hello, decoded world").expect("gzip");
    let compressed = encoder.finish().expect("gzip");

    let mock = Mock::new();
    mock.on(Matcher::get("/gz"))
        .reply(MockResponse::ok(compressed).header("content-encoding", "gzip"));
    let client = client(&mock);

    let mut response = client
        .request(&target(), RequestHead::new(Method::GET, "/gz"), None)
        .await
        .expect("request");
    assert!(
        !response.head.headers.contains_key("content-encoding"),
        "an encoding the client decoded is not left for anyone to decode again"
    );
    assert_eq!(
        response.body.read_to_end().await.expect("body").as_ref(),
        b"hello, decoded world"
    );
}

#[tokio::test]
async fn a_mocked_attempt_leaves_a_trace_at_the_fidelity_it_really_had() {
    let mock = Mock::new();
    mock.on(Matcher::get("/stream")).reply(
        MockResponse::new(StatusCode::OK)
            .chunks(["one", "two", "three"])
            .delay_head(Duration::from_millis(20))
            .delay_chunks(Duration::from_millis(5)),
    );
    let client = client(&mock);

    let mut response = client
        .request_traced(
            &target(),
            RequestHead::new(Method::GET, "/stream"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect("request");
    assert!(
        response.body.trace().is_none(),
        "an attempt still in flight has no trace to hand out"
    );
    let mut chunks = 0;
    while response.body.next_chunk().await.expect("chunk").is_some() {
        chunks += 1;
    }
    assert_eq!(chunks, 3);

    let trace = response.body.trace().expect("a traced attempt has a trace");
    assert_eq!(
        trace.fidelity,
        Fidelity::l0(),
        "no socket was involved, so the trace claims protocol events only"
    );
    assert_eq!(trace.authority, "api.example:80");
    assert_eq!(
        trace
            .log
            .iter()
            .filter(|event| event.kind == EventKind::ChunkBoundary)
            .count(),
        3
    );
    let derived = derive(&trace);
    let ttfb = derived.ttfb_us.value().expect("ttfb is measured");
    assert!(
        ttfb >= 20_000,
        "the scripted head delay is what the trace measured: {ttfb} us"
    );
}

#[tokio::test]
async fn inv_trace_09_a_body_that_fails_part_way_returns_its_trace() {
    let mock = Mock::new();
    mock.on(Matcher::get("/cut")).reply(
        MockResponse::new(StatusCode::OK)
            .chunks(["first", "second", "third"])
            .fail_after_chunks(1, std::io::ErrorKind::ConnectionReset),
    );
    let client = client(&mock);

    let mut response = client
        .request_traced(
            &target(),
            RequestHead::new(Method::GET, "/cut"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect("the head arrives");
    assert_eq!(
        response.body.next_chunk().await.expect("first chunk"),
        Some(Bytes::from_static(b"first"))
    );
    let error = response
        .body
        .next_chunk()
        .await
        .expect_err("the stream is cut");

    // The failure carries the evidence...
    let snapshot = error.trace();
    assert!(snapshot.log.first_of(EventKind::HeadComplete).is_some());
    assert!(snapshot.log.first_of(EventKind::BodyStart).is_some());
    assert!(snapshot.log.first_of(EventKind::Error).is_some());
    assert!(snapshot.log.first_of(EventKind::BodyEnd).is_none());
    assert_eq!(error.diagnostic().code, DiagnosticCode::EGRESS_IO);

    // ...and so does the body, which is now terminal.
    assert_eq!(response.body.state(), BodyState::Failed);
    let trace = response
        .body
        .trace()
        .expect("a failed body still has a trace");
    assert!(trace.log.first_of(EventKind::Error).is_some());
    assert!(
        response.body.next_chunk().await.is_err(),
        "a failed body stays closed"
    );
}

#[tokio::test]
async fn inv_trace_09_an_abandoned_body_has_a_trace() {
    let mock = Mock::new();
    mock.on(Matcher::get("/long"))
        .reply(MockResponse::new(StatusCode::OK).chunks(["a", "b", "c"]));
    let client = client(&mock);

    let mut response = client
        .request_traced(
            &target(),
            RequestHead::new(Method::GET, "/long"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect("request");
    let _ = response.body.next_chunk().await.expect("one chunk");
    assert!(response.body.trace().is_none());

    response.body.abandon();
    assert_eq!(response.body.state(), BodyState::Abandoned);
    let trace = response
        .body
        .trace()
        .expect("an abandoned body has a trace");
    assert!(trace.log.first_of(EventKind::BodyStart).is_some());
    assert!(
        trace.log.first_of(EventKind::BodyEnd).is_none(),
        "the trace does not claim an end the body never reached"
    );
}

#[tokio::test]
async fn a_head_that_never_comes_trips_the_bound_and_returns_evidence() {
    let mock = Mock::new();
    mock.on(Matcher::get("/stall"))
        .reply(MockResponse::ok("late").delay_head(Duration::from_secs(30)));
    let client = client_with(
        &mock,
        ClientConfig {
            response_head_timeout: Some(Duration::from_millis(30)),
            ..ClientConfig::default()
        },
    );

    let error = client
        .request_traced(
            &target(),
            RequestHead::new(Method::GET, "/stall"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect_err("the head bound expires");
    assert!(error.is_timeout());
    assert!(error.is_retryable());
    assert!(
        !error.is_stale_connection(),
        "a silent origin is not a dead pooled socket and is never replayed"
    );
    assert_eq!(error.diagnostic().code, DiagnosticCode::EGRESS_TIMEOUT);
    assert!(
        error
            .trace()
            .log
            .first_of(EventKind::RequestWriteEnd)
            .is_some(),
        "the evidence shows the request was sent before the silence"
    );
}

#[tokio::test]
async fn a_trickling_body_trips_the_total_attempt_bound() {
    let mock = Mock::new();
    mock.on(Matcher::get("/trickle")).reply(
        MockResponse::new(StatusCode::OK)
            .chunks(["x"; 10])
            .delay_chunks(Duration::from_millis(20)),
    );
    let client = client_with(
        &mock,
        ClientConfig {
            request_timeout: Some(Duration::from_millis(70)),
            body_idle_timeout: Some(Duration::from_secs(5)),
            ..ClientConfig::default()
        },
    );

    let mut response = client
        .request(&target(), RequestHead::new(Method::GET, "/trickle"), None)
        .await
        .expect("head");
    let error = response
        .body
        .read_to_end()
        .await
        .expect_err("the total attempt bound expires");
    assert!(error.is_timeout());
}

#[tokio::test]
async fn a_body_that_goes_quiet_trips_the_idle_bound_but_a_long_one_does_not() {
    let mock = Mock::new();
    // Ten chunks, 10 ms apart: far longer in total than the idle bound, never
    // quiet for longer than it.
    mock.on(Matcher::get("/steady")).reply(
        MockResponse::new(StatusCode::OK)
            .chunks(["x"; 10])
            .delay_chunks(Duration::from_millis(10)),
    );
    mock.on(Matcher::get("/quiet")).reply(
        MockResponse::new(StatusCode::OK)
            .chunks(["x", "y"])
            .delay_chunks(Duration::from_secs(30)),
    );
    let client = client_with(
        &mock,
        ClientConfig {
            body_idle_timeout: Some(Duration::from_millis(60)),
            ..ClientConfig::default()
        },
    );

    let (_, body) = get(&client, &target(), "/steady").await;
    assert_eq!(body.len(), 10, "a long stream is never cut for being long");

    let mut response = client
        .request(&target(), RequestHead::new(Method::GET, "/quiet"), None)
        .await
        .expect("head");
    let error = response
        .body
        .read_to_end()
        .await
        .expect_err("the idle bound expires");
    assert!(error.is_timeout());
    assert_eq!(response.body.state(), BodyState::Failed);
}

/// A real origin on a real socket: answers every request with `body`.
async fn origin(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match socket.read(&mut buffer).await {
                        Ok(read) if read > 0 => request.extend_from_slice(&buffer[..read]),
                        _ => return,
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    address
}

#[tokio::test]
async fn unmatched_requests_can_fall_through_to_the_real_wire() {
    let address = origin("from the wire").await;
    let mock = Mock::new();
    mock.on(Matcher::get("/mocked"))
        .reply(MockResponse::ok("from the mock"));
    mock.fallback(netune::Wire::new(TcpConnector::new(), Pool::default()));
    let client = client(&mock);
    let target = Target::plain(address.to_string());

    assert_eq!(
        get(&client, &target, "/mocked").await.1.as_ref(),
        b"from the mock"
    );
    assert_eq!(
        get(&client, &target, "/real").await.1.as_ref(),
        b"from the wire"
    );
    assert_eq!(mock.calls().len(), 1, "only the mocked call is recorded");
}

#[tokio::test]
async fn a_fault_connector_disturbs_a_real_connection_on_a_script() {
    let address = origin("0123456789abcdef0123456789abcdef").await;
    // Reset the connection 60 bytes into the response: past the head, inside
    // the body.
    let connector = FaultConnector::new(TcpConnector::new(), |_target| {
        FaultScript::new([(60, Fault::Reset)])
    });
    let client = Client::new(connector, Pool::default(), ClientConfig::default());
    let target = Target::plain(address.to_string());

    let mut response = client
        .request_traced(
            &target,
            RequestHead::new(Method::GET, "/"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect("the head arrives before the fault");
    let error = response
        .body
        .read_to_end()
        .await
        .expect_err("the scripted reset cuts the body");
    assert_eq!(
        error.io_error_kind(),
        Some(std::io::ErrorKind::ConnectionReset)
    );
    let trace = response.body.trace().expect("trace");
    assert_eq!(
        trace.fidelity,
        Fidelity::l1(),
        "a real socket under the fault layer still reports its socket events"
    );
    assert!(trace.log.bytes_read() > 0);
}

#[cfg(feature = "ws")]
#[tokio::test]
async fn a_websocket_upgrade_runs_over_a_mocked_stream() {
    use netune::WsMessage;

    let (ours, mut peer) = tokio::io::duplex(4096);
    let mock = Mock::new();
    mock.push_stream(ours);
    let client = client(&mock);

    let server = tokio::spawn(async move {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = peer.read(&mut buffer).await.expect("read upgrade");
            request.extend_from_slice(&buffer[..read]);
        }
        let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        let key_line = text
            .lines()
            .find(|line| line.starts_with("sec-websocket-key:"))
            .expect("key header");
        // Header values are case-sensitive; recover the original bytes.
        let offset = text.find(key_line).expect("offset") + "sec-websocket-key:".len();
        let original = String::from_utf8_lossy(&request);
        let key = original[offset..]
            .lines()
            .next()
            .expect("key value")
            .trim()
            .to_string();
        let accept = netune_ws::compute_accept_key(&key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\
             sec-websocket-accept: {accept}\r\n\r\n"
        );
        peer.write_all(response.as_bytes()).await.expect("101");
        // One unmasked server text frame: FIN + text, 5 bytes.
        peer.write_all(&[0x81, 0x05, b'h', b'e', b'l', b'l', b'o'])
            .await
            .expect("frame");
        peer
    });

    let mut stream = client
        .connect_ws(&target(), "/socket")
        .await
        .expect("upgrade over the mocked stream");
    let message = stream.receive().await.expect("receive").expect("message");
    assert!(matches!(message, WsMessage::Text(text) if text == "hello"));
    drop(server.await.expect("join"));
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn mock_routes_http3_targets_identically() {
    use netune::HttpProtocol;

    let mock = Mock::new();
    mock.on(Matcher::get("/v1/models"))
        .reply(MockResponse::ok("h3-mock-ok"));
    let client = client(&mock);

    let h3_target =
        Target::tls("api.example:443", "api.example").with_protocol(HttpProtocol::Http3);
    let mut response = client
        .request(
            &h3_target,
            RequestHead::new(Method::GET, "/v1/models"),
            None,
        )
        .await
        .expect("mock H3 target");
    assert_eq!(response.head.status.as_u16(), 200);
    assert_eq!(
        response.body.read_to_end().await.expect("body").as_ref(),
        b"h3-mock-ok"
    );
    assert_eq!(mock.calls().len(), 1);
}
