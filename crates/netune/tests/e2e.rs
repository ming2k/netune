//! End-to-end: a real socket, the real codec, the real trace.
//!
//! This is the vertical slice ADR-0200's P0 gate needs: bytes arriving on a
//! socket produce events, events produce derived timings, and the timings say
//! what actually happened (including *not applicable* for phases the pool
//! skipped).

#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_trace::{
    AttemptRef, ConnectionInfo, EndpointRef, EventKind, Fidelity, FrameClass, Reason, Recorder,
    RequestTrace, TraceId, Validity, derive,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CHUNKS: usize = 24;
const CHUNK_GAP: Duration = Duration::from_millis(5);

/// Serve `responses` requests on one keep-alive connection.
async fn serve(listener: TcpListener, responses: usize) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    for _ in 0..responses {
        // Read the request head.
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).await.expect("read request");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        // Head, then a chunked body flushed one frame at a time.
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
            )
            .await
            .expect("head");
        socket.flush().await.expect("flush head");
        // Headers first, then a prefill gap before the first token — the shape
        // a real streaming API has, and the shape that makes `server_ttft_us`
        // estimable rather than batched.
        tokio::time::sleep(CHUNK_GAP).await;
        for i in 0..CHUNKS {
            let frame = format!("data: {i}\n");
            let chunk = format!("{:x}\r\n{frame}\r\n", frame.len());
            socket.write_all(chunk.as_bytes()).await.expect("chunk");
            socket.flush().await.expect("flush chunk");
            tokio::time::sleep(CHUNK_GAP).await;
        }
        socket.write_all(b"0\r\n\r\n").await.expect("end");
        socket.flush().await.expect("flush end");
    }
}

fn trace_of(log: netune_trace::EventLog, authority: &str) -> RequestTrace {
    RequestTrace {
        id: TraceId::new("e2e"),
        attempt: AttemptRef {
            round: 1,
            turn: 1,
            attempt: 1,
        },
        endpoint: EndpointRef {
            provider: "e2e".into(),
            model: "e2e-model".into(),
            authority: authority.to_string(),
        },
        connection: ConnectionInfo::default(),
        fidelity: Fidelity::l1(),
        log,
    }
}

/// Run one request, marking one output token per streamed frame the way a
/// provider adapter would.
async fn request_once(
    client: &Client<TcpConnector>,
    target: &Target,
    recorder: Arc<Mutex<Recorder>>,
) -> usize {
    let head = RequestHead::new(Method::POST, "/v1/chat/completions")
        .with_header("content-type", "application/json");
    let mut response = client
        .send(
            target,
            Arc::clone(&recorder),
            head,
            Some(Bytes::from_static(b"{\"stream\":true}")),
        )
        .await
        .expect("send");
    assert_eq!(response.head.status, http::StatusCode::OK);

    let mut frames = 0usize;
    while let Some(chunk) = response.body.next_chunk().await.expect("chunk") {
        if chunk.starts_with(b"data: ") {
            frames += 1;
            let mut recorder = recorder.lock().expect("recorder");
            recorder.frame(FrameClass::Text, 1);
        }
    }
    let mut recorder = recorder.lock().expect("recorder");
    recorder.mark(EventKind::Validated, 0, 0);
    frames
}

fn client() -> Client<TcpConnector> {
    Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    )
}

/// A peer that answers the first request on a connection, then closes the
/// socket without a `close_notify` — exactly what a load balancer or gateway
/// does to an idle keep-alive connection. The next request on that connection
/// finds a dead socket.
///
/// This is the production shape that surfaced to users as
/// `transport error: peer closed connection without sending TLS close_notify`,
/// in long runs of retries that only a model re-selection (which built a fresh
/// pool) cleared.
async fn serve_then_drop_idle(listener: TcpListener) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    // First request: answer it completely so the client pools the connection.
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = socket.read(&mut buffer).await.expect("read request");
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    socket
        .write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
        )
        .await
        .expect("head");
    let frame = b"data: 0\n";
    socket
        .write_all(format!("{:x}\r\n", frame.len()).as_bytes())
        .await
        .expect("chunk size");
    socket.write_all(frame).await.expect("chunk");
    socket.write_all(b"\r\n0\r\n\r\n").await.expect("end");
    socket.flush().await.expect("flush");
    // Now behave like an idle-culling gateway: hard-close with no alert. The
    // socket sits in the client's pool in this state.
    drop(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_socket_the_peer_dropped_is_replaced_transparently() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    // One server lifetime that answers a request and then hard-closes, followed
    // by a fresh listener on the same port serving the replacement connection.
    let server = tokio::spawn(serve_then_drop_idle(listener));

    let client = client();
    let target = Target::plain(address.to_string());

    // First request populates the pool with a connection the peer then kills.
    let first = request_once(
        &client,
        &target,
        Arc::new(Mutex::new(Recorder::start(4096))),
    )
    .await;
    assert_eq!(first, 1, "the first response is served in full");
    server.await.expect("join");
    assert_eq!(
        client.pool().idle_count(&address.to_string()),
        1,
        "the answered connection is pooled"
    );

    // The pooled socket is now dead. A second request must not fail: the
    // transport discards it, reconnects, and answers — all invisible to the
    // caller. Rebind the same port so the reconnect has somewhere to land.
    let listener = TcpListener::bind(address).await.expect("rebind");
    let server = tokio::spawn(serve(listener, 1));
    let recorder = Arc::new(Mutex::new(Recorder::start(4096)));
    let frames = request_once(&client, &target, Arc::clone(&recorder)).await;
    assert_eq!(
        frames, CHUNKS,
        "the request succeeds on a fresh connection after the stale socket is discarded"
    );
    server.await.expect("join");

    let log = recorder.lock().expect("recorder").log().clone();
    assert_eq!(
        log.iter()
            .filter(|event| event.kind == EventKind::ConnectReused)
            .count(),
        1,
        "exactly one reuse event, carrying the idle age"
    );
    assert!(
        log.iter()
            .any(|event| event.kind == EventKind::ConnectStaleDiscarded),
        "the stale socket is recorded as discarded"
    );
    assert!(
        log.iter().any(|event| event.kind == EventKind::TcpStart),
        "a replacement connection was established"
    );

    // The revocation must reach the derivation: this attempt paid for a
    // handshake, so it may not be reported as having ridden a pooled socket.
    let trace = trace_of(log, &address.to_string());
    let derived = derive(&trace);
    assert!(
        derived.tcp_us.is_measured(),
        "the reconnected attempt measures TCP, not ConnectionReused: {:?}",
        derived.tcp_us.validity()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streaming_attempt_produces_a_derivable_trace() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve(listener, 1));

    let recorder = Arc::new(Mutex::new(Recorder::start(4096)));
    let client = client();
    let target = Target::plain(address.to_string());
    let frames = request_once(&client, &target, Arc::clone(&recorder)).await;
    assert_eq!(frames, CHUNKS);

    let trace = trace_of(
        recorder.lock().expect("recorder").log().clone(),
        &address.to_string(),
    );
    let derived = derive(&trace);

    // Connect phases were measured, not guessed.
    assert!(derived.dns_us.is_measured(), "dns: {:?}", derived.dns_us);
    assert!(derived.tcp_us.is_measured(), "tcp: {:?}", derived.tcp_us);
    // No TLS in this slice: the phase is absent, which is a fact, not a zero.
    assert_eq!(
        derived.tls_us.validity(),
        Validity::NotApplicable(Reason::PhaseAbsent)
    );
    // The byte path was recorded.
    assert!(trace.log.bytes_read() > 0, "reads recorded");
    assert!(trace.log.bytes_written() > 0, "writes recorded");
    assert!(trace.log.first_of(EventKind::HeadComplete).is_some());
    assert!(trace.log.first_of(EventKind::BodyStart).is_some());
    assert!(trace.log.first_of(EventKind::BodyEnd).is_some());
    assert_eq!(trace.log.first_of(EventKind::ConnectReused), None);

    // Derived scopes.
    assert!(derived.ttfb_us.is_measured());
    assert!(derived.first_byte_us.is_measured());
    assert!(derived.ttft_us.is_measured());
    assert!(derived.server_ttft_us.is_measured());
    assert!(derived.e2e_us.is_measured());
    assert!(derived.tail_us.is_measured());
    assert!(derived.stream_us.value().expect("span") > 0);

    // The estimator must agree with the cadence the trace itself recorded. The
    // scripted server's true interval is 5 ms of sleep plus the write cost, so
    // the assertion is derived from the trace rather than hard-coded: what is
    // under test is fidelity, not this machine's timer.
    let token_times: Vec<u64> = trace
        .log
        .iter()
        .filter(|event| event.kind == EventKind::OutputToken)
        .map(|event| event.at_ns)
        .collect();
    assert_eq!(token_times.len(), CHUNKS);
    let span = token_times[CHUNKS - 1] - token_times[0];
    let expected = (CHUNKS - 1) as f64 * 1_000_000_000.0 / span as f64;
    // One rate: tokens over the recorded span. The ledger divides; the trace
    // supplies the span, and this asserts the span tracks the scripted cadence.
    let span_us = derived.stream_us.value().expect("stream span");
    let tps = CHUNKS as f64 * 1_000_000.0 / span_us as f64;
    assert!(
        (tps - expected).abs() / expected < 0.05,
        "span rate {tps} must track the recorded cadence {expected}"
    );
    assert!((50.0..1000.0).contains(&tps), "sanity: {tps}");

    // TCP_INFO sampling: the socket's RTT and retransmit count are recorded
    // while the request is in flight — the only packet-adjacent signal a client
    // can obtain without privileges.
    if cfg!(target_os = "linux") {
        assert!(trace.log.first_of(EventKind::TcpInfo).is_some(), "sampled");
        assert!(derived.rtt_us.is_measured(), "rtt: {:?}", derived.rtt_us);
        assert_eq!(derived.retransmits.value(), Some(0), "clean loopback");
    } else {
        assert_eq!(
            derived.rtt_us.validity(),
            Validity::NotEstimable(Reason::TcpInfoUnavailable)
        );
    }
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_reuse_is_attributed_rather_than_charged_to_the_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve(listener, 2));

    let client = client();
    let target = Target::plain(address.to_string());

    let first = Arc::new(Mutex::new(Recorder::start(4096)));
    request_once(&client, &target, Arc::clone(&first)).await;
    let first_trace = trace_of(
        first.lock().expect("recorder").log().clone(),
        &address.to_string(),
    );
    let first_derived = derive(&first_trace);
    assert!(first_derived.dns_us.is_measured());

    let second = Arc::new(Mutex::new(Recorder::start(4096)));
    request_once(&client, &target, Arc::clone(&second)).await;
    let second_trace = trace_of(
        second.lock().expect("recorder").log().clone(),
        &address.to_string(),
    );
    let second_derived = derive(&second_trace);

    assert!(
        second_trace
            .log
            .first_of(EventKind::ConnectReused)
            .is_some(),
        "second request must record that it reused a connection"
    );
    for reading in [second_derived.dns_us, second_derived.tcp_us] {
        assert_eq!(
            reading.validity(),
            Validity::NotApplicable(Reason::ConnectionReused),
            "a reused connection has no connect phase to measure"
        );
    }
    // The request itself was still fully measured.
    assert!(second_derived.ttfb_us.is_measured());
    assert!(second_derived.ttft_us.is_measured());

    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn prewarming_primes_pool_for_zero_handshake_first_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve(listener, 1));

    let client = client();
    let target = Target::plain(address.to_string());

    // Pre-warm the pool before any request has been submitted.
    let warmed = client.prewarm(&target).await.expect("prewarm");
    assert!(warmed, "first prewarm must establish a fresh connection");

    // Idempotent: second prewarm knows the pool is already warm.
    let second_warm = client.prewarm(&target).await.expect("prewarm again");
    assert!(!second_warm, "subsequent prewarm on a warm pool is a no-op");

    // First actual user request immediately hits the warm pool!
    let recorder = Arc::new(Mutex::new(Recorder::start(4096)));
    request_once(&client, &target, Arc::clone(&recorder)).await;
    let trace = trace_of(
        recorder.lock().expect("recorder").log().clone(),
        &address.to_string(),
    );
    let derived = derive(&trace);

    assert!(
        trace.log.first_of(EventKind::ConnectReused).is_some(),
        "first request after prewarm must hit the warm pool with zero handshake"
    );
    assert_eq!(
        derived.dns_us.validity(),
        Validity::NotApplicable(Reason::ConnectionReused),
    );

    let _ = server.await;
}
