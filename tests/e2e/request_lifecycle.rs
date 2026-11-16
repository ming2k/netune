//! End-to-end: a real socket, the real codec, the real trace.
//!
//! This is the vertical slice ADR-0001's P0 gate needs: bytes arriving on a
//! socket produce events, events produce derived timings, and the timings say
//! what actually happened (including *not applicable* for phases the pool
//! skipped).

#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::time::Duration;

use bytes::Bytes;
use http::Method;
use netune::{
    AttemptError, Client, ClientConfig, Pool, RequestBody, RequestHead, Target, TcpConnector,
    TraceConfig,
};
use netune_trace::{
    EventKind, Fidelity, FrameClass, Reason, RequestTrace, TRACE_SCHEMA_VERSION, TraceCollector,
    TraceId, Validity, derive,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CHUNKS: usize = 24;
const CHUNK_GAP: Duration = Duration::from_millis(5);

/// The gap between the response head and the first body byte.
///
/// Deliberately much larger than [`CHUNK_GAP`]. `frame_to_payload_us` is refused as
/// `TransportBatched` when the head and the first body byte are recorded less than
/// `BATCH_GAP_NS` (2 ms) apart, which is the correct behaviour — but it also means the
/// assertion that the scope *is* estimable depends on the client's very first read not
/// collecting both. The head and the first chunk were 5 ms apart, so a client task
/// descheduled for 5 ms under parallel test load delivered them in one read and the gap
/// collapsed to zero, making this test fail roughly one run in eight. The measured
/// quantity (streaming cadence between tokens) is still 5 ms; only the prefill window is
/// widened, so the property under test is unchanged and the flake is gone.
const FIRST_CHUNK_GAP: Duration = Duration::from_millis(80);

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
        // a real streaming API has, and the shape that makes `frame_to_payload_us`
        // estimable rather than batched.
        tokio::time::sleep(FIRST_CHUNK_GAP).await;
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
    RequestTrace::new(
        netune_trace::TraceMeta::new(TraceId::new("e2e"), netune_trace::Direction::Egress),
        authority,
        log,
    )
    .with_fidelity(Fidelity::l1())
}

/// Run one request, marking one output token per streamed frame the way a
/// provider adapter would.
async fn request_once(client: &Client, target: &Target, recorder: TraceCollector) -> usize {
    let head = RequestHead::new(Method::POST, "/v1/chat/completions")
        .with_header("content-type", "application/json");
    let mut response = client
        .send_traced(
            target,
            recorder.clone(),
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
            recorder.frame(FrameClass::Text, 1);
        }
    }
    recorder.mark(EventKind::Validated, 0, 0);
    frames
}

fn client() -> Client {
    client_on(Pool::default())
}

fn client_on(pool: Pool) -> Client {
    Client::new(TcpConnector::new(), pool, ClientConfig::default())
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
    // Now behave like an idle-culling gateway: close the socket cleanly at the
    // TCP layer so the peer sits with an idle, closed socket in its pool.
    let _ = socket.shutdown().await;
    drop(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_socket_the_peer_dropped_is_replaced_transparently() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    // One server lifetime that answers a request and then hard-closes, followed
    // by a fresh listener on the same port serving the replacement connection.
    let server = tokio::spawn(serve_then_drop_idle(listener));

    let pool = Pool::default();
    let client = client_on(pool.clone());
    let target = Target::plain(address.to_string());

    // First request populates the pool with a connection the peer then kills.
    let first = request_once(&client, &target, TraceCollector::start(4096)).await;
    assert_eq!(first, 1, "the first response is served in full");
    server.await.expect("join");
    // Give Tokio's I/O reactor a moment to observe the peer FIN on loaded CI
    // runners so the non-blocking checkout probe does not race epoll delivery.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(
        pool.idle_count(&client.pool_key(&target).expect("plan")),
        1,
        "the answered connection is pooled"
    );

    // The pooled socket is now dead. A second request must not fail: the
    // transport discards it, reconnects, and answers — all invisible to the
    // caller. Rebind the same port so the reconnect has somewhere to land.
    let listener = TcpListener::bind(address).await.expect("rebind");
    let server = tokio::spawn(serve(listener, 1));
    let recorder = TraceCollector::start(4096);
    let frames = request_once(&client, &target, recorder.clone()).await;
    assert_eq!(
        frames, CHUNKS,
        "the request succeeds on a fresh connection after the stale socket is discarded"
    );
    server.await.expect("join");

    let log = recorder.log();
    // The dead socket is caught by the checkout probe, before a request byte
    // is written to it: it was never used, so the attempt never claims reuse
    // and nothing is replayed — which is why a bare POST survives this.
    assert_eq!(
        log.iter()
            .filter(|event| event.kind == EventKind::ConnectReused)
            .count(),
        0,
        "a socket discarded at checkout is not a reuse"
    );
    assert!(
        log.iter()
            .any(|event| event.kind == EventKind::ConnectStaleDiscarded),
        "the stale socket is recorded as discarded"
    );
    assert!(
        recorder
            .diagnostics()
            .iter()
            .any(|record| record.code == netune_trace::DiagnosticCode::EGRESS_POOL_STALE),
        "the stale socket has a non-terminal diagnostic"
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

/// A peer that answers one request, keeps the connection open, then reads the
/// next request in full and closes without answering it. The pooled socket is
/// alive when it is checked out, so the probe passes; it dies only after the
/// request has been delivered — the window in which the origin may already
/// have acted on it.
///
/// The listening socket is dropped as soon as the connection is accepted and
/// `listener_closed` reports that, so a test can rebind the same address for
/// the replay *before* it issues the request that triggers it. Deferring the
/// rebind until this task returns races the client's reconnect: under parallel
/// test load the client can reach a still-unbound port and see
/// `ConnectionRefused`.
async fn serve_then_swallow_the_next(
    listener: TcpListener,
    listener_closed: tokio::sync::oneshot::Sender<()>,
) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    drop(listener);
    let _ = listener_closed.send(());
    for answered in [true, false] {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).await.expect("read request");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        if answered {
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .await
                .expect("response");
            socket.flush().await.expect("flush");
        }
    }
    drop(socket);
}

async fn send(client: &Client, target: &Target, method: Method) -> Result<Bytes, AttemptError> {
    let mut response = client
        .request(target, RequestHead::new(method, "/"), None)
        .await?;
    response.body.read_to_end().await
}

#[tokio::test(flavor = "multi_thread")]
async fn inv_transport_06_a_post_swallowed_by_a_reused_socket_is_not_replayed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let (_listener_closed_tx, _listener_closed_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_then_swallow_the_next(listener, _listener_closed_tx));
    let client = client();
    let target = Target::plain(address.to_string());

    assert_eq!(
        send(&client, &target, Method::GET)
            .await
            .expect("first")
            .as_ref(),
        b"ok"
    );
    // The peer read this POST and then closed. Whether it acted on it is
    // unknowable from here, so the transport must not send a second copy.
    // Nothing listens for a second connection: a replay would fail to connect
    // and surface as a connect error instead of the stale-socket failure.
    let error = send(&client, &target, Method::POST)
        .await
        .expect_err("the swallowed POST must surface, not be replayed");
    assert!(
        error.is_stale_connection() && error.is_retryable(),
        "the failure still tells the caller a retry is plausible: {error}"
    );
    server.await.expect("join");
}

#[tokio::test(flavor = "multi_thread")]
async fn inv_transport_06_a_get_swallowed_by_a_reused_socket_is_replayed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let (listener_closed_tx, listener_closed_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_then_swallow_the_next(listener, listener_closed_tx));
    let client = client();
    let target = Target::plain(address.to_string());

    assert_eq!(
        send(&client, &target, Method::GET)
            .await
            .expect("first")
            .as_ref(),
        b"ok"
    );
    // The same swallow, but a GET is idempotent: the transport reconnects and
    // the caller never sees the dead socket. Bind the replacement listener
    // before issuing the request so the reconnect has somewhere to land.
    listener_closed_rx.await.expect("listener closed");
    let listener = TcpListener::bind(address).await.expect("rebind");
    let replacement = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await.expect("read");
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nagain")
            .await
            .expect("response");
    });
    assert_eq!(
        send(&client, &target, Method::GET)
            .await
            .expect("replayed")
            .as_ref(),
        b"again"
    );
    server.await.expect("join");
    replacement.await.expect("join");
}

async fn serve_early_413(listener: TcpListener) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = socket.read(&mut buffer).await.expect("read head");
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    socket
        .write_all(
            b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await
        .expect("respond");
    socket.flush().await.expect("flush");
    // Deliberately never read the request body.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_early_h1_response_does_not_wait_for_the_upload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve_early_413(listener));
    let client = client();
    let target = Target::plain(address.to_string());

    let (upload_tx, upload_rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    let uploader = tokio::spawn(async move {
        for _ in 0..1024 {
            if upload_tx
                .send(Bytes::from_static(b"upload-chunk"))
                .await
                .is_err()
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    });

    let mut response = tokio::time::timeout(
        Duration::from_secs(1),
        client.request(
            &target,
            RequestHead::new(Method::POST, "/upload"),
            RequestBody::stream(upload_rx),
        ),
    )
    .await
    .expect("the response head must not wait for the upload")
    .expect("413 response");
    assert_eq!(response.head.status, http::StatusCode::PAYLOAD_TOO_LARGE);
    response.body.abandon();
    uploader.abort();
    let _ = uploader.await;
    server.await.expect("join");
}

async fn serve_early_body(listener: TcpListener) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = socket.read(&mut buffer).await.expect("read head");
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    socket
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nbody")
        .await
        .expect("respond");
    socket.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_h1_response_body_is_readable_while_the_upload_is_still_running() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve_early_body(listener));
    let client = client();
    let target = Target::plain(address.to_string());

    let (upload_tx, upload_rx) = tokio::sync::mpsc::channel::<Bytes>(1);
    let uploader = tokio::spawn(async move {
        loop {
            if upload_tx
                .send(Bytes::from_static(b"still-uploading"))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let mut response = tokio::time::timeout(
        Duration::from_secs(1),
        client.request(
            &target,
            RequestHead::new(Method::POST, "/upload"),
            RequestBody::stream(upload_rx),
        ),
    )
    .await
    .expect("the head must arrive while the upload runs")
    .expect("response");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), response.body.read_to_end())
            .await
            .expect("the body must be readable while the upload runs")
            .expect("body")
            .as_ref(),
        b"body"
    );
    uploader.abort();
    let _ = uploader.await;
    server.await.expect("join");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streaming_attempt_produces_a_derivable_trace() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve(listener, 1));

    let recorder = TraceCollector::start(4096);
    let client = client();
    let target = Target::plain(address.to_string());
    let frames = request_once(&client, &target, recorder.clone()).await;
    assert_eq!(frames, CHUNKS);

    let trace = trace_of(recorder.log(), &address.to_string());
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
    assert!(derived.first_payload_us.is_measured());
    assert!(derived.frame_to_payload_us.is_measured());
    assert!(derived.e2e_us.is_measured());
    assert!(derived.tail_us.is_measured());
    assert!(derived.payload_span_us.value().expect("span") > 0);

    // The estimator must agree with the cadence the trace itself recorded. The
    // scripted server's true interval is 5 ms of sleep plus the write cost, so
    // the assertion is derived from the trace rather than hard-coded: what is
    // under test is fidelity, not this machine's timer.
    let token_times: Vec<u64> = trace
        .log
        .iter()
        .filter(|event| event.kind == EventKind::Payload)
        .map(|event| event.at_ns)
        .collect();
    assert_eq!(token_times.len(), CHUNKS);
    let span = token_times[CHUNKS - 1] - token_times[0];
    let expected = (CHUNKS - 1) as f64 * 1_000_000_000.0 / span as f64;
    // One rate: tokens over the recorded span. The ledger divides; the trace
    // supplies the span, and this asserts the span tracks the scripted cadence.
    let span_us = derived.payload_span_us.value().expect("stream span");
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

#[tokio::test]
async fn request_traced_carries_identity_and_honest_fidelity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve(listener, 1));

    let client = client();
    let target = Target::plain(address.to_string());
    let mut response = client
        .request_traced(
            &target,
            RequestHead::new(Method::GET, "/v1/models"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect("traced request");
    let _ = response.body.read_to_end().await.expect("body");

    let trace = response.body.trace().expect("traced body yields a trace");
    assert_eq!(
        trace.identity,
        client.pool_key(&target).expect("plan").identity
    );
    assert_eq!(trace.schema_version, TRACE_SCHEMA_VERSION);
    assert_eq!(trace.fidelity, Fidelity::l1());

    let _ = server.await;
}

#[tokio::test]
async fn request_default_is_counted_but_not_traced() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve(listener, 1));

    let client = client();
    let target = Target::plain(address.to_string());
    let mut response = client
        .request(&target, RequestHead::new(Method::GET, "/v1/models"), None)
        .await
        .expect("default request");
    let _ = response.body.read_to_end().await.expect("body");

    assert!(
        response.body.trace().is_none(),
        "the default L0 observation must not fabricate an event-level trace"
    );
    let counters = response
        .body
        .counters()
        .expect("the default observation yields L0 counters");
    assert!(counters.reads > 0);
    assert!(counters.writes > 0);
    assert!(counters.read_bytes > 0);
    assert!(counters.write_bytes > 0);

    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_reuse_is_attributed_rather_than_charged_to_the_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve(listener, 2));

    let client = client();
    let target = Target::plain(address.to_string());

    let first = TraceCollector::start(4096);
    request_once(&client, &target, first.clone()).await;
    let first_trace = trace_of(first.log(), &address.to_string());
    let first_derived = derive(&first_trace);
    assert!(first_derived.dns_us.is_measured());

    let second = TraceCollector::start(4096);
    request_once(&client, &target, second.clone()).await;
    let second_trace = trace_of(second.log(), &address.to_string());
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
    assert!(second_derived.first_payload_us.is_measured());

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
    let recorder = TraceCollector::start(4096);
    request_once(&client, &target, recorder.clone()).await;
    let trace = trace_of(recorder.log(), &address.to_string());
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

#[tokio::test(flavor = "multi_thread")]
async fn h1_full_duplex_server_closes_after_half_request_and_preserves_trace() {
    use netune::RequestBodySource;

    struct SlowChunks {
        sent: usize,
    }
    impl RequestBodySource for SlowChunks {
        fn next_chunk(&mut self) -> netune::BoxFuture<'_, Result<Option<Bytes>, netune::NetError>> {
            Box::pin(async move {
                if self.sent >= 100 {
                    return Ok(None);
                }
                self.sent += 1;
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(Some(Bytes::from_static(b"upload-chunk-")))
            })
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 256];
        let _ = socket.read(&mut buf).await;
        // Answer immediately after reading only part of the upload, then close.
        socket
            .write_all(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 9\r\nconnection: keep-alive\r\n\r\ntoo-large")
            .await
            .expect("write 413");
        drop(socket);

        // Expect a second connection because the half-written first one must NOT be pooled.
        let accept2 = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
        if let Ok(Ok((mut s2, _))) = accept2 {
            let mut req2 = Vec::new();
            let mut b = [0u8; 1024];
            while !req2.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s2.read(&mut b).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                req2.extend_from_slice(&b[..n]);
            }
            let _ = s2
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .await;
        }
    });

    let pool = Pool::default();
    let client = Client::new(TcpConnector::new(), pool.clone(), ClientConfig::default());
    let target = Target::plain(address.to_string());

    let mut resp = client
        .request_traced(
            &target,
            RequestHead::new(Method::POST, "/half"),
            RequestBody::stream(SlowChunks { sent: 0 }),
            TraceConfig::default(),
        )
        .await
        .expect("early 413 head");
    assert_eq!(resp.head.status, http::StatusCode::PAYLOAD_TOO_LARGE);
    let body = resp.body.read_to_end().await.expect("read 413 body");
    assert_eq!(body.as_ref(), b"too-large");
    let trace = resp
        .body
        .trace()
        .expect("early response trace must be immediately complete");
    assert!(trace.log.bytes_read() > 0, "socket reads must be present");
    assert!(
        trace.log.bytes_written() > 0,
        "socket writes must be present"
    );

    // Next request must dial a fresh connection (not reuse the half-written one).
    let mut resp2 = client
        .request_traced(
            &target,
            RequestHead::new(Method::GET, "/after"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect("second request");
    assert_eq!(resp2.head.status, http::StatusCode::OK);
    let _ = resp2.body.read_to_end().await.expect("body 2");
    let trace2 = resp2.body.trace().expect("trace 2");
    assert_eq!(trace2.log.first_of(EventKind::ConnectReused), None);

    server.await.expect("server join");
}

#[tokio::test(flavor = "multi_thread")]
async fn h1_full_duplex_abandon_mid_response_cancels_upload_and_preserves_trace() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 256];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n")
            .await
            .expect("first chunk");
        // Keep streaming chunks until client disconnects.
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if socket.write_all(b"5\r\nworld\r\n").await.is_err() {
                break;
            }
        }
    });

    let (upload_tx, upload_rx) = tokio::sync::mpsc::channel::<Result<Bytes, netune::NetError>>(4);
    let uploader = tokio::spawn(async move {
        loop {
            if upload_tx
                .send(Ok(Bytes::from_static(b"chunk")))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let pool = Pool::default();
    let client = Client::new(TcpConnector::new(), pool.clone(), ClientConfig::default());
    let target = Target::plain(address.to_string());
    let mut resp = client
        .request_traced(
            &target,
            RequestHead::new(Method::POST, "/stream"),
            RequestBody::stream(upload_rx),
            TraceConfig::default(),
        )
        .await
        .expect("head");
    let first = resp
        .body
        .next_chunk()
        .await
        .expect("chunk 1")
        .expect("some");
    assert_eq!(first.as_ref(), b"hello");

    // Abandon mid-response while upload is still active.
    resp.body.abandon();
    let trace = resp
        .body
        .trace()
        .expect("abandoned body must synchronously return trace");
    assert!(trace.log.bytes_read() > 0);
    assert!(trace.log.bytes_written() > 0);
    let key = client.pool_key(&target).expect("plan");
    assert_eq!(
        pool.idle_count(&key),
        0,
        "abandoned half-written conn must not pool"
    );

    uploader.abort();
    let _ = uploader.await;
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h1_full_duplex_upload_error_surfaces_and_never_pools() {
    use netune::RequestBodySource;

    struct FailingUpload {
        step: usize,
    }
    impl RequestBodySource for FailingUpload {
        fn next_chunk(&mut self) -> netune::BoxFuture<'_, Result<Option<Bytes>, netune::NetError>> {
            Box::pin(async move {
                self.step += 1;
                if self.step == 1 {
                    Ok(Some(Bytes::from_static(b"part1")))
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Err(netune::NetError::Protocol(
                        "simulated upload failure".into(),
                    ))
                }
            })
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 512];
        let _ = socket.read(&mut buf).await;
        // Send response head while upload is about to fail, then wait before finishing body.
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nfirst\r\n")
            .await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });

    let pool = Pool::default();
    let client = Client::new(TcpConnector::new(), pool.clone(), ClientConfig::default());
    let target = Target::plain(address.to_string());
    let mut resp = client
        .request_traced(
            &target,
            RequestHead::new(Method::POST, "/fail-upload"),
            RequestBody::stream(FailingUpload { step: 0 }),
            TraceConfig::default(),
        )
        .await
        .expect("head arrived before upload error");
    let first = resp
        .body
        .next_chunk()
        .await
        .expect("first chunk")
        .expect("some");
    assert_eq!(first.as_ref(), b"first");
    // Wait for upload failure to propagate into next_chunk.
    tokio::time::sleep(Duration::from_millis(40)).await;
    let err = resp
        .body
        .read_to_end()
        .await
        .expect_err("upload failure must surface as AttemptError");
    assert!(err.to_string().contains("simulated upload failure"));
    let trace = err.trace();
    assert!(trace.log.bytes_written() > 0, "error trace keeps writes");
    let key = client.pool_key(&target).expect("plan");
    assert_eq!(pool.idle_count(&key), 0, "failed upload must never pool");

    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h1_full_duplex_fault_io_split_delay_and_truncate_preserve_socket_trace() {
    use netune::{Fault, FaultConnector, FaultScript};

    // Case 1: Fault::Split + Fault::Delay on reads while upload streams concurrently.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 512];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 32\r\n\r\n0123456789abcdef0123456789abcdef",
            )
            .await
            .expect("write body");
    });

    let (upload_tx, upload_rx) = tokio::sync::mpsc::channel::<Result<Bytes, netune::NetError>>(4);
    let uploader = tokio::spawn(async move {
        loop {
            if upload_tx
                .send(Ok(Bytes::from_static(b"streaming")))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let pool = Pool::default();
    let connector = FaultConnector::new(TcpConnector::new(), |_| {
        FaultScript::new([
            (
                0,
                Fault::Split {
                    span: 128,
                    per_read: 5,
                },
            ),
            (20, Fault::Delay(Duration::from_millis(15))),
        ])
    });
    let client = Client::new(connector, pool.clone(), ClientConfig::default());
    let target = Target::plain(address.to_string());
    let mut resp = client
        .request_traced(
            &target,
            RequestHead::new(Method::POST, "/fault-split"),
            RequestBody::stream(upload_rx),
            TraceConfig::default(),
        )
        .await
        .expect("fault split head");
    let body = resp.body.read_to_end().await.expect("fault split body");
    assert_eq!(body.as_ref(), b"0123456789abcdef0123456789abcdef");
    let trace = resp.body.trace().expect("fault split trace");
    assert!(trace.log.bytes_read() > 0);
    assert!(trace.log.bytes_written() > 0);
    let key = client.pool_key(&target).expect("plan");
    assert_eq!(pool.idle_count(&key), 0, "early response must not pool");
    uploader.abort();
    let _ = uploader.await;
    let _ = server.await;

    // Case 2: Fault::Truncate mid-response while upload is still active -> AttemptError keeps socket events.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 512];
        let _ = socket.read(&mut buf).await;
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 64\r\n\r\npartial-payload")
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let (upload_tx2, upload_rx2) = tokio::sync::mpsc::channel::<Result<Bytes, netune::NetError>>(4);
    let uploader2 = tokio::spawn(async move {
        loop {
            if upload_tx2
                .send(Ok(Bytes::from_static(b"streaming")))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let pool2 = Pool::default();
    let connector2 = FaultConnector::new(TcpConnector::new(), |_| {
        FaultScript::new([(45, Fault::Truncate)])
    });
    let client2 = Client::new(connector2, pool2.clone(), ClientConfig::default());
    let target2 = Target::plain(address.to_string());
    let mut resp2 = client2
        .request_traced(
            &target2,
            RequestHead::new(Method::POST, "/fault-truncate"),
            RequestBody::stream(upload_rx2),
            TraceConfig::default(),
        )
        .await
        .expect("head before truncate");
    let err = resp2
        .body
        .read_to_end()
        .await
        .expect_err("truncated response must fail");
    let err_trace = err.trace();
    assert!(
        err_trace.log.bytes_read() > 0,
        "truncated error trace must preserve socket reads"
    );
    assert!(
        err_trace.log.bytes_written() > 0,
        "truncated error trace must preserve socket writes"
    );
    let key2 = client2.pool_key(&target2).expect("plan");
    assert_eq!(pool2.idle_count(&key2), 0);
    uploader2.abort();
    let _ = uploader2.await;
    let _ = server.await;
}
