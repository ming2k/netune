//! Differential oracle: `h2` speaks the same RFC 9113 / RFC 7541 wire protocol we do.
//!
//! ADR-0001 keeps `h2` as a `[dev-dependencies]` oracle rather than a shipping
//! dependency. This suite exercises both roles (`netune-http2` client <-> `h2`
//! server, and `h2` client <-> `netune-http2` server) across framing,
//! `HEADERS`/`CONTINUATION`, HPACK dynamic tables, `SETTINGS`, `WINDOW_UPDATE`,
//! trailers, concurrent streams, early `RST_STREAM`, `GOAWAY`, and invalid-frame
//! rejection.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use netune_http2::client::session::H2ClientSession;
use netune_http2::frame::{FRAME_CONTINUATION, FrameHeader};
use netune_http2::server::{
    H2Handler, H2Request, H2Response as ServerH2Response, NoObserver, ResponseFuture,
    ServerSession, ServerSessionConfig, SessionEnd,
};
use netune_http2::{H2ClientConnection, H2Fingerprint, H2ResponseEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};

async fn read_h2_body(mut body: h2::RecvStream) -> Bytes {
    let mut out = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("h2 body chunk");
        let len = chunk.len();
        out.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(len);
    }
    out.freeze()
}

async fn read_our_body(mut reader: netune_http2::H2StreamReader) -> (Bytes, Vec<(String, String)>) {
    let mut out = BytesMut::new();
    let mut trailers = Vec::new();
    loop {
        match reader.next_event().await.expect("next_event") {
            H2ResponseEvent::Data {
                payload,
                end_stream,
            } => {
                out.extend_from_slice(&payload);
                if end_stream {
                    break;
                }
            }
            H2ResponseEvent::Trailers(fields) => {
                trailers = fields;
                break;
            }
            H2ResponseEvent::End => break,
            _ => {}
        }
    }
    (out.freeze(), trailers)
}

#[tokio::test(flavor = "multi_thread")]
async fn client_roundtrips_continuation_hpack_dynamic_table_and_trailers_against_h2_server() {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);

    let server = tokio::spawn(async move {
        let mut conn = h2::server::Builder::new()
            .initial_window_size(65_535)
            .max_frame_size(16_384)
            .max_concurrent_streams(16)
            .handshake(server_io)
            .await
            .expect("h2 server handshake");

        while let Some(next) = conn.accept().await {
            let (req, mut respond) = next.expect("accept stream");
            tokio::spawn(async move {
                let path = req.uri().path().to_owned();
                let x_big_len = req.headers().get("x-big").map_or(0, |v| v.as_bytes().len());
                let x_dyn = req
                    .headers()
                    .get("x-dynamic-repeat")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let req_body = read_h2_body(req.into_body()).await;

                if path == "/trailers" {
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("x-server", "h2")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    send.send_data(Bytes::from_static(b"hello-trailers"), false)
                        .unwrap();
                    let mut tr = HeaderMap::new();
                    tr.insert("x-checksum", HeaderValue::from_static("abc123"));
                    send.send_trailers(tr).unwrap();
                } else if path == "/big-response-headers" {
                    let mut builder = Response::builder().status(StatusCode::OK);
                    for i in 0..40 {
                        let name = format!("x-resp-{i:02}");
                        let val = "v".repeat(512);
                        builder = builder.header(name, val);
                    }
                    let resp = builder.body(()).unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    send.send_data(Bytes::from_static(b"ok-big-headers"), true)
                        .unwrap();
                } else {
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("x-big-len", x_big_len.to_string())
                        .header("x-dyn-echo", x_dyn)
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    send.send_data(req_body, true).unwrap();
                }
            });
        }
    });

    let conn = H2ClientConnection::handshake(client_io, H2Fingerprint::chrome())
        .await
        .expect("our client handshake");
    let session = H2ClientSession::spawn(conn);
    assert_eq!(session.max_concurrent_streams(), 16);

    // 1. Large request headers forcing HEADERS + CONTINUATION (> 16 KiB) + HPACK dynamic table entry.
    let mut big_headers: Vec<(String, String)> = (0..45)
        .map(|i| (format!("x-hdr-{i:02}"), "a".repeat(512)))
        .collect();
    big_headers.push(("x-big".to_owned(), "b".repeat(2048)));
    big_headers.push((
        "x-dynamic-repeat".to_owned(),
        "dynamic-table-value-0123456789abcdef".to_owned(),
    ));

    let (_sender, head_fut, reader) = session
        .open_request(
            None,
            "POST",
            "example.test",
            "https",
            "/echo",
            &big_headers,
            Some(Bytes::from_static(b"payload-1")),
            false,
            session.request_profile(),
        )
        .await
        .expect("open req 1");
    let head = head_fut.await_head().await.expect("head 1");
    assert_eq!(head.status, 200);
    let (body, _) = read_our_body(reader).await;
    assert_eq!(body.as_ref(), b"payload-1");
    assert!(
        head.headers
            .iter()
            .any(|(k, v)| k == "x-big-len" && v == "2048")
    );

    // 2. Second request reusing the dynamic table header value.
    let repeat_headers = vec![(
        "x-dynamic-repeat".to_owned(),
        "dynamic-table-value-0123456789abcdef".to_owned(),
    )];
    let (_sender, head_fut, reader) = session
        .open_request(
            None,
            "POST",
            "example.test",
            "https",
            "/echo2",
            &repeat_headers,
            Some(Bytes::from_static(b"payload-2")),
            false,
            session.request_profile(),
        )
        .await
        .expect("open req 2");
    let head = head_fut.await_head().await.expect("head 2");
    assert_eq!(head.status, 200);
    assert!(
        head.headers
            .iter()
            .any(|(k, v)| { k == "x-dyn-echo" && v == "dynamic-table-value-0123456789abcdef" })
    );
    let (body, _) = read_our_body(reader).await;
    assert_eq!(body.as_ref(), b"payload-2");

    // 3. Large response headers (> 16 KiB) forcing server-side CONTINUATION frames.
    let (_sender, head_fut, reader) = session
        .open_request(
            None,
            "GET",
            "example.test",
            "https",
            "/big-response-headers",
            &[],
            None,
            false,
            session.request_profile(),
        )
        .await
        .expect("open big resp headers");
    let head = head_fut.await_head().await.expect("big resp head");
    assert_eq!(head.status, 200);
    assert!(head.headers.iter().any(|(k, _)| k == "x-resp-39"));
    let (body, _) = read_our_body(reader).await;
    assert_eq!(body.as_ref(), b"ok-big-headers");

    // 4. Trailers from h2 server.
    let (_sender, head_fut, reader) = session
        .open_request(
            None,
            "GET",
            "example.test",
            "https",
            "/trailers",
            &[],
            None,
            false,
            session.request_profile(),
        )
        .await
        .expect("open trailers");
    let head = head_fut.await_head().await.expect("trailers head");
    assert_eq!(head.status, 200);
    let (body, trailers) = read_our_body(reader).await;
    assert_eq!(body.as_ref(), b"hello-trailers");
    assert!(
        trailers
            .iter()
            .any(|(k, v)| k == "x-checksum" && v == "abc123")
    );

    drop(session);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client_concurrent_streams_and_flow_control_boundaries_against_h2_server() {
    let (client_io, server_io) = tokio::io::duplex(512 * 1024);

    let server = tokio::spawn(async move {
        let mut conn = h2::server::Builder::new()
            .initial_window_size(16_384)
            .initial_connection_window_size(32_768)
            .max_concurrent_streams(32)
            .handshake(server_io)
            .await
            .expect("h2 server handshake");

        while let Some(next) = conn.accept().await {
            let (req, mut respond) = next.expect("accept stream");
            tokio::spawn(async move {
                let req_body = read_h2_body(req.into_body()).await;
                let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                // Stream back in chunks, exercising peer WINDOW_UPDATE replenishment.
                let mut offset = 0;
                while offset < req_body.len() {
                    let end = (offset + 8192).min(req_body.len());
                    send.send_data(req_body.slice(offset..end), end == req_body.len())
                        .unwrap();
                    offset = end;
                }
            });
        }
    });

    let conn = H2ClientConnection::handshake(client_io, H2Fingerprint::chrome())
        .await
        .expect("client handshake");
    let session = H2ClientSession::spawn(conn);

    // 16 concurrent streams, each sending 96 KiB (> 64 KiB initial window).
    let mut tasks = Vec::new();
    for idx in 0..16u8 {
        let session = session.clone();
        tasks.push(tokio::spawn(async move {
            let payload: Vec<u8> = (0..(96 * 1024))
                .map(|i| idx.wrapping_add(i as u8))
                .collect();
            let (sender, head_fut, reader) = session
                .open_request(
                    None,
                    "POST",
                    "example.test",
                    "https",
                    &format!("/stream/{idx}"),
                    &[],
                    None,
                    true,
                    session.request_profile(),
                )
                .await
                .expect("open concurrent stream");
            let mut sender = sender.expect("streaming sender");
            for chunk in payload.chunks(16 * 1024) {
                sender
                    .send_data(Bytes::copy_from_slice(chunk))
                    .await
                    .expect("send_data");
            }
            sender.finish().expect("finish");

            let head = head_fut.await_head().await.expect("head");
            assert_eq!(head.status, 200);
            let (echoed, _) = read_our_body(reader).await;
            assert_eq!(
                echoed.as_ref(),
                payload.as_slice(),
                "stream {idx} body mismatch"
            );
        }));
    }

    for task in tasks {
        task.await.expect("stream task");
    }

    drop(session);
    let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client_early_rst_and_server_goaway_against_h2_server() {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let server_reset_seen = Arc::new(AtomicUsize::new(0));
    let server_reset_seen_bg = Arc::clone(&server_reset_seen);
    let goaway_gate = Arc::new(Notify::new());
    let goaway_gate_bg = Arc::clone(&goaway_gate);

    let server = tokio::spawn(async move {
        let mut conn = h2::server::Builder::new()
            .max_concurrent_streams(16)
            .handshake(server_io)
            .await
            .expect("handshake");

        while let Some(next) = conn.accept().await {
            let (req, mut respond) = next.expect("accept");
            let path = req.uri().path().to_owned();
            if path == "/cancel-me" {
                let reset_seen = Arc::clone(&server_reset_seen_bg);
                tokio::spawn(async move {
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    let _ = send.send_data(Bytes::from_static(b"first-chunk"), false);
                    let err = std::future::poll_fn(|cx| send.poll_reset(cx)).await;
                    if err.is_ok() {
                        reset_seen.fetch_add(1, Ordering::SeqCst);
                    }
                });
            } else if path == "/peer-reset" {
                tokio::spawn(async move {
                    respond.send_reset(h2::Reason::CANCEL);
                });
            } else if path == "/trigger-goaway" {
                let gate = Arc::clone(&goaway_gate_bg);
                tokio::spawn(async move {
                    gate.notified().await;
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    let _ = send.send_data(Bytes::from_static(b"survived-goaway"), true);
                });
                conn.graceful_shutdown();
                goaway_gate_bg.notify_one();
            } else {
                tokio::spawn(async move {
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    let _ = send.send_data(Bytes::from_static(b"healthy"), true);
                });
            }
        }
    });

    let conn = H2ClientConnection::handshake(client_io, H2Fingerprint::chrome())
        .await
        .expect("handshake");
    let session = H2ClientSession::spawn(conn);

    // 1. Client drops H2StreamReader early after first chunk -> h2 server sees RST_STREAM(CANCEL).
    {
        let (_s, head_fut, mut reader) = session
            .open_request(
                None,
                "GET",
                "example.test",
                "https",
                "/cancel-me",
                &[],
                None,
                false,
                session.request_profile(),
            )
            .await
            .unwrap();
        let head = head_fut.await_head().await.unwrap();
        assert_eq!(head.status, 200);
        match reader.next_event().await.unwrap() {
            H2ResponseEvent::Data { payload, .. } => assert_eq!(payload.as_ref(), b"first-chunk"),
            other => panic!("unexpected event: {other:?}"),
        }
        drop(reader);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(server_reset_seen.load(Ordering::SeqCst), 1);

    // 2. Server resets a single stream -> client receives error on that stream, connection survives.
    let (_s, head_fut, _reader) = session
        .open_request(
            None,
            "GET",
            "example.test",
            "https",
            "/peer-reset",
            &[],
            None,
            false,
            session.request_profile(),
        )
        .await
        .unwrap();
    let err = head_fut.await_head().await.unwrap_err();
    assert!(
        err.to_string().contains("RST_STREAM") || err.to_string().contains("reset"),
        "expected reset error, got {err}"
    );

    // Sibling request still succeeds on the same session.
    let (_s, head_fut, reader) = session
        .open_request(
            None,
            "GET",
            "example.test",
            "https",
            "/ok",
            &[],
            None,
            false,
            session.request_profile(),
        )
        .await
        .unwrap();
    assert_eq!(head_fut.await_head().await.unwrap().status, 200);
    let (body, _) = read_our_body(reader).await;
    assert_eq!(body.as_ref(), b"healthy");

    // 3. Server initiates graceful GOAWAY while stream is in flight.
    let (_s, head_fut, reader) = session
        .open_request(
            None,
            "GET",
            "example.test",
            "https",
            "/trigger-goaway",
            &[],
            None,
            false,
            session.request_profile(),
        )
        .await
        .unwrap();
    assert_eq!(head_fut.await_head().await.unwrap().status, 200);
    let (body, _) = read_our_body(reader).await;
    assert_eq!(body.as_ref(), b"survived-goaway");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!session.is_usable(), "session must observe server GOAWAY");

    drop(session);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

struct OracleHandler {
    drain_gate: Arc<Notify>,
}

impl H2Handler for OracleHandler {
    fn handle(&self, mut request: H2Request) -> ResponseFuture<'_> {
        let gate = Arc::clone(&self.drain_gate);
        Box::pin(async move {
            let path = std::str::from_utf8(&request.path).unwrap_or("").to_owned();
            if path == "/big-headers" {
                let mut resp = ServerH2Response::ok(Bytes::from_static(b"big-headers-ok"));
                for i in 0..40 {
                    resp = resp.with_header(format!("x-srv-{i:02}"), "z".repeat(512));
                }
                return resp;
            }
            if path == "/echo-headers" {
                let mut header_count = 0usize;
                for (name, _) in &request.headers {
                    if name.as_str().starts_with("x-cli-") {
                        header_count += 1;
                    }
                }
                let repeat = request
                    .headers
                    .get("x-dyn")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let body = request.body.read_to_end().await;
                return ServerH2Response::ok(body)
                    .with_header("x-cli-count", header_count.to_string())
                    .with_header("x-dyn-echo", repeat);
            }
            if path == "/slow-drain" {
                gate.notified().await;
                return ServerH2Response::ok(Bytes::from_static(b"drained-cleanly"));
            }
            if path == "/stream-out" {
                let body = request.body.read_to_end().await;
                let (tx, rx) = mpsc::channel(4);
                tokio::spawn(async move {
                    for chunk in body.chunks(8192) {
                        if tx.send(Bytes::copy_from_slice(chunk)).await.is_err() {
                            return;
                        }
                    }
                });
                return ServerH2Response::stream(StatusCode::OK, rx);
            }
            let body = request.body.read_to_end().await;
            ServerH2Response::ok(body)
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_client_exercises_our_server_continuation_hpack_flow_control_and_drain() {
    let (client_io, server_io) = tokio::io::duplex(512 * 1024);
    let drain_gate = Arc::new(Notify::new());
    let shutdown = Arc::new(Notify::new());
    let shutdown_wait = Arc::clone(&shutdown);

    let handler = Arc::new(OracleHandler {
        drain_gate: Arc::clone(&drain_gate),
    });
    let mut cfg = ServerSessionConfig::for_tests();
    cfg.local.max_concurrent_streams = 32;
    cfg.settings = cfg.local.parameters();
    cfg.connection_window = 32_768;

    let server_task = tokio::spawn(async move {
        let session = ServerSession::new(handler, cfg, Arc::new(NoObserver));
        session
            .run(server_io, false, async move {
                shutdown_wait.notified().await;
            })
            .await
    });

    let (mut client, conn) = h2::client::Builder::new()
        .initial_window_size(16_384)
        .initial_connection_window_size(32_768)
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("h2 client handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    // 1. Large request headers (> 16 KiB -> CONTINUATION) + dynamic table header.
    let mut req_builder = Request::builder()
        .method(Method::POST)
        .uri("https://example.test/echo-headers");
    for i in 0..45 {
        req_builder = req_builder.header(
            HeaderName::from_bytes(format!("x-cli-{i:02}").as_bytes()).unwrap(),
            HeaderValue::from_str(&"q".repeat(512)).unwrap(),
        );
    }
    req_builder = req_builder.header("x-dyn", "shared-dynamic-entry-987654321");
    let req = req_builder.body(()).unwrap();
    let (resp_fut, mut send_stream) = client.send_request(req, false).unwrap();
    send_stream
        .send_data(Bytes::from_static(b"from-h2-client"), true)
        .unwrap();
    let resp = resp_fut.await.expect("resp 1");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-cli-count").unwrap(), "45");
    assert_eq!(
        resp.headers().get("x-dyn-echo").unwrap(),
        "shared-dynamic-entry-987654321"
    );
    assert_eq!(
        read_h2_body(resp.into_body()).await.as_ref(),
        b"from-h2-client"
    );

    // 2. Large response headers (> 16 KiB -> server CONTINUATION).
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.test/big-headers")
        .body(())
        .unwrap();
    let (resp_fut, _) = client.send_request(req, true).unwrap();
    let resp = resp_fut.await.expect("big-headers resp");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("x-srv-39"));
    assert_eq!(
        read_h2_body(resp.into_body()).await.as_ref(),
        b"big-headers-ok"
    );

    // 3. Concurrent multiplexed streams crossing flow-control windows (12 x 96 KiB).
    let mut req_tasks = Vec::new();
    for idx in 0..12u8 {
        let mut client = client.clone();
        req_tasks.push(tokio::spawn(async move {
            futures_poll_ready(&mut client).await;
            let payload: Vec<u8> = (0..(96 * 1024))
                .map(|i| idx.wrapping_add(i as u8))
                .collect();
            let req = Request::builder()
                .method(Method::POST)
                .uri("https://example.test/stream-out")
                .body(())
                .unwrap();
            let (resp_fut, mut send_stream) = client.send_request(req, false).unwrap();
            let mut offset = 0;
            while offset < payload.len() {
                let end = (offset + 16 * 1024).min(payload.len());
                send_stream.reserve_capacity(end - offset);
                let chunk = Bytes::copy_from_slice(&payload[offset..end]);
                send_stream.send_data(chunk, end == payload.len()).unwrap();
                offset = end;
            }
            let resp = resp_fut.await.expect("concurrent resp");
            assert_eq!(resp.status(), StatusCode::OK);
            let body = read_h2_body(resp.into_body()).await;
            assert_eq!(body.as_ref(), payload.as_slice());
        }));
    }
    for t in req_tasks {
        t.await.expect("concurrent h2 task");
    }

    // 4. Early RST_STREAM from h2 client, followed by healthy stream.
    {
        futures_poll_ready(&mut client).await;
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://example.test/echo")
            .body(())
            .unwrap();
        let (_resp_fut, mut send_stream) = client.send_request(req, false).unwrap();
        send_stream.send_reset(h2::Reason::CANCEL);
    }
    futures_poll_ready(&mut client).await;
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.test/ok")
        .body(())
        .unwrap();
    let (resp_fut, _) = client.send_request(req, true).unwrap();
    let resp = resp_fut.await.expect("post-reset resp");
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Graceful drain while a stream is open -> ServerSession finishes in-flight stream then sends GOAWAY.
    futures_poll_ready(&mut client).await;
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.test/slow-drain")
        .body(())
        .unwrap();
    let (drain_resp_fut, _) = client.send_request(req, true).unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    shutdown.notify_one();
    tokio::time::sleep(Duration::from_millis(20)).await;
    drain_gate.notify_waiters();
    let resp = drain_resp_fut.await.expect("drained resp");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        read_h2_body(resp.into_body()).await.as_ref(),
        b"drained-cleanly"
    );

    let end = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("server shutdown timeout")
        .expect("server join");
    assert!(
        matches!(end, SessionEnd::Drained),
        "expected Drained, got {end:?}"
    );
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn both_implementations_reject_unexpected_continuation_frame() {
    // Verify both h2 and netune-http2 reject a stray CONTINUATION frame outside a header block.
    async fn send_stray_continuation(
        mut stream: tokio::io::DuplexStream,
        as_client: bool,
    ) -> Vec<u8> {
        if as_client {
            stream
                .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                .await
                .unwrap();
        }
        // Empty SETTINGS
        let settings = FrameHeader::new(0, netune_http2::FRAME_SETTINGS, 0, 0);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&settings.encode());
        // Stray CONTINUATION on stream 1 with no preceding HEADERS
        let stray = FrameHeader::new(4, FRAME_CONTINUATION, 0x4, 1);
        buf.extend_from_slice(&stray.encode());
        buf.extend_from_slice(&[0x82, 0x84, 0x86, 0x41]);
        let _ = stream.write_all(&buf).await;
        let _ = stream.flush().await;
        let mut received = Vec::new();
        let _ = tokio::time::timeout(
            Duration::from_millis(250),
            stream.read_to_end(&mut received),
        )
        .await;
        received
    }

    // Our server rejects stray CONTINUATION with SessionEnd::Protocol
    let (wire_client, wire_server) = tokio::io::duplex(64 * 1024);
    let handler = Arc::new(OracleHandler {
        drain_gate: Arc::new(Notify::new()),
    });
    let server_task = tokio::spawn(async move {
        let session = ServerSession::new(
            handler,
            ServerSessionConfig::for_tests(),
            Arc::new(NoObserver),
        );
        session
            .run(wire_server, false, std::future::pending())
            .await
    });
    let bytes_from_ours = send_stray_continuation(wire_client, true).await;
    let end = server_task.await.unwrap();
    assert!(
        matches!(end, SessionEnd::Protocol(_, _)),
        "expected Protocol error, got {end:?}"
    );
    assert!(
        !bytes_from_ours.is_empty(),
        "expected GOAWAY/SETTINGS from our server"
    );

    // h2 server rejects stray CONTINUATION with protocol error too
    let (wire_client, wire_server) = tokio::io::duplex(64 * 1024);
    let h2_server = tokio::spawn(async move {
        let res = h2::server::handshake(wire_server).await;
        match res {
            Ok(mut conn) => conn.accept().await.transpose().is_err(),
            Err(_) => true,
        }
    });
    let _ = send_stray_continuation(wire_client, true).await;
    assert!(
        h2_server.await.unwrap(),
        "h2 server must reject stray CONTINUATION"
    );

    // Verify our client rejects stray CONTINUATION from a wire server
    let (client_io, mut raw_server) = tokio::io::duplex(64 * 1024);
    let send_bad = Arc::new(Notify::new());
    let send_bad_wait = Arc::clone(&send_bad);
    let raw_peer = tokio::spawn(async move {
        let mut preface = [0u8; 24];
        raw_server.read_exact(&mut preface).await.unwrap();
        let mut buf = BytesMut::new();
        // Server SETTINGS + SETTINGS ACK
        buf.extend_from_slice(&FrameHeader::new(0, netune_http2::FRAME_SETTINGS, 0, 0).encode());
        buf.extend_from_slice(&FrameHeader::new(0, netune_http2::FRAME_SETTINGS, 0x1, 0).encode());
        raw_server.write_all(&buf).await.unwrap();
        raw_server.flush().await.unwrap();
        send_bad_wait.notified().await;
        let mut bad = BytesMut::new();
        bad.extend_from_slice(&FrameHeader::new(2, FRAME_CONTINUATION, 0x4, 1).encode());
        bad.extend_from_slice(&[0x88, 0x00]);
        let _ = raw_server.write_all(&bad).await;
        let _ = raw_server.flush().await;
        // Keep the pipe open until the client closes on the protocol error.
        let mut scratch = [0u8; 1024];
        let _ = tokio::time::timeout(Duration::from_secs(2), raw_server.read(&mut scratch)).await;
    });
    let conn = H2ClientConnection::handshake(client_io, H2Fingerprint::chrome())
        .await
        .expect("handshake");
    let session = H2ClientSession::spawn(conn);
    let (_s, head_fut, _r) = session
        .open_request(
            None,
            "GET",
            "example.test",
            "https",
            "/",
            &[],
            None,
            false,
            session.request_profile(),
        )
        .await
        .unwrap();
    send_bad.notify_one();
    assert!(head_fut.await_head().await.is_err());
    let _ = raw_peer.await;
}

async fn futures_poll_ready<B: bytes::Buf>(client: &mut h2::client::SendRequest<B>) {
    std::future::poll_fn(|cx| client.poll_ready(cx))
        .await
        .expect("h2 client poll_ready");
}
