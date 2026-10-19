#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Compile-and-run guard for the how-to guide's examples.
//!
//! `docs/how-to/websocket-client.md` shows code that must stay true to the
//! real API. This test file transcribes each guide snippet verbatim (modulo
//! the network endpoint) and *executes* it against a local mock, so a guide
//! that drifts from the API fails CI instead of lying to readers.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use netune::{Client, ClientConfig, Pool, Target, TcpConnector, WsMessage};
use netune_trace::{EventKind, Recorder};
use netune_ws::{Frame, FrameDecoder, FrameEncoder, Role, compute_accept_key};

/// Minimal origin mock: completes the upgrade, sends `scripted` frames, and
/// holds the connection open.
async fn serve(listener: TcpListener, scripted: Vec<Frame>, _client_closes: bool) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = socket.read(&mut buf).await.expect("read");
        assert!(n > 0);
        request.extend_from_slice(&buf[..n]);
    }
    let req_str = String::from_utf8_lossy(&request);
    let key_line = req_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("sec-websocket-key:"))
        .expect("key");
    let key = key_line.split(':').nth(1).unwrap().trim();
    let accept = compute_accept_key(key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    socket.write_all(response.as_bytes()).await.expect("101");
    socket.flush().await.expect("flush");

    let mut read_buf = BytesMut::new();
    for frame in &scripted {
        let mut out = BytesMut::new();
        FrameEncoder::encode(frame, None, &mut out);
        socket.write_all(&out).await.expect("write scripted");
        socket.flush().await.expect("flush scripted");
    }

    let client_closes = scripted
        .iter()
        .any(|f| f.opcode == netune_ws::Opcode::Close);
    if client_closes {
        // A scripted close was already sent: wait for the client's close
        // reply so the guide's loop shapes a real handshake. Data frames the
        // client sent along the way are skipped.
        loop {
            match FrameDecoder::decode(&mut read_buf, Role::Server, 64 * 1024).expect("decode") {
                Some(f) if f.opcode == netune_ws::Opcode::Close => return,
                Some(_) => continue,
                None => {}
            }
            let n = socket.read_buf(&mut read_buf).await.expect("read close");
            assert!(n > 0, "client never sent the close frame");
        }
    } else {
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// Guide snippet: "Connect and Echo" — transcribed as-is.
#[tokio::test]
async fn guide_connect_and_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();
    tokio::spawn(serve(
        listener,
        vec![
            Frame::text(Bytes::from_static(b"welcome")),
            // Server closes first: the guide's loop breaks on the Close
            // message, then the client sends its own close (the reply).
            Frame::close(Some(netune_ws::CloseCode::NORMAL), "bye"),
        ],
        true,
    ));

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(format!("127.0.0.1:{port}"));

    // Performs DNS → TCP → (TLS) → HTTP/1.1 101 upgrade, all traced.
    let mut ws = client
        .connect_ws(&target, "/v1/stream")
        .await
        .expect("connect_ws");

    ws.send_text(r#"{"type":"subscribe","channel":"ticks"}"#)
        .await
        .expect("send_text");

    let mut saw_text = false;
    while let Some(message) = ws.receive().await.expect("receive") {
        match message {
            WsMessage::Text(text) => {
                println!("text: {text}");
                saw_text = true;
            }
            WsMessage::Binary(data) => println!("binary: {} bytes", data.len()),
            WsMessage::Ping(_) | WsMessage::Pong(_) => { /* auto-ponged already */ }
            WsMessage::Close(reason) => {
                println!("server closed: {reason:?}");
                break;
            }
        }
    }
    assert!(saw_text, "guide's echo loop must observe the scripted text");

    ws.close(netune_ws::CloseCode::NORMAL, "done")
        .await
        .expect("close");
}

/// Guide snippet: "Trace What Happened" — transcribed with the real API.
#[tokio::test]
async fn guide_trace_what_happened() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();
    tokio::spawn(serve(listener, vec![], false));

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(format!("127.0.0.1:{port}"));

    use netune_trace::{
        AttemptRef, ConnectionInfo, EndpointRef, Fidelity, RequestTrace, TraceId, derive,
    };

    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
    let mut ws = client
        .connect_ws_traced(
            &target,
            "/v1/stream",
            Arc::clone(&recorder),
            netune::WsHandshake::default(),
        )
        .await
        .expect("connect_ws_traced");

    ws.close(netune_ws::CloseCode::NORMAL, "done")
        .await
        .expect("close");

    let log = recorder.lock().unwrap().log().clone();
    let trace = RequestTrace {
        id: TraceId::new("guide"),
        attempt: AttemptRef {
            round: 1,
            turn: 1,
            attempt: 1,
        },
        endpoint: EndpointRef {
            provider: "guide".into(),
            model: "guide-model".into(),
            authority: format!("127.0.0.1:{port}"),
        },
        connection: ConnectionInfo::default(),
        fidelity: Fidelity::l1(),
        log,
    };
    let timings = derive(&trace);
    // TTFB: the upgrade round-trip anchor. Measured or not-applicable, it must
    // be a `Reading` the guide can render.
    println!("TTFB: {:?}", timings.ttfb_us);

    // The attempt's log records the upgrade phases.
    assert!(trace.log.first_of(EventKind::HeadComplete).is_some());
}

/// Guide snippet: "Limits" — the struct fields must exist as documented.
#[tokio::test]
async fn guide_limits() {
    use netune::WsLimits;

    let limits = WsLimits {
        max_frame_bytes: 1024 * 1024,
        max_message_bytes: 4 * 1024 * 1024,
    };
    assert_eq!(limits.max_frame_bytes, 1024 * 1024);
}

/// Guide snippet: "Keep a Long Session Alive" — transcribed with the real API.
#[tokio::test]
async fn guide_keep_a_long_session_alive() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();
    tokio::spawn(serve(
        listener,
        vec![Frame::close(Some(netune_ws::CloseCode::NORMAL), "bye")],
        true,
    ));

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(format!("127.0.0.1:{port}"));
    let ws = client
        .connect_ws(&target, "/v1/stream")
        .await
        .expect("connect");

    let mut session = netune::WsSession::new(
        ws,
        netune::WsSessionConfig {
            // Default 20 s, aligned with the pool's idle bound and the 30–60 s
            // cull window edge gateways actually apply (ADR-0005).
            ping_interval: Duration::from_secs(20),
            pong_timeout: Duration::from_secs(10),
        },
    );

    // The guide's loop shape: `while let Some(message) = session.next().await?`
    // terminates on close or error; here the client closes first, so one
    // close() call ends it.
    session
        .close(netune_ws::CloseCode::NORMAL, "guide done")
        .await
        .expect("session close");
}
