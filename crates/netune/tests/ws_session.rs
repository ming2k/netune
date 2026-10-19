#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use netune::{Client, ClientConfig, Pool, Target, TcpConnector, WsMessage};
use netune_trace::Recorder;
use netune_ws::{Frame, FrameDecoder, FrameEncoder, Role, compute_accept_key};

/// Commands the server mock's script can issue against the connection.
enum ServerCmd {
    Send(Frame),
    /// Relay the next client frame to the test through the channel.
    ExpectClientFrame(mpsc::Sender<Frame>),
}

/// Mock origin: completes the upgrade, then executes the scripted commands.
async fn serve_scripted(listener: TcpListener, script: Vec<ServerCmd>) {
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
    for cmd in script {
        match cmd {
            ServerCmd::Send(frame) => {
                let mut out = BytesMut::new();
                FrameEncoder::encode(&frame, None, &mut out);
                socket.write_all(&out).await.expect("write frame");
                socket.flush().await.expect("flush frame");
            }
            ServerCmd::ExpectClientFrame(tx) => {
                let frame = loop {
                    if let Some(f) = FrameDecoder::decode(&mut read_buf, Role::Server, 64 * 1024)
                        .expect("decode")
                    {
                        break f;
                    }
                    let n = socket.read_buf(&mut read_buf).await.expect("read frame");
                    assert!(n > 0, "socket closed waiting for client frame");
                };
                tx.send(frame).await.expect("relay client frame");
            }
        }
    }
    // Hold the connection open so the client's reads block rather than EOF.
    tokio::time::sleep(Duration::from_secs(60)).await;
}

fn test_target(port: u16) -> Target {
    Target::plain(format!("127.0.0.1:{port}"))
}

fn test_client() -> Client<TcpConnector> {
    Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    )
}

#[tokio::test]
async fn pong_deadline_exceeded_fails_the_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    // Server: after upgrade, never answers pings. Hold silent for longer
    // than the session's whole ping+timeout cycle.
    tokio::spawn(serve_scripted(listener, vec![]));

    let client = test_client();
    let ws = client
        .connect_ws(&test_target(port), "/ws")
        .await
        .expect("connect");

    let mut session = netune::WsSession::new(
        ws,
        netune::WsSessionConfig {
            ping_interval: Duration::from_millis(100),
            pong_timeout: Duration::from_millis(200),
        },
    );

    let err = session
        .next()
        .await
        .expect_err("session must fail at the pong deadline");
    assert!(
        err.to_string().contains("pong deadline"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn server_pong_recharges_liveness_and_session_survives() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    // Server: deliver an unsolicited pong well before any deadline.
    tokio::spawn(serve_scripted(
        listener,
        vec![ServerCmd::Send(Frame::pong(Bytes::from_static(
            b"keepalive-echo",
        )))],
    ));

    let client = test_client();
    let ws = client
        .connect_ws(&test_target(port), "/ws")
        .await
        .expect("connect");

    let mut session = netune::WsSession::new(
        ws,
        netune::WsSessionConfig {
            ping_interval: Duration::from_millis(100),
            pong_timeout: Duration::from_millis(200),
        },
    );

    // The pong must surface as a received message, not trip the deadline.
    let msg = session.next().await.expect("next").expect("some");
    assert!(matches!(msg, WsMessage::Pong(_)));
}

#[tokio::test]
async fn client_ping_reaches_the_server_and_pong_answer_discharges() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    // Server: expect one client ping, echo it back as a pong.
    let (tx, mut rx) = mpsc::channel::<Frame>(1);
    let relay = tx.clone();
    tokio::spawn(serve_scripted(
        listener,
        vec![
            ServerCmd::ExpectClientFrame(relay),
            ServerCmd::Send(Frame::pong(Bytes::from_static(b"echo"))),
        ],
    ));

    let client = test_client();
    let ws = client
        .connect_ws(&test_target(port), "/ws")
        .await
        .expect("connect");

    let mut session = netune::WsSession::new(
        ws,
        netune::WsSessionConfig {
            ping_interval: Duration::from_millis(50),
            pong_timeout: Duration::from_millis(500),
        },
    );

    // Drive the session concurrently so its ~50 ms heartbeat actually fires,
    // while we wait for the server mock to relay the ping back here.
    let session_task = tokio::spawn(async move { session.next().await });

    let sent_ping = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("server saw the client ping")
        .expect("ping frame");
    assert_eq!(sent_ping.opcode, netune_ws::Opcode::Ping);
    drop(tx);

    // The echoed pong keeps the session alive and is delivered to us.
    let outcome = tokio::time::timeout(Duration::from_secs(5), session_task)
        .await
        .expect("session survived the pong round-trip")
        .expect("join");
    let msg = outcome.expect("next").expect("some");
    assert!(matches!(msg, WsMessage::Pong(_)));
}

#[tokio::test]
async fn disabled_heartbeat_passes_through_without_timers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    tokio::spawn(serve_scripted(
        listener,
        vec![ServerCmd::Send(Frame::text(Bytes::from_static(b"hello")))],
    ));

    let client = test_client();
    let ws = client
        .connect_ws(&test_target(port), "/ws")
        .await
        .expect("connect");

    let mut session = netune::WsSession::new(
        ws,
        netune::WsSessionConfig {
            ping_interval: Duration::ZERO,
            pong_timeout: Duration::from_secs(10),
        },
    );

    let msg = session.next().await.expect("next").expect("some");
    assert_eq!(msg, WsMessage::Text("hello".to_string()));
}

#[tokio::test]
async fn peer_initiated_pong_does_not_discharge_our_probe() {
    // The liveness-correctness core: a pong whose payload differs from our
    // outstanding ping's payload is peer-initiated liveness evidence — it
    // must NOT discharge our probe, so a peer that pongs arbitrarily but
    // never answers our pings still fails the deadline.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    // Server: on the first client ping relay, reply with a DIFFERENT payload.
    let (tx, mut rx) = mpsc::channel::<Frame>(1);
    let relay = tx.clone();
    tokio::spawn(serve_scripted(
        listener,
        vec![
            ServerCmd::ExpectClientFrame(relay),
            ServerCmd::Send(Frame::pong(Bytes::from_static(b"not-your-answer"))),
        ],
    ));

    let client = test_client();
    let ws = client
        .connect_ws(&test_target(port), "/ws")
        .await
        .expect("connect");

    let session = netune::WsSession::new(
        ws,
        netune::WsSessionConfig {
            ping_interval: Duration::from_millis(50),
            pong_timeout: Duration::from_millis(150),
        },
    );

    // Drive the session concurrently; its ping goes out at ~50 ms. The
    // session stays in the task for its whole life: each `next()` polls it.
    let session = Arc::new(tokio::sync::Mutex::new(session));
    let session_task = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.lock().await.next().await })
    };

    // The server relayed our ping, then sent its decoy pong.
    let sent_ping = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("server saw the client ping")
        .expect("ping frame");
    assert_eq!(sent_ping.opcode, netune_ws::Opcode::Ping);
    drop(tx);

    // First next(): the decoy pong is delivered as a peer-initiated pong
    // (RFC 6455 allows unsolicited pongs for application use), but the
    // probe remains unanswered.
    let first = tokio::time::timeout(Duration::from_secs(5), session_task)
        .await
        .expect("session alive for the decoy delivery")
        .expect("join");
    assert!(
        matches!(&first, Ok(Some(WsMessage::Pong(p))) if p.as_ref() == b"not-your-answer"),
        "decoy pong delivered as peer-initiated pong: {first:?}"
    );

    // The probe is still outstanding, so the *next* call fails the deadline.
    let err = session
        .lock()
        .await
        .next()
        .await
        .expect_err("decoy pong must not discharge the probe");
    assert!(
        err.to_string().contains("pong deadline"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn wsframe_events_record_every_frame_including_fragment_parts() {
    use netune_trace::EventKind;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    // Server: send a fragmented text message in three frames.
    let f1 = Frame::new(
        false,
        netune_ws::Opcode::Text,
        Bytes::from_static(b"part1-"),
    );
    let f2 = Frame::new(
        false,
        netune_ws::Opcode::Continuation,
        Bytes::from_static(b"part2-"),
    );
    let f3 = Frame::new(
        true,
        netune_ws::Opcode::Continuation,
        Bytes::from_static(b"part3"),
    );
    tokio::spawn(serve_scripted(
        listener,
        vec![
            ServerCmd::Send(f1),
            ServerCmd::Send(f2),
            ServerCmd::Send(f3),
        ],
    ));

    let client = test_client();
    let target = test_target(port);
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));

    let mut ws = client
        .connect_ws_traced(
            &target,
            "/ws",
            Arc::clone(&recorder),
            netune::WsHandshake::default(),
        )
        .await
        .expect("connect");

    let msg = ws.receive().await.expect("receive").expect("some");
    assert_eq!(msg, WsMessage::Text("part1-part2-part3".to_string()));

    // Frame-level trace: exactly three WsFrame events, one per fragment part.
    let rec = recorder.lock().unwrap();
    let ws_frames: Vec<_> = rec
        .log()
        .iter()
        .filter(|e| e.kind == EventKind::WsFrame)
        .collect();
    assert_eq!(
        ws_frames.len(),
        3,
        "each fragment part must be individually traced"
    );
    assert_eq!(ws_frames[0].b, 6); // "part1-"
    assert_eq!(ws_frames[1].b, 6); // "part2-"
    assert_eq!(ws_frames[2].b, 5); // "part3"
}

#[tokio::test]
async fn peer_close_code_is_echoed_in_the_reply() {
    // The reply close frame must echo the peer's status code (RFC 6455
    // §5.5.1), not a hard-coded 1000.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    let (tx, mut rx) = mpsc::channel::<Frame>(1);
    let relay = tx.clone();
    tokio::spawn(serve_scripted(
        listener,
        vec![
            ServerCmd::Send(Frame::close(
                Some(netune_ws::CloseCode::POLICY_VIOLATION),
                "",
            )),
            ServerCmd::ExpectClientFrame(relay),
        ],
    ));

    let client = test_client();
    let mut ws = client
        .connect_ws(&test_target(port), "/ws")
        .await
        .expect("connect");

    // Client's receive completes the close handshake.
    let msg = ws.receive().await.expect("receive").expect("close msg");
    assert!(matches!(msg, WsMessage::Close(_)));

    // The server then relays the client's reply close frame.
    drop(tx);
    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("server saw the client's close reply")
        .expect("close frame");
    assert_eq!(reply.opcode, netune_ws::Opcode::Close);
    // Echoed code: 1008 (POLICY_VIOLATION), not 1000.
    assert_eq!(reply.payload.as_ref(), &[0x03, 0xF0]);
}

#[tokio::test]
async fn subprotocol_negotiation_offers_and_validates_the_echo() {
    use netune::WsHandshake;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    // Server mock: capture the offered list, echo the first entry.
    let (tx, mut rx) = mpsc::channel::<String>(1);
    tokio::spawn(async move {
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
        let offered = req_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("sec-websocket-protocol:"))
            .map(|l| l.split(':').nth(1).unwrap().trim().to_string())
            .unwrap_or_default();
        tx.send(offered).await.expect("tx");
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: mcp.v1\r\n\r\n"
        );
        socket.write_all(response.as_bytes()).await.expect("101");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let client = test_client();
    let target = test_target(port);

    let handshake = WsHandshake::default()
        .with_subprotocol("mcp.v1")
        .with_subprotocol("mcp.v0")
        .with_extra_header("authorization", "Bearer test-token");

    let ws = client
        .connect_ws_traced(
            &target,
            "/mcp",
            Arc::new(Mutex::new(Recorder::start(1024))),
            handshake,
        )
        .await
        .expect("subprotocol negotiation must succeed when the echo matches an offer");

    // The offered list reached the server in order.
    let offered = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("server saw the offer")
        .expect("offer");
    assert_eq!(offered, "mcp.v1, mcp.v0");
    drop(ws);
}

#[tokio::test]
async fn subprotocol_echo_mismatch_fails_loudly() {
    use netune::WsHandshake;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    tokio::spawn(async move {
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
        // Echo a subprotocol we never offered, but a valid accept key.
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: surprise.v9\r\n\r\n"
        );
        socket.write_all(response.as_bytes()).await.expect("101");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let client = test_client();
    let handshake = WsHandshake::default().with_subprotocol("mcp.v1");
    let result = client
        .connect_ws_traced(
            &test_target(port),
            "/mcp",
            Arc::new(Mutex::new(Recorder::start(1024))),
            handshake,
        )
        .await;
    let err = match result {
        Ok(_) => panic!("unoffered subprotocol echo must be rejected"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("not offered"), "{err}");
}

#[tokio::test]
async fn close_after_completed_handshake_is_idempotent() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    // Server: closes first, then waits for the client's reply close.
    tokio::spawn(serve_scripted(
        listener,
        vec![
            ServerCmd::Send(Frame::close(Some(netune_ws::CloseCode::NORMAL), "bye")),
            ServerCmd::ExpectClientFrame(mpsc::channel::<Frame>(1).0),
        ],
    ));

    let client = test_client();
    let mut ws = client
        .connect_ws(&test_target(port), "/ws")
        .await
        .expect("connect");

    // Client observes the close, then calls close() again — the guide's
    // natural flow. The second close must be a no-op, not an error.
    let msg = ws.receive().await.expect("receive").expect("close msg");
    assert!(matches!(msg, WsMessage::Close(_)));
    ws.close(netune_ws::CloseCode::NORMAL, "done")
        .await
        .expect("close after completed handshake must be idempotent");
}

#[tokio::test]
async fn text_roundtrip_through_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    // Server: read one client text frame, reply with its uppercase payload.
    let (tx, _rx) = mpsc::channel::<Frame>(1);
    let relay = tx.clone();
    tokio::spawn(serve_scripted(
        listener,
        vec![
            ServerCmd::ExpectClientFrame(relay),
            ServerCmd::Send(Frame::text(Bytes::from_static(b"WORLD"))),
        ],
    ));

    let client = test_client();
    let ws = client
        .connect_ws(&test_target(port), "/ws")
        .await
        .expect("connect");

    let mut session = netune::WsSession::new(ws, netune::WsSessionConfig::default());

    session.send_text("hello").await.expect("send");
    drop(tx);

    let msg = tokio::time::timeout(Duration::from_secs(5), session.next())
        .await
        .expect("roundtrip")
        .expect("next")
        .expect("some");
    assert_eq!(msg, WsMessage::Text("WORLD".to_string()));
}
