#![cfg(feature = "ws")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use netune::{Client, ClientConfig, Pool, Target, TcpConnector, WsMessage};
use netune_trace::{EventKind, TraceCollector};
use netune_ws::{CloseCode, Frame, FrameDecoder, FrameEncoder, Role, compute_accept_key};

/// Read frames from `socket` until one complete frame decodes.
/// Decodes from buffered bytes first so a frame already in `read_buf`
/// (e.g. a Close that arrived with earlier data) is never skipped over.
async fn read_frame(socket: &mut tokio::net::TcpStream, read_buf: &mut BytesMut) -> Frame {
    loop {
        if let Some(f) = FrameDecoder::decode(read_buf, Role::Server, 64 * 1024).expect("decode") {
            return f;
        }
        let n = socket.read_buf(read_buf).await.expect("read frame");
        assert!(n > 0, "server socket closed while waiting for a frame");
    }
}

#[tokio::test]
async fn test_ws_handshake_and_bidirectional_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");

        // 1. Read HTTP Upgrade request
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.expect("read");
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
        }

        let req_str = String::from_utf8_lossy(&request);
        assert!(req_str.contains("GET /chat HTTP/1.1"));
        assert!(req_str.to_lowercase().contains("upgrade: websocket"));

        // Extract Sec-WebSocket-Key
        let key_line = req_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("sec-websocket-key:"))
            .expect("key header");
        let key = key_line.split(':').nth(1).unwrap().trim();
        let accept = compute_accept_key(key);

        // 2. Reply with 101 Switching Protocols
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("write 101");
        socket.flush().await.expect("flush 101");

        // 3. Receive client masked text frame
        let mut read_buf = BytesMut::new();
        let frame = read_frame(&mut socket, &mut read_buf).await;
        assert_eq!(frame.opcode, netune_ws::Opcode::Text);
        assert_eq!(frame.payload.as_ref(), b"Hello server!");

        // 4. Send unmasked text frame back
        let reply_frame = Frame::text(Bytes::from_static(b"Hello from server!"));
        let mut out = BytesMut::new();
        FrameEncoder::encode(&reply_frame, None, &mut out);
        socket.write_all(&out).await.expect("write reply");
        socket.flush().await.expect("flush reply");

        // 5. Send Ping to client
        let ping_frame = Frame::ping(Bytes::from_static(b"heartbeat-token"));
        out.clear();
        FrameEncoder::encode(&ping_frame, None, &mut out);
        socket.write_all(&out).await.expect("write ping");
        socket.flush().await.expect("flush ping");

        // 6. Expect Pong response from client
        let pong_frame = read_frame(&mut socket, &mut read_buf).await;
        assert_eq!(pong_frame.opcode, netune_ws::Opcode::Pong);
        assert_eq!(pong_frame.payload.as_ref(), b"heartbeat-token");

        // 7. Receive client close frame
        let close_frame = read_frame(&mut socket, &mut read_buf).await;
        assert_eq!(close_frame.opcode, netune_ws::Opcode::Close);
    });

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(format!("127.0.0.1:{port}"));
    let recorder = TraceCollector::start(1024);

    let mut ws = client
        .connect_ws_traced(
            &target,
            "/chat",
            recorder.clone(),
            netune::WsHandshake::default(),
        )
        .await
        .expect("connect_ws");

    // Client sends text message
    ws.send_text("Hello server!").await.expect("send_text");

    // Client receives text message
    let msg = ws.receive().await.expect("receive").expect("some msg");
    assert_eq!(msg, WsMessage::Text("Hello from server!".to_string()));

    // Client receives ping (and automatically replies with pong)
    let ping_msg = ws.receive().await.expect("receive").expect("ping msg");
    assert_eq!(
        ping_msg,
        WsMessage::Ping(Bytes::from_static(b"heartbeat-token"))
    );

    // Client sends close
    ws.close(CloseCode::NORMAL, "closing cleanly")
        .await
        .expect("close");

    server_task.await.expect("server join");

    // Verify trace events
    let log = recorder.log();
    assert!(log.first_of(EventKind::RequestWriteStart).is_some());
    assert!(log.first_of(EventKind::HeadComplete).is_some());
    assert!(log.first_of(EventKind::ProtocolFrame).is_some());
}

/// `[INV-WS-05]`: an upgraded socket is never returned to the keep-alive pool.
///
/// The invariant is stated in ADR-0007 and indexed in
/// `docs/dev/invariants.md`, and until this test existed nothing
/// failed if an upgrade path started handing its socket back: a WS connection's
/// state lives on the wire, so a pooled upgrade would hand the next request a
/// stream mid-frame. The assertion is on the pool the client actually owns, not
/// on a proxy for it.
#[tokio::test]
async fn inv_ws_05_an_upgraded_socket_never_enters_the_pool() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.expect("read");
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
        }
        let request = String::from_utf8_lossy(&request).to_string();
        let key = request
            .lines()
            .find(|line| line.to_lowercase().starts_with("sec-websocket-key:"))
            .expect("key")
            .split(':')
            .nth(1)
            .expect("key value")
            .trim();
        let accept = compute_accept_key(key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        socket.write_all(response.as_bytes()).await.expect("101");

        // Complete the close handshake so the client's `close` returns.
        let mut read_buf = BytesMut::new();
        loop {
            match FrameDecoder::decode(&mut read_buf, Role::Server, 64 * 1024).expect("decode") {
                Some(frame) if frame.opcode == netune_ws::Opcode::Close => {
                    let mut out = BytesMut::new();
                    FrameEncoder::encode(
                        &Frame::close(Some(CloseCode::NORMAL), "bye"),
                        None,
                        &mut out,
                    );
                    socket.write_all(&out).await.expect("close reply");
                    return;
                }
                Some(_) => continue,
                None => {}
            }
            let n = socket.read_buf(&mut read_buf).await.expect("read close");
            assert!(n > 0, "client never sent a close frame");
        }
    });

    let authority = format!("127.0.0.1:{port}");
    let pool = Pool::default();
    let client = Client::new(TcpConnector::new(), pool.clone(), ClientConfig::default());
    let target = Target::plain(authority.clone());

    let mut ws = client
        .connect_ws(&target, "/v1/stream")
        .await
        .expect("connect_ws");
    ws.close(CloseCode::NORMAL, "done").await.expect("close");
    server_task.await.expect("server join");

    assert_eq!(
        pool.idle_count(&client.pool_key(&target).expect("plan")),
        0,
        "an upgraded socket must never be released to the keep-alive pool"
    );
}

#[tokio::test]
async fn test_ws_rejection_non_101() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(format!("127.0.0.1:{port}"));
    let result = client.connect_ws(&target, "/missing").await;
    assert!(result.is_err());
    let err_str = result.err().unwrap().to_string();
    assert!(err_str.contains("404"));
}

#[tokio::test]
async fn test_ws_rejection_bad_accept_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: invalid-accept-key\r\n\r\n",
            )
            .await
            .unwrap();
    });

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(format!("127.0.0.1:{port}"));
    let result = client.connect_ws(&target, "/ws").await;
    assert!(result.is_err());
    let err_str = result.err().unwrap().to_string();
    assert!(err_str.contains("mismatch"));
}

/// The upgrade response is peer-controlled: a server can accept the request
/// and never send the 101. The handshake bound must turn that into a connect
/// failure rather than holding the socket until an outer watchdog fires.
#[tokio::test]
async fn a_peer_that_never_answers_the_upgrade_is_bounded() {
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("port").port();
    let (release, released) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        let _ = released.await;
    });

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(format!("127.0.0.1:{port}"));
    let started = std::time::Instant::now();
    let error = match client
        .connect_ws_traced(
            &target,
            "/chat",
            TraceCollector::start(64),
            netune::WsHandshake::default().with_handshake_timeout(Some(Duration::from_millis(100))),
        )
        .await
    {
        Ok(_) => panic!("a peer that never sends 101 must not complete the upgrade"),
        Err(error) => error,
    };
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(80),
        "the error must be the WebSocket handshake bound: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the configured bound must fire long before the 10 s default: {elapsed:?}"
    );
    assert_eq!(error.class(), "connect");
    assert!(
        error.to_string().contains("WebSocket handshake"),
        "the failure must name the stalled phase: {error}"
    );

    let _ = release.send(());
    let _ = server.await;
}
