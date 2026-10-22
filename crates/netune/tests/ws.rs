#![cfg(feature = "ws")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use bytes::{Bytes, BytesMut};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use netune::{Client, ClientConfig, Pool, Target, TcpConnector, WsMessage};
use netune_trace::{EventKind, Recorder};
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
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));

    let mut ws = client
        .connect_ws_traced(
            &target,
            "/chat",
            Arc::clone(&recorder),
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
    let rec = recorder.lock().unwrap();
    assert!(rec.log().first_of(EventKind::RequestWriteStart).is_some());
    assert!(rec.log().first_of(EventKind::HeadComplete).is_some());
    assert!(rec.log().first_of(EventKind::ProtocolFrame).is_some());
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
