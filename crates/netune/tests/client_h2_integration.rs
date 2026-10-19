//! End-to-end integration test: Client natively executes HTTP/2 requests with full tracing (ADR-0006).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use bytes::Bytes;
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_http2::frame::{FRAME_HEADER_LEN, Frame, FrameHeader, SETTING_MAX_CONCURRENT_STREAMS};
use netune_http2::hpack::{HpackDecoder, HpackEncoder};
use netune_trace::Recorder;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn unified_client_transparently_executes_http2_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");

        // 1. Read preface
        let mut preface = [0u8; netune_http2::CLIENT_PREFACE.len()];
        socket.read_exact(&mut preface).await.expect("preface");

        // 2. Read client SETTINGS
        let mut h_buf = [0u8; FRAME_HEADER_LEN];
        socket
            .read_exact(&mut h_buf)
            .await
            .expect("settings header");
        let s_h = FrameHeader::parse(&h_buf).expect("parse s_h");
        let mut s_payload = vec![0u8; s_h.length as usize];
        socket.read_exact(&mut s_payload).await.expect("s_payload");

        // Read client WINDOW_UPDATE
        socket.read_exact(&mut h_buf).await.expect("wu header");
        let wu_h = FrameHeader::parse(&h_buf).expect("parse wu");
        let mut wu_payload = vec![0u8; wu_h.length as usize];
        socket
            .read_exact(&mut wu_payload)
            .await
            .expect("wu payload");

        // Send server SETTINGS
        let s_settings = Frame::Settings {
            ack: false,
            settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 50)],
        };
        socket
            .write_all(&s_settings.encode())
            .await
            .expect("send settings");

        // Read client ACK
        socket.read_exact(&mut h_buf).await.expect("read ack");

        // Read request HEADERS
        socket.read_exact(&mut h_buf).await.expect("req header");
        let req_h = FrameHeader::parse(&h_buf).expect("parse req");
        let mut req_payload = vec![0u8; req_h.length as usize];
        socket
            .read_exact(&mut req_payload)
            .await
            .expect("req payload");

        let decoder = HpackDecoder::new();
        let headers = decoder.decode(&req_payload).expect("decode");
        assert!(headers.iter().any(|(k, v)| k == ":method" && v == "GET"));

        // Reply 200 OK
        let encoder = HpackEncoder::new();
        let resp_headers = Frame::Headers {
            stream_id: req_h.stream_id,
            end_stream: false,
            end_headers: true,
            header_block: encoder.encode(vec![(":status", "200"), ("x-protocol", "h2")]),
        };
        socket
            .write_all(&resp_headers.encode())
            .await
            .expect("write headers");

        let resp_data = Frame::Data {
            stream_id: req_h.stream_id,
            end_stream: true,
            payload: Bytes::from_static(b"unified client http2 response"),
        };
        socket
            .write_all(&resp_data.encode())
            .await
            .expect("write data");
    });

    let target = Target::plain(format!("127.0.0.1:{port}")).with_force_h2(true);
    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let recorder = Arc::new(Mutex::new(Recorder::start(128)));
    let head = RequestHead::new(Method::GET, "/api/data");

    let mut response = client
        .send(&target, recorder.clone(), head, None)
        .await
        .expect("send");

    assert_eq!(response.head.status.as_u16(), 200);
    assert_eq!(response.head.version, http::Version::HTTP_2);
    let body = response.body.read_to_end().await.expect("read body");
    assert_eq!(body.as_ref(), b"unified client http2 response");

    server.await.expect("server completed");
}
