#![cfg(feature = "http2")]
//! End-to-end integration tests for the unified client over HTTP/2.
//!
//! The server here is a hand-written peer, not `netune-server`, because these
//! tests are about the *client's* observable behaviour: when the response head
//! is returned, whether body chunks arrive incrementally, and whether a finished
//! exchange returns the negotiated connection to the pool.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use bytes::Bytes;
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TraceConfig};
use netune_http2::frame::{
    FLAG_ACK, FRAME_HEADER_LEN, FRAME_HEADERS, FRAME_PING, FRAME_SETTINGS, FRAME_WINDOW_UPDATE,
    Frame, FrameHeader, SETTING_MAX_CONCURRENT_STREAMS,
};
use netune_http2::hpack::{HpackDecoder, HpackEncoder};
use netune_trace::Fidelity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

fn client() -> Client<TcpConnector> {
    Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig {
            enable_http2: true,
            ..ClientConfig::default()
        },
    )
}

fn target(port: u16) -> Target {
    Target::plain(format!("127.0.0.1:{port}")).with_force_h2(true)
}

async fn write_frame(socket: &mut TcpStream, frame: Frame) {
    socket
        .write_all(&frame.encode())
        .await
        .expect("write frame");
}

async fn read_frame(socket: &mut TcpStream) -> (FrameHeader, Bytes) {
    let mut header = [0u8; FRAME_HEADER_LEN];
    socket.read_exact(&mut header).await.expect("frame header");
    let header = FrameHeader::parse(&header).expect("parse header");
    let mut payload = vec![0u8; header.length as usize];
    socket
        .read_exact(&mut payload)
        .await
        .expect("frame payload");
    (header, Bytes::from(payload))
}

/// Complete the client preface / SETTINGS exchange from the server side.
async fn handshake(socket: &mut TcpStream) {
    let mut preface = [0u8; netune_http2::CLIENT_PREFACE.len()];
    socket.read_exact(&mut preface).await.expect("preface");
    assert_eq!(&preface, netune_http2::CLIENT_PREFACE);

    let (settings, _) = read_frame(socket).await;
    assert_eq!(settings.frame_type, FRAME_SETTINGS);
    let (window, _) = read_frame(socket).await;
    assert_eq!(window.frame_type, FRAME_WINDOW_UPDATE);

    write_frame(
        socket,
        Frame::Settings {
            ack: false,
            settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 100)],
        },
    )
    .await;

    let (ack, _) = read_frame(socket).await;
    assert_eq!(ack.frame_type, FRAME_SETTINGS);
    assert_eq!(ack.flags & FLAG_ACK, FLAG_ACK);

    write_frame(
        socket,
        Frame::Settings {
            ack: true,
            settings: Vec::new(),
        },
    )
    .await;
}

/// Read frames until the next request HEADERS, skipping housekeeping.
async fn read_request(
    socket: &mut TcpStream,
    decoder: &mut HpackDecoder,
) -> (u32, Vec<(String, String)>) {
    loop {
        let (header, payload) = read_frame(socket).await;
        match header.frame_type {
            FRAME_HEADERS => {
                let fields = decoder.decode(&payload).expect("decode headers");
                return (header.stream_id, fields);
            }
            FRAME_WINDOW_UPDATE | FRAME_SETTINGS | FRAME_PING => continue,
            other => panic!("unexpected frame type {other}"),
        }
    }
}

async fn write_response_head(
    socket: &mut TcpStream,
    encoder: &mut HpackEncoder,
    stream_id: u32,
    status: &'static str,
    end_stream: bool,
) {
    write_frame(
        socket,
        Frame::Headers {
            stream_id,
            end_stream,
            end_headers: true,
            header_block: encoder.encode(vec![(":status", status)]),
        },
    )
    .await;
}

async fn write_body(socket: &mut TcpStream, stream_id: u32, payload: &'static [u8]) {
    write_frame(
        socket,
        Frame::Data {
            stream_id,
            end_stream: true,
            payload: Bytes::from_static(payload),
        },
    )
    .await;
}

/// Consume the connection-level `WINDOW_UPDATE` a completed body returns, so the
/// server task ends with the client's last write already read.
async fn drain_credit(socket: &mut TcpStream) {
    let mut updates = 0;
    while updates < 1 {
        let (header, _) = read_frame(socket).await;
        if header.frame_type == FRAME_WINDOW_UPDATE {
            updates += 1;
        }
    }
}

#[tokio::test]
async fn unified_client_transparently_executes_http2_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        handshake(&mut socket).await;

        let mut decoder = HpackDecoder::new();
        let (stream_id, headers) = read_request(&mut socket, &mut decoder).await;
        assert!(headers.iter().any(|(k, v)| k == ":method" && v == "GET"));
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == ":authority" && v == &format!("127.0.0.1:{port}")),
            "the target authority must ride :authority: {headers:?}"
        );
        // HTTP/2 carries the authority in `:authority`. A `Host` regular header
        // alongside it is rejected by some origins (Google's frontend resets the
        // stream with PROTOCOL_ERROR), so the unified client must never emit one.
        assert!(
            headers.iter().all(|(k, _)| k != "host"),
            "HTTP/2 requests must not carry a Host header: {headers:?}"
        );

        let mut encoder = HpackEncoder::new();
        write_response_head(&mut socket, &mut encoder, stream_id, "200", false).await;
        write_body(&mut socket, stream_id, b"unified client http2 response").await;
        drain_credit(&mut socket).await;
    });

    let client = client();
    let mut response = client
        .request(
            &target(port),
            RequestHead::new(Method::GET, "/api/data"),
            None,
        )
        .await
        .expect("send");

    assert_eq!(response.head.status.as_u16(), 200);
    assert_eq!(response.head.version, http::Version::HTTP_2);
    let body = response.body.read_to_end().await.expect("read body");
    assert_eq!(body.as_ref(), b"unified client http2 response");

    server.await.expect("server completed");
}

#[tokio::test]
async fn an_http2_trace_is_connection_level_l0() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        handshake(&mut socket).await;

        let mut decoder = HpackDecoder::new();
        let (stream_id, _) = read_request(&mut socket, &mut decoder).await;
        let mut encoder = HpackEncoder::new();
        write_response_head(&mut socket, &mut encoder, stream_id, "200", false).await;
        write_body(&mut socket, stream_id, b"l0").await;
        drain_credit(&mut socket).await;
    });

    let client = client();
    let mut response = client
        .request_traced(
            &target(port),
            RequestHead::new(Method::GET, "/l0"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect("traced h2 request");
    let _ = response.body.read_to_end().await.expect("body");

    let trace = response.body.trace().expect("H2 trace");
    assert_eq!(
        trace.fidelity,
        Fidelity::l0(),
        "H2 is connection-level; it must not claim a per-exchange syscall timeline"
    );

    server.await.expect("server completed");
}

/// The defining property of streaming: `send` returns when the response HEADERS
/// arrive, not when the body is complete. The server withholds the body until
/// the test says so, so a client that buffered the response would time out.
#[tokio::test]
async fn the_response_head_arrives_before_the_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (release_tx, release_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        handshake(&mut socket).await;

        let mut decoder = HpackDecoder::new();
        let (stream_id, _) = read_request(&mut socket, &mut decoder).await;
        let mut encoder = HpackEncoder::new();
        write_response_head(&mut socket, &mut encoder, stream_id, "200", false).await;

        release_rx.await.expect("release body");
        write_body(&mut socket, stream_id, b"later body").await;
        drain_credit(&mut socket).await;
    });

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client().request(
            &target(port),
            RequestHead::new(Method::GET, "/stream"),
            None,
        ),
    )
    .await
    .expect("the response head must arrive before the body is sent")
    .expect("send");
    assert_eq!(response.head.status.as_u16(), 200);

    release_tx.send(()).expect("release");
    let mut response = response;
    let body = response.body.read_to_end().await.expect("read body");
    assert_eq!(body.as_ref(), b"later body");

    server.await.expect("server completed");
}

/// A finished body returns the negotiated connection to the pool, and the next
/// request continues it on stream 3 rather than paying a second handshake.
#[tokio::test]
async fn a_finished_http2_body_returns_the_connection_to_the_pool() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        handshake(&mut socket).await;

        let mut decoder = HpackDecoder::new();
        for expected_stream in [1u32, 3u32] {
            let (stream_id, _) = read_request(&mut socket, &mut decoder).await;
            assert_eq!(
                stream_id, expected_stream,
                "the second request must reuse the same connection"
            );
            let mut encoder = HpackEncoder::new();
            write_response_head(&mut socket, &mut encoder, stream_id, "200", false).await;
            write_body(&mut socket, stream_id, b"body").await;
            drain_credit(&mut socket).await;
        }
    });

    let client = client();
    let key = client.pool_key(&target(port)).expect("plan");

    let mut first = client
        .request(&target(port), RequestHead::new(Method::GET, "/one"), None)
        .await
        .expect("first request");
    assert_eq!(
        first.body.read_to_end().await.expect("first body").as_ref(),
        b"body"
    );
    assert_eq!(
        client.pool().idle_count(&key),
        1,
        "a completed HTTP/2 exchange must return its connection to the pool"
    );

    let mut second = client
        .request(&target(port), RequestHead::new(Method::GET, "/two"), None)
        .await
        .expect("second request");
    assert_eq!(
        second
            .body
            .read_to_end()
            .await
            .expect("second body")
            .as_ref(),
        b"body"
    );

    server.await.expect("server completed");
}
