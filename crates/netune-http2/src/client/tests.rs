use super::*;
use crate::connection::CLIENT_PREFACE;
use crate::frame::*;
use crate::hpack::HpackEncoder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A minimal server that completes the handshake and answers one request.
async fn serve_once(socket: &mut TcpStream, body: &'static [u8], status: &'static str) {
    let mut preface = [0u8; CLIENT_PREFACE.len()];
    socket.read_exact(&mut preface).await.expect("preface");
    assert_eq!(&preface, CLIENT_PREFACE);

    let mut header = [0u8; FRAME_HEADER_LEN];
    socket
        .read_exact(&mut header)
        .await
        .expect("settings header");
    let settings = FrameHeader::parse(&header).expect("parse");
    let mut payload = vec![0u8; settings.length as usize];
    socket
        .read_exact(&mut payload)
        .await
        .expect("settings payload");

    socket
        .write_all(
            &Frame::Settings {
                ack: false,
                settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 100)],
            }
            .encode(),
        )
        .await
        .expect("server settings");

    // Client's WINDOW_UPDATE, if the profile sends one.
    loop {
        socket.read_exact(&mut header).await.expect("frame header");
        let frame = FrameHeader::parse(&header).expect("parse");
        let mut payload = vec![0u8; frame.length as usize];
        socket.read_exact(&mut payload).await.expect("payload");
        match frame.frame_type {
            FRAME_WINDOW_UPDATE => continue,
            FRAME_SETTINGS => break,
            other => panic!("unexpected frame {other}"),
        }
    }
    socket
        .write_all(
            &Frame::Settings {
                ack: true,
                settings: Vec::new(),
            }
            .encode(),
        )
        .await
        .expect("ack");

    // The request.
    socket.read_exact(&mut header).await.expect("headers");
    let frame = FrameHeader::parse(&header).expect("parse");
    let mut payload = vec![0u8; frame.length as usize];
    socket.read_exact(&mut payload).await.expect("payload");
    assert_eq!(frame.frame_type, FRAME_HEADERS);
    let stream_id = frame.stream_id;

    let mut encoder = HpackEncoder::new();
    let block = encoder.encode([(":status", status), ("content-type", "text/plain")]);
    socket
        .write_all(
            &Frame::Headers {
                stream_id,
                end_stream: false,
                end_headers: true,
                header_block: block,
            }
            .encode(),
        )
        .await
        .expect("headers");
    socket
        .write_all(
            &Frame::Data {
                stream_id,
                end_stream: true,
                payload: Bytes::from_static(body),
            }
            .encode(),
        )
        .await
        .expect("data");
}

/// A server that completes the handshake and sends a head, two data chunks,
/// and a trailer block, so the client's incremental events can be observed.
async fn serve_streaming(socket: &mut TcpStream) {
    let mut preface = [0u8; CLIENT_PREFACE.len()];
    socket.read_exact(&mut preface).await.expect("preface");
    assert_eq!(&preface, CLIENT_PREFACE);

    let mut header = [0u8; FRAME_HEADER_LEN];
    socket
        .read_exact(&mut header)
        .await
        .expect("settings header");
    let settings = FrameHeader::parse(&header).expect("parse");
    let mut payload = vec![0u8; settings.length as usize];
    socket
        .read_exact(&mut payload)
        .await
        .expect("settings payload");

    socket
        .write_all(
            &Frame::Settings {
                ack: false,
                settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 100)],
            }
            .encode(),
        )
        .await
        .expect("server settings");

    loop {
        socket.read_exact(&mut header).await.expect("frame header");
        let frame = FrameHeader::parse(&header).expect("parse");
        let mut payload = vec![0u8; frame.length as usize];
        socket.read_exact(&mut payload).await.expect("payload");
        match frame.frame_type {
            FRAME_WINDOW_UPDATE => continue,
            FRAME_SETTINGS => break,
            other => panic!("unexpected frame {other}"),
        }
    }
    socket
        .write_all(
            &Frame::Settings {
                ack: true,
                settings: Vec::new(),
            }
            .encode(),
        )
        .await
        .expect("ack");

    socket.read_exact(&mut header).await.expect("headers");
    let frame = FrameHeader::parse(&header).expect("parse");
    let mut payload = vec![0u8; frame.length as usize];
    socket.read_exact(&mut payload).await.expect("payload");
    assert_eq!(frame.frame_type, FRAME_HEADERS);
    let stream_id = frame.stream_id;

    let mut encoder = HpackEncoder::new();
    socket
        .write_all(
            &Frame::Headers {
                stream_id,
                end_stream: false,
                end_headers: true,
                header_block: encoder.encode([(":status", "200")]),
            }
            .encode(),
        )
        .await
        .expect("head");
    socket
        .write_all(
            &Frame::Data {
                stream_id,
                end_stream: false,
                payload: Bytes::from_static(b"hello"),
            }
            .encode(),
        )
        .await
        .expect("data 1");
    socket
        .write_all(
            &Frame::Data {
                stream_id,
                end_stream: false,
                payload: Bytes::from_static(b" world"),
            }
            .encode(),
        )
        .await
        .expect("data 2");
    socket
        .write_all(
            &Frame::Headers {
                stream_id,
                end_stream: true,
                end_headers: true,
                header_block: encoder.encode([("x-trailer", "done")]),
            }
            .encode(),
        )
        .await
        .expect("trailers");

    // The client returns connection-level credit at the end of the stream.
    // The stream is closed, so no stream-level update is required.
    let mut updates = 0;
    while updates < 1 {
        socket.read_exact(&mut header).await.expect("credit header");
        let frame = FrameHeader::parse(&header).expect("credit parse");
        let mut payload = vec![0u8; frame.length as usize];
        socket
            .read_exact(&mut payload)
            .await
            .expect("credit payload");
        if frame.frame_type == FRAME_WINDOW_UPDATE {
            updates += 1;
        }
    }
}

#[tokio::test]
async fn a_streamed_response_delivers_data_and_trailers_incrementally() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        serve_streaming(&mut socket).await;
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let client = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake");
    let (head, mut body) = client
        .request_stream("GET", "example.com", "https", "/v1/models", &[], None)
        .await
        .expect("stream");
    assert_eq!(head.status, 200);
    assert!(!head.end_stream);

    match body.next_event().await.expect("event") {
        H2ResponseEvent::Data {
            payload,
            end_stream,
        } => {
            assert_eq!(&payload[..], b"hello");
            assert!(!end_stream);
        }
        other => panic!("expected data, got {other:?}"),
    }
    match body.next_event().await.expect("event") {
        H2ResponseEvent::Data {
            payload,
            end_stream,
        } => {
            assert_eq!(&payload[..], b" world");
            assert!(!end_stream);
        }
        other => panic!("expected data, got {other:?}"),
    }
    match body.next_event().await.expect("event") {
        H2ResponseEvent::Trailers(fields) => assert!(
            fields
                .iter()
                .any(|(name, value)| name == "x-trailer" && value == "done"),
            "the trailer block must be surfaced: {fields:?}"
        ),
        other => panic!("expected trailers, got {other:?}"),
    }
    assert!(matches!(
        body.next_event().await.expect("event"),
        H2ResponseEvent::End
    ));
    let (_, reusable) = body.into_connection().expect("connection");
    assert!(reusable, "a cleanly finished exchange must be reusable");

    server.await.expect("server");
}

#[tokio::test]
async fn a_request_round_trips_with_the_profile_it_was_opened_with() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        serve_once(&mut socket, b"hello", "200").await;
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let mut client = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake");
    let response = client
        .request("GET", "example.com", "https", "/v1/models", &[], None)
        .await
        .expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(&response.body[..], b"hello");
    assert_eq!(
        response
            .headers
            .iter()
            .find(|(name, _)| name == "content-type")
            .map(|(_, value)| value.as_str()),
        Some("text/plain")
    );
    server.await.expect("server");
}

#[tokio::test]
async fn a_non_success_status_is_reported_not_treated_as_an_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        serve_once(&mut socket, b"nope", "503").await;
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let mut client = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake");
    let response = client
        .request("GET", "example.com", "https", "/", &[], None)
        .await
        .expect("a 503 is a response, not a transport failure");
    assert_eq!(response.status, 503);
    server.await.expect("server");
}

#[test]
fn pseudo_headers_follow_the_profiles_order() {
    let pseudo = [
        (":method", "GET"),
        (":authority", "example.com"),
        (":scheme", "https"),
        (":path", "/"),
    ];
    let chrome = crate::fingerprint::PseudoHeaderOrder::MethodAuthoritySchemePath;
    assert_eq!(
        chrome
            .order(&pseudo)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        vec![":method", ":authority", ":scheme", ":path"]
    );
    let firefox = crate::fingerprint::PseudoHeaderOrder::MethodPathAuthorityScheme;
    assert_eq!(
        firefox
            .order(&pseudo)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        vec![":method", ":path", ":authority", ":scheme"]
    );
}
