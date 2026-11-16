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

async fn read_server_frame(socket: &mut TcpStream) -> Frame {
    let mut header = [0u8; FRAME_HEADER_LEN];
    socket.read_exact(&mut header).await.expect("frame header");
    let frame = FrameHeader::parse(&header).expect("parse header");
    let mut payload = vec![0u8; frame.length as usize];
    socket
        .read_exact(&mut payload)
        .await
        .expect("frame payload");
    Frame::decode(&frame, Bytes::from(payload)).expect("decode frame")
}

async fn server_handshake(socket: &mut TcpStream, settings: Vec<(u16, u32)>) {
    let mut preface = [0u8; CLIENT_PREFACE.len()];
    socket.read_exact(&mut preface).await.expect("preface");
    assert_eq!(&preface, CLIENT_PREFACE);

    let first = read_server_frame(socket).await;
    assert!(matches!(first, Frame::Settings { ack: false, .. }));

    socket
        .write_all(
            &Frame::Settings {
                ack: false,
                settings,
            }
            .encode(),
        )
        .await
        .expect("server settings");

    loop {
        match read_server_frame(socket).await {
            Frame::WindowUpdate { stream_id: 0, .. } => continue,
            Frame::Settings { ack: true, .. } => break,
            other => panic!("unexpected handshake frame {other:?}"),
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
        .expect("server ack");
}

#[tokio::test]
async fn stream_credit_is_not_lost_while_waiting_for_connection_credit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        server_handshake(&mut socket, vec![(SETTING_INITIAL_WINDOW_SIZE, 65_535)]).await;

        let Frame::Headers { stream_id, .. } = read_server_frame(&mut socket).await else {
            panic!("expected request HEADERS");
        };

        // Consume exactly one stream window. The client cannot send more until
        // both the stream and the connection windows are replenished.
        let mut consumed = 0usize;
        while consumed < 65_535 {
            let Frame::Data { payload, .. } = read_server_frame(&mut socket).await else {
                panic!("expected request DATA");
            };
            consumed += payload.len();
        }
        assert_eq!(consumed, 65_535);

        // Send stream credit first. The old writer read the stream update while
        // waiting for the connection window and discarded it, then waited for
        // stream credit that would never arrive.
        socket
            .write_all(
                &Frame::WindowUpdate {
                    stream_id,
                    increment: 65_535,
                }
                .encode(),
            )
            .await
            .expect("stream credit");
        socket
            .write_all(
                &Frame::WindowUpdate {
                    stream_id: 0,
                    increment: 65_535,
                }
                .encode(),
            )
            .await
            .expect("connection credit");

        loop {
            match read_server_frame(&mut socket).await {
                Frame::Data { end_stream, .. } if end_stream => break,
                Frame::Data { .. } => {}
                other => panic!("unexpected frame {other:?}"),
            }
        }

        let block = HpackEncoder::new().encode([(":status", "200")]);
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
            .expect("response head");
        socket
            .write_all(
                &Frame::Data {
                    stream_id,
                    end_stream: true,
                    payload: Bytes::from_static(b"ok"),
                }
                .encode(),
            )
            .await
            .expect("response body");
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let mut client = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake");
    let body = vec![b'q'; 100_000];
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.request("POST", "example.com", "https", "/upload", &[], Some(&body)),
    )
    .await
    .expect("stream credit must not be lost")
    .expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(&response.body[..], b"ok");
    server.await.expect("join");
}

#[tokio::test]
async fn session_multiplexes_interleaved_concurrent_streams() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        server_handshake(&mut socket, vec![(SETTING_MAX_CONCURRENT_STREAMS, 16)]).await;

        let Frame::Headers { stream_id: s1, .. } = read_server_frame(&mut socket).await else {
            panic!("expected first HEADERS");
        };
        let Frame::Headers { stream_id: s2, .. } = read_server_frame(&mut socket).await else {
            panic!("expected second HEADERS");
        };
        assert_ne!(s1, s2);

        let mut encoder = HpackEncoder::new();
        // Reply to stream 2 first, then interleave headers/data out of order.
        let h2 = encoder.encode([(":status", "201")]);
        let h1 = encoder.encode([(":status", "200")]);
        socket
            .write_all(
                &Frame::Headers {
                    stream_id: s2,
                    end_stream: false,
                    end_headers: true,
                    header_block: h2,
                }
                .encode(),
            )
            .await
            .expect("h2");
        socket
            .write_all(
                &Frame::Headers {
                    stream_id: s1,
                    end_stream: false,
                    end_headers: true,
                    header_block: h1,
                }
                .encode(),
            )
            .await
            .expect("h1");
        socket
            .write_all(
                &Frame::Data {
                    stream_id: s2,
                    end_stream: false,
                    payload: Bytes::from_static(b"two-a-"),
                }
                .encode(),
            )
            .await
            .expect("s2a");
        socket
            .write_all(
                &Frame::Data {
                    stream_id: s1,
                    end_stream: true,
                    payload: Bytes::from_static(b"one"),
                }
                .encode(),
            )
            .await
            .expect("s1");
        socket
            .write_all(
                &Frame::Data {
                    stream_id: s2,
                    end_stream: true,
                    payload: Bytes::from_static(b"two-b"),
                }
                .encode(),
            )
            .await
            .expect("s2b");
        let _ = done_rx.await;
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let session = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake")
        .into_session();
    let profile = *session.request_profile();

    let (sender1, head1, mut reader1) = session
        .open_request(
            None,
            "GET",
            "example.com",
            "https",
            "/1",
            &[],
            None,
            false,
            &profile,
        )
        .await
        .expect("open 1");
    assert!(sender1.is_none());
    let (sender2, head2, mut reader2) = session
        .open_request(
            None,
            "GET",
            "example.com",
            "https",
            "/2",
            &[],
            None,
            false,
            &profile,
        )
        .await
        .expect("open 2");
    assert!(sender2.is_none());

    let (r1, r2) = tokio::join!(head1.await_head(), head2.await_head());
    assert_eq!(r1.expect("head 1").status, 200);
    assert_eq!(r2.expect("head 2").status, 201);

    let mut body1 = Vec::new();
    while let H2ResponseEvent::Data { payload, .. } = reader1.next_event().await.expect("r1") {
        body1.extend_from_slice(&payload);
    }
    let mut body2 = Vec::new();
    while let H2ResponseEvent::Data { payload, .. } = reader2.next_event().await.expect("r2") {
        body2.extend_from_slice(&payload);
    }

    assert_eq!(body1, b"one");
    assert_eq!(body2, b"two-a-two-b");
    assert!(session.is_usable());
    assert_eq!(session.active_streams(), 0);
    let _ = done_tx.send(());
    server.await.expect("server");
}

#[tokio::test]
async fn session_answers_idle_ping_and_settings_then_stops_on_goaway() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let (goaway_tx, goaway_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        server_handshake(&mut socket, vec![(SETTING_MAX_CONCURRENT_STREAMS, 16)]).await;

        let opaque = *b"12345678";
        socket
            .write_all(
                &Frame::Ping {
                    ack: false,
                    opaque_data: opaque,
                }
                .encode(),
            )
            .await
            .expect("ping");
        assert!(matches!(
            read_server_frame(&mut socket).await,
            Frame::Ping { ack: true, opaque_data } if opaque_data == opaque
        ));

        socket
            .write_all(
                &Frame::Settings {
                    ack: false,
                    settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 32)],
                }
                .encode(),
            )
            .await
            .expect("peer settings");
        assert!(matches!(
            read_server_frame(&mut socket).await,
            Frame::Settings { ack: true, .. }
        ));

        socket
            .write_all(
                &Frame::GoAway {
                    last_stream_id: 0,
                    error_code: crate::connection::error_code::NO_ERROR,
                    debug_data: Bytes::from_static(b"drain"),
                }
                .encode(),
            )
            .await
            .expect("goaway");
        // Wait for EOF once client driver observes idle GOAWAY and exits cleanly.
        let mut buf = [0u8; 16];
        let n = socket.read(&mut buf).await.expect("eof read");
        assert_eq!(n, 0);
        let _ = goaway_tx.send(());
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let session = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake")
        .into_session();
    let profile = *session.request_profile();

    goaway_rx.await.expect("goaway sent");
    // Idle driver exits on GOAWAY; subsequent opens fail cleanly instead of hanging.
    let err = session
        .open_request(
            None,
            "GET",
            "example.com",
            "https",
            "/",
            &[],
            None,
            false,
            &profile,
        )
        .await
        .err()
        .expect("post-goaway request must fail");
    assert!(
        !session.is_usable(),
        "GOAWAY must mark session unusable: {err}"
    );
    server.await.expect("server");
}

#[tokio::test]
async fn session_goaway_keeps_lower_stream_alive_and_fails_higher_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        server_handshake(&mut socket, vec![(SETTING_MAX_CONCURRENT_STREAMS, 16)]).await;

        let Frame::Headers { stream_id: s1, .. } = read_server_frame(&mut socket).await else {
            panic!("expected s1");
        };
        let Frame::Headers { stream_id: s2, .. } = read_server_frame(&mut socket).await else {
            panic!("expected s2");
        };
        assert_eq!(s1, 1);
        assert_eq!(s2, 3);

        socket
            .write_all(
                &Frame::GoAway {
                    last_stream_id: 1,
                    error_code: crate::connection::error_code::NO_ERROR,
                    debug_data: Bytes::new(),
                }
                .encode(),
            )
            .await
            .expect("goaway");

        let mut encoder = HpackEncoder::new();
        socket
            .write_all(
                &Frame::Headers {
                    stream_id: s1,
                    end_stream: true,
                    end_headers: true,
                    header_block: encoder.encode([(":status", "200")]),
                }
                .encode(),
            )
            .await
            .expect("reply s1");
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let session = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake")
        .into_session();
    let profile = *session.request_profile();

    let (_, h1, mut r1) = session
        .open_request(
            None,
            "GET",
            "example.com",
            "https",
            "/1",
            &[],
            None,
            false,
            &profile,
        )
        .await
        .expect("open 1");
    let (_, h2, _r2) = session
        .open_request(
            None,
            "GET",
            "example.com",
            "https",
            "/2",
            &[],
            None,
            false,
            &profile,
        )
        .await
        .expect("open 2");

    let head1 = h1.await_head().await.expect("stream 1 survives");
    assert_eq!(head1.status, 200);
    r1.mark_empty();

    let err2 = h2
        .await_head()
        .await
        .expect_err("stream 3 above last_stream_id");
    assert!(matches!(err2, H2Error::GoAway { .. }));
    assert!(!session.is_usable());
    server.await.expect("server");
}

#[tokio::test]
async fn session_early_body_drop_sends_cancel_drains_credit_and_reuses_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let (late_done_tx, late_done_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        server_handshake(&mut socket, vec![(SETTING_MAX_CONCURRENT_STREAMS, 16)]).await;

        let Frame::Headers { stream_id: s1, .. } = read_server_frame(&mut socket).await else {
            panic!("expected s1");
        };
        let mut encoder = HpackEncoder::new();
        socket
            .write_all(
                &Frame::Headers {
                    stream_id: s1,
                    end_stream: false,
                    end_headers: true,
                    header_block: encoder.encode([(":status", "200")]),
                }
                .encode(),
            )
            .await
            .expect("h1");
        socket
            .write_all(
                &Frame::Data {
                    stream_id: s1,
                    end_stream: false,
                    payload: Bytes::from(vec![b'a'; 100]),
                }
                .encode(),
            )
            .await
            .expect("d1");

        // Reader drops after reading head + chunk 1 -> expect RST_STREAM(CANCEL) + WINDOW_UPDATE(0, 100).
        let mut saw_rst = false;
        let mut conn_credit = 0u32;
        while !saw_rst || conn_credit < 100 {
            match read_server_frame(&mut socket).await {
                Frame::RstStream {
                    stream_id,
                    error_code,
                } => {
                    assert_eq!(stream_id, s1);
                    assert_eq!(error_code, crate::connection::error_code::CANCEL);
                    saw_rst = true;
                }
                Frame::WindowUpdate {
                    stream_id: 0,
                    increment,
                } => conn_credit += increment,
                other => panic!("unexpected frame {other:?}"),
            }
        }

        // Send a late in-flight DATA frame after RST; client must return connection credit too.
        socket
            .write_all(
                &Frame::Data {
                    stream_id: s1,
                    end_stream: true,
                    payload: Bytes::from(vec![b'z'; 64]),
                }
                .encode(),
            )
            .await
            .expect("late data");
        assert!(matches!(
            read_server_frame(&mut socket).await,
            Frame::WindowUpdate {
                stream_id: 0,
                increment: 64
            }
        ));
        let _ = late_done_tx.send(());

        // Second request must still succeed on the same connection.
        let Frame::Headers { stream_id: s2, .. } = read_server_frame(&mut socket).await else {
            panic!("expected s2");
        };
        assert_eq!(s2, 3);
        socket
            .write_all(
                &Frame::Headers {
                    stream_id: s2,
                    end_stream: false,
                    end_headers: true,
                    header_block: encoder.encode([(":status", "200")]),
                }
                .encode(),
            )
            .await
            .expect("h2");
        socket
            .write_all(
                &Frame::Data {
                    stream_id: s2,
                    end_stream: true,
                    payload: Bytes::from_static(b"survived"),
                }
                .encode(),
            )
            .await
            .expect("d2");
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let session = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake")
        .into_session();
    let profile = *session.request_profile();

    let (_, h1, mut r1) = session
        .open_request(
            None,
            "GET",
            "example.com",
            "https",
            "/abort",
            &[],
            None,
            false,
            &profile,
        )
        .await
        .expect("open 1");
    assert_eq!(h1.await_head().await.expect("h1").status, 200);
    let first = r1.next_event().await.expect("chunk 1");
    assert!(
        matches!(first, H2ResponseEvent::Data { payload, end_stream: false } if payload.len() == 100)
    );
    drop(r1);
    late_done_rx.await.expect("late data handled");

    let (_, h2, mut r2) = session
        .open_request(
            None,
            "GET",
            "example.com",
            "https",
            "/next",
            &[],
            None,
            false,
            &profile,
        )
        .await
        .expect("open 2");
    assert_eq!(h2.await_head().await.expect("h2").status, 200);
    let mut collected = Vec::new();
    while let H2ResponseEvent::Data { payload, .. } = r2.next_event().await.expect("next") {
        collected.extend_from_slice(&payload);
    }
    assert_eq!(collected, b"survived");
    server.await.expect("server");
}

#[tokio::test]
async fn session_streams_request_body_across_peer_flow_control_window_and_respects_max_streams() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        server_handshake(
            &mut socket,
            vec![
                (SETTING_MAX_CONCURRENT_STREAMS, 1),
                (SETTING_INITIAL_WINDOW_SIZE, 1024),
            ],
        )
        .await;

        let Frame::Headers {
            stream_id,
            end_stream: false,
            ..
        } = read_server_frame(&mut socket).await
        else {
            panic!("expected request HEADERS with end_stream=false");
        };

        let mut received = Vec::new();
        while received.len() < 1024 {
            let Frame::Data {
                stream_id: id,
                end_stream,
                payload,
            } = read_server_frame(&mut socket).await
            else {
                panic!("expected DATA");
            };
            assert_eq!(id, stream_id);
            assert!(!end_stream);
            received.extend_from_slice(&payload);
        }
        assert_eq!(received.len(), 1024);

        // Open both stream and connection send windows so the remaining 2048 bytes arrive.
        socket
            .write_all(
                &Frame::WindowUpdate {
                    stream_id,
                    increment: 2048,
                }
                .encode(),
            )
            .await
            .expect("stream win");
        socket
            .write_all(
                &Frame::WindowUpdate {
                    stream_id: 0,
                    increment: 2048,
                }
                .encode(),
            )
            .await
            .expect("conn win");

        loop {
            let Frame::Data {
                stream_id: id,
                end_stream,
                payload,
            } = read_server_frame(&mut socket).await
            else {
                panic!("expected DATA");
            };
            assert_eq!(id, stream_id);
            received.extend_from_slice(&payload);
            if end_stream {
                break;
            }
        }
        assert_eq!(received.len(), 3072);
        assert!(received.iter().all(|b| *b == b'x'));

        let mut encoder = HpackEncoder::new();
        socket
            .write_all(
                &Frame::Headers {
                    stream_id,
                    end_stream: true,
                    end_headers: true,
                    header_block: encoder.encode([(":status", "200")]),
                }
                .encode(),
            )
            .await
            .expect("200");
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let session = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
        .await
        .expect("handshake")
        .into_session();
    let profile = *session.request_profile();

    let permit = session.try_reserve_stream().expect("first permit");
    assert!(
        session.try_reserve_stream().is_none(),
        "SETTINGS_MAX_CONCURRENT_STREAMS=1 must bound reservations"
    );

    let (sender, head, mut reader) = session
        .open_request(
            Some(permit),
            "POST",
            "example.com",
            "https",
            "/upload",
            &[],
            None,
            true,
            &profile,
        )
        .await
        .expect("open upload");
    let mut sender = sender.expect("streaming sender");
    for _ in 0..3 {
        sender
            .send_data(Bytes::from(vec![b'x'; 1024]))
            .await
            .expect("send chunk");
    }
    sender.finish().expect("finish upload");

    let response = head.await_head().await.expect("head");
    assert_eq!(response.status, 200);
    reader.mark_empty();
    assert!(session.try_reserve_stream().is_some());
    server.await.expect("server");
}
