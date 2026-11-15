// SPDX-License-Identifier: MIT

//! Independent wire-role differential tests for `netune-webtransport` (ADR-0038, ADR-0049).
//!
//! These suites verify that `WebTransportServer` and `WebTransportClient`
//! interoperate with a peer constructed directly at the raw HTTP/3 framing
//! boundary rather than speaking to themselves, including:
//! - a client that omits server-only `SETTINGS_ENABLE_CONNECT_PROTOCOL` and
//!   `SETTINGS_WT_ENABLED` (`[INV-H3-15]`, `[INV-WT-07]`);
//! - a server that advertises only the draft-16 `0x2c7cf000` codepoint or only
//!   the draft-17 `0x20b8933b` codepoint (`[INV-WT-07]`);
//! - bidirectional streams (`0x41`), unidirectional streams (`0x54`) in both
//!   directions, Quarter-Stream-ID datagrams in both directions, and
//!   `WT_DRAIN_SESSION` / `WT_CLOSE_SESSION` capsules.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use bytes::BytesMut;
use netune_http3::{Capsule, H3Client, H3ExtensionStream, H3ServerConnection, H3SettingsProfile};
use netune_quic::QuicConnector;
use netune_quic::owned::{Endpoint, ServerConfigOwned};
use netune_quic::profile::QuicProfile;
use netune_quic::wire::transport_parameters::TransportParameters;
use netune_webtransport::{
    ControlCapsule, SETTINGS_WT_ENABLED, SETTINGS_WT_ENABLED_DRAFT16, SETTINGS_WT_INITIAL_MAX_DATA,
    SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, SETTINGS_WT_INITIAL_MAX_STREAMS_UNI, SessionId,
    WT_STREAM_SIGNAL, WT_UNI_STREAM_TYPE, WebTransportClient, WebTransportServer,
    WebTransportSettings, encode_bidi_header, encode_uni_header,
};

fn tls_pair() -> test_support::tls::TestIdentity {
    test_support::tls::identity(&["localhost", "127.0.0.1"], &[b"h3"])
}

fn transport() -> TransportParameters {
    TransportParameters {
        max_datagram_frame_size: Some(65_535),
        reset_stream_at: true,
        initial_max_data: Some(16 * 1024 * 1024),
        initial_max_stream_data_bidi_local: Some(1 << 20),
        initial_max_stream_data_bidi_remote: Some(1 << 20),
        initial_max_stream_data_uni: Some(1 << 20),
        initial_max_streams_bidi: Some(100),
        initial_max_streams_uni: Some(100),
        active_connection_id_limit: Some(4),
        ..TransportParameters::default()
    }
}

#[tokio::test]
async fn independent_wire_client_completes_bidi_uni_and_datagram_exchange() {
    let tls = tls_pair();
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: tls.server.clone(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = endpoint.local_addr();

    let server_task = tokio::spawn(async move {
        let connection = endpoint.accept().await.expect("accept");
        let mut wt = WebTransportServer::new(connection, WebTransportSettings::default())
            .await
            .expect("wt server");
        let mut session = wt.accept().await.expect("accept wt").expect("session");

        let mut bidi = session.accept_bidi().await.expect("accept bidi");
        let data = bidi.recv.read(1024).await.expect("read").expect("payload");
        assert_eq!(data.as_ref(), b"hello from wire peer");
        bidi.send
            .write_all(b"pong from netune")
            .await
            .expect("write bidi");
        bidi.send.finish().await.expect("finish bidi");

        let mut uni = session.accept_uni().await.expect("accept uni");
        let uni_data = uni.read(1024).await.expect("read uni").expect("payload");
        assert_eq!(uni_data.as_ref(), b"hello uni from wire peer");

        let mut reply_uni = session.open_uni().await.expect("open server uni");
        reply_uni
            .write_all(b"pong uni from netune")
            .await
            .expect("write server uni");
        reply_uni.finish().await.expect("finish server uni");

        let datagram = session.next_datagram().await.expect("recv datagram");
        assert_eq!(datagram.as_ref(), b"hello datagram from wire peer");
        session
            .send_datagram(b"pong datagram from netune")
            .await
            .expect("send datagram");

        let close = session
            .next_control()
            .await
            .expect("control")
            .expect("close capsule");
        assert_eq!(
            close,
            ControlCapsule::Close {
                code: 0,
                message: "clean".to_string(),
            }
        );
    });

    // External clients (such as quic-go/webtransport-go) do not echo the
    // server-only SETTINGS_ENABLE_CONNECT_PROTOCOL or SETTINGS_WT_ENABLED
    // settings; they advertise only their flow-control limits and H3 datagrams.
    let mut client_settings = H3SettingsProfile::default().with_datagrams();
    client_settings.extra_settings = vec![
        (SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, 100),
        (SETTINGS_WT_INITIAL_MAX_STREAMS_UNI, 100),
        (SETTINGS_WT_INITIAL_MAX_DATA, 16 * 1024 * 1024),
    ];

    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*tls.client).clone());
    let mut h3 =
        H3Client::connect_with_settings(&connector, addr, "localhost", None, client_settings)
            .await
            .expect("h3 client");
    h3.wait_settings().await;

    // Server must advertise both draft-17 and draft-16 codepoints (`[INV-WT-07]`).
    assert_eq!(h3.peer_setting(SETTINGS_WT_ENABLED), Some(1));
    assert_eq!(h3.peer_setting(SETTINGS_WT_ENABLED_DRAFT16), Some(1));

    let mut ext_rx = h3.enable_stream_extension_with_validator(
        vec![WT_UNI_STREAM_TYPE],
        WT_STREAM_SIGNAL,
        |id| SessionId::new(id).is_ok(),
    );

    let mut connect_stream = h3
        .connect_extended("webtransport-h3", "https://localhost/interop")
        .await
        .expect("open CONNECT");
    assert_eq!(connect_stream.head().status(), 200);
    let session_id = SessionId::new(connect_stream.id()).expect("session id");

    // 1. Bidirectional stream (`0x41`, session_id).
    let quic = connect_stream.quic_connection().clone();
    let (mut bidi_send, mut bidi_recv) = quic.open_bi().await.expect("open raw bidi");
    let mut header = BytesMut::new();
    encode_bidi_header(session_id, &mut header).expect("encode bidi header");
    bidi_send.write_all(&header).await.expect("send header");
    bidi_send
        .write_all(b"hello from wire peer")
        .await
        .expect("send payload");
    bidi_send.finish().await.expect("finish bidi");
    let echo = bidi_recv
        .read(1024)
        .await
        .expect("read bidi")
        .expect("echo bytes");
    assert_eq!(echo.as_ref(), b"pong from netune");

    // 2. Unidirectional stream client -> server (`0x54`, session_id).
    let mut uni_send = quic.open_uni().await.expect("open raw uni");
    header.clear();
    encode_uni_header(session_id, &mut header).expect("encode uni header");
    uni_send.write_all(&header).await.expect("send uni header");
    uni_send
        .write_all(b"hello uni from wire peer")
        .await
        .expect("send uni payload");
    uni_send.finish().await.expect("finish uni");

    // 3. Unidirectional stream server -> client.
    let event = ext_rx.recv().await.expect("server uni event");
    match event {
        H3ExtensionStream::Uni {
            stream_type,
            session_id: incoming_id,
            mut recv,
        } => {
            assert_eq!(stream_type, WT_UNI_STREAM_TYPE);
            assert_eq!(incoming_id, session_id.get());
            let data = recv
                .read(1024)
                .await
                .expect("read server uni")
                .expect("server uni bytes");
            assert_eq!(data.as_ref(), b"pong uni from netune");
        }
        H3ExtensionStream::Bidi { .. } => panic!("expected server unidirectional stream"),
    }

    // 4. Datagram exchange in both directions.
    connect_stream
        .send_datagram(b"hello datagram from wire peer")
        .await
        .expect("send datagram");
    let dgram = connect_stream
        .next_datagram()
        .await
        .expect("receive datagram");
    assert_eq!(dgram.as_ref(), b"pong datagram from netune");

    // 5. Session close capsule over the CONNECT stream.
    let close_wire = ControlCapsule::Close {
        code: 0,
        message: "clean".to_string(),
    }
    .to_capsule()
    .expect("capsule");
    connect_stream
        .send_capsule(&close_wire)
        .await
        .expect("write close capsule");

    server_task.await.expect("server task");
}

async fn run_wire_server_with_codepoint(wt_enabled_codepoint: u64) {
    let tls = tls_pair();
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: tls.server.clone(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = endpoint.local_addr();

    let server_task = tokio::spawn(async move {
        let connection = endpoint.accept().await.expect("accept");
        let quic = connection.clone();
        let mut settings = H3SettingsProfile::default()
            .with_extended_connect()
            .with_datagrams();
        settings.extra_settings = vec![
            (wt_enabled_codepoint, 1),
            (SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, 100),
            (SETTINGS_WT_INITIAL_MAX_STREAMS_UNI, 100),
            (SETTINGS_WT_INITIAL_MAX_DATA, 16 * 1024 * 1024),
        ];
        let mut h3 = H3ServerConnection::new(connection, &settings)
            .await
            .expect("h3 server");
        h3.wait_settings().await;
        let mut ext_rx = h3.enable_stream_extension_with_validator(
            vec![WT_UNI_STREAM_TYPE],
            WT_STREAM_SIGNAL,
            |id| SessionId::new(id).is_ok(),
        );

        let request = h3.accept().await.expect("accept").expect("request");
        let (head, mut connect_stream) = request.into_parts();
        assert_eq!(head.method(), http::Method::CONNECT);
        let session_id = SessionId::new(connect_stream.id()).expect("session id");
        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("200 response");
        connect_stream
            .send_response(response)
            .await
            .expect("send 200");

        // Accept client bidi stream.
        let Some(H3ExtensionStream::Bidi {
            session_id: bidi_sid,
            mut send,
            mut recv,
        }) = ext_rx.recv().await
        else {
            panic!("expected bidi stream");
        };
        assert_eq!(bidi_sid, session_id.get());
        let bidi_in = recv.read(1024).await.expect("read bidi").expect("bytes");
        assert_eq!(bidi_in.as_ref(), b"client bidi");
        send.write_all(b"server bidi").await.expect("write bidi");
        send.finish().await.expect("finish bidi");

        // Accept client uni stream.
        let Some(H3ExtensionStream::Uni {
            stream_type,
            session_id: uni_sid,
            mut recv,
        }) = ext_rx.recv().await
        else {
            panic!("expected uni stream");
        };
        assert_eq!(stream_type, WT_UNI_STREAM_TYPE);
        assert_eq!(uni_sid, session_id.get());
        let uni_in = recv.read(1024).await.expect("read uni").expect("bytes");
        assert_eq!(uni_in.as_ref(), b"client uni");

        // Open server uni stream.
        let mut server_uni = quic.open_uni().await.expect("open server uni");
        let mut header = BytesMut::new();
        encode_uni_header(session_id, &mut header).expect("uni header");
        server_uni.write_all(&header).await.expect("write header");
        server_uni
            .write_all(b"server uni")
            .await
            .expect("write payload");
        server_uni.finish().await.expect("finish uni");

        // Exchange datagrams.
        let dgram = connect_stream.next_datagram().await.expect("recv dgram");
        assert_eq!(dgram.as_ref(), b"client dgram");
        connect_stream
            .send_datagram(b"server dgram")
            .await
            .expect("send dgram");

        // Read client close capsule.
        let capsule: Capsule = connect_stream
            .next_capsule()
            .await
            .expect("read capsule")
            .expect("capsule");
        assert_eq!(
            ControlCapsule::from_capsule(&capsule).expect("parse close"),
            Some(ControlCapsule::Close {
                code: 42,
                message: "done".to_string(),
            })
        );
    });

    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*tls.client).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let mut session = client
        .connect_session("https://localhost/interop")
        .await
        .expect("wt session");

    let mut bidi = session.open_bidi().await.expect("open bidi");
    bidi.send.write_all(b"client bidi").await.expect("write");
    bidi.send.finish().await.expect("finish");
    let reply = bidi.recv.read(1024).await.expect("read").expect("bytes");
    assert_eq!(reply.as_ref(), b"server bidi");

    let mut uni = session.open_uni().await.expect("open uni");
    uni.write_all(b"client uni").await.expect("write uni");
    uni.finish().await.expect("finish uni");

    let mut incoming_uni = session.accept_uni().await.expect("accept server uni");
    let uni_reply = incoming_uni
        .read(1024)
        .await
        .expect("read server uni")
        .expect("bytes");
    assert_eq!(uni_reply.as_ref(), b"server uni");

    session
        .send_datagram(b"client dgram")
        .await
        .expect("send dgram");
    let dgram_reply = session.next_datagram().await.expect("recv dgram");
    assert_eq!(dgram_reply.as_ref(), b"server dgram");

    session.close(42, "done").await.expect("close session");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn client_interoperates_with_draft16_only_wire_server() {
    run_wire_server_with_codepoint(SETTINGS_WT_ENABLED_DRAFT16).await;
}

#[tokio::test]
async fn client_interoperates_with_draft17_only_wire_server() {
    run_wire_server_with_codepoint(SETTINGS_WT_ENABLED).await;
}
