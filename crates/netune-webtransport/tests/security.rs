// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Adversarial WebTransport request, session-ID and flow-control tests
//! (ADR-0037 Gate 5).

use std::sync::Arc;
use std::time::Duration;

use netune_http3::{ExtendedConnectProtocol, H3Client, H3ResponseStream, H3SettingsProfile};
use netune_quic::QuicConnector;
use netune_quic::owned::{Endpoint, ServerConfigOwned};
use netune_quic::profile::QuicProfile;
use netune_quic::wire::transport_parameters::TransportParameters;
use netune_webtransport::{
    ControlCapsule, OriginPolicy, WebTransportClient, WebTransportOrigin, WebTransportServer,
    WebTransportSettings,
};

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn server_tls() -> Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("cert");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(tls)
}

fn client_tls() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(tls)
}

fn transport() -> TransportParameters {
    TransportParameters {
        max_datagram_frame_size: Some(65_535),
        reset_stream_at: true,
        initial_max_data: Some(16 * 1024 * 1024),
        initial_max_stream_data_bidi_local: Some(1 << 20),
        initial_max_stream_data_bidi_remote: Some(1 << 20),
        initial_max_stream_data_uni: Some(1 << 20),
        initial_max_streams_bidi: Some(1000),
        initial_max_streams_uni: Some(1000),
        active_connection_id_limit: Some(4),
        ..TransportParameters::default()
    }
}

async fn origin_server(
    policy: OriginPolicy,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = endpoint.local_addr();
    let task = tokio::spawn(async move {
        let connection = endpoint.accept().await.expect("accept");
        let mut wt = WebTransportServer::new(connection, WebTransportSettings::default())
            .await
            .expect("wt server")
            .with_origin_policy(policy);
        if let Some(session) = wt.accept().await.expect("accept request") {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(session);
        }
    });
    (addr, task)
}

async fn h3_client(addr: std::net::SocketAddr) -> H3Client {
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut profile = H3SettingsProfile::default()
        .with_extended_connect()
        .with_datagrams();
    profile.extra_settings = WebTransportSettings::default().extra_settings();
    H3Client::connect_with_settings(&connector, addr, "localhost", None, profile)
        .await
        .expect("h3 client")
}

async fn connect_request(client: &mut H3Client, uri: &str, origins: &[&str]) -> H3ResponseStream {
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .body(())
        .expect("request");
    request
        .extensions_mut()
        .insert(ExtendedConnectProtocol("webtransport-h3".to_string()));
    for origin in origins {
        request.headers_mut().append(
            http::header::ORIGIN,
            http::HeaderValue::from_str(origin).expect("origin header"),
        );
    }
    client
        .open_request(request)
        .await
        .expect("request head")
        .into_duplex()
        .await
        .expect("response")
}

#[tokio::test]
async fn a_spoofed_scheme_is_rejected() {
    let (addr, task) = origin_server(OriginPolicy::SameOrigin).await;
    let mut client = h3_client(addr).await;
    let response = connect_request(&mut client, "http://localhost/session", &[]).await;
    assert_eq!(response.head().status(), http::StatusCode::BAD_REQUEST);
    task.abort();
}

#[tokio::test]
async fn a_missing_authority_never_establishes_a_session() {
    let (addr, task) = origin_server(OriginPolicy::SameOrigin).await;
    let mut client = h3_client(addr).await;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("/session")
        .body(())
        .expect("request");
    request
        .extensions_mut()
        .insert(ExtendedConnectProtocol("webtransport-h3".to_string()));
    let result = match client.open_request(request).await {
        Ok(body) => body.into_duplex().await.map(|_| ()),
        Err(error) => Err(error),
    };
    assert!(
        result.is_err(),
        "an extended CONNECT without :authority must not establish a session"
    );
    task.abort();
}

#[tokio::test]
async fn a_default_same_origin_policy_rejects_a_spoofed_origin() {
    let (addr, task) = origin_server(OriginPolicy::SameOrigin).await;
    let mut client = h3_client(addr).await;
    let response = connect_request(
        &mut client,
        "https://localhost/session",
        &["https://evil.example"],
    )
    .await;
    assert_eq!(response.head().status(), http::StatusCode::FORBIDDEN);
    task.abort();
}

#[tokio::test]
async fn multiple_origin_headers_are_rejected() {
    let (addr, task) = origin_server(OriginPolicy::SameOrigin).await;
    let mut client = h3_client(addr).await;
    let response = connect_request(
        &mut client,
        "https://localhost/session",
        &["https://localhost", "https://evil.example"],
    )
    .await;
    assert_eq!(response.head().status(), http::StatusCode::BAD_REQUEST);
    task.abort();
}

#[tokio::test]
async fn an_allowlisted_cross_origin_is_accepted() {
    let origin = WebTransportOrigin::parse("https://app.example").expect("origin");
    let (addr, task) = origin_server(OriginPolicy::Allowlist(vec![origin])).await;
    let mut client = h3_client(addr).await;
    let response = connect_request(
        &mut client,
        "https://localhost/session",
        &["https://app.example"],
    )
    .await;
    assert_eq!(response.head().status(), http::StatusCode::OK);
    task.abort();
}

#[tokio::test]
async fn a_client_rejects_a_non_https_session_uri_before_connect() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        let _ = wt.accept().await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let result = client.connect_session("http://localhost/session").await;
    let error = match result {
        Ok(_) => panic!("http must not establish WebTransport"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("https"), "{error}");
    server_task.abort();
}

#[tokio::test]
async fn a_client_enable_setting_does_not_gate_server_admission() {
    let (addr, task) = origin_server(OriginPolicy::SameOrigin).await;
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    // Deliberately omit SETTINGS_WT_ENABLED. draft-17 says the server must
    // ignore this server-only setting when a client sends it.
    let profile = H3SettingsProfile::default()
        .with_extended_connect()
        .with_datagrams();
    let mut client = H3Client::connect_with_settings(&connector, addr, "localhost", None, profile)
        .await
        .expect("h3 client");
    let response = connect_request(&mut client, "https://localhost/session", &[]).await;
    assert_eq!(response.head().status(), http::StatusCode::OK);
    task.abort();
}

#[tokio::test]
async fn a_replayed_flow_control_capsule_is_rejected() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        let error = session
            .next_control()
            .await
            .expect_err("a regressed WT_MAX_DATA must fail");
        assert!(error.to_string().contains("WT_MAX_DATA"), "{error}");
        assert!(
            session.open_bidi().await.is_err(),
            "a flow-control violation must close the session"
        );
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let mut session = client
        .connect_session("https://localhost/flow")
        .await
        .expect("session");
    session
        .send_control(&ControlCapsule::MaxData(1))
        .await
        .expect("send regressed max data");
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("server timeout")
        .expect("server task");
}

#[tokio::test]
async fn a_replayed_stream_limit_capsule_is_rejected() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        let error = session
            .next_control()
            .await
            .expect_err("a regressed WT_MAX_STREAMS must fail");
        assert!(error.to_string().contains("WT_MAX_STREAMS"), "{error}");
        assert!(
            session.open_bidi().await.is_err(),
            "a stream-limit violation must close the session"
        );
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let mut session = client
        .connect_session("https://localhost/streams")
        .await
        .expect("session");
    session
        .send_control(&ControlCapsule::MaxStreams {
            bidi: true,
            maximum: 0,
        })
        .await
        .expect("send regressed max streams");
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("server timeout")
        .expect("server task");
}

#[tokio::test]
async fn a_peer_close_refuses_control_and_new_streams() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        session.close(7, "done").await.expect("server close");
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let mut session = client
        .connect_session("https://localhost/close")
        .await
        .expect("session");
    let close = session
        .next_control()
        .await
        .expect("close")
        .expect("close capsule");
    assert!(matches!(close, ControlCapsule::Close { code: 7, .. }));
    assert!(session.next_control().await.is_err());
    assert!(
        session
            .send_control(&ControlCapsule::MaxData(1 << 20))
            .await
            .is_err(),
        "a closed session must refuse further control"
    );
    assert!(
        session.open_bidi().await.is_err(),
        "a closed session must refuse new streams"
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn a_spoofed_bidi_session_id_closes_the_h3_connection() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        let session = wt.accept().await.expect("accept wt").expect("session");
        tokio::time::timeout(Duration::from_secs(2), session.quic().closed())
            .await
            .expect("server did not observe H3_ID_ERROR");
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let session = client
        .connect_session("https://localhost/spoof")
        .await
        .expect("session");
    let (mut send, _recv) = session.quic().open_bi().await.expect("raw stream");
    // WT_STREAM signal followed by session ID 2 (not a client bidi stream ID).
    let mut header = bytes::BytesMut::new();
    netune_quic::wire::varint::encode(&mut header, 0x41).expect("signal");
    netune_quic::wire::varint::encode(&mut header, 2).expect("session id");
    send.write_all(&header).await.expect("spoofed header");
    send.finish().await.expect("finish spoofed stream");
    tokio::time::timeout(Duration::from_secs(2), session.quic().closed())
        .await
        .expect("client did not observe the H3_ID_ERROR");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn a_spoofed_uni_session_id_closes_the_h3_connection() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        let session = wt.accept().await.expect("accept wt").expect("session");
        tokio::time::timeout(Duration::from_secs(2), session.quic().closed())
            .await
            .expect("server did not observe H3_ID_ERROR");
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let session = client
        .connect_session("https://localhost/spoof-uni")
        .await
        .expect("session");
    let mut send = session.quic().open_uni().await.expect("raw uni stream");
    // WT uni stream type followed by session ID 2.
    let mut header = bytes::BytesMut::new();
    netune_quic::wire::varint::encode(&mut header, 0x54).expect("stream type");
    netune_quic::wire::varint::encode(&mut header, 2).expect("session id");
    send.write_all(&header).await.expect("spoofed header");
    send.finish().await.expect("finish spoofed stream");
    tokio::time::timeout(Duration::from_secs(2), session.quic().closed())
        .await
        .expect("client did not observe the H3_ID_ERROR");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn an_incoming_data_overrun_terminates_the_session() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        let mut wt = WebTransportServer::new(
            connection,
            WebTransportSettings {
                initial_max_data: 4,
                ..WebTransportSettings::default()
            },
        )
        .await
        .expect("wt server");
        let mut session = wt.accept().await.expect("accept wt").expect("session");
        let mut stream = session.accept_bidi().await.expect("accept bidi");
        let error = stream
            .recv
            .read(16)
            .await
            .expect_err("incoming WT_MAX_DATA overrun must fail");
        assert!(error.to_string().contains("WT_MAX_DATA"), "{error}");
        assert!(
            session.open_bidi().await.is_err(),
            "an incoming flow-control violation must close the session"
        );
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let session = client
        .connect_session("https://localhost/incoming-limit")
        .await
        .expect("session");
    let mut header = bytes::BytesMut::new();
    netune_webtransport::encode_bidi_header(session.id(), &mut header).expect("header");
    let mut send = session.quic().open_bi().await.expect("raw stream").0;
    send.write_all(&header).await.expect("header write");
    send.write_all(&[0u8; 8]).await.expect("payload write");
    send.finish().await.expect("finish");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn a_reset_before_payload_surfaces_only_the_stream_header() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        let mut stream = session.accept_bidi().await.expect("accept bidi");
        let result = tokio::time::timeout(Duration::from_secs(2), stream.recv.read(16))
            .await
            .expect("reset timeout");
        assert!(
            result.is_err(),
            "a reset with zero application bytes must not produce data"
        );
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let session = client
        .connect_session("https://localhost/reset-order")
        .await
        .expect("session");
    let mut stream = session.open_bidi().await.expect("open bidi");
    stream
        .send
        .reset_reliable(7, 0)
        .expect("reset reliable header only");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn a_drain_refuses_new_streams() {
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
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
        session.drain().await.expect("drain");
        tokio::time::sleep(Duration::from_millis(500)).await;
    });
    let connector =
        QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config((*client_tls()).clone());
    let mut client = WebTransportClient::connect(
        &connector,
        addr,
        "localhost",
        WebTransportSettings::default(),
    )
    .await
    .expect("wt client");
    let mut session = client
        .connect_session("https://localhost/drain")
        .await
        .expect("session");
    let drain = session
        .next_control()
        .await
        .expect("drain")
        .expect("drain capsule");
    assert!(matches!(drain, ControlCapsule::Drain));
    assert!(
        session.open_bidi().await.is_err(),
        "a draining session must refuse new streams"
    );
    assert!(
        session.open_uni().await.is_err(),
        "a draining session must refuse new unidirectional streams"
    );
    server_task.await.expect("server task");
}
