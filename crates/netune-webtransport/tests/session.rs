// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use netune_quic::QuicConnector;
use netune_quic::owned::{Endpoint, ServerConfigOwned};
use netune_quic::profile::QuicProfile;
use netune_quic::wire::transport_parameters::TransportParameters;
use netune_webtransport::{
    ControlCapsule, WebTransportClient, WebTransportServer, WebTransportSettings,
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

#[tokio::test]
async fn webtransport_session_streams_datagrams_and_close() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: true,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("accept");
        let mut wt = WebTransportServer::new(connection, WebTransportSettings::default())
            .await
            .expect("wt server");
        let mut session = wt.accept().await.expect("accept wt").expect("session");
        let mut stream = session.accept_bidi().await.expect("accept bidi");
        let data = stream.recv.read(1024).await.expect("read").expect("data");
        assert_eq!(data.as_ref(), b"hello");
        stream.send.write_all(b"world").await.expect("write");
        stream.send.finish().await.expect("finish");
        let mut server_uni = session.open_uni().await.expect("open uni");
        server_uni.write_all(b"uni").await.expect("uni write");
        server_uni.finish().await.expect("uni finish");
        let datagram = session.next_datagram().await.expect("datagram");
        assert_eq!(datagram.as_ref(), b"ping");
        session.send_datagram(b"pong").await.expect("send datagram");
        let close = session
            .next_control()
            .await
            .expect("close")
            .expect("capsule");
        assert!(matches!(close, ControlCapsule::Close { code: 7, .. }));
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
        .connect_session("https://localhost/session")
        .await
        .expect("session");
    let mut stream = session.open_bidi().await.expect("open bidi");
    stream.send.write_all(b"hello").await.expect("write");
    stream.send.finish().await.expect("finish");
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv.read(16))
        .await
        .expect("read timeout")
        .expect("read")
        .expect("data");
    assert_eq!(response.as_ref(), b"world");
    let mut uni = session.accept_uni().await.expect("accept uni");
    let uni_data = tokio::time::timeout(std::time::Duration::from_secs(2), uni.read(16))
        .await
        .expect("uni timeout")
        .expect("uni read")
        .expect("uni data");
    assert_eq!(uni_data.as_ref(), b"uni");
    let mut client_uni = session.open_uni().await.expect("open client uni");
    client_uni
        .write_all(b"cuni")
        .await
        .expect("client uni write");
    client_uni.finish().await.expect("client uni finish");
    session.send_datagram(b"ping").await.expect("send datagram");
    let datagram = tokio::time::timeout(std::time::Duration::from_secs(2), session.next_datagram())
        .await
        .expect("datagram timeout")
        .expect("datagram");
    assert_eq!(datagram.as_ref(), b"pong");
    session.close(7, "done").await.expect("close");
    tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
        .await
        .expect("server timeout")
        .expect("server task");
}
