// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end integration and invariant tests for `netune-quic`.
//!
//! Verifies:
//! - `[INV-QUIC-01]`: single crypto provider (`aws-lc-rs`).
//! - `[INV-QUIC-02]`: socket configuration and pre-connect path.
//! - `[INV-QUIC-03]`: monotonic trace event recording in `netune-trace`.
//! - `[INV-EGRESS-01]` / `[INV-QUIC-02]`: confinement precedes the socket.

use std::sync::Arc;

use netune_quic::owned::{Endpoint, ServerConfigOwned};
use netune_quic::profile::QuicProfile;
use netune_quic::socket::QuicSocketConfig;
use netune_quic::wire::transport_parameters::TransportParameters;
use netune_quic::{QuicConnector, QuicError};
use netune_trace::{EventKind, TraceCollector};

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

async fn make_server_endpoint() -> (Endpoint, std::net::SocketAddr) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen cert");
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(
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
        .with_single_cert(cert_chain, key)
        .expect("cert");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let transport = TransportParameters {
        max_datagram_frame_size: Some(65_535),
        initial_max_data: Some(16 * 1024 * 1024),
        initial_max_stream_data_bidi_local: Some(1 << 20),
        initial_max_stream_data_bidi_remote: Some(1 << 20),
        initial_max_stream_data_uni: Some(1 << 20),
        initial_max_streams_bidi: Some(1024),
        initial_max_streams_uni: Some(1024),
        active_connection_id_limit: Some(4),
        ..TransportParameters::default()
    };
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: Arc::new(tls),
            transport,
        },
    )
    .await
    .expect("endpoint");
    let addr = endpoint.local_addr();
    (endpoint, addr)
}

fn client_crypto() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth()
}

#[tokio::test]
async fn test_quic_stream_and_trace_lifecycle() {
    let (server, addr) = make_server_endpoint().await;

    tokio::spawn(async move {
        let conn = server.accept().await.expect("server handshake");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept stream");
        let data = recv.read(128).await.expect("read").expect("bytes");
        send.write_all(&data).await.expect("write");
        send.finish().await.expect("finish");
        conn.closed().await;
    });

    let recorder = TraceCollector::start(1024);
    let connector = QuicConnector::new(QuicProfile::chrome_quic())
        .with_tls_config(client_crypto())
        .with_socket_config(QuicSocketConfig {
            mark: None,
            bind_device: None,
            bind_address: None,
            tos: Some(0),
            recv_buffer_size: Some(65536),
            send_buffer_size: Some(65536),
        });

    let conn = connector
        .connect(addr, "localhost", Some(recorder.clone()))
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_stream().await.expect("open stream");
    send.write_all(b"hello quic").await.expect("write");
    send.finish().await.expect("finish");

    let mut response = Vec::new();
    while let Some(chunk) = recv.read(1024).await.expect("read") {
        response.extend_from_slice(&chunk);
    }
    assert_eq!(&response, b"hello quic");

    let kinds: Vec<EventKind> = recorder.log().iter().map(|event| event.kind).collect();
    assert!(kinds.contains(&EventKind::QuicStart));
    assert!(kinds.contains(&EventKind::QuicEnd));
    assert!(kinds.contains(&EventKind::QuicStreamOpen));
}

/// `[INV-EGRESS-01]` / `[INV-QUIC-02]`: a `StrictPublic` connector refuses a
/// non-public target *before* any socket is created, so no QUIC packet can be
/// sent to loopback or a metadata endpoint.
#[tokio::test]
async fn strict_public_confinement_refuses_a_loopback_target() {
    let (_server, addr) = make_server_endpoint().await;
    assert!(addr.ip().is_loopback(), "the fixture must be loopback");

    let connector = QuicConnector::new(QuicProfile::default_profile())
        .with_tls_config(client_crypto())
        .strict_public();

    let error = connector
        .connect(addr, "localhost", None)
        .await
        .expect_err("loopback must be refused");
    assert!(matches!(error, QuicError::Connect(_)));
}

#[tokio::test]
async fn datagrams_echo_and_enforce_the_peer_mtu() {
    let (server, addr) = make_server_endpoint().await;
    tokio::spawn(async move {
        let conn = server.accept().await.expect("server handshake");
        let datagram = conn.recv_datagram().await.expect("recv datagram");
        conn.send_datagram(datagram).await.expect("send datagram");
    });

    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto());
    let connection = connector
        .connect(addr, "localhost", None)
        .await
        .expect("connect");
    let session = connection.datagram_session();
    let max = session.max_datagram_size().expect("datagrams enabled");
    session.send(b"hello datagram").await.expect("send");
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(2), session.recv())
        .await
        .expect("recv timeout")
        .expect("recv");
    assert_eq!(echoed.as_ref(), b"hello datagram");

    let oversized = vec![0x42; max + 1];
    assert!(matches!(
        session.send(&oversized).await,
        Err(QuicError::DatagramTooLarge { .. })
    ));
}
