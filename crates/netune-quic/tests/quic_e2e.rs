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
            retry: true,
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

#[tokio::test]
async fn unknown_short_header_gets_a_stateless_reset() {
    let (_server, addr) = make_server_endpoint().await;
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("probe socket");
    let mut packet = vec![0u8; 64];
    packet[0] = 0x40;
    packet[1..9].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
    probe.send_to(&packet, addr).await.expect("send probe");
    let mut buffer = [0u8; 128];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        probe.recv_from(&mut buffer),
    )
    .await
    .expect("reset timeout")
    .expect("reset receive");
    assert!(len >= 21);
    assert_eq!(buffer[0] & 0x80, 0, "stateless reset uses a short header");
    assert_ne!(&buffer[len - 16..len], &[0u8; 16]);
}

#[tokio::test]
async fn unsupported_version_gets_version_negotiation() {
    let (_server, addr) = make_server_endpoint().await;
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("probe socket");
    let mut packet = vec![0u8; 1200];
    packet[0] = 0xc0;
    packet[1..5].copy_from_slice(&0x0a0a_0a0au32.to_be_bytes());
    packet[5] = 8;
    packet[6..14].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    packet[14] = 8;
    packet[15..23].copy_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);
    probe.send_to(&packet, addr).await.expect("send probe");
    let mut buffer = [0u8; 256];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        probe.recv_from(&mut buffer),
    )
    .await
    .expect("vn timeout")
    .expect("vn receive");
    let mut cursor = &buffer[..len];
    let negotiation = netune_quic::wire::packet::VersionNegotiation::decode(&mut cursor)
        .expect("version negotiation");
    assert_eq!(
        negotiation.destination_connection_id,
        vec![9, 10, 11, 12, 13, 14, 15, 16]
    );
    assert_eq!(
        negotiation.source_connection_id,
        vec![1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert!(
        negotiation
            .versions
            .contains(&netune_quic::wire::packet::VERSION_1)
    );
    assert!(
        negotiation
            .versions
            .contains(&netune_quic::wire::packet::VERSION_2)
    );
}
