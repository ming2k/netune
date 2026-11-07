// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end integration and invariant tests for `netune-quic`.
//!
//! Verifies:
//! - [INV-QUIC-01]: Single crypto provider (aws-lc-rs).
//! - [INV-QUIC-02]: Socket configuration and pre-connect path.
//! - [INV-QUIC-03]: Monotonic trace event recording in `netune-trace`.
//! - [INV-QUIC-04]: RFC 9221 datagram MTU bounds and explicit size error.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune_quic::profile::QuicProfile;
use netune_quic::socket::QuicSocketConfig;
use netune_quic::{QuicConnector, QuicError};
use netune_trace::{EventKind, Recorder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

fn make_server_endpoint() -> (quinn::Endpoint, std::net::SocketAddr) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen cert");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();

    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der,
    ));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("cert");

    server_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("server crypto"),
    ));

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind server");
    let addr = socket.local_addr().expect("local addr");
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("endpoint");

    (endpoint, addr)
}

#[tokio::test]
async fn test_quic_stream_and_trace_lifecycle() {
    let (server, addr) = make_server_endpoint();

    // Spawn server accept task
    tokio::spawn(async move {
        if let Some(connecting) = server.accept().await {
            let conn = connecting.await.expect("server handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept stream");
            let mut buf = [0u8; 128];
            let n = recv.read(&mut buf).await.expect("read").expect("bytes");
            send.write_all(&buf[..n]).await.expect("write");
            let _ = send.finish();
            let _ = conn.closed().await;
        }
    });

    // Insecure TLS client config for test cert
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));

    let connector = QuicConnector::new(QuicProfile::chrome_quic())
        .with_tls_config(client_crypto)
        .with_socket_config(QuicSocketConfig {
            mark: None,
            bind_device: None,
            bind_address: None,
            tos: Some(0),
            recv_buffer_size: Some(65536),
            send_buffer_size: Some(65536),
        });

    let conn = connector
        .connect(addr, "localhost", Some(Arc::clone(&recorder)))
        .await
        .expect("connect");

    assert!(conn.rtt() >= Duration::ZERO);

    let mut stream = conn.open_stream().await.expect("open stream");
    stream.write_all(b"hello quic").await.expect("write");
    stream.shutdown().await.expect("shutdown");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read");
    assert_eq!(&response, b"hello quic");

    // Verify trace events [INV-QUIC-03]
    let log = recorder.lock().unwrap().log().clone();
    let kinds: Vec<EventKind> = log.iter().map(|e| e.kind).collect();
    assert!(
        kinds.contains(&EventKind::QuicStart),
        "must record QuicStart"
    );
    assert!(kinds.contains(&EventKind::QuicEnd), "must record QuicEnd");
    assert!(
        kinds.contains(&EventKind::QuicStreamOpen),
        "must record QuicStreamOpen"
    );
}

#[tokio::test]
async fn test_datagram_mtu_oversize_fails_cleanly() {
    let (server, addr) = make_server_endpoint();

    tokio::spawn(async move {
        if let Some(connecting) = server.accept().await {
            let conn = connecting.await.expect("server handshake");
            // Echo datagram
            if let Ok(dg) = conn.read_datagram().await {
                let _ = conn.send_datagram(dg);
            }
        }
    });

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector =
        QuicConnector::new(QuicProfile::default_profile()).with_tls_config(client_crypto);

    let conn = connector
        .connect(addr, "localhost", None)
        .await
        .expect("connect");

    let session = conn.datagram_session();

    // Oversized datagram test [INV-QUIC-04]
    let max = session.max_datagram_size().unwrap_or(1200);
    let oversized = vec![0x42; max + 2048];
    let err = session.send(&oversized).expect_err("must fail");

    match err {
        QuicError::DatagramTooLarge { max: m, size: s } => {
            assert_eq!(m, max);
            assert_eq!(s, max + 2048);
        }
        other => panic!("expected DatagramTooLarge, got: {other:?}"),
    }
}

/// `[INV-EGRESS-01]` / `[INV-QUIC-02]`: a `StrictPublic` connector refuses a
/// non-public target *before* any socket is created, so no QUIC packet can be
/// sent to loopback or a metadata endpoint. This is the guard that was missing
/// when the QUIC path dialled the raw caller address unconfined.
#[tokio::test]
async fn strict_public_confinement_refuses_a_loopback_target() {
    // A real listener is bound, so the only reason connect can fail is the policy,
    // not an unreachable port.
    let (_server, addr) = make_server_endpoint();
    assert!(addr.ip().is_loopback(), "the fixture must be loopback");

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector = QuicConnector::new(QuicProfile::default_profile())
        .with_tls_config(client_crypto)
        .strict_public();

    let err = connector
        .connect(addr, "localhost", None)
        .await
        .expect_err("a loopback target must be refused under StrictPublic");
    let message = err.to_string();
    assert!(
        message.contains("confinement"),
        "the refusal must name confinement, got: {message}"
    );
}
