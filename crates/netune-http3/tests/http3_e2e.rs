// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end integration test for HTTP/3 client.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use netune_http3::H3Client;
use netune_quic::QuicConnector;
use netune_quic::profile::QuicProfile;
use netune_trace::{EventKind, Recorder};

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
async fn test_http3_client_request_response_and_trace() {
    let (server, addr) = make_server_endpoint();

    tokio::spawn(async move {
        if let Some(connecting) = server.accept().await {
            let conn = connecting.await.expect("server handshake");
            let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn.clone()))
                .await
                .expect("server h3 connection");

            if let Some(resolver) = h3_conn.accept().await.expect("accept h3 request") {
                let (req, mut stream) = resolver.resolve_request().await.expect("resolve request");
                assert_eq!(req.uri().path(), "/test");
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "text/plain")
                    .body(())
                    .expect("response head");
                stream.send_response(response).await.expect("send response");
                stream
                    .send_data(Bytes::from_static(b"hello http3"))
                    .await
                    .expect("send data");
                stream.finish().await.expect("finish");
            }

            let _ = conn.closed().await;
        }
    });

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto);

    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));

    let conn = connector
        .connect(addr, "localhost", Some(Arc::clone(&recorder)))
        .await
        .expect("quic connect");

    let mut h3_client = H3Client::new(conn.connection(), Some(Arc::clone(&recorder)))
        .await
        .expect("h3 client");

    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/test")
        .body(Bytes::new())
        .expect("request");

    let response = h3_client.execute(request).await.expect("execute");
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), &Bytes::from_static(b"hello http3"));

    // Verify trace events [INV-QUIC-03]
    let log = recorder.lock().unwrap().log().clone();
    let kinds: Vec<EventKind> = log.iter().map(|e| e.kind).collect();
    assert!(
        kinds.contains(&EventKind::H3StreamStart),
        "must record H3StreamStart"
    );
    assert!(
        kinds.contains(&EventKind::H3HeadComplete),
        "must record H3HeadComplete"
    );
    assert!(
        kinds.contains(&EventKind::H3Finished),
        "must record H3Finished so body and end-to-end spans are derivable"
    );

    // The trace must be derivable, not merely populated: [INV-QUIC-03] promises a pure
    // function of the recorded events, and this is that function.
    let derived = netune_trace::derive_h3(&netune_trace::RequestTrace {
        id: netune_trace::TraceId::new("http3-e2e"),
        attempt: netune_trace::AttemptRef {
            round: 1,
            turn: 1,
            attempt: 1,
        },
        endpoint: netune_trace::EndpointRef {
            provider: "test".into(),
            model: "test".into(),
            authority: addr.to_string(),
        },
        connection: netune_trace::ConnectionInfo::default(),
        fidelity: netune_trace::Fidelity::l0(),
        log,
    });
    assert!(derived.ttfb_us.is_measured(), "TTFB must be derivable");
    assert!(derived.e2e_us.is_measured(), "end-to-end must be derivable");
}
