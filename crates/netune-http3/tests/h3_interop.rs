// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Differential interop against the crates.io `h3` crate.
//!
//! `h3` is a dev-dependency only. These tests prove that the owned H3/QPACK
//! implementation speaks the wire protocol to an independent implementation,
//! not merely to itself.

use std::sync::Arc;

use bytes::{Buf, Bytes};
use netune_http3::{H3Client, H3ServerConnection, H3SettingsProfile};
use netune_quic::QuicConnector;
use netune_quic::profile::QuicProfile;

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

fn server_endpoint() -> (quinn::Endpoint, std::net::SocketAddr) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
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
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("server crypto"),
    ));
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = socket.local_addr().expect("addr");
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("endpoint");
    (endpoint, addr)
}

fn client_crypto() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth()
}

fn request() -> http::Request<Bytes> {
    http::Request::builder()
        .method("GET")
        .uri("https://localhost/interop")
        .body(Bytes::new())
        .expect("request")
}

#[tokio::test]
async fn owned_client_interoperates_with_h3_server() {
    let (server, addr) = server_endpoint();
    tokio::spawn(async move {
        if let Some(connecting) = server.accept().await {
            let conn = connecting.await.expect("handshake");
            let mut h3 = h3::server::builder()
                .build(h3_quinn::Connection::new(conn))
                .await
                .expect("h3 server");
            while let Some(resolver) = h3.accept().await.expect("accept") {
                let (_request, mut stream) = resolver.resolve_request().await.expect("resolve");
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("response");
                stream.send_response(response).await.expect("head");
                stream
                    .send_data(Bytes::from_static(b"h3-server"))
                    .await
                    .expect("body");
                stream.finish().await.expect("finish");
            }
        }
    });

    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto());
    let mut client = H3Client::connect(&connector, addr, "localhost", None)
        .await
        .expect("client");
    let response = client.execute(request()).await.expect("execute");
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), &Bytes::from_static(b"h3-server"));
}

#[tokio::test]
async fn h3_client_interoperates_with_owned_server() {
    let (server, addr) = server_endpoint();
    tokio::spawn(async move {
        if let Some(connecting) = server.accept().await {
            let conn = connecting.await.expect("handshake");
            let mut h3 = H3ServerConnection::new(conn, &H3SettingsProfile::default())
                .await
                .expect("owned server");
            while let Some(request) = h3.accept().await.expect("accept") {
                let (_request, mut stream) = request.into_parts();
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("response");
                stream.send_response(response).await.expect("head");
                stream
                    .send_data(Bytes::from_static(b"owned-server"))
                    .await
                    .expect("body");
                stream.finish().await.expect("finish");
            }
        }
    });

    let quic = QuicConnector::new(QuicProfile::chrome_quic())
        .with_tls_config(client_crypto())
        .connect(addr, "localhost", None)
        .await
        .expect("quic");
    let connection = quic.connection().clone();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("h3 client");
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let stream = send_request
        .send_request(request().map(|_| ()))
        .await
        .expect("send request");
    let mut stream = stream;
    stream.finish().await.expect("finish request");
    let response = stream.recv_response().await.expect("response");
    assert_eq!(response.status(), 200);
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("body") {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    assert_eq!(body, b"owned-server");

    drop(stream);
    drop(send_request);
    driver.abort();
    drop(quic);
}
