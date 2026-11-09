// SPDX-License-Identifier: MIT

#![cfg(feature = "owned-quic")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end: owned async endpoint against a quinn server.

use std::sync::Arc;
use std::time::Duration;

use netune_quic::owned::{ClientConfigOwned, Endpoint};
use netune_quic::wire::transport_parameters::TransportParameters;

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

fn client_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

fn transport() -> TransportParameters {
    TransportParameters {
        initial_max_data: Some(1 << 20),
        initial_max_stream_data_bidi_local: Some(1 << 18),
        initial_max_stream_data_bidi_remote: Some(1 << 18),
        initial_max_stream_data_uni: Some(1 << 18),
        initial_max_streams_bidi: Some(100),
        initial_max_streams_uni: Some(100),
        active_connection_id_limit: Some(2),
        ..TransportParameters::default()
    }
}

#[tokio::test]
async fn owned_endpoint_exchanges_a_bidi_stream_with_quinn() {
    let (server, addr) = server_endpoint();
    let server_task = tokio::spawn(async move {
        if let Some(connecting) = server.accept().await
            && let Ok(connection) = connecting.await
        {
            if let Ok((mut send, mut recv)) = connection.accept_bi().await
                && let Ok(data) = recv.read_to_end(1024).await
            {
                assert_eq!(data, b"hello");
                let _ = send.write_all(b"world").await;
                let _ = send.finish();
            }
            let _ = connection.closed().await;
        }
    });

    let endpoint = Endpoint::client().await.expect("client endpoint");
    let connection = endpoint
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_config(),
                transport: transport(),
            },
        )
        .await
        .expect("connect");
    let (mut send, mut recv) = connection.open_bi().await.expect("open bi");
    send.write_all(b"hello").await.expect("write");
    send.finish().await.expect("finish");
    let response = tokio::time::timeout(Duration::from_secs(2), recv.read(1024))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(response.as_deref(), Some(b"world".as_slice()));
    server_task.abort();
}
