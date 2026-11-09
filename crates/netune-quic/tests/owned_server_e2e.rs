// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end: owned async endpoint against the owned server core.

use std::sync::Arc;
use std::time::Duration;

use netune_quic::owned::{ClientConfigOwned, Endpoint, ServerConfigOwned};
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

fn server_tls() -> Arc<rustls::ServerConfig> {
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
    Arc::new(tls)
}

fn client_tls() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.enable_early_data = true;
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
async fn owned_server_exchanges_a_bidi_stream_with_owned_client() {
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
        let (mut send, mut recv) = connection.accept_bi().await.expect("accept bi");
        let data = recv.read(1024).await.expect("read").expect("data");
        assert_eq!(data.as_ref(), b"hello");
        connection.initiate_key_update().expect("server key update");
        send.write_all(b"world").await.expect("write");
        send.finish().await.expect("finish");
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    let client = Endpoint::client().await.expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    connection.initiate_key_update().expect("client key update");
    let (mut send, mut recv) = connection.open_bi().await.expect("open bi");
    send.write_all(b"hello").await.expect("write");
    send.finish().await.expect("finish");
    let response = tokio::time::timeout(Duration::from_secs(2), recv.read(1024))
        .await
        .expect("read timeout")
        .expect("read")
        .expect("data");
    assert_eq!(response.as_ref(), b"world");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn owned_server_speaks_quic_v2_with_owned_client() {
    use netune_quic::wire::packet::VERSION_2;

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
        let (mut send, mut recv) = connection.accept_bi().await.expect("accept bi");
        let data = recv.read(1024).await.expect("read").expect("data");
        assert_eq!(data.as_ref(), b"v2");
        send.write_all(b"two").await.expect("write");
        send.finish().await.expect("finish");
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    let client = Endpoint::client().await.expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport(),
                versions: vec![VERSION_2],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    let (mut send, mut recv) = connection.open_bi().await.expect("open bi");
    send.write_all(b"v2").await.expect("write");
    send.finish().await.expect("finish");
    let response = tokio::time::timeout(Duration::from_secs(2), recv.read(1024))
        .await
        .expect("read timeout")
        .expect("read")
        .expect("data");
    assert_eq!(response.as_ref(), b"two");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn empty_stream_fin_is_delivered() {
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
        let (_send, mut recv) = connection.accept_bi().await.expect("accept bi");
        let end = tokio::time::timeout(Duration::from_secs(2), recv.read(16))
            .await
            .expect("fin timeout")
            .expect("read");
        assert!(end.is_none(), "empty FIN must read as end of stream");
    });

    let client = Endpoint::client().await.expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    let (mut send, _recv) = connection.open_bi().await.expect("open bi");
    send.finish().await.expect("finish");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn resumed_session_sends_early_data() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: true,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: true,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let connection = match server.accept().await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };
                let Ok(data) = recv.read(1024).await else {
                    return;
                };
                let Some(data) = data else { return };
                assert_eq!(data.as_ref(), b"early");
                let _ = send.write_all(b"ok").await;
                let _ = send.finish().await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            });
        }
    });
    let client_endpoint = Endpoint::client().await.expect("client endpoint");
    let cache = std::sync::Arc::new(netune_quic::owned::SessionCache::new());
    let tls = client_tls();
    let first = client_endpoint
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: tls.clone(),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                enable_early_data: true,
                session_cache: Some(cache.clone()),
            },
        )
        .await
        .expect("first connect");
    // Let the server's NewSessionTicket flight reach rustls before reconnecting.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(first);

    let second = client_endpoint
        .connect_early(
            addr,
            "localhost",
            ClientConfigOwned {
                tls,
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                enable_early_data: true,
                session_cache: Some(cache),
            },
        )
        .await
        .expect("second connect");
    assert!(
        second.early_data_available(),
        "session cache and early keys"
    );
    let (mut send, mut recv) = second.open_bi().await.expect("open early bi");
    send.write_all(b"early").await.expect("early write");
    send.finish().await.expect("early finish");
    second.wait_established().await;
    assert!(second.early_data_accepted(), "server accepted early data");
    let response = tokio::time::timeout(Duration::from_secs(2), recv.read(16))
        .await
        .expect("response timeout")
        .expect("response read")
        .expect("response bytes");
    assert_eq!(response.as_ref(), b"ok");
    server_task.await.expect("server task");
}
