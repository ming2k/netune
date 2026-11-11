// SPDX-License-Identifier: MIT

#![cfg(feature = "http3")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! HTTP/3 ingress over a real QUIC handshake, with a netune HTTP/3 client.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use netune_http3::{H3Client, H3SettingsProfile};
use netune_quic::QuicConnector;
use netune_quic::profile::QuicProfile;
use netune_server::{
    CollectingObserver, H3Server, Handler, HandlerFuture, IncomingRequest, RequestBody, Response,
    ServerConfig,
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
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("cert"),
    )
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

struct Echo;

impl Handler for Echo {
    fn handle<'a>(
        &'a self,
        request: IncomingRequest,
        mut body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            if request.target_str() == Some("/stream") {
                let (tx, rx) = tokio::sync::mpsc::channel(4);
                tokio::spawn(async move {
                    for chunk in [b"one ".as_slice(), b"two ", b"three"] {
                        let _ = tx.send(Bytes::copy_from_slice(chunk)).await;
                    }
                });
                return Response::stream(http::StatusCode::OK, rx);
            }
            let data = body.read_to_end().await.unwrap_or_default();
            let mut response = format!("{} {:?}", request.method, request.version);
            if !data.is_empty() {
                response.push(' ');
                response.push_str(std::str::from_utf8(&data).unwrap_or("<binary>"));
            }
            Response::ok(response)
        })
    }
}

#[tokio::test]
async fn h3_ingress_serves_streaming_request_and_records_trace() {
    let observer = Arc::new(CollectingObserver::default());
    let config = ServerConfig::for_tests().with_trace_sink(observer.clone());
    let server = H3Server::bind(
        "127.0.0.1:0",
        config,
        server_tls(),
        H3SettingsProfile::dynamic(),
        Arc::new(Echo),
    )
    .await
    .expect("bind h3 server");
    let addr = server.local_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(server.serve(async move {
        let _ = shutdown_rx.await;
    }));

    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto());
    let mut client = H3Client::connect_with_settings(
        &connector,
        addr,
        "localhost",
        None,
        H3SettingsProfile::dynamic(),
    )
    .await
    .expect("h3 client");

    let request = http::Request::builder()
        .method("POST")
        .uri("https://localhost/echo")
        .body(())
        .expect("request");
    let mut upload = client.open_request(request).await.expect("open request");
    upload
        .send_data(Bytes::from_static(b"streamed"))
        .await
        .expect("send body");
    let mut response = upload.finish().await.expect("response");
    let body = {
        let mut bytes = Vec::new();
        while let Some(mut chunk) = response.next_chunk().await.expect("body chunk") {
            bytes.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        Bytes::from(bytes)
    };
    assert_eq!(body, Bytes::from_static(b"POST HTTP/3.0 streamed"));

    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/health")
        .body(Bytes::new())
        .expect("request");
    let response = client.execute(request).await.expect("execute");
    assert_eq!(response.body(), &Bytes::from_static(b"GET HTTP/3.0"));

    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/stream")
        .body(Bytes::new())
        .expect("request");
    let response = client.execute(request).await.expect("execute stream");
    assert_eq!(response.body(), &Bytes::from_static(b"one two three"));

    drop(client);
    let _ = shutdown_tx.send(());
    serving.await.expect("serve task");

    let traces = observer.take();
    assert_eq!(
        traces.len(),
        1,
        "one QUIC connection must produce one trace"
    );
    assert_eq!(traces[0].protocol, netune_server::ServedProtocol::Http3);
    assert_eq!(traces[0].fidelity, netune_trace::Fidelity::l0());
    assert_eq!(traces[0].exchanges, 3);
    let derived = netune_trace::derive_ingress_exchanges(&netune_trace::RequestTrace {
        meta: netune_trace::TraceMeta::new(
            netune_trace::TraceId::new("h3-ingress"),
            netune_trace::Direction::Ingress,
        ),
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
        identity: netune_trace::ConnectionIdentity::default(),
        schema_version: netune_trace::TRACE_SCHEMA_VERSION,
        fidelity: traces[0].fidelity,
        log: traces[0].log.clone(),
        diagnostics: traces[0].diagnostics.clone(),
    });
    assert_eq!(derived.len(), 3, "each request is its own exchange");
}

#[tokio::test]
async fn a_failed_handshake_is_published_and_the_listener_keeps_serving() {
    let server = H3Server::bind(
        "127.0.0.1:0",
        ServerConfig::for_tests(),
        server_tls(),
        H3SettingsProfile::default(),
        Arc::new(Echo),
    )
    .await
    .expect("bind h3 server");
    let addr = server.local_addr();
    let mut handshake_errors = server.subscribe_handshake_errors();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(server.serve(async move {
        let _ = shutdown_rx.await;
    }));

    let mut bad_profile = QuicProfile::chrome_quic();
    bad_profile.alpn = vec![b"not-h3".to_vec()];
    let bad = tokio::spawn(async move {
        let connector = QuicConnector::new(bad_profile).with_tls_config(client_crypto());
        let _ = connector.connect(addr, "localhost", None).await;
    });
    let error = tokio::time::timeout(std::time::Duration::from_secs(5), handshake_errors.recv())
        .await
        .expect("the failed handshake must be published")
        .expect("handshake error channel");
    assert!(!error.to_string().is_empty());
    bad.abort();
    let _ = bad.await;

    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto());
    let mut client = H3Client::connect(&connector, addr, "localhost", None)
        .await
        .expect("the listener still accepts");
    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/health")
        .body(Bytes::new())
        .expect("request");
    let response = client.execute(request).await.expect("health request");
    assert_eq!(response.body(), &Bytes::from_static(b"GET HTTP/3.0"));

    drop(client);
    let _ = shutdown_tx.send(());
    serving.await.expect("serve task");
}

#[tokio::test]
async fn h3_ingress_serves_over_a_custom_socket_stack() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp");
    let socket: Arc<dyn netune_quic::QuicUdpSocket> = Arc::new(socket);
    let server = H3Server::bind_with_socket_and_options(
        socket,
        ServerConfig::for_tests(),
        server_tls(),
        H3SettingsProfile::default(),
        Arc::new(Echo),
        netune_quic::owned::ServerOptions {
            keep_alive: Some(Duration::from_millis(100)),
            congestion_factory: None,
        },
    )
    .await
    .expect("bind h3 server over custom socket");
    let addr = server.local_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(server.serve(async move {
        let _ = shutdown_rx.await;
    }));

    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto());
    let mut client = H3Client::connect(&connector, addr, "localhost", None)
        .await
        .expect("h3 client over custom socket");
    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/health")
        .body(Bytes::new())
        .expect("request");
    let response = client.execute(request).await.expect("health request");
    assert_eq!(response.body(), &Bytes::from_static(b"GET HTTP/3.0"));

    drop(client);
    let _ = shutdown_tx.send(());
    serving.await.expect("serve task");
}
