// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end integration test for HTTP/3 client.

use std::sync::Arc;

use bytes::Bytes;
use netune_http3::H3Client;
use netune_quic::QuicConnector;
use netune_quic::owned::{Endpoint, ServerConfigOwned};
use netune_quic::profile::QuicProfile;
use netune_quic::wire::transport_parameters::TransportParameters;
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
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: true,
        },
    )
    .await
    .expect("endpoint");
    let addr = endpoint.local_addr();
    (endpoint, addr)
}

#[tokio::test]
async fn test_http3_client_request_response_and_trace() {
    let (server, addr) = make_server_endpoint().await;

    tokio::spawn(async move {
        {
            let conn = server.accept().await.expect("server handshake");
            let mut h3_conn = netune_http3::H3ServerConnection::new(
                conn,
                &netune_http3::H3SettingsProfile::dynamic(),
            )
            .await
            .expect("server h3 connection");

            while let Some(request) = h3_conn.accept().await.expect("accept h3 request") {
                let (req, mut stream) = request.into_parts();
                let path = req.uri().path().to_string();
                tokio::spawn(async move {
                    let mut body = Vec::new();
                    while let Some(chunk) = stream.recv_data().await.expect("recv data") {
                        body.extend_from_slice(&chunk);
                    }
                    let trailers = stream
                        .recv_trailers()
                        .await
                        .expect("recv trailers")
                        .unwrap_or_default();
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/plain")
                        .body(())
                        .expect("response head");
                    stream.send_response(response).await.expect("send response");
                    if path == "/response-trailers" {
                        stream
                            .send_data(Bytes::from_static(b"trailer body"))
                            .await
                            .expect("send trailer body");
                        let mut trailers = http::HeaderMap::new();
                        trailers
                            .insert("x-response-trailer", http::HeaderValue::from_static("done"));
                        stream
                            .send_trailers(trailers)
                            .await
                            .expect("send response trailers");
                        return;
                    }
                    let payload = if path == "/upload" {
                        Bytes::from(body)
                    } else if path == "/trailers" {
                        Bytes::from(
                            trailers
                                .get("x-check")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("missing")
                                .to_string(),
                        )
                    } else {
                        Bytes::from(format!("hello {path}"))
                    };
                    stream.send_data(payload).await.expect("send data");
                    stream.finish().await.expect("finish");
                });
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

    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto);

    let recorder = TraceCollector::start(1024);

    let mut h3_client = H3Client::connect_with_settings(
        &connector,
        addr,
        "localhost",
        Some(recorder.clone()),
        netune_http3::H3SettingsProfile::dynamic(),
    )
    .await
    .expect("h3 client")
    .with_request_profile(netune_http3::H3RequestProfile::chrome());
    assert_eq!(h3_client.quic_profile(), Some("chrome-quic"));
    assert_eq!(h3_client.settings_profile().name, "dynamic");
    assert_eq!(h3_client.request_profile().name, "chrome");

    // Streaming path: the response head is returned before the body is drained.
    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/one")
        .body(Bytes::new())
        .expect("request");
    let mut stream = h3_client.send(request).await.expect("send");
    assert_eq!(stream.head().status(), 200);
    let body = stream.read_to_end().await.expect("read streamed body");
    assert_eq!(body, Bytes::from_static(b"hello /one"));
    let trace = stream.trace().expect("per-exchange H3 trace");
    assert_eq!(trace.fidelity, netune_trace::Fidelity::l0());
    assert_eq!(
        trace.identity.h3_profile.as_deref(),
        Some("chrome-quic"),
        "H3 connection identity is the resolved QUIC profile"
    );
    assert_eq!(
        trace.identity.h3_settings_profile.as_deref(),
        Some("dynamic"),
        "HTTP/3 SETTINGS shape the connection and are part of its identity"
    );

    // Streaming upload: the request body is written in pieces and is never
    // buffered as one request object.
    let upload = http::Request::builder()
        .method("POST")
        .uri("https://localhost/upload")
        .body(())
        .expect("upload request");
    let mut upload = h3_client
        .open_request(upload)
        .await
        .expect("open request stream");
    upload
        .send_data(Bytes::from_static(b"streamed "))
        .await
        .expect("first upload chunk");
    upload
        .send_data(Bytes::from_static(b"request body"))
        .await
        .expect("second upload chunk");
    let mut stream = upload.finish().await.expect("finish upload");
    assert_eq!(
        stream.read_to_end().await.expect("upload response"),
        Bytes::from_static(b"streamed request body")
    );

    // Request trailers finish the stream and remain observable by the peer.
    let request = http::Request::builder()
        .method("POST")
        .uri("https://localhost/trailers")
        .body(())
        .expect("trailer request");
    let mut upload = h3_client.open_request(request).await.expect("open request");
    upload
        .send_data(Bytes::from_static(b"body"))
        .await
        .expect("trailer body");
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-check", http::HeaderValue::from_static("done"));
    let mut stream = upload.send_trailers(trailers).await.expect("send trailers");
    assert_eq!(
        stream.read_to_end().await.expect("trailer response"),
        Bytes::from_static(b"done")
    );

    // Response trailers use the same dynamic path and are visible after the body.
    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/response-trailers")
        .body(Bytes::new())
        .expect("response trailer request");
    let mut stream = h3_client
        .send(request)
        .await
        .expect("send response trailer");
    assert_eq!(
        stream.read_to_end().await.expect("trailer body"),
        Bytes::from_static(b"trailer body")
    );
    let trailers = stream.trailers().await.expect("response trailers");
    assert_eq!(
        trailers
            .and_then(|trailers| trailers.get("x-response-trailer").cloned())
            .and_then(|value| value.to_str().ok().map(str::to_string)),
        Some("done".to_string())
    );

    // Buffered path: `execute` is the bounded convenience over `send`.
    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/two")
        .body(Bytes::new())
        .expect("request");
    let response = h3_client.execute(request).await.expect("execute");
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), &Bytes::from_static(b"hello /two"));
    assert!(response.trace.is_some());

    // Repeated requests with changing field values exercise dynamic QPACK
    // insertions, header acknowledgements and table eviction over one
    // connection.
    for index in 0..24 {
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://localhost/bulk/{index}"))
            .header("x-dynamic", format!("value-{index}"))
            .body(Bytes::new())
            .expect("bulk request");
        let response = h3_client.execute(request).await.expect("bulk execute");
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.body(),
            &Bytes::from(format!("hello /bulk/{index}"))
        );
    }

    // The buffered path enforces the configured body ceiling.
    h3_client = h3_client.with_config(netune_http3::H3ClientConfig {
        max_body_bytes: 1,
        ..netune_http3::H3ClientConfig::default()
    });
    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/too-large")
        .body(Bytes::new())
        .expect("request");
    let error = h3_client
        .execute(request)
        .await
        .expect_err("body ceiling must fail");
    assert!(matches!(
        error,
        netune_http3::H3Error::BodyTooLarge { limit: 1 }
    ));

    // Verify trace events [INV-QUIC-03]
    let log = recorder.log();
    let streams: Vec<u32> = log
        .iter()
        .filter(|event| event.kind == EventKind::H3StreamStart)
        .map(|event| event.stream)
        .collect();
    assert_eq!(streams.len(), 30, "each request is its own exchange");
    assert_ne!(streams[0], streams[1], "exchange ids must differ");
    assert_ne!(streams[1], streams[2], "exchange ids must differ");
    assert_ne!(streams[2], streams[3], "exchange ids must differ");
    assert!(streams[4..].iter().all(|id| *id > streams[3]));
    let kinds: Vec<EventKind> = log.iter().map(|event| event.kind).collect();
    for kind in [
        EventKind::H3StreamStart,
        EventKind::H3HeadComplete,
        EventKind::H3Finished,
    ] {
        assert!(kinds.contains(&kind), "must record {kind:?}");
    }

    // The trace must be derivable, not merely populated: [INV-QUIC-03] promises a pure
    // function of the recorded events, and this is that function. A multi-exchange log
    // must not be attributed to the first request.
    let trace = netune_trace::RequestTrace {
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
        identity: netune_trace::ConnectionIdentity::default(),
        schema_version: netune_trace::TRACE_SCHEMA_VERSION,
        fidelity: netune_trace::Fidelity::l0(),
        log,
    };
    let single = netune_trace::derive_h3(&trace);
    assert_eq!(
        single.ttfb_us.validity().reason(),
        Some(netune_trace::Reason::MultipleExchanges),
        "a two-request log has no single TTFB"
    );
    let exchanges = netune_trace::derive_h3_exchanges(&trace);
    assert_eq!(exchanges.len(), 30);
    assert!(
        exchanges[..29]
            .iter()
            .all(|derived| derived.ttfb_us.is_measured() && derived.e2e_us.is_measured()),
        "each completed exchange must derive its own TTFB and end-to-end span"
    );
    assert!(
        !exchanges[29].e2e_us.is_measured(),
        "the body-ceiling failure must not fabricate an end-to-end span"
    );
}

#[tokio::test]
async fn http3_datagrams_are_routed_to_the_request_stream() {
    let (server, addr) = make_server_endpoint().await;
    tokio::spawn(async move {
        let conn = server.accept().await.expect("server handshake");
        let settings = netune_http3::H3SettingsProfile::dynamic().with_datagrams();
        let mut h3_conn = netune_http3::H3ServerConnection::new(conn, &settings)
            .await
            .expect("server h3 connection");
        let request = h3_conn.accept().await.expect("accept").expect("request");
        let (_req, mut stream) = request.into_parts();
        while stream.recv_data().await.expect("body").is_some() {}
        let datagram =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.next_datagram())
                .await
                .expect("datagram timeout")
                .expect("datagram");
        assert_eq!(datagram.as_ref(), b"ping");
        stream.send_datagram(b"pong").await.expect("send datagram");
        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("response");
        stream.send_response(response).await.expect("response head");
        stream.finish().await.expect("finish");
    });

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto);
    let mut client = H3Client::connect_with_settings(
        &connector,
        addr,
        "localhost",
        None,
        netune_http3::H3SettingsProfile::dynamic().with_datagrams(),
    )
    .await
    .expect("h3 client");
    let request = http::Request::builder()
        .method("POST")
        .uri("https://localhost/datagrams")
        .body(())
        .expect("request");
    let mut body = client.open_request(request).await.expect("open request");
    body.send_datagram(b"ping").await.expect("send datagram");
    let mut response = body.finish().await.expect("response");
    let datagram =
        tokio::time::timeout(std::time::Duration::from_secs(1), response.next_datagram())
            .await
            .expect("datagram timeout")
            .expect("datagram");
    assert_eq!(datagram.as_ref(), b"pong");
}

#[tokio::test]
async fn extended_connect_protocol_crosses_the_h3_boundary() {
    let (server, addr) = make_server_endpoint().await;
    tokio::spawn(async move {
        let conn = server.accept().await.expect("server handshake");
        let settings = netune_http3::H3SettingsProfile::default().with_extended_connect();
        let mut h3_conn = netune_http3::H3ServerConnection::new(conn, &settings)
            .await
            .expect("server h3 connection");
        let request = h3_conn.accept().await.expect("accept").expect("request");
        let (req, mut stream) = request.into_parts();
        assert_eq!(
            req.extensions()
                .get::<netune_http3::ExtendedConnectProtocol>(),
            Some(&netune_http3::ExtendedConnectProtocol(
                "webtransport".to_string()
            ))
        );
        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("response");
        stream.send_response(response).await.expect("response head");
        stream.finish().await.expect("finish");
    });

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto);
    let mut client = H3Client::connect_with_settings(
        &connector,
        addr,
        "localhost",
        None,
        netune_http3::H3SettingsProfile::default().with_extended_connect(),
    )
    .await
    .expect("h3 client");
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost/session")
        .body(())
        .expect("request");
    request
        .extensions_mut()
        .insert(netune_http3::ExtendedConnectProtocol(
            "webtransport".to_string(),
        ));
    let response = client
        .send(request.map(|_| Bytes::new()))
        .await
        .expect("send");
    assert_eq!(response.head().status(), 200);
}

#[tokio::test]
async fn resumed_h3_session_sends_early_request() {
    let (server, addr) = make_server_endpoint().await;
    // A listener owns the UDP demultiplexer; accepted connections need it to
    // keep routing datagrams while their handlers run. Keep the endpoint alive
    // for the duration of both exchanges.
    let server = Arc::new(server);
    let accept_loop = server.clone();
    tokio::spawn(async move {
        for _ in 0..2 {
            let Ok(conn) = accept_loop.accept().await else {
                return;
            };
            let settings = netune_http3::H3SettingsProfile::default();
            let Ok(mut h3_conn) = netune_http3::H3ServerConnection::new(conn, &settings).await
            else {
                continue;
            };
            tokio::spawn(async move {
                while let Ok(Some(request)) = h3_conn.accept().await {
                    let (_request, mut stream) = request.into_parts();
                    while stream.recv_data().await.expect("body").is_some() {}
                    let response = http::Response::builder()
                        .status(200)
                        .body(())
                        .expect("response");
                    stream.send_response(response).await.expect("head");
                    let _ = stream.send_data(Bytes::from_static(b"ok")).await;
                    let _ = stream.finish().await;
                }
            });
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
    let request = || {
        http::Request::builder()
            .method("GET")
            .uri("https://localhost/early")
            .body(Bytes::new())
            .expect("request")
    };

    let mut first = H3Client::connect(&connector, addr, "localhost", None)
        .await
        .expect("first h3 session");
    let first_response = first.send(request()).await.expect("first response");
    assert_eq!(first_response.head().status(), 200);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(first);

    let mut second = H3Client::connect_early(&connector, addr, "localhost", None)
        .await
        .expect("early h3 session");
    let response = second.send(request()).await.expect("early response");
    assert_eq!(response.head().status(), 200);
    second.wait_handshake().await.expect("handshake");
    assert!(second.early_data_accepted(), "server accepted 0-RTT");
    drop(server);
}

#[tokio::test]
async fn capsule_protocol_round_trips_on_extended_connect() {
    let (server, addr) = make_server_endpoint().await;
    tokio::spawn(async move {
        let conn = server.accept().await.expect("server handshake");
        let settings = netune_http3::H3SettingsProfile::default().with_extended_connect();
        let mut h3_conn = netune_http3::H3ServerConnection::new(conn, &settings)
            .await
            .expect("server h3 connection");
        let request = h3_conn.accept().await.expect("accept").expect("request");
        let (_req, mut stream) = request.into_parts();
        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("response");
        stream.send_response(response).await.expect("response head");
        let capsule = stream
            .next_capsule()
            .await
            .expect("read capsule")
            .expect("capsule");
        assert_eq!(capsule.kind, 0x1234);
        assert_eq!(capsule.value.as_ref(), b"ping");
        stream
            .send_capsule(&netune_http3::Capsule::new(
                0x1234,
                Bytes::from_static(b"pong"),
            ))
            .await
            .expect("send capsule");
        stream.finish().await.expect("finish");
    });

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto);
    let mut client = H3Client::connect_with_settings(
        &connector,
        addr,
        "localhost",
        None,
        netune_http3::H3SettingsProfile::default().with_extended_connect(),
    )
    .await
    .expect("h3 client");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut session = client
        .connect_extended("webtransport", "https://localhost/session")
        .await
        .expect("extended connect");
    session
        .send_capsule(&netune_http3::Capsule::new(
            0x1234,
            Bytes::from_static(b"ping"),
        ))
        .await
        .expect("send capsule");
    let capsule = tokio::time::timeout(std::time::Duration::from_secs(1), session.next_capsule())
        .await
        .expect("capsule timeout")
        .expect("capsule read")
        .expect("capsule");
    assert_eq!(capsule.kind, 0x1234);
    assert_eq!(capsule.value.as_ref(), b"pong");
}
