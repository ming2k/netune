//! Ingress HTTP/2 interop oracle: a real `h2` client driving `netune_server::Server`.
//!
//! Covers plaintext prior-knowledge HTTP/2 (when `http2` is enabled) and TLS
//! ALPN `h2` (when `tls` is also enabled), verifying concurrent streams, large
//! bodies, streaming responses, and graceful drain against an independent HTTP/2
//! implementation.

#![cfg(feature = "http2")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use netune_server::{
    Handler, HandlerFuture, IncomingRequest, Protocols, RequestBody, Response, Server, ServerConfig,
};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};

struct OracleEcho;

impl Handler for OracleEcho {
    fn handle<'a>(
        &'a self,
        request: IncomingRequest,
        mut body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            let path = String::from_utf8_lossy(&request.target).into_owned();
            if path == "/stream" {
                let bytes = body.read_to_end().await.unwrap_or_default();
                let (tx, rx) = mpsc::channel(4);
                tokio::spawn(async move {
                    for chunk in bytes.chunks(8192) {
                        if tx.send(Bytes::copy_from_slice(chunk)).await.is_err() {
                            return;
                        }
                    }
                });
                return Response::stream(StatusCode::OK, rx);
            }
            let bytes = body.read_to_end().await.unwrap_or_default();
            Response::ok(bytes)
                .with_header("x-method", request.method.as_str())
                .with_header("x-path", path)
        })
    }
}

async fn read_h2_body(mut body: h2::RecvStream) -> Bytes {
    let mut out = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("h2 body chunk");
        let len = chunk.len();
        out.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(len);
    }
    out.freeze()
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_client_interoperates_with_server_over_plaintext_prior_knowledge() {
    let mut cfg = ServerConfig::default();
    cfg.protocols = Protocols::HTTP2;
    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(OracleEcho))
        .await
        .expect("bind");
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let shutdown_wait = Arc::clone(&shutdown);
    let serve_task = tokio::spawn(async move {
        server
            .serve(async move {
                shutdown_wait.notified().await;
            })
            .await;
    });

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let (client, conn) = h2::client::handshake(tcp)
        .await
        .expect("h2 client handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut tasks = Vec::new();
    for idx in 0..8u8 {
        let mut client = client.clone();
        tasks.push(tokio::spawn(async move {
            std::future::poll_fn(|cx| client.poll_ready(cx))
                .await
                .expect("poll_ready");
            let payload: Vec<u8> = (0..(96 * 1024))
                .map(|i| idx.wrapping_add(i as u8))
                .collect();
            let req = Request::builder()
                .method(Method::POST)
                .uri("http://127.0.0.1/stream")
                .body(())
                .unwrap();
            let (resp_fut, mut send) = client.send_request(req, false).unwrap();
            for chunk in payload.chunks(16 * 1024) {
                send.reserve_capacity(chunk.len());
                send.send_data(Bytes::copy_from_slice(chunk), false)
                    .unwrap();
            }
            send.send_data(Bytes::new(), true).unwrap();
            let resp = resp_fut.await.expect("response");
            assert_eq!(resp.status(), StatusCode::OK);
            let body = read_h2_body(resp.into_body()).await;
            assert_eq!(body.as_ref(), payload.as_slice());
        }));
    }
    for t in tasks {
        t.await.expect("task");
    }

    drop(client);
    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(3), serve_task)
        .await
        .expect("server drain timeout");
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;
}

#[cfg(feature = "tls")]
#[tokio::test(flavor = "multi_thread")]
async fn h2_client_interoperates_with_server_over_tls_alpn_h2() {
    use netune_server::TlsTermination;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let mut srv_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    srv_tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut cfg = ServerConfig::default();
    cfg.protocols = Protocols::BOTH;
    cfg = cfg.with_tls(TlsTermination::single(Arc::new(srv_tls)));

    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(OracleEcho))
        .await
        .expect("bind tls server");
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let shutdown_wait = Arc::clone(&shutdown);
    let serve_task = tokio::spawn(async move {
        server
            .serve(async move {
                shutdown_wait.notified().await;
            })
            .await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut cli_tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"h2".to_vec()];

    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cli_tls));
    let tls_stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("tls connect");
    assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

    let (mut client, conn) = h2::client::handshake(tls_stream)
        .await
        .expect("h2 tls handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://localhost/echo")
        .body(())
        .unwrap();
    let (resp_fut, mut send) = client.send_request(req, false).unwrap();
    send.send_data(Bytes::from_static(b"over-tls-alpn-h2"), true)
        .unwrap();
    let resp = resp_fut.await.expect("tls h2 resp");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-method").unwrap(), "POST");
    assert_eq!(
        resp.headers().get("x-path").unwrap(),
        "https://localhost/echo"
    );
    assert_eq!(
        read_h2_body(resp.into_body()).await.as_ref(),
        b"over-tls-alpn-h2"
    );

    drop(client);
    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(3), serve_task)
        .await
        .expect("server drain timeout");
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;
}
