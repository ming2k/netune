//! Reproducible transport performance baseline for the Stable tier.
//!
//! Run with:
//! `cargo bench --bench baseline`
//! (or `cargo bench --all-features --bench baseline` to also run H3/QUIC).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, StatusCode};
use netune::{
    Client, ClientConfig, HttpProtocol, Observation, Pool, PoolConfig, RequestBody, RequestHead,
    Target, TcpConnector,
};
use netune_server::{
    Handler, HandlerFuture, IncomingRequest, Protocols, RequestBody as ServerRequestBody, Response,
    Server, ServerConfig,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

struct BenchHandler;

impl Handler for BenchHandler {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        mut body: ServerRequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            let bytes = body.read_to_end().await.unwrap_or_default();
            if bytes.is_empty() {
                Response::ok(Bytes::from_static(b"ok"))
            } else {
                Response::ok(bytes)
            }
        })
    }
}

fn report(name: &str, iters: usize, total_bytes: usize, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let rps = iters as f64 / secs;
    let avg_us = secs * 1_000_000.0 / iters as f64;
    let mbps = (total_bytes as f64 / (1024.0 * 1024.0)) / secs;
    println!(
        "{name:<42} | {iters:>6} iters | {avg_us:>8.1} us/op | {rps:>9.1} req/s | {mbps:>7.2} MiB/s"
    );
}

async fn bench_h1_pool_hit(rt: &tokio::runtime::Runtime) {
    let _ = rt;
    let mut cfg = ServerConfig::default();
    cfg.protocols = Protocols::HTTP1;
    cfg.max_requests_per_connection = 10_000;
    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(BenchHandler))
        .await
        .unwrap();
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let sw = Arc::clone(&shutdown);
    let srv = tokio::spawn(async move {
        server.serve(async move { sw.notified().await }).await;
    });

    let mut ccfg = ClientConfig::default();
    ccfg.observation = Observation::Off;
    let client = Client::new(TcpConnector::new(), Pool::default(), ccfg);
    let target = Target::plain(addr.to_string()).with_protocol(HttpProtocol::Http1);

    // Warm up
    for _ in 0..10 {
        let mut r = client
            .request(&target, RequestHead::new(Method::GET, "/"), None)
            .await
            .unwrap();
        let _ = r.body.read_to_end().await.unwrap();
    }

    let iters = 1000;
    let start = Instant::now();
    let mut total_bytes = 0usize;
    for _ in 0..iters {
        let mut r = client
            .request(&target, RequestHead::new(Method::GET, "/"), None)
            .await
            .unwrap();
        let b = r.body.read_to_end().await.unwrap();
        total_bytes += b.len();
    }
    report("h1_pooled_get_off", iters, total_bytes, start.elapsed());

    shutdown.notify_one();
    let _ = srv.await;
}

async fn bench_h1_cold_dial() {
    let mut cfg = ServerConfig::default();
    cfg.protocols = Protocols::HTTP1;
    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(BenchHandler))
        .await
        .unwrap();
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let sw = Arc::clone(&shutdown);
    let srv = tokio::spawn(async move {
        server.serve(async move { sw.notified().await }).await;
    });

    let mut ccfg = ClientConfig::default();
    ccfg.observation = Observation::Off;
    let mut pcfg = PoolConfig::default();
    pcfg.max_idle_total = 0;
    let client = Client::new(TcpConnector::new(), Pool::new(pcfg), ccfg);
    let target = Target::plain(addr.to_string()).with_protocol(HttpProtocol::Http1);

    let iters = 300;
    let start = Instant::now();
    let mut total_bytes = 0usize;
    for _ in 0..iters {
        let mut r = client
            .request(&target, RequestHead::new(Method::GET, "/"), None)
            .await
            .unwrap();
        let b = r.body.read_to_end().await.unwrap();
        total_bytes += b.len();
    }
    report("h1_cold_dial_get_off", iters, total_bytes, start.elapsed());

    shutdown.notify_one();
    let _ = srv.await;
}

async fn bench_h1_duplex_post_throughput() {
    let mut cfg = ServerConfig::default();
    cfg.protocols = Protocols::HTTP1;
    cfg.max_requests_per_connection = 10_000;
    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(BenchHandler))
        .await
        .unwrap();
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let sw = Arc::clone(&shutdown);
    let srv = tokio::spawn(async move {
        server.serve(async move { sw.notified().await }).await;
    });

    let mut ccfg = ClientConfig::default();
    ccfg.observation = Observation::Off;
    let client = Client::new(TcpConnector::new(), Pool::default(), ccfg);
    let target = Target::plain(addr.to_string()).with_protocol(HttpProtocol::Http1);
    let payload = Bytes::from(vec![b'x'; 256 * 1024]);

    let iters = 100;
    let start = Instant::now();
    for _ in 0..iters {
        let mut r = client
            .request(
                &target,
                RequestHead::new(Method::POST, "/echo"),
                RequestBody::Full(payload.clone()),
            )
            .await
            .unwrap();
        let b = r.body.read_to_end().await.unwrap();
        assert_eq!(b.len(), payload.len());
    }
    report(
        "h1_duplex_post_256k_roundtrip",
        iters,
        iters * payload.len() * 2,
        start.elapsed(),
    );

    shutdown.notify_one();
    let _ = srv.await;
}

async fn bench_tcp_split_mutex_vs_native() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let chunk = vec![0xABu8; 32 * 1024];
    let chunks = 512usize; // 16 MiB each way = 32 MiB duplex

    // 1. Mutex-wrapped split (current SplitShared pattern)
    let stream = TcpStream::connect(addr).await.unwrap();
    let shared = Arc::new(std::sync::Mutex::new(stream));
    let s_w = Arc::clone(&shared);
    let c_w = chunk.clone();
    let t0 = Instant::now();
    let writer = tokio::spawn(async move {
        for _ in 0..chunks {
            let mut offset = 0;
            while offset < c_w.len() {
                let n = std::future::poll_fn(|cx| {
                    let mut guard = s_w.lock().unwrap();
                    std::pin::Pin::new(&mut *guard).poll_write(cx, &c_w[offset..])
                })
                .await
                .unwrap();
                offset += n;
            }
        }
    });
    let mut read_total = 0usize;
    let mut rbuf = vec![0u8; 32 * 1024];
    while read_total < chunks * chunk.len() {
        let n = std::future::poll_fn(|cx| {
            let mut guard = shared.lock().unwrap();
            let mut rb = tokio::io::ReadBuf::new(&mut rbuf);
            match std::pin::Pin::new(&mut *guard).poll_read(cx, &mut rb) {
                std::task::Poll::Ready(Ok(())) => {
                    std::task::Poll::Ready(Ok::<_, std::io::Error>(rb.filled().len()))
                }
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await
        .unwrap();
        if n == 0 {
            break;
        }
        read_total += n;
    }
    writer.await.unwrap();
    report(
        "raw_tcp_mutex_split_16m_duplex",
        chunks,
        chunks * chunk.len() * 2,
        t0.elapsed(),
    );
    drop(shared);

    // 2. Native TcpStream::into_split() (lock-free halves)
    let stream2 = TcpStream::connect(addr).await.unwrap();
    let (mut rh, mut wh) = stream2.into_split();
    let c_w2 = chunk.clone();
    let t1 = Instant::now();
    let writer2 = tokio::spawn(async move {
        for _ in 0..chunks {
            wh.write_all(&c_w2).await.unwrap();
        }
    });
    let mut read_total2 = 0usize;
    while read_total2 < chunks * chunk.len() {
        let n = rh.read(&mut rbuf).await.unwrap();
        if n == 0 {
            break;
        }
        read_total2 += n;
    }
    writer2.await.unwrap();
    report(
        "raw_tcp_native_into_split_16m_duplex",
        chunks,
        chunks * chunk.len() * 2,
        t1.elapsed(),
    );

    let _ = echo.await;
}

async fn bench_h2_multiplexed_throughput() {
    let mut cfg = ServerConfig::default();
    cfg.protocols = Protocols::HTTP2;
    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(BenchHandler))
        .await
        .unwrap();
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let sw = Arc::clone(&shutdown);
    let srv = tokio::spawn(async move {
        server.serve(async move { sw.notified().await }).await;
    });

    let mut ccfg = ClientConfig::default();
    ccfg.observation = Observation::Off;
    let client = Client::new(TcpConnector::new(), Pool::default(), ccfg);
    let target = Target::plain(addr.to_string()).with_protocol(HttpProtocol::Http2);

    // Prime H2 session
    let mut r = client
        .request(&target, RequestHead::new(Method::GET, "/"), None)
        .await
        .unwrap();
    assert_eq!(r.head.status, StatusCode::OK);
    let _ = r.body.read_to_end().await.unwrap();

    let streams = 64usize;
    let payload = Bytes::from(vec![b'h'; 64 * 1024]);
    let start = Instant::now();
    let mut tasks = Vec::with_capacity(streams);
    for _ in 0..streams {
        let c = client.clone();
        let t = target.clone();
        let p = payload.clone();
        tasks.push(tokio::spawn(async move {
            let mut r = c
                .request(
                    &t,
                    RequestHead::new(Method::POST, "/h2"),
                    RequestBody::Full(p.clone()),
                )
                .await
                .unwrap();
            let b = r.body.read_to_end().await.unwrap();
            assert_eq!(b.len(), p.len());
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    report(
        "h2_64_concurrent_64k_streams",
        streams,
        streams * payload.len() * 2,
        start.elapsed(),
    );

    shutdown.notify_one();
    let _ = srv.await;
}

#[cfg(feature = "http3")]
#[derive(Debug)]
struct BenchAcceptAnyCert;

#[cfg(feature = "http3")]
impl rustls::client::danger::ServerCertVerifier for BenchAcceptAnyCert {
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
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(feature = "http3")]
async fn bench_h3_rtt_and_throughput() {
    use netune_http3::{H3Client, H3ServerConnection, H3SettingsProfile};
    use netune_quic::QuicConnector;
    use netune_quic::owned::{Endpoint, ServerConfigOwned};
    use netune_quic::profile::QuicProfile;
    use netune_quic::wire::transport_parameters::TransportParameters;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let transport = TransportParameters {
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
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .unwrap();
    let addr = endpoint.local_addr();
    let srv = tokio::spawn(async move {
        if let Ok(conn) = endpoint.accept().await
            && let Ok(mut h3_conn) =
                H3ServerConnection::new(conn, &H3SettingsProfile::dynamic()).await
        {
            while let Ok(Some(req)) = h3_conn.accept().await {
                let (_head, mut stream) = req.into_parts();
                tokio::spawn(async move {
                    let mut body = Vec::new();
                    while let Ok(Some(chunk)) = stream.recv_data().await {
                        body.extend_from_slice(&chunk);
                    }
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    if stream.send_response(resp).await.is_ok() {
                        let payload = if body.is_empty() {
                            Bytes::from_static(b"ok")
                        } else {
                            Bytes::from(body)
                        };
                        let _ = stream.send_data(payload).await;
                        let _ = stream.finish().await;
                    }
                });
            }
        }
    });

    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(BenchAcceptAnyCert))
        .with_no_client_auth();
    let connector = QuicConnector::new(QuicProfile::chrome_quic()).with_tls_config(client_crypto);
    let mut h3_client = H3Client::connect_with_settings(
        &connector,
        addr,
        "localhost",
        None,
        H3SettingsProfile::dynamic(),
    )
    .await
    .unwrap();

    // Warm up
    for _ in 0..4 {
        let req = http::Request::builder()
            .method("GET")
            .uri("https://localhost/")
            .body(Bytes::new())
            .unwrap();
        let mut s = h3_client.send(req).await.unwrap();
        let _ = s.read_to_end().await.unwrap();
    }

    let rtt_iters = 200;
    let t0 = Instant::now();
    let mut bytes_rtt = 0usize;
    for _ in 0..rtt_iters {
        let req = http::Request::builder()
            .method("GET")
            .uri("https://localhost/")
            .body(Bytes::new())
            .unwrap();
        let mut s = h3_client.send(req).await.unwrap();
        bytes_rtt += s.read_to_end().await.unwrap().len();
    }
    report("h3_sequential_get_off", rtt_iters, bytes_rtt, t0.elapsed());

    let bulk_iters = 32;
    let bulk_payload = Bytes::from(vec![b'q'; 64 * 1024]);
    let t1 = Instant::now();
    for _ in 0..bulk_iters {
        let req = http::Request::builder()
            .method("POST")
            .uri("https://localhost/bulk")
            .body(bulk_payload.clone())
            .unwrap();
        let mut s = h3_client.send(req).await.unwrap();
        let resp = s.read_to_end().await.unwrap();
        assert_eq!(resp.len(), bulk_payload.len());
    }
    report(
        "h3_post_64k_roundtrip",
        bulk_iters,
        bulk_iters * bulk_payload.len() * 2,
        t1.elapsed(),
    );

    srv.abort();
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    println!("=== netune performance baseline ===");
    rt.block_on(async {
        bench_tcp_split_mutex_vs_native().await;
        bench_h1_pool_hit(&rt).await;
        bench_h1_cold_dial().await;
        bench_h1_duplex_post_throughput().await;
        bench_h2_multiplexed_throughput().await;
        #[cfg(feature = "http3")]
        bench_h3_rtt_and_throughput().await;
    });
}
