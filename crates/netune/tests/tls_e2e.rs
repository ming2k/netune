//! TLS end to end: a real handshake against a real certificate, traced.
//!
//! The point of this test is that `tls_us` stops being `PhaseAbsent` and starts
//! being a measurement, and that the negotiated parameters land in the trace so
//! a surface can say *what* was negotiated, not just how long it took.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TlsConnector};
use netune_trace::{
    Alpn, AttemptRef, ConnectionInfo, EndpointRef, EventKind, Fidelity, FrameClass, Reason,
    Recorder, RequestTrace, TraceId, Validity,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const CHUNKS: usize = 24;
/// Head first, then a prefill gap before the first token: the shape that makes
/// `server_ttft_us` estimable rather than batched.
const PREFILL_GAP: std::time::Duration = std::time::Duration::from_millis(250);

async fn serve_tls(listener: TcpListener, acceptor: TlsAcceptor, responses: usize) {
    let (socket, _) = listener.accept().await.expect("accept");
    let mut stream = acceptor.accept(socket).await.expect("tls accept");
    for _ in 0..responses {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("read request");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
            )
            .await
            .expect("head");
        stream.flush().await.expect("flush head");
        tokio::time::sleep(PREFILL_GAP).await;
        for i in 0..CHUNKS {
            let frame = format!("data: {i}\n");
            let chunk = format!("{:x}\r\n{frame}\r\n", frame.len());
            stream.write_all(chunk.as_bytes()).await.expect("chunk");
            stream.flush().await.expect("flush chunk");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        stream.write_all(b"0\r\n\r\n").await.expect("end");
        stream.flush().await.expect("flush end");
    }
}

fn trace_of(log: netune_trace::EventLog, authority: &str) -> RequestTrace {
    RequestTrace {
        id: TraceId::new("tls-e2e"),
        attempt: AttemptRef {
            round: 1,
            turn: 1,
            attempt: 1,
        },
        endpoint: EndpointRef {
            provider: "e2e".into(),
            model: "e2e-model".into(),
            authority: authority.to_string(),
        },
        connection: ConnectionInfo::default(),
        fidelity: Fidelity::l1(),
        log,
    }
}

async fn request_once<C: netune::Connector>(
    client: &Client<C>,
    target: &Target,
    recorder: Arc<Mutex<Recorder>>,
) {
    let head = RequestHead::new(Method::POST, "/v1/chat/completions")
        .with_header("content-type", "application/json");
    let mut response = client
        .send(
            target,
            Arc::clone(&recorder),
            head,
            Some(Bytes::from_static(b"{\"stream\":true}")),
        )
        .await
        .expect("send");
    assert_eq!(response.head.status, http::StatusCode::OK);
    while let Some(chunk) = response.body.next_chunk().await.expect("chunk") {
        if chunk.starts_with(b"data: ") {
            recorder
                .lock()
                .expect("recorder")
                .frame(FrameClass::Text, 1);
        }
    }
    recorder
        .lock()
        .expect("recorder")
        .mark(EventKind::Validated, 0, 0);
}

fn tls_client(config: Arc<rustls::ClientConfig>) -> Client<TlsConnector<TcpConnector>> {
    Client::new(
        TlsConnector::new(TcpConnector::new(), config),
        Pool::default(),
        ClientConfig::default(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tls_attempt_measures_the_handshake_and_records_negotiation() {
    let certified = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve_tls(listener, acceptor, 1));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("root");
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let client = tls_client(Arc::new(config));
    let target = Target::tls(address.to_string(), "localhost");
    let recorder = Arc::new(Mutex::new(Recorder::start(4096)));
    request_once(&client, &target, Arc::clone(&recorder)).await;

    let trace = trace_of(
        recorder.lock().expect("recorder").log().clone(),
        &address.to_string(),
    );
    let derived = netune_trace::derive(&trace);

    assert!(derived.dns_us.is_measured());
    assert!(derived.tcp_us.is_measured());
    assert!(derived.tls_us.is_measured(), "tls: {:?}", derived.tls_us);
    assert!(derived.ttfb_us.is_measured());
    assert!(derived.ttft_us.is_measured());
    assert!(derived.server_ttft_us.is_measured());
    assert!(derived.e2e_us.is_measured());
    assert!(derived.stream_us.value().is_some(), "stream span measured");

    let info = trace
        .log
        .first_of(EventKind::TlsInfo)
        .expect("negotiation recorded");
    assert_eq!(Alpn::from_code(info.a as u8), Some(Alpn::Http11));
    assert_eq!(info.b, 13, "TLS 1.3 with a modern rustls");

    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_tls_reuse_has_no_handshake_to_charge() {
    let certified = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve_tls(listener, acceptor, 2));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("root");
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = tls_client(Arc::new(config));
    let target = Target::tls(address.to_string(), "localhost");

    let first = Arc::new(Mutex::new(Recorder::start(4096)));
    request_once(&client, &target, Arc::clone(&first)).await;
    let first_trace = trace_of(
        first.lock().expect("recorder").log().clone(),
        &address.to_string(),
    );
    assert!(netune_trace::derive(&first_trace).tls_us.is_measured());

    let second = Arc::new(Mutex::new(Recorder::start(4096)));
    request_once(&client, &target, Arc::clone(&second)).await;
    let second_trace = trace_of(
        second.lock().expect("recorder").log().clone(),
        &address.to_string(),
    );
    let second_derived = netune_trace::derive(&second_trace);

    assert!(
        second_trace
            .log
            .first_of(EventKind::ConnectReused)
            .is_some()
    );
    for reading in [
        second_derived.dns_us,
        second_derived.tcp_us,
        second_derived.tls_us,
    ] {
        assert_eq!(
            reading.validity(),
            Validity::NotApplicable(Reason::ConnectionReused),
            "a reused TLS connection has no handshake to charge"
        );
    }
    assert!(second_derived.ttft_us.is_measured());

    let _ = server.await;
}
