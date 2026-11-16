//! Per-request TLS identity selection: presets chosen at request time.
//!
//! The router connector resolves each named profile before the handshake;
//! the pool keys the connection on the identity (profile + engine), so every
//! identity's connections stay in their own slice. Together these tests pin
//! the behaviours that make identities a *request-level* choice:
//!
//! 1. the target's profile name reaches the wire (observed via negotiated ALPN),
//! 2. an unknown name fails loudly instead of downgrading to the default,
//! 3. a custom-composed profile is selectable exactly like a preset,
//! 4. a pooled connection from one identity is never handed to a request that
//!    asked for another,
//! 5. an unknown engine name fails loudly ([`INV-TLS-09`]).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use bytes::Bytes;
use http::Method;
use netune::{
    Client, ClientConfig, Pool, Preset, RequestHead, Target, TcpConnector, TlsRouterConnector,
};
use netune_trace::TraceCollector;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// An HTTP/1.1 server that echoes the ALPN the client *negotiated*, so the
/// test can tell which identity handshook. One request per connection; the
/// response carries `connection: close` so every request is a fresh
/// handshake and the pool assertions stay unambiguous.
async fn serve(listener: TcpListener, acceptor: TlsAcceptor) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mut stream = match acceptor.accept(socket).await {
                Ok(stream) => stream,
                Err(error) => {
                    eprintln!("DBG srv accept error: {error}");
                    return;
                }
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let alpn = stream
                .get_ref()
                .1
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .unwrap_or_default();
            let body = format!("alpn={alpn}");
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// A TLS server offering both protocols (the client's offer decides what is
/// negotiated) plus the target and the identity's certificate.
struct Fixture {
    target: Target,
    certificate: Vec<u8>,
    _server: tokio::task::JoinHandle<()>,
}

async fn fixture() -> Fixture {
    let certified = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let _server = tokio::spawn(serve(listener, acceptor));

    Fixture {
        target: Target::tls(address.to_string(), "localhost"),
        certificate: cert_der.as_ref().to_vec(),
        _server,
    }
}

/// A body read to completion, as the response body bytes.
async fn body_of(response: &mut netune::Response) -> String {
    let bytes = response.body.read_to_end().await.expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf8")
}

/// One router client trusting the test identity: the built-in presets'
/// *fingerprint surfaces* (ALPN offers) are kept but the trust policy is
/// pinned to the test CA. This is exactly the composition a real embedder
/// would do ([`INV-TLS-08`]: trust is a policy on the connector).
fn pinned_client(fixture: &Fixture) -> Client {
    pinned_client_on(fixture, Pool::default())
}

fn pinned_client_on(fixture: &Fixture, pool: Pool) -> Client {
    let default_profile = Preset::NetuneDefault.profile();
    let stream_profile = Preset::AntigravityCliStream.profile();
    let connector = TlsRouterConnector::new(TcpConnector::new())
        .with_verifier(netune_tls::Verifier::Pinned(fixture.certificate.clone()))
        .with_profile_named(Preset::NetuneDefault.name(), default_profile)
        .with_profile_named(Preset::AntigravityCliStream.name(), stream_profile);
    Client::new(connector, pool, ClientConfig::default())
}

async fn get(client: &Client, target: &Target) -> String {
    let head = RequestHead::new(Method::GET, "/");
    let recorder = TraceCollector::start(1024);
    let mut response = client
        .send_traced(target, recorder, head, None::<Bytes>)
        .await
        .expect("send");
    body_of(&mut response).await
}

/// The default identity (h1-only offer) negotiates `http/1.1`; the stream
/// preset (h2-first offer) negotiates `h2` — same server, same client, two
/// requests, two identities.
#[tokio::test]
async fn the_profile_selection_reaches_the_wire_per_request() {
    let fixture = fixture().await;
    let client = pinned_client(&fixture);

    let default_body = get(&client, &fixture.target).await;
    assert_eq!(default_body, "alpn=http/1.1");

    let stream_target = fixture
        .target
        .clone()
        .with_tls_profile(Preset::AntigravityCliStream.name());
    let stream_body = get(&client, &stream_target).await;
    assert_eq!(stream_body, "alpn=h2", "the stream preset presents h2");
}

/// A name nobody registered is a loud connect error listing the known
/// presets, never a silent downgrade to the default identity.
#[tokio::test]
async fn an_unknown_profile_name_fails_loudly() {
    let fixture = fixture().await;
    let client = pinned_client(&fixture);
    let target = fixture
        .target
        .clone()
        .with_tls_profile("no-such-fingerprint");

    let head = RequestHead::new(Method::GET, "/");
    let recorder = TraceCollector::start(1024);
    let error = match client
        .send_traced(&target, recorder, head, None::<Bytes>)
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("unknown profile must fail, not downgrade"),
    };
    let message = error.to_string();
    assert!(message.contains("no-such-fingerprint"), "{message}");
    assert!(
        message.contains("antigravity-cli-stream"),
        "the error names the built-in presets: {message}"
    );
}

/// An unknown engine name is a loud connect error ([`INV-TLS-09`]), never a
/// silent fallback.
#[tokio::test]
async fn an_unknown_engine_name_fails_loudly() {
    let fixture = fixture().await;
    let client = pinned_client(&fixture);
    let target = fixture.target.clone().with_tls_engine("no-such-engine");

    let head = RequestHead::new(Method::GET, "/");
    let recorder = TraceCollector::start(1024);
    let error = match client
        .send_traced(&target, recorder, head, None::<Bytes>)
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("unknown engine must fail, not fallback"),
    };
    let message = error.to_string();
    assert!(message.contains("no-such-engine"), "{message}");
    assert!(
        message.contains("netune-tls"),
        "the error names the engine: {message}"
    );
}

/// A custom-composed profile (an ALPN knob on a preset base) is selectable by
/// its own name, like any preset.
#[tokio::test]
async fn a_custom_composed_profile_is_selectable_by_name() {
    let fixture = fixture().await;
    let custom = Preset::AntigravityCliStream
        .profile()
        .with_alpn(&[b"http/1.1".as_slice()]);
    let connector = TlsRouterConnector::new(TcpConnector::new())
        .with_verifier(netune_tls::Verifier::Pinned(fixture.certificate.clone()))
        .with_profile_named("my-composed-identity", custom);
    let client = Client::new(connector, Pool::default(), ClientConfig::default());

    let target = fixture
        .target
        .clone()
        .with_tls_profile("my-composed-identity");
    let body = get(&client, &target).await;
    assert_eq!(
        body, "alpn=http/1.1",
        "the custom ALPN knob reached the wire"
    );
}

/// Pool isolation: a pooled connection from one identity is never handed to a
/// request that asked for another. The server closes after each response, so
/// prewarmed connections go idle before the close arrives and the pool does
/// hold one per identity.
#[tokio::test]
async fn the_pool_never_reuses_across_identities() {
    let fixture = fixture().await;
    let pool = Pool::default();
    let client = pinned_client_on(&fixture, pool.clone());

    client
        .prewarm(&fixture.target)
        .await
        .expect("prewarm default identity");
    let stream_target = fixture
        .target
        .clone()
        .with_tls_profile(Preset::AntigravityCliStream.name());
    client
        .prewarm(&stream_target)
        .await
        .expect("prewarm stream");

    // Each identity's slice holds exactly its own connection: the stream
    // request cannot consume the default slice and vice versa.
    assert_eq!(
        pool.idle_count(&client.pool_key(&fixture.target).expect("plan")),
        1,
        "default identity slice"
    );
    assert_eq!(
        pool.idle_count(&client.pool_key(&stream_target).expect("plan")),
        1,
        "stream identity slice"
    );

    // Both identities still answer their own requests.
    let default_body = get(&client, &fixture.target).await;
    assert_eq!(default_body, "alpn=http/1.1");
    let stream_body = get(&client, &stream_target).await;
    assert_eq!(stream_body, "alpn=h2");
}

/// `[INV-TRACE-10]`: the tap sits on the socket, beneath TLS.
///
/// A traced HTTPS attempt must show socket writes and reads *during* the
/// handshake (the ClientHello leaving, the server's flight arriving), and its
/// read total must be the ciphertext that crossed the socket: strictly more
/// than the plaintext response the codec was handed.
#[tokio::test]
async fn inv_trace_10_a_traced_tls_attempt_records_socket_events_under_the_handshake() {
    use netune::TraceConfig;
    use netune_trace::{EventKind, Fidelity};

    let fixture = fixture().await;
    let client = pinned_client(&fixture);
    let mut response = client
        .request_traced(
            &fixture.target,
            RequestHead::new(Method::GET, "/"),
            None,
            TraceConfig::default(),
        )
        .await
        .expect("traced request");
    let plaintext = response.body.read_to_end().await.expect("body").len() as u64;
    let trace = response.body.trace().expect("trace");
    assert_eq!(trace.fidelity, Fidelity::l1());
    assert!(!trace.connection.reused);
    assert!(trace.connection.local_port.is_some());

    let tls_start = trace
        .log
        .first_of(EventKind::TlsStart)
        .expect("TlsStart")
        .at_ns;
    let tls_end = trace.log.first_of(EventKind::TlsEnd).expect("TlsEnd").at_ns;
    let during_handshake = |kind: EventKind| {
        trace
            .log
            .iter()
            .any(|event| event.kind == kind && event.at_ns >= tls_start && event.at_ns <= tls_end)
    };
    assert!(
        during_handshake(EventKind::Write),
        "the ClientHello is a socket write inside the TLS phase"
    );
    assert!(
        during_handshake(EventKind::Read),
        "the server's flight is a socket read inside the TLS phase"
    );
    assert!(
        trace.log.bytes_read() > plaintext,
        "socket reads count ciphertext and handshake bytes ({} read, {plaintext} plaintext)",
        trace.log.bytes_read()
    );
}

#[tokio::test]
async fn client_builder_http2_syncs_default_rustls_alpn_on_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 4096];
        let mut filled = 0usize;
        while filled < 5 {
            let n = socket
                .read(&mut buf[filled..])
                .await
                .expect("read record header");
            if n == 0 {
                break;
            }
            filled += n;
        }
        let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        while filled < 5 + rec_len {
            let n = socket
                .read(&mut buf[filled..])
                .await
                .expect("read record body");
            if n == 0 {
                break;
            }
            filled += n;
        }
        let parsed =
            netune_trace::ClientHello::parse(&buf[5..5 + rec_len]).expect("parse client hello");
        parsed.alpn_protocols
    });

    let client = Client::builder().http2(true).build();
    assert!(client.config().enable_http2);
    let target = Target::tls(address.to_string(), "example.com");
    // The peer closes after reading ClientHello, so the request returns an error;
    // what we assert is the exact ALPN list offered on the wire by default rustls.
    let _ = client
        .request(&target, RequestHead::new(Method::GET, "/"), None)
        .await;

    let alpns = server.await.expect("server join");
    assert_eq!(alpns, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
}
