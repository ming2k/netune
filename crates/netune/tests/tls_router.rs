//! Per-request TLS fingerprint selection: presets chosen at request time.
//!
//! The router connector compiles each named preset lazily and handshakes with
//! the one the target names; the pool keeps every identity's connections in
//! their own slice. Together these tests pin the behaviours that make
//! fingerprints a *request-level* choice:
//!
//! 1. the target's profile name reaches the wire (observed via negotiated ALPN),
//! 2. an unknown name fails loudly instead of downgrading to the default,
//! 3. a custom-composed profile is selectable exactly like a preset,
//! 4. a pooled connection from one identity is never handed to a request that
//!    asked for another.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::Method;
use netune::{
    Client, ClientConfig, Pool, Preset, RequestHead, Target, TcpConnector, TlsRouterConnector,
};
use netune_trace::Recorder;
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
            let Ok(mut stream) = acceptor.accept(socket).await else {
                return;
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
/// negotiated) plus the target and the pinned root store.
struct Fixture {
    target: Target,
    roots: rustls::RootCertStore,
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

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("root");

    Fixture {
        target: Target::tls(address.to_string(), "localhost"),
        roots,
        _server,
    }
}

/// A body read to completion, as the response body bytes.
async fn body_of(response: &mut netune::Response) -> String {
    let bytes = response.body.read_to_end().await.expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf8")
}

/// One router client whose built-in presets are unusable against the test CA:
/// both preset names are overridden with CA-pinned variants that keep each
/// preset's *fingerprint surface* (ALPN offer) but trust the test root. This
/// is exactly the composition a real embedder would do.
fn pinned_client(fixture: &Fixture) -> Client<TlsRouterConnector<TcpConnector>> {
    let default_profile = Preset::NetuneDefault
        .profile()
        .with_roots(fixture.roots.clone());
    let codex_profile = Preset::CodexReqwest
        .profile()
        .with_roots(fixture.roots.clone());
    let connector = TlsRouterConnector::new(TcpConnector::new())
        .with_profile_named(Preset::NetuneDefault.name(), default_profile)
        .with_profile_named(Preset::CodexReqwest.name(), codex_profile);
    Client::new(connector, Pool::default(), ClientConfig::default())
}

async fn get(client: &Client<TlsRouterConnector<TcpConnector>>, target: &Target) -> String {
    let head = RequestHead::new(Method::GET, "/");
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
    let mut response = client
        .send(target, recorder, head, None::<Bytes>)
        .await
        .expect("send");
    body_of(&mut response).await
}

/// The default identity (h1-only offer) negotiates `http/1.1`; the codex
/// preset (h2-first offer, per hyper-rustls) negotiates `h2` — same server,
/// same client, two requests, two identities.
#[tokio::test]
async fn the_profile_selection_reaches_the_wire_per_request() {
    let fixture = fixture().await;
    let client = pinned_client(&fixture);

    let default_body = get(&client, &fixture.target).await;
    assert_eq!(default_body, "alpn=http/1.1");

    let codex_target = fixture
        .target
        .clone()
        .with_tls_profile(Preset::CodexReqwest.name());
    let codex_body = get(&client, &codex_target).await;
    assert_eq!(codex_body, "alpn=h2", "the codex preset presents h2");
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
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
    let error = match client.send(&target, recorder, head, None::<Bytes>).await {
        Err(error) => error,
        Ok(_) => panic!("unknown profile must fail, not downgrade"),
    };
    let message = error.to_string();
    assert!(message.contains("no-such-fingerprint"), "{message}");
    assert!(
        message.contains("codex-reqwest"),
        "the error names the built-in presets: {message}"
    );
}

/// A custom-composed profile (two knobs on a preset base) is selectable by
/// its own name, like any preset.
#[tokio::test]
async fn a_custom_composed_profile_is_selectable_by_name() {
    let fixture = fixture().await;
    let custom = Preset::CodexReqwest
        .profile()
        .with_roots(fixture.roots.clone())
        .with_alpn(&[b"http/1.1".as_slice()]);
    let connector = TlsRouterConnector::new(TcpConnector::new())
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
/// request that asked for another. The server requires handshakes to be
/// `http/1.1`-compatible (it speaks only 1.1), so a cross-identity reuse would
/// surface as an ALPN negotiation failure on the second request — and the
/// pool counters prove the slices stayed separate.
#[tokio::test]
async fn the_pool_never_reuses_across_identities() {
    let fixture = fixture().await;
    let client = pinned_client(&fixture);

    // Warm one default-identity connection into the pool: server closes after
    // each response, so nothing is actually pooled — but prewarm's connection
    // goes idle before the server's close arrives, so the pool does hold one.
    client
        .prewarm(&fixture.target)
        .await
        .expect("prewarm default identity");
    let codex_target = fixture
        .target
        .clone()
        .with_tls_profile(Preset::CodexReqwest.name());
    client.prewarm(&codex_target).await.expect("prewarm codex");

    // Each identity's slice holds exactly its own connection: the codex
    // request cannot consume the default slice and vice versa.
    assert_eq!(
        client.pool().idle_count(&fixture.target.authority),
        1,
        "default identity slice"
    );
    assert_eq!(
        client.pool().idle_count(&format!(
            "{}#{}",
            fixture.target.authority,
            Preset::CodexReqwest.name()
        )),
        1,
        "codex identity slice"
    );

    // Both identities still answer their own requests.
    let default_body = get(&client, &fixture.target).await;
    assert_eq!(default_body, "alpn=http/1.1");
    let codex_body = get(&client, &codex_target).await;
    assert_eq!(codex_body, "alpn=h2");
}
