//! TLS termination, proven with a real handshake.
//!
//! A mock TLS layer would test the mock. These tests generate a certificate, run a real `rustls`
//! handshake against a real listener, and assert what an operator depends on: the right certificate is
//! served for the name asked for, ALPN decides the protocol inside the handshake, the handshake is
//! bounded in time, and the handshake's completion is a recorded fact (`IngressTlsEnd`).

#![cfg(feature = "tls")]
#![allow(clippy::expect_used, clippy::unwrap_used)]
mod support;

use std::sync::Arc;
use std::time::Duration;

use netune_server::{
    Handler, HandlerFuture, IncomingRequest, Protocols, RequestBody, Response, ServedProtocol,
    Server, ServerConfig, TlsTermination,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

/// A certificate for `names`, plus the client configuration that trusts it.
struct Identity {
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    name: &'static str,
}

/// Generate a self-signed identity for `name`, advertising `alpn`.
fn identity(name: &'static str, alpn: &[&[u8]]) -> Identity {
    let certificate =
        rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("certificate");
    let der = CertificateDer::from(certificate.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(certificate.signing_key.serialize_der()).expect("key");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).expect("trust anchor");

    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .expect("server config");
    let mut server = server;
    server.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();

    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();

    Identity {
        server: Arc::new(server),
        client: Arc::new(client),
        name,
    }
}

/// An echo handler so a request's arrival is unambiguous.
struct Echo;

impl Handler for Echo {
    fn handle<'a>(
        &'a self,
        request: IncomingRequest,
        mut body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            let bytes = body.read_to_end().await.unwrap_or_default();
            Response::ok(bytes)
                .with_header("x-method", request.method.as_str())
                .with_header("x-version", format!("{:?}", request.version))
        })
    }
}

async fn with_server<F, Fut>(server: Server, body: F)
where
    F: FnOnce(std::net::SocketAddr) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let address = server.local_addr();
    let (shutdown, wait) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = wait.await;
            })
            .await;
    });
    body(address).await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("the server drained")
        .expect("no panic");
}

/// Perform a real handshake and return the stream plus the negotiated ALPN identifier.
async fn connect_tls(
    address: std::net::SocketAddr,
    identity: &Identity,
    offers: &[&[u8]],
) -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    Option<Vec<u8>>,
) {
    let mut client = (*identity.client).clone();
    client.alpn_protocols = offers.iter().map(|protocol| protocol.to_vec()).collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let name = ServerName::try_from(identity.name.to_owned()).expect("server name");
    let stream = connector
        .connect(name, stream)
        .await
        .expect("a real handshake against a real listener");
    let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    (stream, alpn)
}

/// Read one complete HTTP/1.1 response off the stream (status line + head; body read separately).
async fn read_response<S: AsyncReadExt + Unpin>(stream: &mut S) -> String {
    let mut collected = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("the peer answered")
            .expect("read");
        if read == 0 {
            break;
        }
        collected.extend_from_slice(&buffer[..read]);
        if collected.windows(4).any(|window| window == b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&collected).into_owned();
            // A content-length body follows the head; keep reading until it is complete.
            if let Some(end) = text.find("\r\n\r\n") {
                let head = &text[..end];
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if collected.len() >= end + 4 + length {
                    return text;
                }
            }
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tls_listener_serves_http11_over_a_real_handshake() {
    let generated = identity("probe.test", &[b"http/1.1"]);
    let termination = TlsTermination::single(Arc::clone(&generated.server));
    let config = ServerConfig::for_tests()
        .with_protocols(Protocols::HTTP1)
        .with_tls(termination);
    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("bind");

    with_server(server, |address| async move {
        let (mut stream, alpn) = connect_tls(address, &generated, &[b"http/1.1"]).await;
        assert_eq!(alpn.as_deref(), Some(&b"http/1.1"[..]));
        stream
            .write_all(b"POST /echo HTTP/1.1\r\nHost: probe.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .expect("write");
        let response = read_response(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.ends_with("hello"), "the body crossed TLS: {response}");
        assert!(
            response.contains("x-version: HTTP/1.1"),
            "the handler saw an HTTP/1.1 request: {response}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn alpn_h2_selects_http2_inside_the_handshake() {
    // The protocol decision for a TLS connection is made by ALPN *during* the handshake, and the
    // HTTP/2 preface is never read from the socket by the listener — `rustls` has already negotiated.
    let generated = identity("probe.test", &[b"h2", b"http/1.1"]);
    let termination = TlsTermination::single(Arc::clone(&generated.server));
    let config = ServerConfig::for_tests().with_tls(termination);
    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = config.with_trace_sink(Arc::clone(&observer) as _);
    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("bind");

    with_server(server, |address| async move {
        let (stream, alpn) = connect_tls(address, &generated, &[b"h2", b"http/1.1"]).await;
        assert_eq!(alpn.as_deref(), Some(&b"h2"[..]), "h2 was preferred");

        let mut client = netune_http2::client::H2ClientConnection::handshake(
            stream,
            netune_http2::H2Fingerprint::chrome(),
        )
        .await
        .expect("the h2 preface flows inside the tunnel");
        let response = client
            .request(
                "POST",
                "probe.test",
                "https",
                "/echo",
                &[],
                Some(b"over h2"),
            )
            .await
            .expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(&response.body[..], b"over h2");
    })
    .await;

    let traces = observer.take();
    assert_eq!(
        traces
            .iter()
            .map(|trace| trace.protocol)
            .collect::<Vec<_>>(),
        vec![ServedProtocol::Http2],
        "the trace names the protocol ALPN selected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_offers_only_an_unserved_alpn_is_refused_by_the_handshake() {
    // `rustls` refuses an ALPN mismatch itself, which is why the listener does not need a second check:
    // the peer never reaches HTTP at all, so there is no protocol confusion to have.
    let generated = identity("probe.test", &[b"http/1.1"]);
    let termination = TlsTermination::single(Arc::clone(&generated.server));
    let config = ServerConfig::for_tests()
        .with_protocols(Protocols::HTTP1)
        .with_tls(termination);
    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("bind");

    with_server(server, |address| async move {
        let mut client = (*generated.client).clone();
        client.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let name = ServerName::try_from("probe.test".to_owned()).expect("name");
        let outcome = connector.connect(name, stream).await;
        assert!(
            outcome.is_err(),
            "a client that offers only h2 to an HTTP/1.1-only listener fails the handshake"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_untrusted_name_fails_the_handshake_rather_than_serving() {
    // The certificate is for `probe.test`; connecting as `other.test` must fail at verification. A
    // listener that could be reached under any name would make every certificate meaningless.
    let generated = identity("probe.test", &[b"http/1.1"]);
    let termination = TlsTermination::single(Arc::clone(&generated.server));
    let config = ServerConfig::for_tests()
        .with_protocols(Protocols::HTTP1)
        .with_tls(termination);
    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("bind");

    with_server(server, |address| async move {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&generated.client));
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let name = ServerName::try_from("other.test".to_owned()).expect("name");
        assert!(
            connector.connect(name, stream).await.is_err(),
            "a mismatched name must not verify"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_stalls_mid_handshake_is_cut_off_at_the_bound() {
    // The cheapest attack on a TLS listener is to open a socket and never speak: nothing about the
    // handshake is application code, so nothing else bounds it.
    let generated = identity("probe.test", &[b"http/1.1"]);
    let termination = TlsTermination::single(Arc::clone(&generated.server));
    let config = ServerConfig::for_tests()
        .with_protocols(Protocols::HTTP1)
        .with_head_timeout(Duration::from_millis(200))
        .with_tls(termination);
    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = config.with_trace_sink(Arc::clone(&observer) as _);
    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("bind");

    with_server(server, |address| async move {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        // One byte of a record header, then nothing.
        stream.write_all(&[0x16]).await.expect("write");
        let mut collected = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut collected))
            .await
            .expect("the listener closed the stalled handshake");
        let _ = read;
    })
    .await;

    let traces = observer.take();
    assert_eq!(traces.len(), 1, "the connection was traced");
    let codes: Vec<u32> = traces[0]
        .log
        .iter()
        .filter(|event| event.kind == netune_trace::EventKind::Error)
        .map(|event| event.a)
        .collect();
    assert_eq!(
        codes,
        vec![netune_server::ERROR_TLS_HANDSHAKE],
        "a stalled handshake is classified as one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_completed_handshake_is_a_recorded_fact() {
    // The reason a listener terminates TLS itself rather than deferring to a proxy: the handshake's
    // completion is a recorded event the derivation can anchor on.
    let generated = identity("probe.test", &[b"http/1.1"]);
    let termination = TlsTermination::single(Arc::clone(&generated.server));
    let observer = Arc::new(netune_server::CollectingObserver::default());
    let config = ServerConfig::for_tests()
        .with_protocols(Protocols::HTTP1)
        .with_tls(termination)
        .with_trace_sink(Arc::clone(&observer) as _);
    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("bind");

    with_server(server, |address| async move {
        let (mut stream, _) = connect_tls(address, &generated, &[b"http/1.1"]).await;
        stream
            .write_all(b"GET /x HTTP/1.1\r\nHost: probe.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let _ = read_response(&mut stream).await;
    })
    .await;

    let traces = observer.take();
    let trace = traces.first().expect("traced");
    assert!(
        trace
            .log
            .iter()
            .any(|event| event.kind == netune_trace::EventKind::IngressTlsEnd),
        "the handshake's end is in the trace, so its cost is derivable"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn per_name_selection_serves_the_certificate_the_peer_asked_for() {
    // The SNI is the whole reason `LazyConfigAcceptor` is used instead of a fixed configuration: a
    // listener with two certificates must serve the right one, and serving the wrong one verifies
    // against the wrong name.
    let first = identity("a.test", &[b"http/1.1"]);
    let second = identity("b.test", &[b"http/1.1"]);
    let termination = TlsTermination::per_name(
        vec![
            ("a.test".to_owned(), Arc::clone(&first.server)),
            ("b.test".to_owned(), Arc::clone(&second.server)),
        ],
        Arc::clone(&first.server),
    );
    let config = ServerConfig::for_tests()
        .with_protocols(Protocols::HTTP1)
        .with_tls(termination);
    let server = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect("bind");

    with_server(server, |address| async move {
        // `b.test` must verify against *its own* certificate, which is what proves the SNI was used.
        let (mut stream, _) = connect_tls(address, &second, &[b"http/1.1"]).await;
        stream
            .write_all(b"GET /x HTTP/1.1\r\nHost: b.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let response = read_response(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bind_is_refused_when_the_tls_configuration_does_not_advertise_what_is_served() {
    // A listener that claims HTTP/2 but whose TLS configuration offers only `http/1.1` would negotiate
    // a protocol it then refuses on every connection. Failing at bind time is the only useful moment to
    // learn that.
    let generated = identity("probe.test", &[b"http/1.1"]);
    let termination = TlsTermination::single(Arc::clone(&generated.server));
    let config = ServerConfig::for_tests()
        .with_protocols(Protocols::BOTH)
        .with_tls(termination);
    let error = Server::bind("127.0.0.1:0", config, Arc::new(Echo))
        .await
        .expect_err("a TLS configuration that cannot serve the offered protocols is refused");
    assert!(
        format!("{error}").contains("ALPN"),
        "the reason names what is wrong: {error}"
    );
}
