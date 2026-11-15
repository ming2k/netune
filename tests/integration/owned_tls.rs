//! The owned TLS engine end to end through `netune`'s public surface: a
//! target that selects the `netune-tls` engine connects through the
//! egress connector chain, handshakes with a `rustls` server peer, and
//! serves an HTTP request over the owned record layer — with the engine
//! choice keyed into the connection identity ([`INV-TLS-09`]).
//!
//! The server pins the two versions the engine speaks: TLS 1.3 and TLS 1.2.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use netune::{Connector, TlsRouterConnector};
use netune_test_support::tls::identity;

fn drive_server(
    listener: std::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        let mut connection = rustls::ServerConnection::new(config).expect("server connection");
        let mut buffer = [0u8; 16_384];
        let mut received = Vec::new();
        let mut responded = false;
        loop {
            while connection.wants_write() {
                let written = connection
                    .write_tls(&mut &mut buffer[..])
                    .expect("write_tls");
                if written == 0 {
                    break;
                }
                use std::io::Write as _;
                socket.write_all(&buffer[..written]).expect("write");
            }
            if responded {
                break;
            }
            let mut read = 0usize;
            loop {
                match socket.read(&mut buffer[read..]) {
                    Ok(0) => break,
                    Ok(n) => read += n,
                    Err(_) => break,
                }
                if read > 0 {
                    break;
                }
            }
            if read == 0 {
                break;
            }
            use std::io::Read as _;
            connection.read_tls(&mut &buffer[..read]).expect("read_tls");
            connection.process_new_packets().expect("process");
            let mut plaintext = [0u8; 1024];
            if let Ok(size) = connection.reader().read(&mut plaintext)
                && size > 0
            {
                received.extend_from_slice(&plaintext[..size]);
                use std::io::Write as _;
                connection
                    .writer()
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .expect("respond");
                responded = true;
            }
        }
        received
    })
}

fn plaintext_of(server: std::thread::JoinHandle<Vec<u8>>) -> Vec<u8> {
    server.join().expect("server thread")
}

#[tokio::test]
async fn the_owned_engine_serves_http_over_both_versions() {
    for (suite, versions) in [
        (
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            &[&rustls::version::TLS13][..],
        ),
        (
            rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            &[&rustls::version::TLS12][..],
        ),
    ] {
        let identity = identity(&["localhost"], &[b"http/1.1"]);
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites = vec![suite];
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key.clone()),
                ),
            )
            .expect("server certificate");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = drive_server(listener, Arc::new(server_config));

        // The owned engine is selected per target; the verifier pins the test
        // identity. The connect chain is the production one: TCP connector
        // wrapped by the TLS router.
        let connector = TlsRouterConnector::new(netune::TcpConnector::new()).with_verifier(
            netune_tls::Verifier::Pinned(identity.certificate.as_ref().to_vec()),
        );
        let target = netune::Target::tls(format!("127.0.0.1:{port}"), "localhost")
            .with_tls_profile("antigravity-cli-stream")
            .with_tls_engine("netune-tls");
        let recorder = netune_trace::TraceCollector::start(64);
        let established = connector
            .connect(&target, &recorder)
            .await
            .expect("owned handshake through netune");

        // ALPN and the trace facts.
        assert_eq!(established.alpn, Some(netune_trace::Alpn::Http11));
        let trace = recorder.snapshot(netune_trace::Fidelity::l0());
        let tls_end = trace
            .log
            .iter()
            .any(|event| event.kind == netune_trace::EventKind::TlsEnd);
        assert!(tls_end, "the handshake is a recorded phase");

        // An HTTP request over the owned stream, written through
        // `Established`'s transport.
        let mut stream = established.stream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        assert!(
            response.starts_with(b"HTTP/1.1 200 OK"),
            "the server answered over the owned engine: {:?}",
            String::from_utf8_lossy(&response)
        );

        let answer = plaintext_of(server);
        assert!(
            answer.starts_with(b"GET / HTTP/1.1"),
            "the server received the request over the owned engine: {:?}",
            String::from_utf8_lossy(&answer)
        );
    }
}

#[test]
fn the_engine_choice_is_connection_identity() {
    use netune::Target;

    let plain = Target::tls("origin:443", "origin.example");
    let owned = plain.clone().with_tls_engine("netune-tls");
    assert!(plain.tls_engine().is_none());
    assert_eq!(owned.tls_engine(), Some("netune-tls"));
    // Engine choice is connection identity: the pool keys on it, so a
    // rustls-path connection is never shared with an owned-engine one
    // ([INV-TLS-09]).
    assert_ne!(
        owned.tls_engine(),
        plain.tls_engine(),
        "the engine choice must be request-visible, hence identity-visible"
    );
}
