// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end: owned async endpoint against the owned server core.

use std::sync::Arc;
use std::time::Duration;

use netune_quic::owned::{AcceptError, ClientConfigOwned, Endpoint, ServerConfigOwned};
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

fn server_tls_with_cert() -> (
    Arc<rustls::ServerConfig>,
    rustls::pki_types::CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let leaf = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let cert_chain = vec![leaf.clone()];
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
    (Arc::new(tls), leaf)
}

fn server_tls() -> Arc<rustls::ServerConfig> {
    server_tls_with_cert().0
}

fn verified_client_tls(
    cert: rustls::pki_types::CertificateDer<'static>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("root");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
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

fn client_tls_with_alpn(alpn: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut config = (*client_tls()).clone();
    config.alpn_protocols = vec![alpn.to_vec()];
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
                congestion_factory: None,
                keep_alive: None,
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
    let response = tokio::time::timeout(Duration::from_secs(5), recv.read(1024))
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
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    let (mut send, mut recv) = connection.open_bi().await.expect("open bi");
    send.write_all(b"v2").await.expect("write");
    send.finish().await.expect("finish");
    let response = tokio::time::timeout(Duration::from_secs(5), recv.read(1024))
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
        let end = tokio::time::timeout(Duration::from_secs(5), recv.read(16))
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
                congestion_factory: None,
                keep_alive: None,
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
                congestion_factory: None,
                keep_alive: None,
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
                congestion_factory: None,
                keep_alive: None,
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
    second.wait_established().await.expect("established");
    assert!(second.early_data_accepted(), "server accepted early data");
    let response = tokio::time::timeout(Duration::from_secs(5), recv.read(16))
        .await
        .expect("response timeout")
        .expect("response read")
        .expect("response bytes");
    assert_eq!(response.as_ref(), b"ok");
    server_task.await.expect("server task");
}

// --- consumer seams ------------------------------------------------------

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use netune_quic::{
    CongestionController, CongestionControllerFactory, QuicConnector, QuicError, QuicProfile,
    QuicSocketConfig, QuicUdpSocket, QuicUdpSocketFactory,
};
use tokio::net::UdpSocket;

struct RecordingSocket {
    inner: UdpSocket,
    xor: u8,
    sends: AtomicUsize,
    max_send: AtomicUsize,
}

impl RecordingSocket {
    fn new(inner: UdpSocket, xor: u8) -> Self {
        Self {
            inner,
            xor,
            sends: AtomicUsize::new(0),
            max_send: AtomicUsize::new(0),
        }
    }

    fn sends(&self) -> usize {
        self.sends.load(Ordering::Relaxed)
    }

    fn max_send(&self) -> usize {
        self.max_send.load(Ordering::Relaxed)
    }
}

impl QuicUdpSocket for RecordingSocket {
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let result = QuicUdpSocket::poll_recv_from(&self.inner, cx, buf);
        if let Poll::Ready(Ok((length, peer))) = result {
            if self.xor != 0 {
                for byte in &mut buf[..length] {
                    *byte ^= self.xor;
                }
            }
            Poll::Ready(Ok((length, peer)))
        } else {
            result
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut wire = buf.to_vec();
        if self.xor != 0 {
            for byte in &mut wire {
                *byte ^= self.xor;
            }
        }
        let result = QuicUdpSocket::poll_send_to(&self.inner, cx, &wire, target);
        if let Poll::Ready(Ok(sent)) = result {
            self.sends.fetch_add(1, Ordering::Relaxed);
            self.max_send.fetch_max(sent, Ordering::Relaxed);
        }
        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[derive(Default)]
struct RecordingFactory {
    calls: AtomicUsize,
    target: Mutex<Option<SocketAddr>>,
    config: Mutex<Option<QuicSocketConfig>>,
}

impl QuicUdpSocketFactory for RecordingFactory {
    fn create(
        &self,
        target: SocketAddr,
        config: &QuicSocketConfig,
    ) -> io::Result<Arc<dyn QuicUdpSocket>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        *self.target.lock().expect("target lock") = Some(target);
        *self.config.lock().expect("config lock") = Some(config.clone());
        let socket = config.create_tokio_socket(target)?;
        Ok(Arc::new(RecordingSocket::new(socket, 0)))
    }
}

#[derive(Default)]
struct RecordingCongestionFactory {
    builds: AtomicUsize,
}

struct FixedWindow;

impl CongestionController for FixedWindow {
    fn window(&self) -> u64 {
        64 * 1024
    }

    fn on_ack(&mut self, _acked_bytes: u64, _now: Instant, _rtt: Option<Duration>) {}

    fn on_loss(&mut self, _now: Instant, _lost_bytes: u64) {}

    fn on_pto(&mut self, _now: Instant) {}
}

impl CongestionControllerFactory for RecordingCongestionFactory {
    fn build(&self, _now: Instant, _mtu: u16) -> Box<dyn CongestionController> {
        self.builds.fetch_add(1, Ordering::Relaxed);
        Box::new(FixedWindow)
    }
}

fn connector() -> QuicConnector {
    let mut profile = QuicProfile::default_profile();
    profile.name = "consumer-seam-test";
    QuicConnector::new(profile).with_tls_config((*client_tls()).clone())
}

#[tokio::test]
async fn a_connector_factory_creates_one_socket_after_confinement() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
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
        send.write_all(&data).await.expect("echo");
        send.finish().await.expect("finish");
    });

    let factory = Arc::new(RecordingFactory::default());
    let congestion = Arc::new(RecordingCongestionFactory::default());
    let socket_config = QuicSocketConfig {
        recv_buffer_size: Some(64 * 1024),
        ..QuicSocketConfig::default()
    };
    let connection = connector()
        .with_socket_config(socket_config.clone())
        .with_socket_factory(factory.clone())
        .with_congestion_factory(congestion.clone())
        .connect(addr, "localhost", None)
        .await
        .expect("connect");
    assert_eq!(factory.calls.load(Ordering::Relaxed), 1);
    assert_eq!(congestion.builds.load(Ordering::Relaxed), 1);
    assert_eq!(*factory.target.lock().expect("target lock"), Some(addr));
    assert_eq!(
        *factory.config.lock().expect("config lock"),
        Some(socket_config)
    );
    assert!(
        connection
            .peer_certificates()
            .is_some_and(|chain| !chain.is_empty()),
        "QuicConnection exposes the verified chain"
    );

    let (mut send, mut recv) = connection.open_stream().await.expect("open stream");
    send.write_all(b"factory").await.expect("write");
    send.finish().await.expect("finish");
    let echoed = tokio::time::timeout(Duration::from_secs(5), recv.read(64))
        .await
        .expect("timeout")
        .expect("read")
        .expect("data");
    assert_eq!(echoed.as_ref(), b"factory");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn a_refused_target_never_invokes_the_socket_factory() {
    let factory = Arc::new(RecordingFactory::default());
    let error = connector()
        .with_socket_factory(factory.clone())
        .strict_public()
        .connect_early("127.0.0.1:9".parse().expect("address"), "localhost", None)
        .await
        .expect_err("loopback is refused");
    assert!(matches!(error, QuicError::Connect(_)));
    assert_eq!(factory.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn an_obfuscated_socket_carries_a_session_in_both_directions() {
    let server_udp = UdpSocket::bind("127.0.0.1:0").await.expect("server bind");
    let server_socket = Arc::new(RecordingSocket::new(server_udp, 0x5a));
    let server = Endpoint::server_with_socket(
        server_socket.clone(),
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
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
        assert_eq!(data.as_ref(), b"obfuscated");
        send.write_all(b"clear").await.expect("write");
        send.finish().await.expect("finish");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let client_socket = Arc::new(RecordingSocket::new(client_udp, 0x5a));
    let client = Endpoint::client_with_socket(client_socket.clone())
        .await
        .expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    assert!(
        connection
            .peer_certificates()
            .is_some_and(|chain| !chain.is_empty()),
        "the verified peer chain is exposed"
    );
    let (mut send, mut recv) = connection.open_bi().await.expect("open bi");
    send.write_all(b"obfuscated").await.expect("write");
    send.finish().await.expect("finish");
    let response = tokio::time::timeout(Duration::from_secs(5), recv.read(64))
        .await
        .expect("timeout")
        .expect("read")
        .expect("data");
    assert_eq!(response.as_ref(), b"clear");
    assert!(client_socket.sends() > 0);
    assert!(server_socket.sends() > 0);
    assert!(
        client_socket.max_send() <= 1200,
        "client sent a {} byte datagram",
        client_socket.max_send()
    );
    assert!(
        server_socket.max_send() <= 1200,
        "server sent a {} byte datagram",
        server_socket.max_send()
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn many_streams_never_produce_an_oversized_datagram() {
    let server_udp = UdpSocket::bind("127.0.0.1:0").await.expect("server bind");
    let server_socket = Arc::new(RecordingSocket::new(server_udp, 0));
    let server = Endpoint::server_with_socket(
        server_socket.clone(),
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("accept");
        for _ in 0..8 {
            let (mut send, mut recv) = connection.accept_bi().await.expect("accept bi");
            let mut total = 0;
            while total < 1000 {
                let Some(chunk) = recv.read(4096).await.expect("read") else {
                    break;
                };
                total += chunk.len();
            }
            assert_eq!(total, 1000);
            send.write_all(b"ok").await.expect("write");
            send.finish().await.expect("finish");
        }
    });

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let client_socket = Arc::new(RecordingSocket::new(client_udp, 0));
    let client = Endpoint::client_with_socket(client_socket.clone())
        .await
        .expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: Some(Arc::new(RecordingCongestionFactory::default())),
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    for _ in 0..8 {
        let (mut send, _recv) = connection.open_bi().await.expect("open bi");
        send.write_all(&vec![7; 1000]).await.expect("write");
        send.finish().await.expect("finish");
    }
    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server completion")
        .expect("server task");
    assert!(
        client_socket.max_send() <= 1200,
        "client sent a {} byte datagram",
        client_socket.max_send()
    );
    assert!(
        server_socket.max_send() <= 1200,
        "server sent a {} byte datagram",
        server_socket.max_send()
    );
}

#[tokio::test]
async fn a_zero_keep_alive_is_rejected_before_any_socket_is_created() {
    let factory = Arc::new(RecordingFactory::default());
    let mut profile = QuicProfile::default_profile();
    profile.keep_alive = Some(Duration::ZERO);
    let error = QuicConnector::new(profile)
        .with_socket_factory(factory.clone())
        .connect_early("127.0.0.1:9".parse().expect("address"), "localhost", None)
        .await
        .expect_err("zero keep-alive is invalid");
    assert!(matches!(error, QuicError::Config(_)));
    assert_eq!(factory.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_factory_is_invoked_once_for_each_connection() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let connection = server.accept().await.expect("accept");
            drop(connection);
        }
    });

    let factory = Arc::new(RecordingFactory::default());
    let connector = connector().with_socket_factory(factory.clone());
    for _ in 0..2 {
        let connection = connector
            .connect(addr, "localhost", None)
            .await
            .expect("connect");
        drop(connection);
    }
    assert_eq!(factory.calls.load(Ordering::Relaxed), 2);
    server_task.await.expect("server task");
}

#[tokio::test]
async fn peer_certificates_are_post_verification() {
    let (tls, cert) = server_tls_with_cert();
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls,
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("accept");
        drop(connection);
    });

    let client = Endpoint::client().await.expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: verified_client_tls(cert),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("verified connect");
    assert!(
        connection
            .peer_certificates()
            .is_some_and(|chain| !chain.is_empty()),
        "the verified chain is exposed"
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn an_untrusted_certificate_never_yields_a_connection() {
    let (tls, _) = server_tls_with_cert();
    let (_, wrong_cert) = server_tls_with_cert();
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls,
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let client = Endpoint::client().await.expect("client endpoint");
    let error = match client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: verified_client_tls(wrong_cert),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
    {
        Ok(_) => panic!("the wrong root must fail"),
        Err(error) => error,
    };
    assert!(
        matches!(error, QuicError::Tls(_)),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn closing_an_endpoint_wakes_a_handshake_wait() {
    let endpoint = Endpoint::client().await.expect("client endpoint");
    let sink = UdpSocket::bind("127.0.0.1:0").await.expect("sink bind");
    let connection = endpoint
        .connect_early(
            sink.local_addr().expect("sink address"),
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("early connection");
    let waiter = connection.clone();
    let wait = tokio::spawn(async move { waiter.wait_established().await });
    let closed_waiter = connection.clone();
    let closed = tokio::spawn(async move { closed_waiter.closed().await });
    endpoint.close();
    let error = tokio::time::timeout(Duration::from_secs(1), wait)
        .await
        .expect("the endpoint close must wake the wait")
        .expect("waiter task");
    assert!(matches!(error, Err(QuicError::Closed(_))));
    tokio::time::timeout(Duration::from_secs(1), closed)
        .await
        .expect("the endpoint close must wake Connection::closed")
        .expect("closed task");
    assert!(connection.is_closed());
}

#[tokio::test]
async fn closing_an_endpoint_wakes_accept() {
    let endpoint = Arc::new(Endpoint::client().await.expect("endpoint"));
    let waiter = endpoint.clone();
    let accept = tokio::spawn(async move { waiter.accept().await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    endpoint.close();
    let error = tokio::time::timeout(Duration::from_secs(1), accept)
        .await
        .expect("the endpoint close must wake accept")
        .expect("accept task");
    assert!(matches!(error, Err(AcceptError::EndpointClosed)));
}

#[tokio::test]
async fn dropping_the_listener_keeps_an_accepted_connection_alive() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("accept");
        drop(server);
        let (mut send, mut recv) = connection.accept_bi().await.expect("accept bi");
        let data = recv.read(1024).await.expect("read").expect("data");
        send.write_all(&data).await.expect("echo");
        send.finish().await.expect("finish");
        tokio::time::sleep(Duration::from_millis(50)).await;
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
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    let (mut send, mut recv) = connection.open_bi().await.expect("open bi");
    send.write_all(b"survives").await.expect("write");
    send.finish().await.expect("finish");
    let response = tokio::time::timeout(Duration::from_secs(5), recv.read(64))
        .await
        .expect("timeout")
        .expect("read")
        .expect("data");
    assert_eq!(response.as_ref(), b"survives");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn a_failed_handshake_is_observed_and_accept_continues() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();

    let bad = Endpoint::client().await.expect("bad client endpoint");
    let bad_task = tokio::spawn(async move {
        let _ = bad
            .connect(
                addr,
                "localhost",
                ClientConfigOwned {
                    tls: client_tls_with_alpn(b"not-h3"),
                    transport: transport(),
                    versions: vec![netune_quic::wire::packet::VERSION_1],
                    congestion: netune_quic::CongestionAlgorithm::NewReno,
                    congestion_factory: None,
                    keep_alive: None,
                    enable_early_data: false,
                    session_cache: None,
                },
            )
            .await;
    });
    let accepted = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("accept must report the failed handshake");
    let error = match accepted {
        Ok(_) => panic!("the handshake failure is not a connection"),
        Err(error) => error,
    };
    assert!(matches!(error, AcceptError::Handshake(_)));
    bad_task.abort();
    let _ = bad_task.await;

    let good = Endpoint::client().await.expect("good client endpoint");
    let connection = good
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport(),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("the listener still accepts");
    let accepted = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("accept after failure")
        .expect("the next handshake succeeds");
    drop(accepted);
    drop(connection);
}

#[tokio::test]
#[ignore = "long-running soak: run explicitly in the scheduled workflow"]
async fn soak_echoes_many_streams_under_keepalive() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("accept");
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let mut total = 0;
            while total < 4096 {
                let Some(chunk) = recv.read(8192).await.expect("read") else {
                    break;
                };
                total += chunk.len();
            }
            send.write_all(&vec![0x5a; 4096]).await.expect("echo");
            send.finish().await.expect("finish");
        }
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
                congestion_factory: None,
                keep_alive: Some(Duration::from_millis(100)),
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    for _ in 0..80 {
        let (mut send, mut recv) = connection.open_bi().await.expect("open bi");
        send.write_all(&vec![0x5a; 4096]).await.expect("write");
        send.finish().await.expect("finish");
        let mut total = 0;
        while total < 4096 {
            let Some(chunk) = tokio::time::timeout(Duration::from_secs(5), recv.read(8192))
                .await
                .expect("soak read timeout")
                .expect("read")
            else {
                break;
            };
            total += chunk.len();
        }
        assert_eq!(total, 4096, "the soak echo was truncated");
    }
    connection.close(0, "soak complete");
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}

fn transport_with_mtu(mtu: u16) -> TransportParameters {
    let mut transport = transport();
    transport.max_udp_payload_size = Some(u64::from(mtu));
    transport
}

async fn wait_for_path_mtu(connection: &netune_quic::owned::Connection, minimum: usize) -> usize {
    for _ in 0..100 {
        let mtu = connection.path_mtu();
        if mtu >= minimum {
            return mtu;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    connection.path_mtu()
}

#[tokio::test]
async fn dplpmtud_validates_a_larger_loopback_path() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport_with_mtu(1500),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(connection);
    });

    let client = Endpoint::client().await.expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport_with_mtu(1500),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    assert_eq!(
        connection.path_mtu(),
        1200,
        "the minimum is the starting point"
    );
    let mtu = wait_for_path_mtu(&connection, 1500).await;
    assert_eq!(
        mtu, 1500,
        "loopback must validate the full configured path MTU"
    );
    drop(connection);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}

#[tokio::test]
async fn dplpmtud_never_exceeds_the_advertised_ceiling() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport_with_mtu(1280),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(connection);
    });

    let client = Endpoint::client().await.expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport_with_mtu(1280),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    let mtu = wait_for_path_mtu(&connection, 1280).await;
    assert_eq!(mtu, 1280);
    assert!(mtu <= 1280);
    drop(connection);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}

struct BlackholeSocket {
    inner: UdpSocket,
    max_datagram: usize,
}

impl QuicUdpSocket for BlackholeSocket {
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        QuicUdpSocket::poll_recv_from(&self.inner, cx, buf)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        if buf.len() > self.max_datagram {
            // Pretend the datagram was sent: the path drops it, so no ACK can
            // validate this size.
            return Poll::Ready(Ok(buf.len()));
        }
        QuicUdpSocket::poll_send_to(&self.inner, cx, buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[tokio::test]
async fn dplpmtud_does_not_validate_a_black_holed_size() {
    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport_with_mtu(1500),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(connection);
    });

    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    let socket = Arc::new(BlackholeSocket {
        inner: udp,
        max_datagram: 1200,
    });
    let client = Endpoint::client_with_socket(socket)
        .await
        .expect("client endpoint");
    let connection = client
        .connect(
            addr,
            "localhost",
            ClientConfigOwned {
                tls: client_tls(),
                transport: transport_with_mtu(1500),
                versions: vec![netune_quic::wire::packet::VERSION_1],
                congestion: netune_quic::CongestionAlgorithm::NewReno,
                congestion_factory: None,
                keep_alive: None,
                enable_early_data: false,
                session_cache: None,
            },
        )
        .await
        .expect("connect");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        connection.path_mtu(),
        1200,
        "a probe that never gets an ACK must not raise the MTU"
    );
    drop(connection);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}

#[tokio::test]
async fn server_addresses_a_client_with_a_zero_length_source_cid() {
    use bytes::Bytes;
    use netune_quic::crypto::{initial_keys, protect_long};
    use netune_quic::wire::packet::{LongPacket, LongType, VERSION_1};

    let server = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: server_tls(),
            transport: transport(),
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await
    .expect("server endpoint");
    let addr = server.local_addr();

    let original_dcid = b"netune-raw".to_vec();
    let keys = initial_keys(&original_dcid, rustls::Side::Client).expect("initial keys");
    let mut payload = vec![0u8; 1200];
    payload[0] = 0x01; // PING makes the packet ACK-eliciting; the rest is PADDING.
    let packet = LongPacket {
        ty: LongType::Initial,
        version: VERSION_1,
        destination_connection_id: original_dcid,
        source_connection_id: Vec::new(),
        token: Vec::new(),
        packet_number: 0,
        packet_number_len: 4,
        payload: Bytes::from(payload),
    };
    let protected = protect_long(&packet, &keys.local).expect("protect Initial");

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("raw client socket");
    client
        .send_to(&protected, addr)
        .await
        .expect("send Initial");
    let mut response = [0u8; 1500];
    let (received, _) =
        tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
            .await
            .expect("server response timeout")
            .expect("receive server response");
    assert!(response[0] & 0x80 != 0, "expected a long-header response");

    let mut cursor = &response[5..received];
    let dcid_len = usize::from(cursor[0]);
    let dcid = cursor[1..1 + dcid_len].to_vec();
    cursor = &cursor[1 + dcid_len..];
    let scid_len = usize::from(cursor[0]);
    let scid = cursor[1..1 + scid_len].to_vec();

    assert!(
        dcid.is_empty(),
        "server must address the client's zero-length SCID, got {dcid:?}"
    );
    assert!(
        !scid.is_empty(),
        "server must choose an independent, non-zero source CID"
    );
}
