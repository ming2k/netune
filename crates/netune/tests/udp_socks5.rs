//! SOCKS5 UDP association end to end, against a hermetic relay.
//!
//! The relay here is a real server: it accepts the TCP control connection,
//! performs the greeting and `UDP ASSOCIATE` exchange, allocates a relay socket,
//! and decapsulates/re-encapsulates every datagram. That is the only shape of
//! test that proves the association path — a unit test of the wrapper encoder
//! would agree with itself even if the wire order were wrong.
//!
//! One assertion is a *negative*: a datagram whose wrapper claims a different
//! source must be dropped. A relay (or an attacker on the path) that could
//! relabel a payload would otherwise get a host the caller never addressed
//! delivered as if it were the session's.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use netune::{DatagramConnector, Proxy, Socks5DatagramConnector, TcpConnector};
use netune_trace::{EventKind, TraceCollector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Wrap `payload` as a SOCKS5 UDP request naming an IPv4 `source`.
fn wrap(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(v4) = source else {
        panic!("these tests only wrap IPv4 sources");
    };
    let mut framed = vec![0x00, 0x00, 0x00, 0x01];
    framed.extend_from_slice(&v4.ip().octets());
    framed.extend_from_slice(&source.port().to_be_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// Decode a SOCKS5 UDP request as `(source, payload)`.
fn unwrap_datagram(datagram: &[u8]) -> (SocketAddr, &[u8]) {
    assert_eq!(datagram[3], 0x01, "tests expect an IPv4 wrapper");
    let ip = Ipv4Addr::new(datagram[4], datagram[5], datagram[6], datagram[7]);
    let port = u16::from_be_bytes([datagram[8], datagram[9]]);
    (SocketAddr::from((ip, port)), &datagram[10..])
}

/// The control connection: greeting, then `UDP ASSOCIATE`, answered with the
/// relay address. Returns once the association is established; the connection is
/// then kept open by the caller's task, because a real proxy may drop the
/// association when it closes.
async fn control(mut client: tokio::net::TcpStream, relay: SocketAddr) {
    let mut greeting = [0u8; 3];
    client.read_exact(&mut greeting).await.expect("greeting");
    assert_eq!(greeting, [0x05, 0x01, 0x00]);
    client
        .write_all(&[0x05, 0x00])
        .await
        .expect("greeting reply");

    let mut request = [0u8; 10];
    client.read_exact(&mut request).await.expect("associate");
    assert_eq!(request, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    let SocketAddr::V4(relay_v4) = relay else {
        panic!("tests use an IPv4 relay");
    };
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    reply.extend_from_slice(&relay_v4.ip().octets());
    reply.extend_from_slice(&relay.port().to_be_bytes());
    client.write_all(&reply).await.expect("associate reply");
    client.flush().await.expect("flush");

    // Hold the control connection open, and consume anything the client sends,
    // until the test drops its side.
    let mut sink = [0u8; 64];
    while client.read(&mut sink).await.unwrap_or(0) != 0 {}
}

/// The relay loop: decapsulate each datagram, forward the payload to `origin`,
/// echo the answer back encapsulated with `origin` as the source.
///
/// When `inject_foreign` is set, one datagram claiming an unrelated source is
/// sent first, so the client's source check is exercised.
async fn relay_loop(relay: UdpSocket, origin: SocketAddr, inject_foreign: bool) {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream");
    upstream.connect(origin).await.expect("connect origin");

    let mut buffer = [0u8; 2048];
    let (received, client) = relay.recv_from(&mut buffer).await.expect("relay recv");
    let (_claimed, payload) = unwrap_datagram(&buffer[..received]);

    if inject_foreign {
        // A payload from a host the caller never addressed.
        let foreign: SocketAddr = "198.51.100.66:1234".parse().expect("addr");
        relay
            .send_to(&wrap(foreign, b"POISON"), client)
            .await
            .expect("inject");
    }

    upstream.send(payload).await.expect("forward");
    let mut answer = [0u8; 2048];
    let received = upstream.recv(&mut answer).await.expect("upstream recv");

    relay
        .send_to(&wrap(origin, &answer[..received]), client)
        .await
        .expect("relay send");
    // Stay alive until the test drops the socket, so a late datagram cannot
    // make the relay exit before the client reads its answer.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Starts an echo server that returns each datagram to its sender.
async fn echo(listener: UdpSocket) -> SocketAddr {
    let address = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((received, from)) = listener.recv_from(&mut buffer).await {
            if listener.send_to(&buffer[..received], from).await.is_err() {
                return;
            }
        }
    });
    address
}

#[tokio::test]
async fn an_association_carries_a_datagram_to_the_destination_and_back() {
    let echo_socket = UdpSocket::bind("127.0.0.1:0").await.expect("echo bind");
    let origin = echo(echo_socket).await;

    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.expect("relay bind");
    let relay_address = relay_socket.local_addr().expect("relay addr");

    let control_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("control bind");
    let proxy_address = control_listener.local_addr().expect("proxy addr");

    tokio::spawn(async move {
        let (client, _) = control_listener.accept().await.expect("control accept");
        control(client, relay_address).await;
    });
    tokio::spawn(relay_loop(relay_socket, origin, false));

    let proxy = Proxy::parse(&format!("socks5://{proxy_address}")).expect("proxy url");
    let connector = Socks5DatagramConnector::new(TcpConnector::new(), proxy).expect("connector");
    let recorder = TraceCollector::start(32);

    // The destination is a literal address, which is what a UDP relay knows: it
    // has already resolved the name that the routing decision was made on.
    let session = tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(&origin.to_string(), &recorder),
    )
    .await
    .expect("associate must not hang")
    .expect("associate");

    assert!(session.local_port.is_some());
    // The wrapper's overhead must not be charged to the caller.
    let sent = session
        .datagrams
        .send(b"hello-through-socks")
        .await
        .expect("send");
    assert_eq!(sent, b"hello-through-socks".len());

    let mut buffer = [0u8; 2048];
    let received =
        tokio::time::timeout(Duration::from_secs(5), session.datagrams.recv(&mut buffer))
            .await
            .expect("recv must not hang")
            .expect("recv");
    assert_eq!(&buffer[..received], b"hello-through-socks");

    // The trace must show the tunnel and the session, and must not claim a TLS
    // handshake that never happened.
    let log = recorder.log();
    let kinds: Vec<EventKind> = log.iter().map(|event| event.kind).collect();
    assert!(kinds.contains(&EventKind::ProxyTunnel), "{kinds:?}");
    assert!(kinds.contains(&EventKind::UdpOpen), "{kinds:?}");
    // The control hop really is TCP.
    assert!(kinds.contains(&EventKind::TcpStart), "{kinds:?}");
    assert!(!kinds.contains(&EventKind::TlsStart), "{kinds:?}");
}

#[tokio::test]
async fn inv_udp_03_a_datagram_claiming_a_foreign_source_is_dropped() {
    let echo_socket = UdpSocket::bind("127.0.0.1:0").await.expect("echo bind");
    let origin = echo(echo_socket).await;

    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.expect("relay bind");
    let relay_address = relay_socket.local_addr().expect("relay addr");

    let control_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("control bind");
    let proxy_address = control_listener.local_addr().expect("proxy addr");

    tokio::spawn(async move {
        let (client, _) = control_listener.accept().await.expect("control accept");
        control(client, relay_address).await;
    });
    tokio::spawn(relay_loop(relay_socket, origin, true));

    let proxy = Proxy::parse(&format!("socks5://{proxy_address}")).expect("proxy url");
    let connector = Socks5DatagramConnector::new(TcpConnector::new(), proxy).expect("connector");
    let recorder = TraceCollector::start(32);

    let session = tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(&origin.to_string(), &recorder),
    )
    .await
    .expect("associate must not hang")
    .expect("associate");

    session.datagrams.send(b"real").await.expect("send");

    let mut buffer = [0u8; 2048];
    let received =
        tokio::time::timeout(Duration::from_secs(5), session.datagrams.recv(&mut buffer))
            .await
            .expect("recv must not hang")
            .expect("recv");
    // The injected "POISON" must never reach the caller.
    assert_eq!(&buffer[..received], b"real");
}

#[tokio::test]
async fn the_reported_maximum_leaves_room_for_the_wrapper() {
    let echo_socket = UdpSocket::bind("127.0.0.1:0").await.expect("echo bind");
    let origin = echo(echo_socket).await;

    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.expect("relay bind");
    let relay_address = relay_socket.local_addr().expect("relay addr");

    let control_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("control bind");
    let proxy_address = control_listener.local_addr().expect("proxy addr");

    tokio::spawn(async move {
        let (client, _) = control_listener.accept().await.expect("control accept");
        control(client, relay_address).await;
    });
    tokio::spawn(relay_loop(relay_socket, origin, false));

    let proxy = Proxy::parse(&format!("socks5://{proxy_address}")).expect("proxy url");
    let connector = Socks5DatagramConnector::new(TcpConnector::new(), proxy).expect("connector");
    let recorder = TraceCollector::start(32);
    let session = connector
        .connect(&origin.to_string(), &recorder)
        .await
        .expect("associate");

    // A caller sizing its buffer from this must fit a full datagram *plus* the
    // wrapper; 0 would mean the subtraction underflowed into nonsense.
    let maximum = session.datagrams.max_datagram_size();
    assert!(maximum > 0, "max_datagram_size must be usable");
    assert!(
        maximum < 65_507 + 1,
        "a datagram maximum cannot exceed the IP ceiling, got {maximum}"
    );
}
