// SPDX-License-Identifier: MIT

//! UDP socket stack and pre-connect configuration for QUIC (RFC 9000).
//!
//! Enforces `[INV-SOCKET-01]`: socket options (SO_MARK, IP_TOS, interface
//! binding) must be applied to the underlying UDP socket before any QUIC packet
//! or flight is transmitted. `[INV-EGRESS-01]` is enforced one layer up by
//! [`crate::QuicConnector`], which refuses a non-public target before it calls
//! into this module to create a socket.
//!
//! Also provides the extension seam for custom socket wrappers (such as packet
//! obfuscation, fragmentation, or port hopping).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// An abstract asynchronous UDP socket used by the owned QUIC endpoint.
///
/// This is the extension seam for datagram transforms such as Hysteria 2's
/// Salamander/Gecko obfuscation and port hopping. The endpoint owns the trait
/// object, so a wrapper can rewrite the bytes and the local socket underneath
/// without the QUIC state machine knowing.
///
/// Implementations must be cheap to poll and must not block. `poll_recv_from`
/// fills `buf` with one datagram and returns its length and peer address; a
/// datagram larger than `buf` must be dropped, not truncated. `poll_send_to`
/// must send the whole datagram or return an error: a short UDP write is never
/// a valid QUIC packet. A port-hopping wrapper must report its logical peer
/// address, not each physical hop, or QUIC will treat every hop as path
/// migration.
pub trait QuicUdpSocket: Send + Sync + 'static {
    /// Poll for one datagram from any peer.
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;

    /// Poll until one datagram has been sent to `target`.
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;

    /// The local address the socket is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Creates one [`QuicUdpSocket`] for a new connection.
///
/// The factory is called only after egress confinement has accepted `target`
/// ([`INV-EGRESS-01`](crate::QuicConnector::with_confinement)), and before the
/// first Initial packet. It receives the same [`QuicSocketConfig`] the default
/// socket path would apply, so a custom stack can honour every pre-connect
/// option or reject it. The returned socket is owned by exactly one endpoint
/// for the lifetime of exactly one connection; a factory that returns the same
/// socket to concurrent calls would make datagram demultiplexing ambiguous.
/// `create` runs on the connector's async task and must not block.
pub trait QuicUdpSocketFactory: Send + Sync + 'static {
    /// Create the socket stack for one new connection to `target`.
    fn create(
        &self,
        target: SocketAddr,
        config: &QuicSocketConfig,
    ) -> io::Result<Arc<dyn QuicUdpSocket>>;
}

/// The default factory: a `tokio` UDP socket configured from
/// [`QuicSocketConfig`].
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioUdpSocketFactory;

impl QuicUdpSocketFactory for TokioUdpSocketFactory {
    fn create(
        &self,
        target: SocketAddr,
        config: &QuicSocketConfig,
    ) -> io::Result<Arc<dyn QuicUdpSocket>> {
        Ok(Arc::new(config.create_tokio_socket(target)?))
    }
}

impl QuicUdpSocket for UdpSocket {
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut read = tokio::io::ReadBuf::new(buf);
        match UdpSocket::poll_recv_from(self, cx, &mut read) {
            Poll::Ready(Ok(address)) => Poll::Ready(Ok((read.filled().len(), address))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send_to(self, cx, buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }
}

/// Waits for one datagram on an abstract socket.
pub(crate) async fn recv_from(
    socket: &dyn QuicUdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    std::future::poll_fn(|cx| socket.poll_recv_from(cx, buf)).await
}

/// Sends one datagram on an abstract socket.
pub(crate) async fn send_to(
    socket: &dyn QuicUdpSocket,
    buf: &[u8],
    target: SocketAddr,
) -> io::Result<usize> {
    let sent = std::future::poll_fn(|cx| socket.poll_send_to(cx, buf, target)).await?;
    if sent != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short UDP write: sent {sent} of {} bytes", buf.len()),
        ));
    }
    Ok(sent)
}

/// L3/L4 pre-connect socket parameters for QUIC datagram endpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicSocketConfig {
    /// Socket mark (`SO_MARK`), applied before any packet leaves.
    /// Used for loop-evasion in proxy environments ([INV-MARK-01]).
    pub mark: Option<u32>,
    /// Bind socket to a specific network interface (`SO_BINDTODEVICE`).
    pub bind_device: Option<String>,
    /// Bind socket to a specific local source IP/port before connect.
    pub bind_address: Option<SocketAddr>,
    /// Type of Service / Traffic Class byte (`IP_TOS` / `IPV6_TCLASS`).
    pub tos: Option<u8>,
    /// Receive buffer size (`SO_RCVBUF`).
    pub recv_buffer_size: Option<usize>,
    /// Send buffer size (`SO_SNDBUF`).
    pub send_buffer_size: Option<usize>,
}

impl QuicSocketConfig {
    /// Creates a non-blocking `tokio::net::UdpSocket` with all configured options applied.
    pub fn create_tokio_socket(
        &self,
        destination: SocketAddr,
    ) -> io::Result<tokio::net::UdpSocket> {
        let domain = if destination.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;

        if let Some(size) = self.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = self.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }

        // Apply SO_MARK on Linux before any packet leaves the host.
        if let Some(mark) = self.mark {
            #[cfg(target_os = "linux")]
            socket.set_mark(mark)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = mark;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SO_MARK is only supported on Linux",
                ));
            }
        }

        // Apply TOS / DSCP.
        if let Some(tos) = self.tos {
            if destination.is_ipv6() {
                socket.set_tclass_v6(tos as u32)?;
            } else {
                socket.set_tos_v4(tos as u32)?;
            }
        }

        // Bind device if specified.
        if let Some(device) = &self.bind_device {
            #[cfg(target_os = "linux")]
            socket.bind_device(Some(device.as_bytes()))?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = device;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SO_BINDTODEVICE is only supported on Linux",
                ));
            }
        }

        // Bind source address if configured, else bind wildcard with matching family.
        if let Some(bind_addr) = self.bind_address {
            socket.bind(&bind_addr.into())?;
        } else {
            let any: SocketAddr = if destination.is_ipv6() {
                (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
            } else {
                (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
            };
            socket.bind(&any.into())?;
        }

        let std_socket: std::net::UdpSocket = socket.into();
        tokio::net::UdpSocket::from_std(std_socket)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct CountingSocket {
        inner: UdpSocket,
        sends: AtomicUsize,
    }

    impl QuicUdpSocket for CountingSocket {
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
            let result = QuicUdpSocket::poll_send_to(&self.inner, cx, buf, target);
            if matches!(result, Poll::Ready(Ok(_))) {
                self.sends.fetch_add(1, Ordering::Relaxed);
            }
            result
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
    }

    #[tokio::test]
    async fn an_abstract_socket_carries_a_datagram_and_counts_the_send() {
        // The seam is only useful if the endpoint actually polls the wrapper. This proves the
        // wrapper's send and receive paths move bytes, and that the wrapper sees the call.
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("binds");
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("binds");
        let target = receiver.local_addr().expect("address");
        let sender = Arc::new(CountingSocket {
            inner: sender,
            sends: AtomicUsize::new(0),
        });

        let sent = send_to(sender.as_ref(), b"quic", target)
            .await
            .expect("sends");
        assert_eq!(sent, 4);
        assert_eq!(sender.sends.load(Ordering::Relaxed), 1);

        let mut buffer = [0u8; 16];
        let (received, peer) = recv_from(&receiver, &mut buffer).await.expect("receives");
        assert_eq!(&buffer[..received], b"quic");
        assert_eq!(peer, sender.local_addr().expect("local address"));
    }
}
