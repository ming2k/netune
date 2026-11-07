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

pub use quinn::udp::{RecvMeta, Transmit};
pub use quinn::{AsyncUdpSocket, UdpPoller};
use socket2::{Domain, Protocol, Socket, Type};

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
            let _ = socket.set_recv_buffer_size(size);
        }
        if let Some(size) = self.send_buffer_size {
            let _ = socket.set_send_buffer_size(size);
        }

        // Apply SO_MARK on Linux before any packet leaves the host.
        if let Some(mark) = self.mark {
            #[cfg(target_os = "linux")]
            socket.set_mark(mark)?;
            #[cfg(not(target_os = "linux"))]
            let _ = mark;
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
            let _ = device;
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
