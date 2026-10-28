//! L3/L4 socket configuration and transport parameter tuning (ADR-0006).
//!
//! Standard OS defaults expose passive operating system fingerprints (p0f):
//! default TTLs (Linux=64, Windows=128), initial window sizes, and MSS limits.
//!
//! [`SocketConfig`] allows fine-tuning these parameters at the transport boundary
//! so the client can align its TCP stack characteristics with the claimed user agent.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;

/// L3/L4 transport tuning parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketConfig {
    /// Disable Nagle's algorithm (`TCP_NODELAY`). Default is `true`.
    pub nodelay: bool,
    /// Time-to-Live (`IP_TTL`) for outbound packets.
    ///
    /// Useful for passive OS fingerprint alignment:
    /// - Linux/Android: ~64
    /// - Windows: ~128
    /// - macOS/iOS: ~64
    pub ttl: Option<u32>,
    /// Socket receive buffer size (`SO_RCVBUF`).
    pub recv_buffer_size: Option<usize>,
    /// Socket send buffer size (`SO_SNDBUF`).
    pub send_buffer_size: Option<usize>,
    /// Maximum Segment Size (`TCP_MAXSEG`), where supported.
    pub mss: Option<u32>,
    /// Socket mark (`SO_MARK`), applied **before** `connect(2)`.
    ///
    /// A mark set after the handshake cannot affect the SYN, so this one option
    /// runs on the pre-connect path: the socket is created, marked, and then
    /// connected. Linux only; requires `CAP_NET_ADMIN` or `CAP_NET_RAW`.
    pub mark: Option<u32>,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            nodelay: true,
            ttl: None,
            recv_buffer_size: None,
            send_buffer_size: None,
            mss: None,
            mark: None,
        }
    }
}

impl SocketConfig {
    /// Standard stock configuration with Nagle disabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emulate a Windows TCP stack baseline (TTL = 128).
    pub fn windows_baseline() -> Self {
        Self {
            nodelay: true,
            ttl: Some(128),
            recv_buffer_size: Some(65_536),
            send_buffer_size: Some(65_536),
            mss: None,
            mark: None,
        }
    }

    /// Emulate a Linux/macOS TCP stack baseline (TTL = 64).
    pub fn unix_baseline() -> Self {
        Self {
            nodelay: true,
            ttl: Some(64),
            recv_buffer_size: Some(131_072),
            send_buffer_size: Some(131_072),
            mss: None,
            mark: None,
        }
    }

    /// Set `TCP_NODELAY`.
    pub fn with_nodelay(mut self, nodelay: bool) -> Self {
        self.nodelay = nodelay;
        self
    }

    /// Set IP Time-to-Live (`IP_TTL`).
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set socket receive buffer size (`SO_RCVBUF`).
    pub fn with_recv_buffer_size(mut self, bytes: usize) -> Self {
        self.recv_buffer_size = Some(bytes);
        self
    }

    /// Set socket send buffer size (`SO_SNDBUF`).
    pub fn with_send_buffer_size(mut self, bytes: usize) -> Self {
        self.send_buffer_size = Some(bytes);
        self
    }

    /// Set Maximum Segment Size (`TCP_MAXSEG`).
    pub fn with_mss(mut self, mss: u32) -> Self {
        self.mss = Some(mss);
        self
    }

    /// Set the socket mark (`SO_MARK`) applied before `connect(2)`.
    ///
    /// Linux only; setting a mark requires `CAP_NET_ADMIN` or `CAP_NET_RAW`.
    pub fn with_mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Apply these configuration knobs to a connected [`TcpStream`].
    pub fn apply(&self, stream: &TcpStream) -> Result<(), io::Error> {
        let _ = stream.set_nodelay(self.nodelay);

        if let Some(ttl) = self.ttl {
            let _ = stream.set_ttl(ttl);
        }

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = stream.as_raw_fd();

            if let Some(rcv) = self.recv_buffer_size {
                let size = rcv as libc::c_int;
                // SAFETY: valid socket fd and standard SOL_SOCKET option.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUF,
                        std::ptr::from_ref(&size).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }

            if let Some(snd) = self.send_buffer_size {
                let size = snd as libc::c_int;
                // SAFETY: valid socket fd and standard SOL_SOCKET option.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        std::ptr::from_ref(&size).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }

            #[cfg(target_os = "linux")]
            if let Some(mss) = self.mss {
                let val = mss as libc::c_int;
                // SAFETY: valid socket fd and IPPROTO_TCP option.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_MAXSEG,
                        std::ptr::from_ref(&val).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        }

        Ok(())
    }
}

/// Connects `address`, applying pre-connect options when any are configured.
///
/// Without pre-connect options this is exactly [`TcpStream::connect`]. With a
/// mark, the socket must be created by hand: `SO_MARK` is consulted when the
/// route for the SYN is chosen, so applying it after the handshake would be
/// too late.
pub(crate) async fn connect(address: SocketAddr, config: &SocketConfig) -> io::Result<TcpStream> {
    if config.mark.is_none() {
        return TcpStream::connect(address).await;
    }

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    apply_pre_connect_options(&socket, config)?;

    match socket.connect(&address.into()) {
        // Connected immediately, or the connection is in progress.
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(error) => return Err(error),
    }

    let stream = TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    // `writable` also fires for a failed connection; the pending error is only
    // visible through `take_error`.
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}

/// The payload a UDP socket carries when the kernel will not report its limit.
///
/// 65 507 = 65 535 − 20 (IPv4 header) − 8 (UDP header). It is the IPv4 maximum,
/// used only as a ceiling when the socket refuses `SO_SNDBUF`.
pub(crate) const UDP_MAX_PAYLOAD: usize = 65_507;

/// Creates an unconnected UDP socket with the pre-connect options applied.
///
/// The datagram twin of [`connect`]: the callers differ (a UDP socket is
/// connected by a synchronous syscall, a TCP one has a handshake to await) but
/// the option ordering is the same, and duplicating it would let one path drift.
pub(crate) fn udp_socket(
    address: SocketAddr,
    config: &SocketConfig,
) -> io::Result<tokio::net::UdpSocket> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    apply_pre_connect_options(&socket, config)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// The largest payload a connected UDP socket will carry in one datagram.
///
/// Derived from the socket's send buffer: the kernel refuses a datagram larger
/// than `SO_SNDBUF`, so a caller sizing a buffer from this cannot build a
/// payload that is guaranteed to fail. Never exceeds [`UDP_MAX_PAYLOAD`], which
/// is the IP-imposed ceiling no buffer setting can raise.
pub(crate) fn udp_max_datagram_size(socket: &tokio::net::UdpSocket) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let mut size: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: valid UDP socket fd, and `size`/`length` describe the buffer
        // `setsockopt`/`getsockopt` write into.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_mut(&mut size).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // Linux reports double the usable value for bookkeeping overhead.
        let usable = (size.max(0) as usize) / 2;
        if usable == 0 {
            return Ok(UDP_MAX_PAYLOAD);
        }
        Ok(usable.min(UDP_MAX_PAYLOAD))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        Ok(UDP_MAX_PAYLOAD)
    }
}

#[allow(unused_variables)]
fn apply_pre_connect_options(socket: &Socket, config: &SocketConfig) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(mark) = config.mark {
        socket.set_mark(mark)?;
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if config.mark.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_MARK is only supported on Linux",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socket_config_applies_successfully() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let connect_fut = TcpStream::connect(addr);
        let accept_fut = listener.accept();

        let (client, server) = tokio::join!(connect_fut, accept_fut);
        let client = client.expect("connect");
        let (server, _) = server.expect("accept");

        let config = SocketConfig::windows_baseline()
            .with_ttl(128)
            .with_nodelay(true);

        assert!(config.apply(&client).is_ok());
        assert_eq!(client.ttl().ok(), Some(128));

        assert!(config.apply(&server).is_ok());
    }
}
