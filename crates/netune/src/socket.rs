//! L3/L4 socket configuration and transport parameter tuning (ADR-0006).
//!
//! Standard OS defaults expose passive operating system fingerprints (p0f):
//! default TTLs (Linux=64, Windows=128), initial window sizes, and MSS limits.
//!
//! [`SocketConfig`] allows fine-tuning these parameters at the transport boundary
//! so the client can align its TCP stack characteristics with the claimed user agent.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

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
    /// Bind the socket to an interface (`SO_BINDTODEVICE`), before `connect(2)`.
    ///
    /// # Why a caller needs this
    ///
    /// A multi-homed box has one routing table and often more than one uplink. A proxy that
    /// dials its upstream over "whatever the default route says" cannot express "this group
    /// always leaves through `wg0`", and a policy-routing rule keyed on an interface cannot
    /// see the dial at all. Binding the device is the direct way to say it.
    ///
    /// Linux only, and needs `CAP_NET_RAW`. An interface name that does not exist is
    /// reported (`ENODEV`) rather than ignored: a silently unbound socket would leave through
    /// the default route while the configuration claims otherwise.
    pub bind_device: Option<String>,
    /// Bind the socket to a local source address, before `connect(2)`.
    ///
    /// The source address is what the peer sees and what a reply is routed back to, so it is
    /// part of the identity of a dial rather than an optimisation. Applies to TCP and
    /// datagram sockets alike.
    ///
    /// A source whose family differs from the destination's is refused before the socket is
    /// created, because the kernel would reject the `bind` with a less specific error.
    pub bind_address: Option<SocketAddr>,
    /// Enable TCP keepalive probes (`SO_KEEPALIVE`) with this idle time.
    ///
    /// # Why this is not the default
    ///
    /// A pooled HTTP connection has its own idle bound (ADR-0005) and a dead socket is
    /// recovered by a retry. A long-lived tunnel has neither: without keepalive, a middlebox
    /// that silently drops the flow leaves both ends believing the session is alive until one
    /// of them writes. This is the knob that turns "it hung after ten minutes" into a closed
    /// socket with an error.
    ///
    /// The value is the idle time before the first probe; probe count and interval use the
    /// platform defaults.
    pub keepalive: Option<Duration>,
    /// Set the IP type-of-service / DSCP byte (`IP_TOS`, `IPV6_TCLASS`), before `connect(2)`.
    ///
    /// The value is the raw 8-bit field, so a caller that wants DSCP 46 (EF) passes
    /// `46 << 2`. Applied before the SYN because the first packet carries it, and a
    /// classifier that routes on DSCP sees only that first packet.
    pub tos: Option<u8>,
    /// Enable TCP Fast Open (`TCP_FASTOPEN_CONNECT`) so the first write can carry data.
    ///
    /// Linux only. Reported as `Unsupported` elsewhere rather than ignored, so a caller that
    /// asked for a one-RTT handshake does not silently get a two-RTT one.
    pub tcp_fast_open: bool,
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
            bind_device: None,
            bind_address: None,
            keepalive: None,
            tos: None,
            tcp_fast_open: false,
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
            ..Self::default()
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
            ..Self::default()
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

    /// Bind the socket to an interface (`SO_BINDTODEVICE`) before `connect(2)`.
    ///
    /// Linux only; needs `CAP_NET_RAW`.
    pub fn with_bind_device(mut self, device: impl Into<String>) -> Self {
        self.bind_device = Some(device.into());
        self
    }

    /// Bind the socket to a local source address before `connect(2)`.
    pub fn with_bind_address(mut self, address: SocketAddr) -> Self {
        self.bind_address = Some(address);
        self
    }

    /// Enable TCP keepalive with `idle` as the time before the first probe.
    pub fn with_keepalive(mut self, idle: Duration) -> Self {
        self.keepalive = Some(idle);
        self
    }

    /// Set the IP type-of-service / DSCP byte.
    ///
    /// The raw 8-bit field: DSCP 46 (EF) is `46 << 2`.
    pub fn with_tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Enable TCP Fast Open so the first write can carry data.
    ///
    /// Linux only.
    pub fn with_tcp_fast_open(mut self, enabled: bool) -> Self {
        self.tcp_fast_open = enabled;
        self
    }

    /// Whether any configured option must be applied **before** the handshake.
    ///
    /// # Why this is one predicate
    ///
    /// [`connect`] has a fast path (`TcpStream::connect`) for the common case and a manual
    /// socket for the pre-connect case. That fast path used to test `mark.is_none()` only, so
    /// every other pre-connect option was **silently dropped**: a caller that set
    /// `bind_device` or `bind_address` got an unbound socket that left through the default
    /// route while its configuration said otherwise. Adding an option here is what keeps the
    /// two paths from drifting again.
    #[must_use]
    pub(crate) fn needs_manual_socket(&self) -> bool {
        self.mark.is_some()
            || self.bind_device.is_some()
            || self.bind_address.is_some()
            || self.tos.is_some()
    }

    /// Apply these configuration knobs to a connected [`TcpStream`].
    ///
    /// # Errors
    ///
    /// Returns the first `setsockopt` or `set_*` failure. Every knob this method applies was
    /// asked for by the caller, so a silent failure would leave the session behaving
    /// differently from how it was configured with nothing to point at. A knob that cannot
    /// work on this platform is reported with `ErrorKind::Unsupported` rather than ignored.
    pub fn apply(&self, stream: &TcpStream) -> Result<(), io::Error> {
        // `TCP_NODELAY` is the default-on knob: report a failure rather than let a caller
        // believe Nagle was disabled when it was not.
        stream.set_nodelay(self.nodelay)?;

        if let Some(ttl) = self.ttl {
            stream.set_ttl(ttl)?;
        }

        if let Some(idle) = self.keepalive {
            apply_keepalive(stream, idle)?;
        }

        if self.tcp_fast_open {
            apply_tcp_fast_open(stream)?;
        }

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = stream.as_raw_fd();

            if let Some(rcv) = self.recv_buffer_size {
                let size = rcv as libc::c_int;
                // SAFETY: valid socket fd and standard SOL_SOCKET option.
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUF,
                        std::ptr::from_ref(&size).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            if let Some(snd) = self.send_buffer_size {
                let size = snd as libc::c_int;
                // SAFETY: valid socket fd and standard SOL_SOCKET option.
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        std::ptr::from_ref(&size).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            #[cfg(target_os = "linux")]
            if let Some(mss) = self.mss {
                let val = mss as libc::c_int;
                // SAFETY: valid socket fd and IPPROTO_TCP option.
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_MAXSEG,
                        std::ptr::from_ref(&val).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        Ok(())
    }
}

/// Enables `SO_KEEPALIVE` and sets the idle time before the first probe.
///
/// `TCP_KEEPIDLE` is Linux's name for the same value macOS calls `TCP_KEEPALIVE`; the two are
/// handled separately so a caller gets the setting it asked for on either.
fn apply_keepalive(stream: &TcpStream, idle: Duration) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let on: libc::c_int = 1;
        // SAFETY: `fd` is a live socket; `on` is a live `c_int` passed with its own length.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                std::ptr::from_ref(&on).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }

        // A sub-second idle time would be rounded to zero, which the kernel reads as "no
        // change"; one second is the floor the syscall accepts.
        let seconds = idle.as_secs().max(1) as libc::c_int;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let option = libc::TCP_KEEPIDLE;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let option = libc::TCP_KEEPALIVE;
        // SAFETY: as above, with an `IPPROTO_TCP` option of the same `c_int` width.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                option,
                std::ptr::from_ref(&seconds).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (stream, idle);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP keepalive is only supported on Unix",
        ))
    }
}

/// Enables `TCP_FASTOPEN_CONNECT`.
///
/// The option is set after the handshake has begun but before any data is written, which is
/// the point: it lets the first `write` carry a payload in the SYN instead of waiting a round
/// trip. A kernel without it returns `ENOPROTOOPT`, which is reported rather than swallowed.
fn apply_tcp_fast_open(stream: &TcpStream) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let on: libc::c_int = 1;
        // SAFETY: `fd` is a live socket; `on` is a live `c_int` passed with its own length.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                std::ptr::from_ref(&on).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = stream;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP_FASTOPEN_CONNECT is only supported on Linux",
        ))
    }
}

/// Connects `address`, applying pre-connect options when any are configured.
///
/// Without pre-connect options this is exactly [`TcpStream::connect`]. With a
/// mark, the socket must be created by hand: `SO_MARK` is consulted when the
/// route for the SYN is chosen, so applying it after the handshake would be
/// too late.
pub(crate) async fn connect(address: SocketAddr, config: &SocketConfig) -> io::Result<TcpStream> {
    if !config.needs_manual_socket() {
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

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(device) = &config.bind_device {
        // `socket2` takes the name as bytes and appends the NUL itself.
        socket.bind_device(Some(device.as_bytes()))?;
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if config.bind_device.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_BINDTODEVICE is only supported on Linux",
        ));
    }

    if let Some(address) = config.bind_address {
        // The family is checked here rather than left to `bind`: the kernel's `EINVAL` for a
        // mismatched family does not say which of the two addresses was wrong.
        if address.is_ipv4() != socket_domain_is_v4(socket)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bind address {address} has a different address family from the socket"),
            ));
        }
        socket.bind(&address.into())?;
    }

    if let Some(tos) = config.tos {
        apply_tos(socket, tos)?;
    }

    Ok(())
}

/// Whether the socket was created with the IPv4 domain.
///
/// `socket2` does not expose the domain back, so it is recovered from `getsockname`'s family.
fn socket_domain_is_v4(socket: &Socket) -> io::Result<bool> {
    // A socket that is not yet bound still reports its family through `local_addr`, which
    // returns the wildcard address of the socket's own family.
    Ok(socket
        .local_addr()?
        .as_socket()
        .is_some_and(|a| a.is_ipv4()))
}

/// Applies `IP_TOS` (`IPV6_TCLASS` for a v6 socket).
///
/// The two families use different levels and options for the same field, and `socket2` has no
/// portable setter, so this is a direct `setsockopt`.
fn apply_tos(socket: &Socket, tos: u8) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let v4 = socket_domain_is_v4(socket)?;
        let (level, option) = if v4 {
            (libc::IPPROTO_IP, libc::IP_TOS)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
        };
        let value = libc::c_int::from(tos);
        // SAFETY: `fd` is a live socket owned by the caller, and `value` is a live `c_int`
        // whose address is passed with its own length.
        let result = unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                std::ptr::from_ref(&value).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (socket, tos);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IP_TOS is only supported on Unix",
        ))
    }
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

    #[test]
    fn every_pre_connect_option_forces_the_manual_socket_path() {
        // The falsifier for a silently-dropped option. `connect` has a fast path and a manual
        // one, and the fast path used to test `mark.is_none()` only: a caller that set
        // `bind_device` or `bind_address` got a socket that never had it applied, while the
        // configuration said it did. Each option below must be enough on its own.
        assert!(!SocketConfig::default().needs_manual_socket());
        assert!(SocketConfig::default().with_mark(1).needs_manual_socket());
        assert!(
            SocketConfig::default()
                .with_bind_device("lo")
                .needs_manual_socket()
        );
        assert!(
            SocketConfig::default()
                .with_bind_address("127.0.0.1:0".parse().expect("addr"))
                .needs_manual_socket()
        );
        assert!(SocketConfig::default().with_tos(0xb8).needs_manual_socket());
    }

    #[tokio::test]
    async fn a_bound_source_address_is_what_the_peer_sees() {
        // `bind_address` is part of the identity of a dial: the peer must see the source the
        // caller asked for, not the route's choice. Proving it needs the option to survive
        // the manual-socket path, which is exactly what the predicate above guards.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let config =
            SocketConfig::default().with_bind_address("127.0.0.2:0".parse().expect("source"));

        let (client, server) = tokio::join!(connect(address, &config), listener.accept());
        let client = client.expect("connect");
        let (server, peer) = server.expect("accept");

        assert_eq!(
            peer.ip(),
            "127.0.0.2".parse::<std::net::IpAddr>().expect("addr"),
            "the peer must see the bound source address"
        );
        // The socket is usable: a bound source that broke the connection would make the
        // address assertion above vacuous.
        drop(client);
        drop(server);
    }

    #[tokio::test]
    async fn a_bind_address_of_the_wrong_family_is_refused_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let config = SocketConfig::default().with_bind_address("[::1]:0".parse().expect("source"));
        let error = connect(address, &config)
            .await
            .expect_err("a v6 source cannot bind a v4 destination");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("address family"), "{error}");
    }

    #[tokio::test]
    async fn keepalive_is_applied_to_the_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let config = SocketConfig::default().with_keepalive(std::time::Duration::from_secs(30));

        let (client, server) = tokio::join!(TcpStream::connect(address), listener.accept());
        let client = client.expect("connect");
        let (_server, _) = server.expect("accept");
        config.apply(&client).expect("keepalive applies");

        // `SO_KEEPALIVE` is readable back through `socket2`; asking the kernel rather than
        // trusting the call is what makes this an assertion instead of a smoke test.
        let socket = socket2::SockRef::from(&client);
        assert!(socket.keepalive().expect("reads"));
    }

    #[test]
    fn a_missing_interface_is_reported_rather_than_ignored() {
        // A silently unbound socket would leave through the default route while the
        // configuration claims a device, so `ENODEV` has to surface.
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("socket");
        let config = SocketConfig::default().with_bind_device("daer-no-such-device");
        let error = apply_pre_connect_options(&socket, &config).expect_err("must fail");
        assert_eq!(error.raw_os_error(), Some(libc::ENODEV), "{error}");
    }
}
