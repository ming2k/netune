//! Datagrams: connected UDP sockets and SOCKS5 UDP association.
//!
//! TCP hands back a stream that is identical for every proxy protocol; datagrams
//! do not compose that way. A plain UDP flow, a SOCKS5 association and a QUIC
//! session all carry *datagrams*, but the framing that puts a destination
//! alongside the payload differs per protocol. So the abstraction is split in
//! two, deliberately:
//!
//! * [`DatagramTransport`] — the bytes. `send`/`recv` carry a payload, and the
//!   destination is fixed when the session is opened.
//! * [`DatagramConnector`] — establishing one. It returns an
//!   [`EstablishedDatagrams`] whose session is *connected* to a single peer.
//!
//! The second choice deserves its argument, because a protocol that multiplexes
//! several peers over one socket (SOCKS5 UDP associate, QUIC's connection IDs,
//! WireGuard) could be served by a per-datagram destination instead. It is not,
//! because a per-datagram destination cannot be confinement-checked: the peer is
//! named *after* the socket is open and would change per datagram, so
//! [`EgressConfinement`] would have nothing to check before the first send. The
//! invariant that egress is confined before a socket opens ([ADR-0002]) is worth
//! more than the socket-count saving. A protocol that needs many peers opens one
//! session per peer and owns the demultiplexing above this layer; the SOCKS5
//! association below does exactly that for the one case where the proxy, not
//! netune, decides the peer.
//!
//! Direct datagrams are connected sockets, not `send_to`/`recv_from`: a connected
//! socket keeps the kernel's ICMP error reporting and its reverse-path filter
//! meaningful, and it makes `recv` impossible to confuse with a datagram from an
//! unrelated host.
//!
//! [ADR-0002]: ../../../docs/adr/0002-egress-confinement-policy.md

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use netune_trace::{EventKind, TraceCollector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::connect::{Connector, EgressConfinement, Target, is_public_ip};
use crate::dns::{DnsResolver, SystemResolver};
use crate::error::NetError;
use crate::proxy::Proxy;
use crate::socket::SocketConfig;

/// The default port a datagram target resolves to when its authority omits one.
///
/// Unlike TCP's historical port 80 there is no conventional default for a bare
/// datagram authority, so a missing port is an error rather than a guess: a
/// datagram sent to the wrong port is a silent packet loss, not a failed
/// handshake the caller can see.
const NO_DEFAULT_PORT: &str = "";

/// A payload-carrying datagram session to one peer.
///
/// The peer is fixed at [`DatagramConnector::connect`]; a session that needs a
/// second peer is a second session. Implementations must be safe to drive from
/// two tasks at once (`send` and `recv` on the same session), which is why the
/// trait is `Send + Sync` rather than pinned to `&mut self`.
pub trait DatagramTransport: Send + Sync {
    /// Send one datagram. A payload larger than the path MTU is the kernel's
    /// problem (it fragments or refuses); this layer never splits a datagram,
    /// because a split datagram is a different protocol message.
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>>;

    /// Receive one datagram into `buffer`, returning its length.
    ///
    /// A datagram that does not fit is truncated by the kernel and its excess
    /// discarded — the returned length is what fits, never what was sent. A
    /// protocol that cares must size its buffer from the transport's maximum
    /// ([`Self::max_datagram_size`]).
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>>;

    /// The largest payload this session will carry in one datagram.
    ///
    /// A connected UDP socket reports the path MTU-derived limit the kernel
    /// will accept; a tunnelled session reports what its framing can encode.
    /// Callers size their buffers from this rather than assuming 64 KiB.
    fn max_datagram_size(&self) -> usize;
}

/// A datagram session that has been established.
pub struct EstablishedDatagrams {
    /// The session. Boxed like [`crate::Established::stream`] so a connector can
    /// return a tunnel without naming its type.
    pub datagrams: Box<dyn DatagramTransport>,
    /// Local port, when the platform exposes it. Distinguishes concurrent
    /// sessions to the same peer.
    pub local_port: Option<u16>,
}

impl std::fmt::Debug for EstablishedDatagrams {
    /// Prints the shape, never the payload or the peer's identity beyond what a
    /// trace already records: a session is not a place to leak a destination
    /// into an error message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishedDatagrams")
            .field("local_port", &self.local_port)
            .finish_non_exhaustive()
    }
}

/// Establishes a datagram session to one peer.
///
/// The async method returns a boxed future instead of using `async fn`, so the
/// trait stays object-safe: a caller can hold `Box<dyn DatagramConnector>` and
/// choose the transport at runtime, which is exactly what a proxy chain does.
pub trait DatagramConnector: Send + Sync {
    /// Open a session to `authority` (`host:port`).
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a TraceCollector,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    >;
}

/// A connected [`UdpSocket`], which is all a direct datagram session needs.
struct ConnectedUdp {
    socket: UdpSocket,
    /// Cached at connect time: `max_datagram_size` is on a hot path (once per
    /// send in a QUIC loop) and must not cost a syscall.
    max_datagram_size: usize,
}

impl DatagramTransport for ConnectedUdp {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>>
    {
        Box::pin(self.socket.send(payload))
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>>
    {
        Box::pin(self.socket.recv(buffer))
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }
}

/// Resolves, then opens a datagram socket to one peer, with egress confinement
/// and socket tuning applied exactly as the TCP path applies them.
///
/// The UDP side of [`crate::TcpConnector`]: same resolver, same confinement
/// policy, same `SocketConfig` (a UDP socket needs `SO_MARK` before its first
/// datagram for the same reason a TCP socket needs it before its `SYN`).
#[derive(Debug, Clone)]
pub struct UdpConnector<R: DnsResolver = SystemResolver> {
    pub confinement: EgressConfinement,
    pub resolver: Arc<R>,
    pub socket_config: SocketConfig,
    /// Upper bound on the resolution phase. A datagram has no handshake to
    /// time out on, so only resolution is bounded here; the caller owns the
    /// send/receive deadline.
    pub connect_timeout: Option<Duration>,
}

impl Default for UdpConnector<SystemResolver> {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpConnector<SystemResolver> {
    pub fn new() -> Self {
        Self {
            confinement: EgressConfinement::Unrestricted,
            resolver: Arc::new(SystemResolver),
            socket_config: SocketConfig::default(),
            connect_timeout: Some(crate::connect::CONNECT_TIMEOUT),
        }
    }

    pub fn strict_public() -> Self {
        Self {
            confinement: EgressConfinement::StrictPublic,
            ..Self::new()
        }
    }
}

impl<R: DnsResolver> UdpConnector<R> {
    pub fn with_resolver(resolver: Arc<R>) -> Self {
        Self {
            confinement: EgressConfinement::Unrestricted,
            resolver,
            socket_config: SocketConfig::default(),
            connect_timeout: Some(crate::connect::CONNECT_TIMEOUT),
        }
    }

    pub fn with_socket_config(mut self, config: SocketConfig) -> Self {
        self.socket_config = config;
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Resolve `host`/`port` and return the first address permitted by
    /// `self.confinement`.
    ///
    /// Public because a tunnelled connector needs the proxy hop resolved under
    /// the same policy as a direct one; a second implementation of this rule is
    /// a second place for it to be wrong.
    pub async fn resolve_one(&self, host: &str, port: u16) -> Result<SocketAddr, NetError> {
        let resolve = self.resolver.resolve(host, port);
        let addresses = match self.connect_timeout {
            Some(timeout) => tokio::time::timeout(timeout, resolve).await.map_err(|_| {
                NetError::Resolve(format!(
                    "DNS resolution for {host} exceeded the {}s timeout",
                    timeout.as_secs()
                ))
            })?,
            None => resolve.await,
        }?;
        let Some(address) = addresses.first().copied() else {
            return Err(NetError::Resolve(format!("no addresses for {host}")));
        };
        if self.confinement == EgressConfinement::StrictPublic {
            for addr in &addresses {
                if !is_public_ip(addr.ip()) {
                    return Err(NetError::Security(format!(
                        "refusing to open a datagram socket to non-public address {} for '{host}'",
                        addr.ip()
                    )));
                }
            }
        }
        Ok(address)
    }
}

impl<R: DnsResolver> DatagramConnector for UdpConnector<R> {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a TraceCollector,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let (host, port) = split_datagram_authority(authority)?;

            recorder.mark(EventKind::DnsStart, 0, 0);
            let address = self.resolve_one(host, port).await?;
            recorder.mark(EventKind::DnsEnd, 1, 0);

            let socket = open_connected(address, &self.socket_config)
                .await
                .map_err(|error| NetError::Connect(error.to_string()))?;
            let local_port = socket.local_addr().ok().map(|address| address.port());
            let max_datagram_size = max_datagram_size(&socket);

            recorder.mark(EventKind::UdpOpen, 1, 0);

            Ok(EstablishedDatagrams {
                datagrams: Box::new(ConnectedUdp {
                    socket,
                    max_datagram_size,
                }),
                local_port,
            })
        })
    }
}

/// Opens and connects a UDP socket, applying pre-connect options.
///
/// Separate from [`crate::socket::connect`] because the socket types differ, but
/// the option ordering is the same and load-bearing: `SO_MARK` is consulted when
/// the first datagram's route is chosen, so it must be set before `connect` and
/// certainly before any send.
async fn open_connected(
    address: SocketAddr,
    config: &SocketConfig,
) -> io::Result<tokio::net::UdpSocket> {
    let socket = crate::socket::udp_socket(address, config)?;
    socket.connect(address).await?;
    Ok(socket)
}

/// Shares [`crate::socket::read_socket_config`]-shaped buffers with the TCP path
/// by asking the connected socket for its write window: the kernel refuses a
/// datagram larger than the send buffer, so reporting more would invite a
/// payload that can only fail.
fn max_datagram_size(socket: &UdpSocket) -> usize {
    crate::socket::udp_max_datagram_size(socket).unwrap_or(crate::socket::UDP_MAX_PAYLOAD)
}

/// Splits a datagram authority into host and port.
///
/// Unparseable or absent ports are refused rather than defaulted: see
/// [`NO_DEFAULT_PORT`].
fn split_datagram_authority(authority: &str) -> Result<(&str, u16), NetError> {
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
        NetError::Resolve(format!(
            "datagram authority {authority:?} has no port and there is no default (wanted {NO_DEFAULT_PORT:?})"
        ))
    })?;
    let port = port
        .parse::<u16>()
        .map_err(|error| NetError::Resolve(format!("invalid port in authority: {error}")))?;
    Ok((host.trim_start_matches('[').trim_end_matches(']'), port))
}

// ---------------------------------------------------------------------------
// SOCKS5 UDP association
// ---------------------------------------------------------------------------

/// A SOCKS5 UDP association provisioned by the proxy.
///
/// Destinations are **literal IP addresses**. A UDP destination named by domain
/// would require `Target` to carry a second address channel that TLS verification
/// and the pool key must both ignore; that is an architectural change with its
/// own ADR, not a field to bolt on. The refusal is explicit
/// ([`NetError::UnsupportedEncoding`]) rather than a silent local resolution,
/// because resolving here would move the DNS decision away from the caller that
/// owns the routing policy. Closing the gap is tracked as a named request, not a
/// latent surprise.
pub struct Socks5DatagramConnector<C: Connector> {
    inner: C,
    proxy: Proxy,
    handshake_timeout: Option<Duration>,
}

impl<C: Connector> std::fmt::Debug for Socks5DatagramConnector<C> {
    /// Names the proxy scheme, never its credentials: a proxy URL can carry a
    /// password, and a debug line is the easiest place to leak one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5DatagramConnector")
            .field("proxy", &self.proxy.authority())
            .finish_non_exhaustive()
    }
}

impl<C: Connector> Socks5DatagramConnector<C> {
    /// `inner` must reach the proxy itself (normally a [`crate::TcpConnector`]).
    /// A non-SOCKS5 proxy is refused here, at construction, rather than at the
    /// first datagram: HTTP `CONNECT` has no UDP associate and a connector that
    /// cannot work should not be buildable.
    pub fn new(inner: C, proxy: Proxy) -> Result<Self, NetError> {
        if !matches!(proxy, Proxy::Socks5 { .. }) {
            return Err(NetError::Connect(
                "only a SOCKS5 proxy can associate a UDP datagram session".into(),
            ));
        }
        Ok(Self {
            inner,
            proxy,
            handshake_timeout: Some(crate::handshake::DEFAULT_HANDSHAKE_TIMEOUT),
        })
    }

    /// Replace the UDP-associate bound. `None` removes it; only do that when an
    /// outer deadline exists that reports the stall as a connection failure.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}

impl<C: Connector> DatagramConnector for Socks5DatagramConnector<C> {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a TraceCollector,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let destination = socks5_udp_destination(authority)?;

            // The control connection goes to the proxy, never to the peer.
            let control_target = Target::plain(self.proxy.authority().to_string());
            let established = self.inner.connect(&control_target, recorder).await?;
            let mut control = established.stream;

            let bound = crate::handshake::bound(
                self.handshake_timeout,
                "socks5 UDP associate",
                self.proxy.authority(),
                socks5_udp_associate(&mut control),
            )
            .await??;
            recorder.mark(EventKind::ProxyTunnel, 0, 0);

            // The local socket binds a wildcard address, not the reply's: a
            // proxy usually answers with its *own* (often public) address, which
            // cannot be bound here.
            let any = if bound.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let relay = UdpSocket::bind(any)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 UDP relay bind: {error}")))?;
            let relay_address = relay
                .local_addr()
                .map_err(|error| NetError::Connect(format!("socks5 UDP relay address: {error}")))?;
            let peer = relay_bound_peer(bound, &self.proxy)?;
            let max_datagram_size = max_datagram_size(&relay) - SOCKS5_UDP_HEADER_CEILING;

            recorder.mark(EventKind::UdpOpen, 1, 0);

            Ok(EstablishedDatagrams {
                datagrams: Box::new(Socks5AssociatedUdp {
                    relay,
                    destination,
                    peer,
                    max_datagram_size,
                    _control: std::sync::Mutex::new(control),
                }),
                local_port: Some(relay_address.port()),
            })
        })
    }
}

/// Where to send encapsulated datagrams, given what the proxy answered.
///
/// A wildcard address in the reply (`0.0.0.0`, the usual answer for "send it
/// wherever you like") is replaced by the proxy's own host, keeping the replied
/// port: the datagrams must reach the proxy, and the proxy is the only host this
/// connector is allowed to send to without a second resolution step.
fn relay_bound_peer(bound: SocketAddr, proxy: &Proxy) -> Result<SocketAddr, NetError> {
    if !bound.ip().is_unspecified() {
        return Ok(bound);
    }
    let authority = match proxy {
        Proxy::Socks5 { authority, .. } => authority,
        // Unreachable: `new` refuses anything else. Kept explicit so a future
        // variant cannot silently fall through to the wrong host.
        Proxy::Http { .. } => {
            return Err(NetError::Connect(
                "only a SOCKS5 proxy can associate a UDP datagram session".into(),
            ));
        }
    };
    let (host, _port) = crate::connect::split_target_authority(authority)?;
    let ip = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        // A proxy named by domain has already been resolved by the inner
        // connector for the control connection; the datagrams must reach the same
        // host, and `local` records nothing about it. Resolving again would be a
        // second, silent DNS decision. Refusing is honest.
        Err(_) => {
            return Err(NetError::Connect(format!(
                "socks5: proxy {host:?} answered a wildcard UDP relay address and is named by domain, which is not supported"
            )));
        }
    };
    // A replied port of 0 is meaningless, and substituting the *proxy's own*
    // port would aim datagrams at its SOCKS listener: a failure that surfaces
    // far from its cause. There is nothing to infer from, so refuse here.
    if bound.port() == 0 {
        return Err(NetError::Connect(
            "socks5: UDP associate answered a wildcard relay address with port 0, which cannot be used"
                .into(),
        ));
    }
    Ok(SocketAddr::new(ip, bound.port()))
}

/// The association's single destination, as `(ip, port)`.
fn socks5_udp_destination(authority: &str) -> Result<SocketAddr, NetError> {
    let (host, port) = split_datagram_authority(authority)?;
    let ip = host.parse::<std::net::IpAddr>().map_err(|_| {
        NetError::UnsupportedEncoding(format!(
            "socks5 UDP destination {authority:?} is a domain; only literal addresses are supported \
             (remote name resolution for datagrams is a named gap, not a silent local lookup)"
        ))
    })?;
    Ok(SocketAddr::new(ip, port))
}

/// The SOCKS5 UDP request header's ceiling: `RSV(2) FRAG(1) ATYP(1)`
/// `ADDR(≤255+1) PORT(2)`.
///
/// Sized for the domain case even though only literals are emitted today, so the
/// maximum payload a caller derives from it stays valid if the gap above closes.
const SOCKS5_UDP_HEADER_CEILING: usize = 2 + 1 + 1 + 256 + 2;

/// A datagram session riding a SOCKS5 UDP association.
struct Socks5AssociatedUdp {
    relay: UdpSocket,
    /// The encapsulated destination: an association is per-peer by design (see
    /// the module note on confinement), so every datagram names it.
    destination: SocketAddr,
    /// The proxy's relay address, resolved once at association time.
    peer: SocketAddr,
    max_datagram_size: usize,
    /// Retained, never driven: a SOCKS5 proxy may tear the association down when
    /// its control connection closes, so the stream must outlive the session.
    /// A `Transport` is `Send` but not `Sync`, and a session must be both, so it
    /// sits behind a mutex that is never contended.
    _control: std::sync::Mutex<Box<dyn crate::connect::Transport>>,
}

impl DatagramTransport for Socks5AssociatedUdp {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut framed = Vec::with_capacity(payload.len() + SOCKS5_UDP_HEADER_CEILING);
            socks5_udp_encode(self.destination, payload, &mut framed);
            // The wrapper is a constant 10 bytes for an IPv4 peer and 22 for an
            // IPv6 one; deriving it from the encoded length keeps that true even
            // if the encoder grows a field.
            let wrapper = framed.len() - payload.len();
            let written = self.relay.send_to(&framed, self.peer).await?;
            // Report *payload* bytes, never framed bytes: a caller checking
            // `sent == payload.len()` must not see the wrapper's overhead.
            Ok(written.saturating_sub(wrapper).min(payload.len()))
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut scratch = vec![0u8; buffer.len() + SOCKS5_UDP_HEADER_CEILING];
            loop {
                let (received, _from) = self.relay.recv_from(&mut scratch).await?;
                let Some(decoded) = socks5_udp_decode(&scratch[..received]) else {
                    // Malformed, or a fragment we never emit: dropping it is the
                    // only safe reading, since accepting a partial datagram as
                    // whole would corrupt the protocol above.
                    continue;
                };
                // A datagram that claims another source must never be handed up
                // as this session's: that would let the proxy inject a reply
                // from a host the caller never addressed.
                if decoded.source != self.destination {
                    continue;
                }
                let copied = decoded.data.len().min(buffer.len());
                buffer[..copied].copy_from_slice(&decoded.data[..copied]);
                return Ok(copied);
            }
        })
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }
}

/// A decoded SOCKS5 UDP request.
struct DecodedDatagram<'a> {
    source: SocketAddr,
    data: &'a [u8],
}

/// Writes `RSV RSV FRAG ATYP ADDR PORT PAYLOAD` for `destination`.
fn socks5_udp_encode(destination: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, RSV, FRAG=0 (unfragmented)
    match destination {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&destination.port().to_be_bytes());
    out.extend_from_slice(payload);
}

/// Decodes a SOCKS5 UDP request, rejecting fragments and malformed headers.
///
/// `None` means "not a datagram this session can use" — the caller drops it. A
/// stray or hostile datagram must never kill a working association.
fn socks5_udp_decode(datagram: &[u8]) -> Option<DecodedDatagram<'_>> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    // RSV(2) FRAG(1) ATYP(1)
    let atyp = *datagram.get(3)?;
    if datagram[2] != 0x00 {
        return None;
    }
    match atyp {
        0x01 => {
            let raw = datagram.get(4..10)?;
            let ip = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
            let port = u16::from_be_bytes([raw[4], raw[5]]);
            Some(DecodedDatagram {
                source: SocketAddr::from((ip, port)),
                data: &datagram[10..],
            })
        }
        0x04 => {
            let raw = datagram.get(4..22)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw[..16]);
            let port = u16::from_be_bytes([raw[16], raw[17]]);
            Some(DecodedDatagram {
                source: SocketAddr::from((Ipv6Addr::from(octets), port)),
                data: &datagram[22..],
            })
        }
        // A domain source cannot match an IP destination, so it is dropped by
        // the source check rather than decoded and compared as text.
        _ => None,
    }
}

/// Opens a SOCKS5 UDP association on a freshly connected control stream and
/// returns the relay address the proxy allocated.
///
/// The control connection reached the proxy through `inner`, not through
/// `ProxyConnector`, so the SOCKS5 greeting is this function's job.
async fn socks5_udp_associate(
    control: &mut Box<dyn crate::connect::Transport>,
) -> Result<SocketAddr, NetError> {
    let greeting: &[u8] = &[0x05, 0x01, 0x00];
    control
        .write_all(greeting)
        .await
        .map_err(|error| NetError::Connect(format!("socks5 greeting: {error}")))?;
    let mut chosen = [0u8; 2];
    control
        .read_exact(&mut chosen)
        .await
        .map_err(|error| NetError::Connect(format!("socks5 greeting reply: {error}")))?;
    if chosen[0] != 0x05 || chosen[1] != 0x00 {
        // Credentials for a UDP association would need their own exchange; until
        // an authenticated association is implemented, say so rather than send
        // datagrams a proxy will drop.
        return Err(NetError::Connect(
            "socks5: UDP associate needs the no-auth method".into(),
        ));
    }

    // UDP ASSOCIATE with a wildcard local address: netune does not know which
    // local address the relay socket will bind to, and proxies accept 0.0.0.0:0.
    let request = [0x05u8, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    control
        .write_all(&request)
        .await
        .map_err(|error| NetError::Connect(format!("socks5 UDP associate: {error}")))?;

    let mut reply = [0u8; 4];
    control
        .read_exact(&mut reply)
        .await
        .map_err(|error| NetError::Connect(format!("socks5 UDP associate reply: {error}")))?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(NetError::Connect(format!(
            "socks5: UDP associate refused (code {:#04x})",
            reply[1]
        )));
    }
    read_socks5_bound_address(control, reply[3]).await
}

/// Reads the address body of a SOCKS5 reply whose `ATYP` was already consumed.
async fn read_socks5_bound_address(
    control: &mut Box<dyn crate::connect::Transport>,
    atyp: u8,
) -> Result<SocketAddr, NetError> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    match atyp {
        0x01 => {
            let mut raw = [0u8; 6];
            control
                .read_exact(&mut raw)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 bound address: {error}")))?;
            let ip = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
            let port = u16::from_be_bytes([raw[4], raw[5]]);
            Ok(SocketAddr::from((ip, port)))
        }
        0x04 => {
            let mut raw = [0u8; 18];
            control
                .read_exact(&mut raw)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 bound address: {error}")))?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw[..16]);
            let port = u16::from_be_bytes([raw[16], raw[17]]);
            Ok(SocketAddr::from((Ipv6Addr::from(octets), port)))
        }
        0x03 => {
            let mut length = [0u8; 1];
            control
                .read_exact(&mut length)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 bound address: {error}")))?;
            let mut rest = vec![0u8; length[0] as usize + 2];
            control
                .read_exact(&mut rest)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 bound address: {error}")))?;
            let port = u16::from_be_bytes([rest[rest.len() - 2], rest[rest.len() - 1]]);
            // Resolving a relay named by domain would need the caller's resolver
            // and would be a silent second DNS decision; refuse instead.
            Err(NetError::Connect(format!(
                "socks5: UDP relay returned a domain name (port {port}), which is not supported"
            )))
        }
        other => Err(NetError::Connect(format!(
            "socks5: unknown address type {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn an_authority_without_a_port_is_refused_rather_than_defaulted() {
        let error = split_datagram_authority("example.com").expect_err("no port");
        assert_eq!(error.class(), "resolve");
        assert!(error.to_string().contains("no default"), "{error}");
    }

    #[test]
    fn datagram_authorities_split_including_ipv6_literals() {
        assert_eq!(
            split_datagram_authority("example.com:443").expect("split"),
            ("example.com", 443)
        );
        assert_eq!(
            split_datagram_authority("[2001:db8::1]:51820").expect("split"),
            ("2001:db8::1", 51820)
        );
    }

    #[tokio::test]
    async fn a_connected_session_carries_a_datagram_both_ways() {
        // A loopback UDP socket pair: the cheapest proof that send/recv are
        // wired to the same socket and that the session is really connected.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = server.local_addr().expect("addr");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client.connect(server_addr).await.expect("connect");

        let session = ConnectedUdp {
            socket: client,
            max_datagram_size: 1400,
        };
        assert_eq!(session.max_datagram_size(), 1400);

        let sent = session.send(b"ping").await.expect("send");
        assert_eq!(sent, 4);
        let mut buffer = [0u8; 64];
        let (received, from) = server.recv_from(&mut buffer).await.expect("recv");
        assert_eq!(&buffer[..received], b"ping");

        server.send_to(b"pong", from).await.expect("reply");
        let received = session.recv(&mut buffer).await.expect("recv");
        assert_eq!(&buffer[..received], b"pong");
    }

    #[tokio::test]
    async fn inv_udp_01_confinement_precedes_the_datagram_socket() {
        let connector = UdpConnector::<SystemResolver>::strict_public();
        let recorder = TraceCollector::start(8);
        let error = connector
            .connect("127.0.0.1:9", &recorder)
            .await
            .expect_err("must refuse loopback");
        assert_eq!(error.class(), "security");
        // Nothing may claim a session was opened.
        assert!(
            !recorder
                .log()
                .iter()
                .any(|event| event.kind == EventKind::UdpOpen),
            "a refused session must not record UdpOpen"
        );
    }

    #[tokio::test]
    async fn inv_udp_05_a_session_records_open_and_never_a_handshake() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let authority = server.local_addr().expect("addr").to_string();
        let connector = UdpConnector::<SystemResolver>::new();
        let recorder = TraceCollector::start(8);

        let established = connector
            .connect(&authority, &recorder)
            .await
            .expect("connect");
        assert!(established.local_port.is_some());

        let kinds: Vec<EventKind> = recorder.log().iter().map(|event| event.kind).collect();
        assert!(kinds.contains(&EventKind::DnsStart));
        assert!(kinds.contains(&EventKind::UdpOpen));
        // A datagram session has no handshake, so it must not claim one.
        assert!(!kinds.contains(&EventKind::TcpStart));
        assert!(!kinds.contains(&EventKind::TlsStart));
    }

    #[test]
    fn a_socks5_wrapper_round_trips_an_ipv4_destination() {
        let destination: SocketAddr = "192.0.2.9:51820".parse().expect("addr");
        let mut framed = Vec::new();
        socks5_udp_encode(destination, b"payload", &mut framed);

        // RSV RSV FRAG ATYP, then the address, then the payload.
        assert_eq!(&framed[..4], &[0x00, 0x00, 0x00, 0x01]);
        let decoded = socks5_udp_decode(&framed).expect("decode");
        assert_eq!(decoded.source, destination);
        assert_eq!(decoded.data, b"payload");
    }

    #[test]
    fn a_socks5_wrapper_round_trips_an_ipv6_destination() {
        let destination: SocketAddr =
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
        let mut framed = Vec::new();
        socks5_udp_encode(destination, b"v6", &mut framed);
        assert_eq!(framed[3], 0x04);
        let decoded = socks5_udp_decode(&framed).expect("decode");
        assert_eq!(decoded.source, destination);
        assert_eq!(decoded.data, b"v6");
    }

    #[test]
    fn inv_udp_04_a_fragment_is_refused() {
        // FRAG != 0: netune never emits fragments, so accepting one would let a
        // partial message masquerade as complete.
        let mut framed = vec![0x00, 0x00, 0x01, 0x01, 192, 0, 2, 9, 0xca, 0x84];
        framed.extend_from_slice(b"partial");
        assert!(socks5_udp_decode(&framed).is_none());
    }

    #[test]
    fn truncated_and_unknown_wrappers_are_dropped_not_panicked_on() {
        assert!(socks5_udp_decode(&[]).is_none());
        assert!(socks5_udp_decode(&[0x00, 0x00, 0x00]).is_none());
        // ATYP present but the address is cut short.
        assert!(socks5_udp_decode(&[0x00, 0x00, 0x00, 0x01, 192, 0]).is_none());
        // Unknown ATYP.
        assert!(socks5_udp_decode(&[0x00, 0x00, 0x00, 0x09, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_domain_destination_is_refused_with_a_reason() {
        let error = socks5_udp_destination("example.com:53").expect_err("domain");
        assert_eq!(error.class(), "encoding");
        assert!(error.to_string().contains("literal"), "{error}");
    }

    #[test]
    fn a_literal_destination_is_accepted_including_ipv6() {
        assert_eq!(
            socks5_udp_destination("198.51.100.4:53").expect("ipv4"),
            "198.51.100.4:53".parse().expect("addr")
        );
        assert_eq!(
            socks5_udp_destination("[2001:db8::53]:53").expect("ipv6"),
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53), 53))
        );
    }

    #[test]
    fn a_wildcard_relay_reply_falls_back_to_the_proxy_host() {
        let proxy = Proxy::parse("socks5://203.0.113.7:1080").expect("proxy");
        let wildcard: SocketAddr = "0.0.0.0:51820".parse().expect("addr");
        assert_eq!(
            relay_bound_peer(wildcard, &proxy).expect("peer"),
            "203.0.113.7:51820".parse::<SocketAddr>().expect("addr")
        );
    }

    #[test]
    fn a_wildcard_relay_with_port_zero_is_refused_rather_than_guessed() {
        // Substituting the proxy's own port would send datagrams to its SOCKS
        // port: a failure that surfaces far from its cause.
        let proxy = Proxy::parse("socks5://203.0.113.7:1080").expect("proxy");
        let zero: SocketAddr = "0.0.0.0:0".parse().expect("addr");
        let error = relay_bound_peer(zero, &proxy).expect_err("must refuse");
        assert!(error.to_string().contains("port 0"), "{error}");
    }

    #[test]
    fn an_explicit_relay_address_is_used_verbatim() {
        let proxy = Proxy::parse("socks5://203.0.113.7:1080").expect("proxy");
        let explicit: SocketAddr = "198.51.100.9:9999".parse().expect("addr");
        assert_eq!(relay_bound_peer(explicit, &proxy).expect("peer"), explicit);
    }

    #[test]
    fn a_domain_named_proxy_cannot_serve_a_wildcard_relay() {
        // The proxy was reached by name, so its IP is unavailable here; guessing
        // would send traffic somewhere unintended.
        let proxy = Proxy::parse("socks5://proxy.example:1080").expect("proxy");
        let wildcard: SocketAddr = "0.0.0.0:51820".parse().expect("addr");
        let error = relay_bound_peer(wildcard, &proxy).expect_err("must refuse");
        assert!(error.to_string().contains("named by domain"), "{error}");
    }

    #[test]
    fn only_a_socks5_proxy_can_build_a_datagram_connector() {
        let http = Proxy::parse("http://203.0.113.7:8080").expect("proxy");
        let inner = crate::TcpConnector::new();
        let error = Socks5DatagramConnector::new(inner, http).expect_err("http has no associate");
        assert!(error.to_string().contains("only a SOCKS5"), "{error}");
    }

    #[test]
    fn the_header_ceiling_covers_the_widest_domain_wrapper() {
        // 2 RSV + 1 FRAG + 1 ATYP + (1 length + 255 name) + 2 port.
        assert_eq!(SOCKS5_UDP_HEADER_CEILING, 2 + 1 + 1 + 1 + 255 + 2);
    }

    #[test]
    fn an_ipv4_wrapper_never_exceeds_the_ceiling() {
        let mut framed = Vec::new();
        socks5_udp_encode("203.0.113.1:1".parse().expect("addr"), &[], &mut framed);
        assert!(framed.len() <= SOCKS5_UDP_HEADER_CEILING);
        let mut framed6 = Vec::new();
        socks5_udp_encode(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1)),
            &[],
            &mut framed6,
        );
        assert!(framed6.len() <= SOCKS5_UDP_HEADER_CEILING);
    }
}
