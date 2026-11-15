//! Connection establishment with per-phase timing.
//!
//! Each phase is bracketed by events in the attempt's recorder, which is what
//! makes `dns_us` / `tcp_us` / `tls_us` measurements rather than guesses — and
//! what makes them *absent* (`ConnectionReused`) when the pool answered instead.

use std::sync::Arc;
use std::time::Duration;

use netune_trace::{
    ConnectionIdentity, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EvasionPolicy,
    EventKind, TraceCollector,
};

use crate::dns::{DnsResolver, SystemResolver};
use crate::error::{ConnectError, ConnectErrorKind, NetError, ResolveError};
use crate::profile::ProfileId;
use crate::socket::SocketConfig;

/// Default upper bound on the DNS + TCP establishment phases.
///
/// Long enough for a slow resolver plus a transcontinental RTT; far shorter
/// than any legitimate streaming watchdog above the transport.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A stream the HTTP codec can drive: anything readable, writable and boxable.
pub trait Transport: AsyncReadWrite + Send + Unpin {}
impl<T: AsyncReadWrite + Send + Unpin> Transport for T {}

/// Blanket supertrait so `Box<dyn Transport>` satisfies the codec's bounds.
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> AsyncReadWrite for T {}

/// How to reach a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `host:port`.
    pub authority: String,
    /// Everything fixed at connection establishment that changes what the peer
    /// sees or which pooled socket may serve this target. The pool keys on the
    /// whole value ([`crate::pool::PoolKey`]).
    pub identity: ConnectionIdentity,
    /// Mandate HTTP/2 framing (bypasses HTTP/1.1 negotiation).
    ///
    /// This is a request protocol decision, not a connection identity: a pooled
    /// HTTP/2 connection is selected by protocol, and a pooled HTTP/1.1 socket
    /// is never handed to a request that mandates HTTP/2.
    pub force_h2: bool,
    /// The HTTP/1 request-header wire profile, when this request speaks H1.
    ///
    /// Per request and deliberately outside `ConnectionIdentity`: header order
    /// and casing do not make two sockets interchangeable, so they must not key
    /// the pool. `None` uses the client's default profile.
    pub h1_profile: Option<ProfileId>,
    /// The HTTP/2 request-header profile, when this request speaks H2.
    ///
    /// Per request and outside `ConnectionIdentity`: pseudo-header order changes
    /// one HEADERS block, not the connection. `None` uses the selected H2
    /// fingerprint's request half.
    pub h2_request_profile: Option<ProfileId>,
}

impl Target {
    /// A plaintext target.
    pub fn plain(authority: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            identity: ConnectionIdentity::default(),
            force_h2: false,
            h1_profile: None,
            h2_request_profile: None,
        }
    }

    /// A TLS target: `authority` is the socket address, `server_name` is the
    /// name verified against the certificate.
    pub fn tls(authority: impl Into<String>, server_name: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            identity: ConnectionIdentity {
                tls_server_name: Some(server_name.into()),
                ..ConnectionIdentity::default()
            },
            force_h2: false,
            h1_profile: None,
            h2_request_profile: None,
        }
    }

    /// The TLS profile name requested for this target, if any.
    pub fn tls_profile(&self) -> Option<&str> {
        self.identity.tls_profile.as_deref()
    }

    /// The server name verified against the certificate, if this is TLS.
    pub fn tls_server_name(&self) -> Option<&str> {
        self.identity.tls_server_name.as_deref()
    }

    /// Select the TLS engine that handshakes this target: a name registered
    /// with the connector's engine registry. Engine choice is connection
    /// identity ([`INV-TLS-09`]): two engines are never pooled as one.
    pub fn with_tls_engine(mut self, engine: impl Into<String>) -> Self {
        self.identity.tls_engine = Some(engine.into());
        self
    }

    /// The TLS engine name requested for this target, if any.
    pub fn tls_engine(&self) -> Option<&str> {
        self.identity.tls_engine.as_deref()
    }

    /// The wire-shaping policy requested for this target.
    pub fn evasion(&self) -> EvasionPolicy {
        self.identity.evasion
    }

    /// This target with an explicit TLS profile selection. A plaintext target
    /// ignores the name (there is no hello to shape).
    pub fn with_tls_profile(mut self, profile: impl Into<String>) -> Self {
        self.identity.tls_profile = Some(profile.into());
        self
    }

    /// This target with a named wire-shaping policy. A plaintext target carries
    /// it in the identity but cannot apply it to a TLS hello.
    pub fn with_evasion(mut self, evasion: EvasionPolicy) -> Self {
        self.identity.evasion = evasion;
        self
    }

    /// Mandate HTTP/2 protocol wire framing.
    pub fn with_force_h2(mut self, enabled: bool) -> Self {
        self.force_h2 = enabled;
        self
    }

    /// Select an HTTP/1 request-header wire profile by name.
    ///
    /// The name is resolved by the client's `H1Registry` before a connection is
    /// opened; an unknown name is a loud failure, never a default fallback.
    pub fn with_h1_profile(mut self, profile: impl Into<ProfileId>) -> Self {
        self.h1_profile = Some(profile.into());
        self
    }

    /// Select an HTTP/2 connection profile by name.
    ///
    /// The name is resolved by the client's `H2Registry` while the connection
    /// plan is built; an unknown name fails before a socket is opened.
    pub fn with_h2_profile(mut self, profile: impl Into<String>) -> Self {
        self.identity.h2_profile = Some(profile.into());
        self
    }

    /// Select an HTTP/2 request-header profile by name.
    ///
    /// This half changes pseudo-header order for this request; it does not
    /// change connection identity or the pool key.
    pub fn with_h2_request_profile(mut self, profile: impl Into<ProfileId>) -> Self {
        self.h2_request_profile = Some(profile.into());
        self
    }

    /// Split an absolute URL into a target and an origin-form path.
    ///
    /// Keeps the HTTP stack's URL parsing in one place: callers migrating from
    /// a raw client should not each hand-roll scheme/authority/path handling.
    pub fn from_url(url: &str) -> Result<(Self, String), NetError> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| {
            NetError::Connect(ConnectError::config(
                DiagnosticPhase::Dispatch,
                format!("url has no scheme: {url}"),
            ))
        })?;
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(NetError::Connect(ConnectError::config(
                DiagnosticPhase::Dispatch,
                format!("url has no host: {url}"),
            )));
        }
        let default_port = if scheme == "https" { 443 } else { 80 };
        let authority = normalize_authority(authority, default_port);
        let target = match scheme {
            "https" => {
                let host = authority_host(&authority).to_string();
                Self::tls(authority, host)
            }
            "http" => Self::plain(authority),
            other => {
                return Err(NetError::Connect(ConnectError::config(
                    DiagnosticPhase::Dispatch,
                    format!("unsupported scheme: {other}"),
                )));
            }
        };
        Ok((target, path.to_string()))
    }
}

/// Append `:{default_port}` to `raw` if it does not already carry an explicit
/// `:port` suffix (respecting both bracketed and bare IPv6 literals).
pub(crate) fn normalize_authority(raw: &str, default_port: u16) -> String {
    if let Some(after_bracket) = raw.strip_prefix('[') {
        let has_port = after_bracket
            .split_once(']')
            .and_then(|(_, rest)| rest.strip_prefix(':'))
            .is_some_and(|port| !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()));
        return if has_port {
            raw.to_string()
        } else {
            let host = raw.strip_suffix(':').unwrap_or(raw);
            format!("{host}:{default_port}")
        };
    }
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V6(_) => format!("[{raw}]:{default_port}"),
            std::net::IpAddr::V4(_) => format!("{raw}:{default_port}"),
        };
    }
    let has_port = raw
        .rsplit_once(':')
        .is_some_and(|(_, port)| !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()));
    if has_port {
        raw.to_string()
    } else {
        let host = raw.strip_suffix(':').unwrap_or(raw);
        format!("{host}:{default_port}")
    }
}

/// Extract the unbracketed host or IP literal from an `authority` (`host:port`,
/// `[ipv6]:port`, or bare IP literal) for certificate verification and header derivation.
pub(crate) fn authority_host(authority: &str) -> &str {
    if let Some(after_bracket) = authority.strip_prefix('[')
        && let Some((host, _)) = after_bracket.split_once(']')
    {
        return host;
    }
    if authority.parse::<std::net::IpAddr>().is_ok() {
        return authority;
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// A freshly established connection.
pub struct Established {
    pub stream: Box<dyn Transport>,
    /// Local port, when the platform exposes it. Distinguishes concurrent
    /// connections to the same authority.
    pub local_port: Option<u16>,
    /// A duplicate handle to the same socket, kept so `TCP_INFO` can be sampled
    /// while the connection is in use. `None` when the platform refused the
    /// duplicate, which only costs the RTT/retransmit scopes.
    pub socket: Option<std::net::TcpStream>,
    /// Negotiated ALPN protocol (e.g. `Alpn::H2` or `Alpn::Http11`), if TLS was established.
    ///
    /// This is the trace vocabulary; [`Self::alpn_protocol`] carries the exact wire name for
    /// callers whose protocol uses a name the enum does not know.
    pub alpn: Option<netune_trace::Alpn>,
    /// Raw negotiated ALPN protocol name, exactly as TLS selected it.
    ///
    /// `None` means the peer selected no ALPN, or no TLS handshake happened. A proxy protocol
    /// may negotiate a private name (or none at all); the enum above cannot represent that, so
    /// this field is the authoritative value for protocol code.
    pub alpn_protocol: Option<Vec<u8>>,
}

/// Opens connections. Implemented by `TcpConnector` today; the TLS layer wraps
/// its output rather than replacing it.
pub trait Connector: Send + Sync {
    fn connect(
        &self,
        target: &Target,
        recorder: &TraceCollector,
    ) -> impl std::future::Future<Output = Result<Established, NetError>> + Send;

    /// A stable description of the socket shape this connector applies.
    ///
    /// Two `Client`s can share a `Pool` while using different `SocketConfig`
    /// values; a pooled connection established with one shape must not serve the
    /// other. The orchestrator folds this fragment into `ConnectionIdentity`.
    /// Wrappers that delegate the dial delegate this too.
    fn socket_shape(&self) -> Option<String> {
        None
    }

    /// A stable description of the route a dial takes, when it is not direct.
    ///
    /// A proxy authority is part of connection identity: the same target reached
    /// through two proxies is not the same socket identity. Credentials are not
    /// included.
    fn route_shape(&self) -> Option<String> {
        None
    }
}

/// Egress confinement policy for connection establishment (ADR-0002).
///
/// Re-exported from `netune-egress`, the single source of truth shared by the
/// TCP connector, the datagram sessions and `netune-quic`. Keeping the
/// definition there is what makes the QUIC path enforce the same rule the TCP
/// path does ([INV-EGRESS-01]).
pub use netune_egress::{ConfinementRefused, EgressConfinement, is_public_ip};

/// Resolves, then connects over TCP with optional egress confinement and socket tuning.
#[derive(Debug, Clone)]
pub struct TcpConnector<R: DnsResolver = SystemResolver> {
    pub confinement: EgressConfinement,
    pub resolver: Arc<R>,
    pub socket_config: SocketConfig,
    /// Upper bound on the *connection establishment* phases (DNS + TCP).
    ///
    /// Distinct from a request timeout: a streaming request must never carry
    /// an overall deadline (a long generation must not be cut mid-stream), yet
    /// an unreachable endpoint must not hang the dial forever. Without this
    /// bound a black-hole address — the target accepts TCP but no data ever
    /// flows, or DNS resolves and the SYN dies silently — blocks the attempt
    /// until some outer layer's watchdog fires (the harness's stream idle
    /// timeout), which reports the stall as a generation failure rather than
    /// a connection failure.
    ///
    /// Default 10 s: long enough for a slow resolver plus a transcontinental
    /// RTT, far shorter than any legitimate watchdog above.
    pub connect_timeout: Option<Duration>,
}

impl Default for TcpConnector<SystemResolver> {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpConnector<SystemResolver> {
    pub fn new() -> Self {
        Self {
            confinement: EgressConfinement::Unrestricted,
            resolver: Arc::new(SystemResolver),
            socket_config: SocketConfig::default(),
            connect_timeout: Some(CONNECT_TIMEOUT),
        }
    }

    pub fn strict_public() -> Self {
        Self {
            confinement: EgressConfinement::StrictPublic,
            resolver: Arc::new(SystemResolver),
            socket_config: SocketConfig::default(),
            connect_timeout: Some(CONNECT_TIMEOUT),
        }
    }
}

impl<R: DnsResolver> TcpConnector<R> {
    pub fn with_resolver(resolver: Arc<R>) -> Self {
        Self {
            confinement: EgressConfinement::Unrestricted,
            resolver,
            socket_config: SocketConfig::default(),
            connect_timeout: Some(CONNECT_TIMEOUT),
        }
    }

    pub fn with_socket_config(mut self, config: SocketConfig) -> Self {
        self.socket_config = config;
        self
    }

    /// Bound the DNS + TCP establishment phases. `None` restores the
    /// unbounded dial (tests that drive a mock listener through a paused
    /// runtime may want that; production never does).
    pub fn with_connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }
}

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

/// Parses `host:port`, `[ipv6]:port`, `[ipv6]`, `ipv6`, or `host` into `(host, Option<port>)`.
///
/// The returned `host` is always unbracketed so both `SystemResolver` and literal
/// `IpAddr` parsers consume it directly.
pub(crate) fn parse_authority(authority: &str) -> Result<(&str, Option<u16>), &'static str> {
    if authority.is_empty() {
        return Err("empty authority");
    }
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let Some((host, rest)) = after_bracket.split_once(']') else {
            return Err("unclosed IPv6 bracket");
        };
        if host.is_empty() {
            return Err("empty IPv6 host");
        }
        if rest.is_empty() {
            return Ok((host, None));
        }
        let Some(port_str) = rest.strip_prefix(':') else {
            return Err("unexpected characters after ']'");
        };
        let port = port_str.parse::<u16>().map_err(|_| "invalid port")?;
        return Ok((host, Some(port)));
    }
    if authority.parse::<std::net::IpAddr>().is_ok() {
        return Ok((authority, None));
    }
    match authority.rsplit_once(':') {
        Some((host, port_str)) => {
            if host.is_empty() {
                return Err("empty host");
            }
            if host.contains(':') || host.contains('[') || host.contains(']') {
                return Err("IPv6 literals with a port must be bracketed");
            }
            let port = port_str.parse::<u16>().map_err(|_| "invalid port")?;
            Ok((host, Some(port)))
        }
        None => {
            if authority.contains('[') || authority.contains(']') {
                return Err("malformed IPv6 bracket");
            }
            Ok((authority, None))
        }
    }
}

/// Splits an `authority` into unbracketed host and port, defaulting the port to `80` when absent.
///
/// Shared by the TCP and datagram paths so both read a node authority the same
/// way; a disagreement here would make `host:port` mean two things depending on
/// which transport a caller happened to use.
pub(crate) fn split_target_authority(authority: &str) -> Result<(&str, u16), NetError> {
    let (host, port) = parse_authority(authority).map_err(|reason| {
        NetError::Resolve(ResolveError::invalid_authority(
            authority,
            format!("invalid authority {authority:?}: {reason}"),
        ))
    })?;
    Ok((host, port.unwrap_or(80)))
}

/// Interleave IPv6 and IPv4 candidates per RFC 8305 while preserving resolver order within each family.
pub(crate) fn order_happy_eyeballs(
    addresses: &[std::net::SocketAddr],
) -> Vec<std::net::SocketAddr> {
    if addresses.len() <= 1 {
        return addresses.to_vec();
    }
    let first_is_v6 = addresses[0].is_ipv6();
    let mut primary = Vec::with_capacity(addresses.len());
    let mut secondary = Vec::new();
    for &addr in addresses {
        if addr.is_ipv6() == first_is_v6 {
            primary.push(addr);
        } else {
            secondary.push(addr);
        }
    }
    let mut ordered = Vec::with_capacity(addresses.len());
    let mut p = primary.into_iter();
    let mut s = secondary.into_iter();
    loop {
        match (p.next(), s.next()) {
            (Some(a), Some(b)) => {
                ordered.push(a);
                ordered.push(b);
            }
            (Some(a), None) => ordered.push(a),
            (None, Some(b)) => ordered.push(b),
            (None, None) => break,
        }
    }
    ordered
}

async fn connect_happy_eyeballs_with<S, F, Fut>(
    ordered: &[std::net::SocketAddr],
    deadline: Option<tokio::time::Instant>,
    connect_timeout: Option<Duration>,
    stagger_delay: Duration,
    target_authority: &str,
    mut dial: F,
) -> Result<(std::net::SocketAddr, S), NetError>
where
    S: Send + 'static,
    F: FnMut(std::net::SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<S>> + Send + 'static,
{
    if let Some(deadline) = deadline
        && tokio::time::Instant::now() >= deadline
    {
        return Err(NetError::Connect(ConnectError::timeout(
            DiagnosticPhase::Tcp,
            target_authority,
            "TCP connect",
            connect_timeout.unwrap_or_default(),
        )));
    }

    if ordered.len() == 1 {
        let addr = ordered[0];
        let fut = dial(addr);
        let outcome = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, fut).await {
                Ok(result) => result,
                Err(_) => {
                    return Err(NetError::Connect(ConnectError::timeout(
                        DiagnosticPhase::Tcp,
                        addr.to_string(),
                        "TCP connect",
                        connect_timeout.unwrap_or_default(),
                    )));
                }
            },
            None => fut.await,
        };
        return outcome.map(|stream| (addr, stream)).map_err(|error| {
            NetError::Connect(ConnectError::io(
                DiagnosticPhase::Tcp,
                addr.to_string(),
                error,
            ))
        });
    }

    let mut join_set = tokio::task::JoinSet::new();
    let first = ordered[0];
    let first_fut = dial(first);
    join_set.spawn(async move { (first, first_fut.await) });
    let mut next_idx = 1usize;
    let mut stagger = Box::pin(tokio::time::sleep(stagger_delay));
    let mut last_error: Option<(std::net::SocketAddr, std::io::Error)> = None;

    let race = async {
        loop {
            tokio::select! {
                joined = join_set.join_next(), if !join_set.is_empty() => {
                    match joined {
                        Some(Ok((addr, Ok(stream)))) => {
                            join_set.abort_all();
                            return Ok((addr, stream));
                        }
                        Some(Ok((addr, Err(error)))) => {
                            last_error = Some((addr, error));
                            if next_idx < ordered.len() {
                                let candidate = ordered[next_idx];
                                next_idx += 1;
                                let fut = dial(candidate);
                                join_set.spawn(async move { (candidate, fut.await) });
                                stagger.as_mut().reset(tokio::time::Instant::now() + stagger_delay);
                            } else if join_set.is_empty() {
                                if let Some((fail_addr, fail_err)) = last_error.take() {
                                    return Err(NetError::Connect(ConnectError::io(
                                        DiagnosticPhase::Tcp,
                                        fail_addr.to_string(),
                                        fail_err,
                                    )));
                                }
                                break;
                            }
                        }
                        Some(Err(join_err)) => {
                            if join_set.is_empty() && next_idx >= ordered.len() {
                                return Err(NetError::Connect(
                                    ConnectError::new(
                                        DiagnosticPhase::Tcp,
                                        ConnectErrorKind::Protocol,
                                        format!("connect task aborted for {target_authority}: {join_err}"),
                                    )
                                    .with_peer(target_authority),
                                ));
                            }
                        }
                        None => break,
                    }
                }
                () = &mut stagger, if next_idx < ordered.len() => {
                    let candidate = ordered[next_idx];
                    next_idx += 1;
                    let fut = dial(candidate);
                    join_set.spawn(async move { (candidate, fut.await) });
                    stagger.as_mut().reset(tokio::time::Instant::now() + stagger_delay);
                }
            }
        }
        Err(NetError::Connect(
            ConnectError::new(
                DiagnosticPhase::Tcp,
                ConnectErrorKind::Protocol,
                format!("no connect attempts remained for {target_authority}"),
            )
            .with_peer(target_authority),
        ))
    };

    match deadline {
        Some(deadline) => match tokio::time::timeout_at(deadline, race).await {
            Ok(result) => result,
            Err(_) => Err(NetError::Connect(ConnectError::timeout(
                DiagnosticPhase::Tcp,
                target_authority,
                "TCP connect",
                connect_timeout.unwrap_or_default(),
            ))),
        },
        None => race.await,
    }
}

impl<R: DnsResolver> Connector for TcpConnector<R> {
    fn socket_shape(&self) -> Option<String> {
        Some(self.socket_config.canonical())
    }

    async fn connect(
        &self,
        target: &Target,
        recorder: &TraceCollector,
    ) -> Result<Established, NetError> {
        let deadline = self
            .connect_timeout
            .map(|timeout| tokio::time::Instant::now() + timeout);
        let (host, port) = match split_target_authority(&target.authority) {
            Ok(parts) => parts,
            Err(error) => {
                recorder.record_error(error.diagnostic());
                return Err(error);
            }
        };

        recorder.mark(EventKind::DnsStart, 0, 0);
        let resolve = self.resolver.resolve(host, port);
        let addresses = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, resolve).await {
                Ok(result) => result,
                Err(_) => {
                    let error = NetError::Resolve(ResolveError::timeout(
                        host,
                        self.connect_timeout.unwrap_or_default(),
                    ));
                    recorder.record_error(error.diagnostic().with_public_field("host", host));
                    return Err(error);
                }
            },
            None => resolve.await,
        };
        let addresses = match addresses {
            Ok(addresses) => addresses,
            Err(error) => {
                recorder.record_error(error.diagnostic());
                return Err(error);
            }
        };
        recorder.mark(EventKind::DnsEnd, addresses.len() as u32, 0);
        if addresses.is_empty() {
            let error = NetError::Resolve(ResolveError::empty(&target.authority));
            recorder.record_error(
                error
                    .diagnostic()
                    .with_public_field("authority", &target.authority),
            );
            return Err(error);
        }

        if self.confinement == EgressConfinement::StrictPublic {
            for addr in &addresses {
                if !is_public_ip(addr.ip()) {
                    let message = format!(
                        "refusing to connect to non-public address {} for '{}'",
                        addr.ip(),
                        target.authority
                    );
                    recorder.record_error(
                        DiagnosticRecord::new(DiagnosticCode::EGRESS_SECURITY)
                            .with_phase(DiagnosticPhase::Tcp)
                            .with_message(message.clone())
                            .with_public_field("address", addr.ip().to_string()),
                    );
                    return Err(NetError::Security(message));
                }
            }
        }

        let ordered = order_happy_eyeballs(&addresses);
        recorder.mark(EventKind::TcpStart, 0, 0);
        let (address, stream) = match connect_happy_eyeballs_with(
            &ordered,
            deadline,
            self.connect_timeout,
            HAPPY_EYEBALLS_DELAY,
            &target.authority,
            |addr| {
                let config = self.socket_config.clone();
                async move { crate::socket::connect(addr, &config).await }
            },
        )
        .await
        {
            Ok(connected) => connected,
            Err(error) => {
                let mut record = error.diagnostic();
                if let Some(peer) = error.connect_error().and_then(|c| c.peer.as_deref()) {
                    record = record.with_public_field("address", peer);
                }
                if let Some(kind) = error.io_error_kind() {
                    record = record.with_field("kind", format!("{kind:?}"));
                }
                recorder.record_error(record);
                return Err(error);
            }
        };
        if let Err(error) = self.socket_config.apply(&stream) {
            let message = error.to_string();
            recorder.record_error(
                DiagnosticRecord::new(DiagnosticCode::EGRESS_CONFIG)
                    .with_phase(DiagnosticPhase::Tcp)
                    .with_message(message.clone()),
            );
            return Err(NetError::Connect(
                ConnectError::config(DiagnosticPhase::Tcp, message)
                    .with_peer(address.to_string())
                    .with_source(error),
            ));
        }
        let local_port = stream.local_addr().ok().map(|address| address.port());
        recorder.mark(EventKind::TcpEnd, 0, 0);

        // A duplicated descriptor for the same socket: the HTTP path owns the
        // stream, the sampler owns this one, and neither blocks the other.
        let socket = crate::tcp_info::duplicate(&stream);

        let stream_transport: Box<dyn Transport> = match target.evasion() {
            EvasionPolicy::None => Box::new(stream),
            EvasionPolicy::SniSplit {
                chunk_size,
                segment_limit,
                gap_us,
            } => {
                let mut segmented = crate::evasion::SegmentingIo::new(
                    stream,
                    usize::from(chunk_size),
                    usize::from(segment_limit),
                );
                if gap_us > 0 {
                    segmented = segmented.with_gap(Duration::from_micros(u64::from(gap_us)));
                }
                Box::new(segmented)
            }
        };

        Ok(Established {
            stream: stream_transport,
            local_port,
            socket,
            alpn: None,
            alpn_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confinement_predicate_is_the_shared_egress_crate() {
        // The truth table lives in `netune-egress` (asserted there in full). What matters
        // *here* is the wiring: `netune`'s re-export is the shared predicate, so the TCP and
        // datagram paths cannot drift from the QUIC path. A thin sample is enough to catch a
        // re-export that stops pointing at `netune-egress`.
        assert!(std::ptr::fn_addr_eq(
            is_public_ip as fn(std::net::IpAddr) -> bool,
            netune_egress::is_public_ip as fn(std::net::IpAddr) -> bool,
        ));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn strict_public_confinement_rejects_loopback() {
        let connector = TcpConnector::strict_public();
        let target = Target::plain("127.0.0.1:80");
        let recorder = TraceCollector::start(64);
        let result = connector.connect(&target, &recorder).await;
        assert!(matches!(result, Err(NetError::Security(_))));
    }

    #[tokio::test]
    async fn connector_uses_custom_resolver_and_socket_config() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let resolver = Arc::new(
            crate::dns::StaticResolver::new()
                .with_host("custom.origin", "127.0.0.1".parse().unwrap()),
        );
        let socket_config = SocketConfig::windows_baseline().with_ttl(128);
        let connector = TcpConnector::with_resolver(resolver).with_socket_config(socket_config);

        let target = Target::plain(format!("custom.origin:{port}"));
        let recorder = TraceCollector::start(64);

        let accept_fut = listener.accept();
        let connect_fut = connector.connect(&target, &recorder);

        let (accepted, established) = tokio::join!(accept_fut, connect_fut);
        assert!(accepted.is_ok());
        let established = established.expect("connect");
        assert!(established.local_port.is_some());
    }

    #[tokio::test]
    async fn connect_timeout_bounds_a_stalling_resolver() {
        // A DNS resolve that never completes is the deterministic black hole
        // (an unroutable IP's behaviour depends on the local routing table:
        // TEST-NET ranges may be swallowed by a NAT that answers instantly,
        // so a "dial to nowhere" is not portable). The resolver arm is
        // controlled by us: hang forever, and the connector's timeout must
        // convert that into an explicit `NetError::Resolve`.
        #[derive(Debug)]
        struct NeverResolver;
        impl crate::dns::DnsResolver for NeverResolver {
            fn resolve<'a>(
                &'a self,
                _host: &'a str,
                _port: u16,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<Vec<std::net::SocketAddr>, NetError>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(std::future::pending())
            }
        }

        let connector = TcpConnector::with_resolver(Arc::new(NeverResolver))
            .with_connect_timeout(Some(Duration::from_millis(200)));
        let target = Target::plain("slow.origin:443");
        let recorder = TraceCollector::start(64);

        let started = tokio::time::Instant::now();
        let error = match connector.connect(&target, &recorder).await {
            Ok(_) => panic!("a never-resolving resolver must time out"),
            Err(error) => error,
        };
        let elapsed = started.elapsed();

        assert!(
            elapsed >= Duration::from_millis(180),
            "the error must be the connect timeout, not an instant refusal: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the resolve must be bounded by the configured timeout: {elapsed:?}"
        );
        assert!(
            error.to_string().contains("connect timeout"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn from_url_handles_ipv6_literals_and_empty_ports() {
        let (target, path) = Target::from_url("https://[::1]/v1/chat").expect("ipv6 default port");
        assert_eq!(path, "/v1/chat");
        assert_eq!(target.authority, "[::1]:443");
        assert_eq!(target.tls_server_name(), Some("::1"));

        let (target, path) =
            Target::from_url("https://[2001:db8::1234]:8443/x").expect("ipv6 explicit port");
        assert_eq!(path, "/x");
        assert_eq!(target.authority, "[2001:db8::1234]:8443");
        assert_eq!(target.tls_server_name(), Some("2001:db8::1234"));

        let (target, path) = Target::from_url("https://example.com:/a").expect("empty port");
        assert_eq!(path, "/a");
        assert_eq!(target.authority, "example.com:443");
        assert_eq!(target.tls_server_name(), Some("example.com"));

        assert_eq!(normalize_authority("::1", 443), "[::1]:443");
        assert_eq!(normalize_authority("2001:db8::", 443), "[2001:db8::]:443");
        assert_eq!(authority_host("::1"), "::1");
        assert_eq!(authority_host("2001:db8::"), "2001:db8::");
    }

    #[test]
    fn split_target_authority_handles_ipv6_literals_and_defaults() {
        assert_eq!(
            split_target_authority("[::1]:8443").expect("bracketed ipv6 with port"),
            ("::1", 8443)
        );
        assert_eq!(
            split_target_authority("[::1]").expect("bracketed ipv6 default port"),
            ("::1", 80)
        );
        assert_eq!(
            split_target_authority("::1").expect("bare ipv6 default port"),
            ("::1", 80)
        );
        let invalid =
            split_target_authority("2001:db8::zz:8080").expect_err("unbracketed invalid + port");
        assert!(!invalid.is_retryable());
        assert_eq!(invalid.diagnostic().code, DiagnosticCode::EGRESS_CONFIG);
    }

    #[test]
    fn happy_eyeballs_interleaves_address_families() {
        let v6_a: std::net::SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v6_b: std::net::SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let v4_a: std::net::SocketAddr = "198.51.100.1:443".parse().unwrap();
        let v4_b: std::net::SocketAddr = "198.51.100.2:443".parse().unwrap();
        let ordered = order_happy_eyeballs(&[v6_a, v6_b, v4_a, v4_b]);
        assert_eq!(ordered, vec![v6_a, v4_a, v6_b, v4_b]);
    }

    #[tokio::test]
    async fn connector_falls_back_when_first_address_refuses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_port = listener.local_addr().unwrap().port();
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        #[derive(Debug)]
        struct TwoAddrResolver(std::net::SocketAddr, std::net::SocketAddr);
        impl crate::dns::DnsResolver for TwoAddrResolver {
            fn resolve<'a>(
                &'a self,
                _host: &'a str,
                _port: u16,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<Vec<std::net::SocketAddr>, NetError>>
                        + Send
                        + 'a,
                >,
            > {
                let addrs = vec![self.0, self.1];
                Box::pin(async move { Ok(addrs) })
            }
        }

        let resolver = Arc::new(TwoAddrResolver(
            std::net::SocketAddr::from(([127, 0, 0, 1], closed_port)),
            std::net::SocketAddr::from(([127, 0, 0, 1], live_port)),
        ));
        let connector = TcpConnector::with_resolver(resolver)
            .with_connect_timeout(Some(Duration::from_secs(2)));
        let recorder = TraceCollector::start(64);
        let target = Target::plain("dual.example:443");
        let (accepted, established) =
            tokio::join!(listener.accept(), connector.connect(&target, &recorder));
        assert!(accepted.is_ok());
        assert!(established.is_ok());
    }

    #[tokio::test]
    async fn happy_eyeballs_stagger_recovers_from_stalling_primary_address() {
        let first: std::net::SocketAddr = "198.51.100.1:443".parse().unwrap();
        let second: std::net::SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let started = tokio::time::Instant::now();
        let result = connect_happy_eyeballs_with(
            &[first, second],
            Some(started + Duration::from_secs(5)),
            Some(Duration::from_secs(5)),
            Duration::from_millis(40),
            "example.com:443",
            |addr| async move {
                if addr == first {
                    std::future::pending::<std::io::Result<&'static str>>().await
                } else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok("connected")
                }
            },
        )
        .await;
        let (winner, payload) = result.expect("secondary address must win before full timeout");
        assert_eq!(winner, second);
        assert_eq!(payload, "connected");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "expected ~50ms staggered winner, got {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn single_deadline_spans_dns_and_tcp_without_doubling() {
        #[derive(Debug)]
        struct SlowResolver;
        impl crate::dns::DnsResolver for SlowResolver {
            fn resolve<'a>(
                &'a self,
                _host: &'a str,
                port: u16,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<Vec<std::net::SocketAddr>, NetError>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
                })
            }
        }

        // Resolve consumes 150ms of the 220ms budget, leaving only 70ms for TCP.
        let started = tokio::time::Instant::now();
        let total_budget = Duration::from_millis(220);
        let deadline = started + total_budget;

        let resolve_res = tokio::time::timeout_at(deadline, SlowResolver.resolve("example", 443))
            .await
            .expect("resolve fits inside 220ms budget")
            .expect("addrs");
        let err = connect_happy_eyeballs_with::<(), _, _>(
            &resolve_res,
            Some(deadline),
            Some(total_budget),
            HAPPY_EYEBALLS_DELAY,
            "example:443",
            |_| async move { std::future::pending::<std::io::Result<()>>().await },
        )
        .await
        .expect_err("remaining budget must bound TCP dial");

        let elapsed = started.elapsed();
        assert!(err.is_timeout(), "expected timeout error, got {err}");
        assert_eq!(err.diagnostic().code, DiagnosticCode::EGRESS_TIMEOUT);
        assert!(
            elapsed < Duration::from_millis(360),
            "expected combined DNS+TCP timeout near 220ms, not doubled 440ms; got {elapsed:?}"
        );
    }
}
