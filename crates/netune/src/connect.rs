//! Connection establishment with per-phase timing.
//!
//! Each phase is bracketed by events in the attempt's recorder, which is what
//! makes `dns_us` / `tcp_us` / `tls_us` measurements rather than guesses — and
//! what makes them *absent* (`ConnectionReused`) when the pool answered instead.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune_trace::{EventKind, Recorder};

use crate::dns::{DnsResolver, SystemResolver};
use crate::error::NetError;
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
    /// Server name for TLS; `None` means plaintext.
    pub tls_server_name: Option<String>,
    /// Which TLS fingerprint identity to present on this target, by profile
    /// name (`"codex-reqwest"`, …). `None` selects the connector's default —
    /// for `TlsRouterConnector` that is [`crate::tls_profile::TlsProfile::
    /// netune_default`], and a plain [`crate::tls::TlsConnector`] ignores the
    /// name entirely (it has only one identity to offer).
    ///
    /// The pool keys on this: a connection handshook under one identity is
    /// never handed to a request that asked for another, because the pooled
    /// session's hello is already on the wire and cannot be changed.
    pub tls_profile: Option<String>,
    /// Enable early-flight TCP segmentation to defeat middlebox SNI inspection (ADR-0006).
    pub sni_segmentation: bool,
    /// Mandate HTTP/2 framing (bypasses HTTP/1.1 negotiation).
    pub force_h2: bool,
}

impl Target {
    /// A plaintext target.
    pub fn plain(authority: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            tls_server_name: None,
            tls_profile: None,
            sni_segmentation: false,
            force_h2: false,
        }
    }

    /// A TLS target: `authority` is the socket address, `server_name` is the
    /// name verified against the certificate.
    pub fn tls(authority: impl Into<String>, server_name: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            tls_server_name: Some(server_name.into()),
            tls_profile: None,
            sni_segmentation: false,
            force_h2: false,
        }
    }

    /// This target with an explicit TLS profile selection. A plaintext target
    /// ignores the name (there is no hello to shape).
    pub fn with_tls_profile(mut self, profile: impl Into<String>) -> Self {
        self.tls_profile = Some(profile.into());
        self
    }

    /// Enable SNI micro-segmentation to evade DPI.
    pub fn with_sni_segmentation(mut self, enabled: bool) -> Self {
        self.sni_segmentation = enabled;
        self
    }

    /// Mandate HTTP/2 protocol wire framing.
    pub fn with_force_h2(mut self, enabled: bool) -> Self {
        self.force_h2 = enabled;
        self
    }

    /// Split an absolute URL into a target and an origin-form path.
    ///
    /// Keeps the HTTP stack's URL parsing in one place: callers migrating from
    /// a raw client should not each hand-roll scheme/authority/path handling.
    pub fn from_url(url: &str) -> Result<(Self, String), NetError> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| NetError::Connect(format!("url has no scheme: {url}")))?;
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(NetError::Connect(format!("url has no host: {url}")));
        }
        let default_port = if scheme == "https" { 443 } else { 80 };
        let has_port = authority
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.chars().all(|character| character.is_ascii_digit()));
        let authority = if has_port {
            authority.to_string()
        } else {
            format!("{authority}:{default_port}")
        };
        let target = match scheme {
            "https" => {
                let host = authority
                    .rsplit_once(':')
                    .map_or(authority.as_str(), |(host, _)| host)
                    .to_string();
                Self::tls(authority, host)
            }
            "http" => Self::plain(authority),
            other => {
                return Err(NetError::Connect(format!("unsupported scheme: {other}")));
            }
        };
        Ok((target, path.to_string()))
    }
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
    pub alpn: Option<netune_trace::Alpn>,
}

/// Opens connections. Implemented by `TcpConnector` today; the TLS layer wraps
/// its output rather than replacing it.
pub trait Connector: Send + Sync {
    fn connect(
        &self,
        target: &Target,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> impl std::future::Future<Output = Result<Established, NetError>> + Send;
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

/// Splits an `authority` into host and port, defaulting the port when absent.
///
/// Shared by the TCP and datagram paths so both read a node authority the same
/// way; a disagreement here would make `host:port` mean two things depending on
/// which transport a caller happened to use.
pub(crate) fn split_target_authority(authority: &str) -> Result<(&str, u16), NetError> {
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse::<u16>().map_err(|error| {
                NetError::Resolve(format!("invalid port in authority: {error}"))
            })?;
            Ok((host, port))
        }
        None => Ok((authority, 80)),
    }
}

impl<R: DnsResolver> Connector for TcpConnector<R> {
    async fn connect(
        &self,
        target: &Target,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, NetError> {
        let (host, port) = split_target_authority(&target.authority)?;

        {
            let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
            recorder.mark(EventKind::DnsStart, 0, 0);
        }
        let resolve = self.resolver.resolve(host, port);
        let addresses = match self.connect_timeout {
            Some(timeout) => tokio::time::timeout(timeout, resolve).await.map_err(|_| {
                NetError::Resolve(format!(
                    "DNS resolution for {host} exceeded the {}s connect timeout",
                    timeout.as_secs()
                ))
            })?,
            None => resolve.await,
        }?;
        {
            let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
            recorder.mark(EventKind::DnsEnd, addresses.len() as u32, 0);
        }
        let Some(address) = addresses.first().copied() else {
            return Err(NetError::Resolve(format!(
                "no addresses for {}",
                target.authority
            )));
        };

        if self.confinement == EgressConfinement::StrictPublic {
            for addr in &addresses {
                if !is_public_ip(addr.ip()) {
                    return Err(NetError::Security(format!(
                        "refusing to connect to non-public address {} for '{}'",
                        addr.ip(),
                        target.authority
                    )));
                }
            }
        }

        {
            let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
            recorder.mark(EventKind::TcpStart, 0, 0);
        }
        let dial = crate::socket::connect(address, &self.socket_config);
        let stream = match self.connect_timeout {
            Some(timeout) => tokio::time::timeout(timeout, dial).await.map_err(|_| {
                NetError::Connect(format!(
                    "TCP connect to {address} exceeded the {}s connect timeout",
                    timeout.as_secs()
                ))
            })?,
            None => dial.await,
        }
        .map_err(|error| NetError::Connect(error.to_string()))?;
        self.socket_config
            .apply(&stream)
            .map_err(|error| NetError::Connect(error.to_string()))?;
        let local_port = stream.local_addr().ok().map(|address| address.port());
        {
            let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
            recorder.mark(EventKind::TcpEnd, 0, 0);
        }

        // A duplicated descriptor for the same socket: the HTTP path owns the
        // stream, the sampler owns this one, and neither blocks the other.
        let socket = crate::tcp_info::duplicate(&stream);

        let stream_transport: Box<dyn Transport> = if target.sni_segmentation {
            Box::new(crate::evasion::SegmentingIo::for_sni(stream))
        } else {
            Box::new(stream)
        };

        Ok(Established {
            stream: stream_transport,
            local_port,
            socket,
            alpn: None,
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
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
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
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));

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
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));

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
}
