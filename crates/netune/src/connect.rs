//! Connection establishment with per-phase timing.
//!
//! Each phase is bracketed by events in the attempt's recorder, which is what
//! makes `dns_us` / `tcp_us` / `tls_us` measurements rather than guesses — and
//! what makes them *absent* (`ConnectionReused`) when the pool answered instead.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune_trace::{EventKind, Recorder};
use tokio::net::TcpStream;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressConfinement {
    /// Standard unrestricted egress (for configured LLM endpoints and proxies).
    #[default]
    Unrestricted,
    /// Strict public egress: rejects loopback, RFC 1918 private, link-local,
    /// carrier-grade NAT, cloud metadata, and multicast addresses.
    StrictPublic,
}

/// True only for globally-routable addresses. Rejects loopback, private RFC1918
/// ranges, link-local, cloud metadata, carrier-grade NAT, and unspecified/broadcast.
pub fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            let [a, b, c, _d] = octets;
            // Cloud instance-metadata endpoint (AWS/Azure/GCP): link-local 169.254.169.254
            if octets == [169, 254, 169, 254] {
                return false;
            }
            if v4.is_loopback()        // 127.0.0.0/8
                || v4.is_private()     // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()  // 169.254/16
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast()
            // 255.255.255.255
            {
                return false;
            }
            // Carrier-grade NAT (100.64.0.0/10)
            if a == 100 && (b & 0xc0) == 64 {
                return false;
            }
            // Documentation/benchmarking networks (198.18.0.0/15, 198.51.100/24, 203.0.113/24)
            if a == 198 && (18..=19).contains(&b) {
                return false;
            }
            if a == 192 && b == 0 && (c == 0 || c == 2) {
                return false;
            }
            if a == 198 && b == 51 && c == 100 {
                return false;
            }
            if a == 203 && b == 0 && c == 113 {
                return false;
            }
            // Reserved / Class E
            if a >= 240 {
                return false;
            }
            true
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let seg0 = v6.segments()[0];
            // Unique-local fc00::/7 (RFC 4193)
            if (seg0 & 0xfe00) == 0xfc00 {
                return false;
            }
            // Link-local fe80::/10 (RFC 4291)
            if (seg0 & 0xffc0) == 0xfe80 {
                return false;
            }
            // IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(std::net::IpAddr::V4(v4));
            }
            true
        }
    }
}

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

impl<R: DnsResolver> Connector for TcpConnector<R> {
    async fn connect(
        &self,
        target: &Target,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, NetError> {
        let (host, port) = match target.authority.rsplit_once(':') {
            Some((h, p)) => {
                let p = p.parse::<u16>().map_err(|error| {
                    NetError::Resolve(format!("invalid port in authority: {error}"))
                })?;
                (h, p)
            }
            None => (target.authority.as_str(), 80),
        };

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
        let dial = TcpStream::connect(address);
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
    fn test_is_public_ip() {
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("172.16.0.1".parse().unwrap()));
        assert!(!is_public_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(!is_public_ip("fe80::1".parse().unwrap()));
        assert!(!is_public_ip("fc00::1".parse().unwrap()));

        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
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
