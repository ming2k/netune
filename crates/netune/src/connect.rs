//! Connection establishment with per-phase timing.
//!
//! Each phase is bracketed by events in the attempt's recorder, which is what
//! makes `dns_us` / `tcp_us` / `tls_us` measurements rather than guesses — and
//! what makes them *absent* (`ConnectionReused`) when the pool answered instead.

use std::sync::{Arc, Mutex};

use netune_trace::{EventKind, Recorder};
use tokio::net::TcpStream;

use crate::error::NetError;

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
}

impl Target {
    /// A plaintext target.
    pub fn plain(authority: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            tls_server_name: None,
        }
    }

    /// A TLS target: `authority` is the socket address, `server_name` is the
    /// name verified against the certificate.
    pub fn tls(authority: impl Into<String>, server_name: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            tls_server_name: Some(server_name.into()),
        }
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

/// Egress confinement policy for connection establishment (ADR-0204).
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

/// Resolves, then connects over TCP with optional egress confinement.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpConnector {
    pub confinement: EgressConfinement,
}

impl TcpConnector {
    pub const fn new() -> Self {
        Self {
            confinement: EgressConfinement::Unrestricted,
        }
    }

    pub const fn strict_public() -> Self {
        Self {
            confinement: EgressConfinement::StrictPublic,
        }
    }
}

impl Connector for TcpConnector {
    async fn connect(
        &self,
        target: &Target,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, NetError> {
        {
            let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
            recorder.mark(EventKind::DnsStart, 0, 0);
        }
        let addresses: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&target.authority)
            .await
            .map_err(|error| NetError::Resolve(error.to_string()))?
            .collect();
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
        let stream = TcpStream::connect(address)
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;
        // Streaming responses are small, latency-sensitive writes: Nagle would
        // add up to 40 ms per flush.
        let _ = stream.set_nodelay(true);
        let local_port = stream.local_addr().ok().map(|address| address.port());
        {
            let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
            recorder.mark(EventKind::TcpEnd, 0, 0);
        }

        // A duplicated descriptor for the same socket: the HTTP path owns the
        // stream, the sampler owns this one, and neither blocks the other.
        let socket = crate::tcp_info::duplicate(&stream);

        Ok(Established {
            stream: Box::new(stream),
            local_port,
            socket,
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
}
