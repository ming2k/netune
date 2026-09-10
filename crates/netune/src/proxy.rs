//! Proxies: HTTP `CONNECT` and SOCKS5.
//!
//! A proxy changes *where the socket goes*, not what travels through it, so the
//! connector chain keeps its shape: `TlsConnector<ProxyConnector<TcpConnector>>`
//! connects to the proxy, tunnels to the target, and only then runs the TLS
//! handshake with the target's certificate. The trace therefore still shows the
//! target's `TlsStart`/`TlsEnd`, and `tcp_us` measures the hop to the proxy —
//! which is what actually happened.
//!
//! Both handshakes are bounded and typed: a proxy that answers garbage, refuses
//! the tunnel, or demands credentials we do not have produces a [`NetError`],
//! never a silently truncated stream.

use base64::Engine as _;
use netune_http1::{Http1Reader, Limits};
use netune_trace::{EventKind, Recorder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::connect::{Connector, Established, Target, Transport};
use crate::error::NetError;

/// Which proxy to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proxy {
    /// HTTP `CONNECT` tunnel (`http://user:pass@host:port`).
    Http {
        authority: String,
        credentials: Option<(String, String)>,
    },
    /// SOCKS5 (`socks5://user:pass@host:port`); `socks5h` is treated as SOCKS5
    /// with remote name resolution, which is what we ask for anyway.
    Socks5 {
        authority: String,
        credentials: Option<(String, String)>,
    },
}

impl Proxy {
    /// Parse a proxy URL.
    pub fn parse(url: &str) -> Result<Self, NetError> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| NetError::Connect(format!("proxy url has no scheme: {url}")))?;
        let (userinfo, authority) = match rest.rsplit_once('@') {
            Some((userinfo, authority)) => (Some(userinfo), authority),
            None => (None, rest),
        };
        let authority = authority.trim_end_matches('/').to_string();
        if authority.is_empty() {
            return Err(NetError::Connect("proxy url has no host".into()));
        }
        let credentials = userinfo.map(|userinfo| match userinfo.split_once(':') {
            Some((user, password)) => (user.to_string(), password.to_string()),
            None => (userinfo.to_string(), String::new()),
        });
        match scheme {
            "http" | "https" => Ok(Self::Http {
                authority,
                credentials,
            }),
            "socks5" | "socks5h" => Ok(Self::Socks5 {
                authority,
                credentials,
            }),
            other => Err(NetError::Connect(format!(
                "unsupported proxy scheme: {other}"
            ))),
        }
    }

    fn authority(&self) -> &str {
        match self {
            Self::Http { authority, .. } | Self::Socks5 { authority, .. } => authority,
        }
    }
}

/// A connector that reaches `target` through `proxy`.
pub struct ProxyConnector<C: Connector> {
    inner: C,
    proxy: Proxy,
}

impl<C: Connector> ProxyConnector<C> {
    pub fn new(inner: C, proxy: Proxy) -> Self {
        Self { inner, proxy }
    }
}

impl<C: Connector> Connector for ProxyConnector<C> {
    async fn connect(
        &self,
        target: &Target,
        recorder: &std::sync::Arc<std::sync::Mutex<Recorder>>,
    ) -> Result<Established, NetError> {
        // The socket goes to the proxy; the target is named inside the tunnel.
        let hop = Target::plain(self.proxy.authority().to_string());
        let established = self.inner.connect(&hop, recorder).await?;
        let mut stream = established.stream;

        match &self.proxy {
            Proxy::Http { credentials, .. } => {
                http_connect(&mut stream, &target.authority, credentials.as_ref()).await?;
            }
            Proxy::Socks5 { credentials, .. } => {
                socks5_connect(&mut stream, &target.authority, credentials.as_ref()).await?;
            }
        }
        {
            let mut recorder = recorder.lock().unwrap_or_else(|error| error.into_inner());
            recorder.mark(EventKind::ProxyTunnel, 0, 0);
        }

        Ok(Established {
            stream,
            local_port: established.local_port,
            socket: established.socket,
        })
    }
}

/// Establish an HTTP `CONNECT` tunnel to `authority`.
async fn http_connect(
    stream: &mut Box<dyn Transport>,
    authority: &str,
    credentials: Option<&(String, String)>,
) -> Result<(), NetError> {
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some((user, password)) = credentials {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| NetError::Connect(format!("proxy CONNECT write: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| NetError::Connect(format!("proxy CONNECT flush: {error}")))?;

    let mut reader = Http1Reader::with_limits(stream, Limits::default());
    let head = reader
        .read_response_head(&http::Method::CONNECT)
        .await
        .map_err(|error| NetError::Connect(format!("proxy CONNECT response: {error}")))?;
    if !head.status.is_success() {
        return Err(NetError::Connect(format!(
            "proxy refused the tunnel: HTTP {}",
            head.status
        )));
    }
    Ok(())
}

/// Establish a SOCKS5 tunnel to `authority` (domain name resolution is left to
/// the proxy, which is the point of using one).
async fn socks5_connect(
    stream: &mut Box<dyn Transport>,
    authority: &str,
    credentials: Option<&(String, String)>,
) -> Result<(), NetError> {
    let (host, port) = split_authority(authority)?;
    let host = host.to_string();

    // Greeting: offer user/pass auth when we have it, then "no auth".
    let greeting: &[u8] = if credentials.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream
        .write_all(greeting)
        .await
        .map_err(|error| NetError::Connect(format!("socks5 greeting: {error}")))?;
    let mut chosen = [0u8; 2];
    stream
        .read_exact(&mut chosen)
        .await
        .map_err(|error| NetError::Connect(format!("socks5 greeting reply: {error}")))?;
    if chosen[0] != 0x05 {
        return Err(NetError::Connect("socks5: not a SOCKS5 proxy".into()));
    }
    match chosen[1] {
        0x00 => {}
        0x02 => {
            let (user, password) = credentials
                .ok_or_else(|| NetError::Connect("socks5: proxy requires credentials".into()))?;
            if user.len() > 255 || password.len() > 255 {
                return Err(NetError::Connect("socks5: credential too long".into()));
            }
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream
                .write_all(&auth)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 auth: {error}")))?;
            let mut reply = [0u8; 2];
            stream
                .read_exact(&mut reply)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 auth reply: {error}")))?;
            if reply[1] != 0x00 {
                return Err(NetError::Connect("socks5: authentication rejected".into()));
            }
        }
        0xFF => {
            return Err(NetError::Connect(
                "socks5: no acceptable auth method".into(),
            ));
        }
        other => {
            return Err(NetError::Connect(format!(
                "socks5: unsupported auth method {other}"
            )));
        }
    }

    // CONNECT with an ATYP=domain request.
    if host.len() > 255 {
        return Err(NetError::Connect("socks5: host too long".into()));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| NetError::Connect(format!("socks5 connect: {error}")))?;

    let mut reply = [0u8; 4];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|error| NetError::Connect(format!("socks5 connect reply: {error}")))?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(NetError::Connect(format!(
            "socks5: connect failed (code {:#04x})",
            reply[1]
        )));
    }
    // Drain the bound address, whose length depends on ATYP.
    match reply[3] {
        0x01 => {
            let mut rest = [0u8; 4 + 2];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 bound address: {error}")))?;
        }
        0x04 => {
            let mut rest = [0u8; 16 + 2];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 bound address: {error}")))?;
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 bound address: {error}")))?;
            let mut rest = vec![0u8; length[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|error| NetError::Connect(format!("socks5 bound address: {error}")))?;
        }
        other => {
            return Err(NetError::Connect(format!(
                "socks5: unknown address type {other}"
            )));
        }
    }
    Ok(())
}

fn split_authority(authority: &str) -> Result<(&str, u16), NetError> {
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| NetError::Connect(format!("authority has no port: {authority}")))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| NetError::Connect(format!("authority has an invalid port: {authority}")))?;
    Ok((host.trim_start_matches('[').trim_end_matches(']'), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_urls_parse_with_and_without_credentials() {
        assert_eq!(
            Proxy::parse("http://127.0.0.1:8080").expect("parse"),
            Proxy::Http {
                authority: "127.0.0.1:8080".into(),
                credentials: None
            }
        );
        assert_eq!(
            Proxy::parse("socks5://user:secret@proxy.example:1080").expect("parse"),
            Proxy::Socks5 {
                authority: "proxy.example:1080".into(),
                credentials: Some(("user".into(), "secret".into()))
            }
        );
        assert_eq!(
            Proxy::parse("socks5h://proxy.example:1080/").expect("parse"),
            Proxy::Socks5 {
                authority: "proxy.example:1080".into(),
                credentials: None
            }
        );
    }

    #[test]
    fn an_unknown_scheme_is_refused() {
        let error = Proxy::parse("ftp://proxy.example:21").expect_err("unsupported");
        assert_eq!(error.class(), "connect");
    }

    #[test]
    fn authority_splitting_handles_ipv6_literals() {
        assert_eq!(
            split_authority("example.com:443").expect("split"),
            ("example.com", 443)
        );
        assert_eq!(split_authority("[::1]:8443").expect("split"), ("::1", 8443));
        assert!(split_authority("example.com").is_err());
    }
}
