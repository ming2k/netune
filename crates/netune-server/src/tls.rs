//! TLS termination for the listener (RFC 8446, RFC 7301 ALPN).
//!
//! # Why termination belongs *here* and not in front
//!
//! [ADR-0011](../../../docs/adr/0011-server-side-ingress-transport.md) rejected a fronting proxy for
//! a specific reason: whoever owns the TLS read loop owns the accept-queue dwell time, the
//! upload/handler overlap and the write-side stall cause, and will not report them per request. With
//! TLS in front, every stream of this transport's trace would begin *after* the handshake — so
//! `IngressTlsEnd` would be a number nobody measured, and the handshake cost would be attributed to
//! nothing.
//!
//! A server that terminates TLS itself can say what the handshake cost. That is the whole argument,
//! and it is the same one `netune`'s client side already makes for owning its TLS.
//!
//! # The protocol decision moves into the handshake
//!
//! On a plaintext listener the protocol is chosen from the first bytes (`PRI *`). On a TLS listener it
//! is chosen by ALPN, and the choice must be made *per connection* — a virtual host may serve different
//! certificates, and a client may offer a protocol this listener does not. [`rustls::server::Acceptor`]
//! exists for exactly that: it reads the ClientHello, exposes the SNI and the ALPN offer, and *then* a
//! configuration is selected. A listener that instead guessed from its own default would serve the
//! wrong certificate to the wrong name, which is a silent security failure rather than a visible one.
//!
//! # What is deliberately not here
//!
//! - **No session resumption tuning.** `rustls` keeps its own ticket store; a bound on it is a decision
//!   for a deployment whose session volume is known.
//! - **No client certificates.** mTLS is a deployment policy; a transport that required one would be
//!   unusable for the public case.
//! - **No cipher or version policy.** That is [`TlsProfile`](../../../docs/adr/0004-tls-fingerprint-profiles-pool-isolation.md)'s
//!   business on the egress side and an operator's on the ingress side; this module takes a
//!   `rustls::ServerConfig` and uses it.

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::rustls;

/// Which ALPN protocol a completed handshake selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Negotiated {
    /// `h2`.
    Http2,
    /// `http/1.1`, or no ALPN at all.
    Http1,
}

impl Negotiated {
    /// Classify what the peer and the configuration agreed on.
    ///
    /// A peer that offered nothing is HTTP/1.1: RFC 7301 makes ALPN optional, and a client that omits
    /// it is asking for the protocol that existed first. A peer that offered only protocols this
    /// listener does not serve is *not* silently downgraded — [`accept`] refuses it before this is
    /// asked.
    pub(crate) fn from_alpn(protocol: Option<&[u8]>) -> Self {
        match protocol {
            Some(b"h2") => Self::Http2,
            _ => Self::Http1,
        }
    }
}

/// Why a TLS connection could not be established.
#[derive(Debug)]
pub(crate) enum TlsError {
    /// The handshake failed: a protocol error, an unsupported client, an untrusted name.
    Handshake(String),
    /// The peer sent nothing, or the listener's own timeout expired.
    Idle,
}

impl TlsError {
    /// One line for a trace or a log. Never includes key material.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::Handshake(detail) => detail.clone(),
            Self::Idle => "the client did not begin a handshake in time".to_owned(),
        }
    }
}

/// Read a ClientHello, select a configuration, finish the handshake, and report what was negotiated.
///
/// `select` is called with the SNI name the peer asked for, so a listener with several certificates
/// can answer the right one. It is a closure rather than a map because a deployment may resolve a
/// certificate from a store this crate knows nothing about.
///
/// The whole handshake is bounded by `timeout`: a peer that opens a socket and stalls costs the
/// holder, exactly as the HTTP head bound does. A handshake is the cheapest thing to attack and the
/// most expensive to hold open, because nothing about it is application code.
pub(crate) async fn accept<S, F>(
    stream: S,
    timeout: std::time::Duration,
    select: F,
) -> Result<(tokio_rustls::server::TlsStream<S>, Negotiated), TlsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    F: FnOnce(Option<&str>) -> Arc<rustls::ServerConfig>,
{
    let handshake = async {
        let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
        let start = acceptor
            .await
            .map_err(|error| TlsError::Handshake(error.to_string()))?;
        let server_name = start.client_hello().server_name().map(str::to_owned);
        let configuration = select(server_name.as_deref());
        // A configuration with no ALPN protocols would accept a peer that offered none and refuse one
        // that offered any, which is the opposite of a default. `rustls` itself refuses a mismatch, so
        // this only records the outcome.
        let stream = start
            .into_stream(configuration)
            .await
            .map_err(|error| TlsError::Handshake(error.to_string()))?;
        let negotiated = Negotiated::from_alpn(stream.get_ref().1.alpn_protocol());
        Ok::<_, TlsError>((stream, negotiated))
    };

    match tokio::time::timeout(timeout, handshake).await {
        Ok(result) => result,
        Err(_) => Err(TlsError::Idle),
    }
}

/// Write a plaintext refusal on a stream that already completed a handshake, then close.
///
/// Used when the negotiated protocol is one the listener does not serve. A TLS connection cannot
/// simply drop the socket with no bytes: the peer would see a truncated session with no status, which
/// is indistinguishable from the network failing.
pub(crate) async fn write_refusal<S>(stream: &mut S, status: &str, timeout: std::time::Duration)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let response = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    let _ = tokio::time::timeout(timeout, stream.write_all(response.as_bytes())).await;
    let _ = tokio::time::timeout(timeout, stream.shutdown()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_selects_h2_only_for_h2() {
        assert_eq!(Negotiated::from_alpn(Some(b"h2")), Negotiated::Http2);
        assert_eq!(Negotiated::from_alpn(Some(b"http/1.1")), Negotiated::Http1);
        assert_eq!(
            Negotiated::from_alpn(None),
            Negotiated::Http1,
            "ALPN is optional (RFC 7301); no offer means the original protocol"
        );
        assert_eq!(
            Negotiated::from_alpn(Some(b"spdy/3")),
            Negotiated::Http1,
            "an identifier we do not serve is not h2"
        );
    }

    #[test]
    fn every_error_has_a_reason_that_names_it() {
        assert!(TlsError::Idle.reason().contains("handshake"));
        assert_eq!(
            TlsError::Handshake("bad record".to_owned()).reason(),
            "bad record"
        );
    }
}
