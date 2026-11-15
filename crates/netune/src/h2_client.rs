//! High-level HTTP/2 client with Akamai fingerprint impersonation (ADR-0006).
//!
//! Orchestrates the full lifecycle over any [`Connector`] (TCP, TLS, or Proxy),
//! records phase boundaries in [`TraceCollector`], and executes requests matching
//! a declared [`H2Fingerprint`].

use http::Method;
use netune_http2::{H2ClientConnection, H2Fingerprint, H2Response};
use netune_trace::{EventKind, TraceCollector};

use crate::connect::{Connector, Target};
use crate::error::NetError;

/// An HTTP/2 client that drives requests with precise Akamai fingerprinting.
pub struct H2Client<C: Connector> {
    connector: C,
    fingerprint: H2Fingerprint,
    handshake_timeout: Option<std::time::Duration>,
}

impl<C: Connector> H2Client<C> {
    /// Create a new H2 client over `connector` using `fingerprint`.
    pub fn new(connector: C, fingerprint: H2Fingerprint) -> Self {
        Self {
            connector,
            fingerprint,
            handshake_timeout: Some(crate::handshake::DEFAULT_HANDSHAKE_TIMEOUT),
        }
    }

    /// Replace the HTTP/2 preface + SETTINGS bound. `None` removes it; only do
    /// that when an outer deadline reports the stall as a connection failure.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Access the configured fingerprint.
    pub fn fingerprint(&self) -> &H2Fingerprint {
        &self.fingerprint
    }

    /// Execute a request over a freshly negotiated HTTP/2 connection.
    pub async fn send(
        &self,
        target: &Target,
        method: Method,
        path: &str,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
        recorder: &TraceCollector,
    ) -> Result<H2Response, NetError> {
        let established = self.connector.connect(target, recorder).await?;

        recorder.mark(EventKind::RequestWriteStart, 0, 0);

        let scheme = if target.tls_server_name().is_some() {
            "https"
        } else {
            "http"
        };
        let authority = &target.authority;

        let mut h2 = crate::handshake::bound(
            self.handshake_timeout,
            netune_trace::DiagnosticPhase::Http2,
            "HTTP/2 handshake",
            authority,
            recorder,
            H2ClientConnection::handshake(established.stream, self.fingerprint.clone()),
        )
        .await?
        .map_err(|e| NetError::Protocol(format!("HTTP/2 handshake: {e}")))?;

        let response = h2
            .request(
                method.as_str(),
                authority,
                scheme,
                path,
                extra_headers,
                body,
            )
            .await
            .map_err(|e| NetError::Protocol(format!("HTTP/2 request: {e}")))?;

        recorder.mark(EventKind::RequestWriteEnd, response.body.len() as u32, 0);
        recorder.mark(EventKind::HeadComplete, response.status as u32, 0);
        recorder.mark(EventKind::BodyEnd, response.body.len() as u32, 0);

        Ok(response)
    }
}

#[cfg(test)]
mod tests;
