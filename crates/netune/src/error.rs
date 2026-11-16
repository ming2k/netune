//! Typed transport failures with an explicit retry verdict.
//!
//! The enum is the narrow error vocabulary. The public attempt boundary wraps it
//! in [`AttemptError`], which carries the trace snapshot that proves what the
//! transport recorded. A failure without evidence is not a reviewable failure.

use std::ops::Deref;
use std::time::Duration;

use netune_http1::HttpError;
use netune_trace::{
    Diagnose, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, RetryVerdict, TraceSnapshot,
};

/// Specific reason authority parsing or DNS resolution failed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolveErrorKind {
    /// Authority syntax or port was invalid (non-retryable configuration error).
    InvalidAuthority,
    /// DNS resolution exceeded the connection deadline (retryable).
    Timeout,
    /// DNS resolution returned zero usable addresses (retryable).
    Empty,
    /// Underlying resolver or OS lookup failure (retryable).
    Failed,
}

/// Structured failure from authority parsing or DNS resolution.
#[non_exhaustive]
#[derive(Debug)]
pub struct ResolveError {
    /// Classification of the resolution failure.
    pub kind: ResolveErrorKind,
    /// Target host or authority that failed to resolve.
    pub host: String,
    /// Human-readable error detail.
    pub message: String,
    /// Underlying OS I/O error, when available.
    pub source: Option<std::io::Error>,
}

impl ResolveError {
    /// Construct a resolution failure with explicit kind, target host, and detail message.
    pub fn new(
        kind: ResolveErrorKind,
        host: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            host: host.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Attach the underlying OS I/O error.
    #[must_use]
    pub fn with_source(mut self, source: std::io::Error) -> Self {
        self.source = Some(source);
        self
    }

    /// Authority syntax or port could not be parsed.
    pub fn invalid_authority(authority: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ResolveErrorKind::InvalidAuthority, authority, message)
    }

    /// DNS resolution exceeded the allowed connection deadline.
    pub fn timeout(host: impl Into<String>, limit: Duration) -> Self {
        let host = host.into();
        let message = format!(
            "DNS resolution for {host} exceeded the {} ms connect timeout",
            limit.as_millis()
        );
        Self::new(ResolveErrorKind::Timeout, host, message)
    }

    /// DNS resolution yielded no addresses for `host`.
    pub fn empty(host: impl Into<String>) -> Self {
        let host = host.into();
        let message = format!("no addresses found for {host}");
        Self::new(ResolveErrorKind::Empty, host, message)
    }

    /// Underlying OS/resolver I/O error.
    pub fn io(host: impl Into<String>, error: std::io::Error) -> Self {
        let host = host.into();
        let message = format!("{host}: {error}");
        Self::new(ResolveErrorKind::Failed, host, message).with_source(error)
    }

    /// Whether resolution failed because the deadline expired.
    pub fn is_timeout(&self) -> bool {
        self.kind == ResolveErrorKind::Timeout
            || self
                .source
                .as_ref()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::TimedOut)
    }

    /// Whether another attempt could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        !matches!(self.kind, ResolveErrorKind::InvalidAuthority)
    }

    /// Diagnostic code and retry verdict matching this resolution failure.
    pub const fn diagnostic_code(&self) -> DiagnosticCode {
        match self.kind {
            ResolveErrorKind::InvalidAuthority => DiagnosticCode::EGRESS_CONFIG,
            ResolveErrorKind::Timeout => DiagnosticCode::EGRESS_TIMEOUT,
            ResolveErrorKind::Empty | ResolveErrorKind::Failed => DiagnosticCode::EGRESS_DNS_FAILED,
        }
    }
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

/// Category of connection-establishment failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectErrorKind {
    /// Timed out waiting for socket connect or handshake completion.
    Timeout,
    /// Socket or stream I/O failure (`std::io::ErrorKind` preserved).
    Io(std::io::ErrorKind),
    /// Invalid configuration, URL, authority, or unknown profile/engine.
    Config,
    /// TLS handshake, verifier, or session parameter failure.
    Tls,
    /// Proxy tunnel negotiation or relay failure.
    Proxy,
    /// Higher-level handshake or stream failure during connect/upgrade.
    Protocol,
}

/// Structured failure from connection establishment (TCP, TLS, proxy, or handshake).
#[non_exhaustive]
#[derive(Debug)]
pub struct ConnectError {
    /// Handshake/connect phase where the failure occurred.
    pub phase: DiagnosticPhase,
    /// Classification of the connection error.
    pub kind: ConnectErrorKind,
    /// Peer address or server name, when known.
    pub peer: Option<String>,
    /// Human-readable error detail.
    pub message: String,
    /// Underlying source error, when available.
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl ConnectError {
    /// Construct a connection-establishment failure.
    pub fn new(phase: DiagnosticPhase, kind: ConnectErrorKind, message: impl Into<String>) -> Self {
        Self {
            phase,
            kind,
            peer: None,
            message: message.into(),
            source: None,
        }
    }

    /// Attach the peer/authority string associated with this failure.
    #[must_use]
    pub fn with_peer(mut self, peer: impl Into<String>) -> Self {
        self.peer = Some(peer.into());
        self
    }

    /// Attach the underlying error cause.
    #[must_use]
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// Handshake or socket connect exceeded its timeout budget.
    pub fn timeout(
        phase: DiagnosticPhase,
        peer: impl Into<String>,
        phase_label: &str,
        limit: Duration,
    ) -> Self {
        let peer = peer.into();
        let message = format!(
            "{phase_label} with {peer} exceeded {} ms",
            limit.as_millis()
        );
        Self::new(phase, ConnectErrorKind::Timeout, message).with_peer(peer)
    }

    /// OS or transport I/O error during connection establishment.
    pub fn io(phase: DiagnosticPhase, peer: impl Into<String>, error: std::io::Error) -> Self {
        let peer = peer.into();
        let kind = ConnectErrorKind::Io(error.kind());
        let message = format!("{peer}: {error}");
        Self::new(phase, kind, message)
            .with_peer(peer)
            .with_source(error)
    }

    /// Configuration, profile, or URL validation error.
    pub fn config(phase: DiagnosticPhase, message: impl Into<String>) -> Self {
        Self::new(phase, ConnectErrorKind::Config, message)
    }

    /// TLS handshake or cryptographic preparation error.
    pub fn tls(peer: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(DiagnosticPhase::Tls, ConnectErrorKind::Tls, message).with_peer(peer)
    }

    /// Proxy tunnel or SOCKS5 association error.
    pub fn proxy(peer: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(DiagnosticPhase::Proxy, ConnectErrorKind::Proxy, message).with_peer(peer)
    }

    /// Higher-level handshake or protocol error during establishment.
    pub fn protocol(
        phase: DiagnosticPhase,
        peer: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(phase, ConnectErrorKind::Protocol, message).with_peer(peer)
    }

    /// Underlying `std::io::ErrorKind`, when this failure originated in OS I/O.
    pub fn io_kind(&self) -> Option<std::io::ErrorKind> {
        match self.kind {
            ConnectErrorKind::Io(kind) => Some(kind),
            _ => self
                .source
                .as_deref()
                .and_then(|err| err.downcast_ref::<std::io::Error>())
                .map(std::io::Error::kind),
        }
    }

    /// Whether the failure was a timeout (explicit deadline or OS `ETIMEDOUT`).
    pub fn is_timeout(&self) -> bool {
        matches!(
            self.kind,
            ConnectErrorKind::Timeout | ConnectErrorKind::Io(std::io::ErrorKind::TimedOut)
        )
    }

    /// Whether another attempt could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            ConnectErrorKind::Timeout | ConnectErrorKind::Io(_) | ConnectErrorKind::Proxy
        )
    }

    /// Diagnostic code aligned with [`netune_trace::DiagnosticCode`].
    pub const fn diagnostic_code(&self) -> DiagnosticCode {
        match self.kind {
            ConnectErrorKind::Timeout | ConnectErrorKind::Io(std::io::ErrorKind::TimedOut) => {
                DiagnosticCode::EGRESS_TIMEOUT
            }
            ConnectErrorKind::Config => DiagnosticCode::EGRESS_CONFIG,
            ConnectErrorKind::Tls => DiagnosticCode::EGRESS_TLS_FAILED,
            ConnectErrorKind::Proxy => DiagnosticCode::EGRESS_PROXY_FAILED,
            ConnectErrorKind::Protocol => match self.phase {
                DiagnosticPhase::WebSocket => DiagnosticCode::EGRESS_WS_FAILED,
                DiagnosticPhase::Http2 => DiagnosticCode::EGRESS_HTTP2_PROTOCOL,
                _ => DiagnosticCode::EGRESS_PROTOCOL,
            },
            ConnectErrorKind::Io(_) => match self.phase {
                DiagnosticPhase::Proxy => DiagnosticCode::EGRESS_PROXY_FAILED,
                DiagnosticPhase::Tls => DiagnosticCode::EGRESS_TLS_FAILED,
                DiagnosticPhase::WebSocket => DiagnosticCode::EGRESS_WS_FAILED,
                DiagnosticPhase::Http2 => DiagnosticCode::EGRESS_HTTP2_HANDSHAKE,
                DiagnosticPhase::Dns => DiagnosticCode::EGRESS_DNS_FAILED,
                DiagnosticPhase::Tcp => DiagnosticCode::EGRESS_TCP_FAILED,
                _ => DiagnosticCode::EGRESS_IO,
            },
        }
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

/// Why a request could not be completed at the transport layer.
#[non_exhaustive]
#[derive(Debug)]
pub enum NetError {
    /// The authority could not be parsed or resolved.
    Resolve(ResolveError),
    /// TCP, proxy tunnel, TLS, or handshake establishment failed.
    Connect(ConnectError),
    /// The peer spoke broken HTTP, exceeded a limit, or the stream ended early.
    Http(HttpError),
    /// The transport failed.
    Io(std::io::Error),
    /// The response used a `Content-Encoding` this client cannot decode.
    UnsupportedEncoding(String),
    /// A `Content-Encoding` stream was corrupt or truncated.
    Decode(String),
    /// The redirect chain exceeded the configured limit.
    TooManyRedirects(u8),
    /// Blocked by egress security policy (non-public / SSRF address).
    Security(String),
    /// A higher-level protocol negotiation or framing failure (e.g. HTTP/2 error).
    Protocol(String),
    /// A protocol-level refusal delivered *before* the request was processed
    /// (HTTP/2 `GOAWAY` covering only earlier streams, or `REFUSED_STREAM`).
    ///
    /// Distinct from [`Self::Protocol`] because replaying it on a fresh
    /// connection is safe: the peer has told us it did not process this stream.
    RetryableProtocol(String),
    /// A bound on the exchange itself expired after the request was
    /// dispatched: the response head or the next body bytes did not arrive in
    /// time.
    ///
    /// Distinct from a connect-phase timeout ([`Self::Connect`]) and from an
    /// OS-level `ETIMEDOUT` ([`Self::Io`]): the connection was established and
    /// the request was sent, so this is never the signature of a stale pooled
    /// socket and is never replayed transparently.
    Timeout {
        /// Exchange phase during which the deadline expired.
        phase: DiagnosticPhase,
        /// What was being waited for, e.g. `"response head"`.
        waiting_for: &'static str,
        /// Configured timeout duration that elapsed.
        limit: Duration,
    },
}

impl NetError {
    /// Structured DNS / authority resolution failure, when this error is one.
    pub fn resolve_error(&self) -> Option<&ResolveError> {
        match self {
            Self::Resolve(error) => Some(error),
            _ => None,
        }
    }

    /// Structured connection-establishment failure, when this error is one.
    pub fn connect_error(&self) -> Option<&ConnectError> {
        match self {
            Self::Connect(error) => Some(error),
            _ => None,
        }
    }

    /// Whether this failure is a timeout (deadline expiry or OS `ETIMEDOUT`).
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::Resolve(error) => error.is_timeout(),
            Self::Connect(error) => error.is_timeout(),
            Self::Io(error) => error.kind() == std::io::ErrorKind::TimedOut,
            Self::Http(HttpError::Io(error)) => error.kind() == std::io::ErrorKind::TimedOut,
            Self::Timeout { .. } => true,
            _ => false,
        }
    }

    /// Underlying `std::io::ErrorKind`, when an OS I/O error caused this failure.
    pub fn io_error_kind(&self) -> Option<std::io::ErrorKind> {
        match self {
            Self::Resolve(error) => error.source.as_ref().map(std::io::Error::kind),
            Self::Connect(error) => error.io_kind(),
            Self::Io(error) => Some(error.kind()),
            Self::Http(HttpError::Io(error)) => Some(error.kind()),
            _ => None,
        }
    }

    /// Stable classification for retry policy and telemetry.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Resolve(_) => "resolve",
            Self::Connect(_) => "connect",
            Self::Http(error) => error.class(),
            Self::Io(_) => "io",
            Self::UnsupportedEncoding(_) => "encoding",
            Self::Decode(_) => "decode",
            Self::TooManyRedirects(_) => "redirect",
            Self::Security(_) => "security",
            Self::Protocol(_) | Self::RetryableProtocol(_) => "protocol",
            Self::Timeout { .. } => "timeout",
        }
    }

    /// Whether another attempt could plausibly succeed.
    ///
    /// A broken HTTP peer will speak the same broken HTTP again, a corrupt body
    /// will decode to garbage again, an invalid configuration/profile stays
    /// invalid, and an unsupported encoding will stay unsupported: only transient
    /// resolution, connect and transport failures are worth retrying.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Resolve(error) => error.is_retryable(),
            Self::Connect(error) => error.is_retryable(),
            Self::Io(_) => true,
            Self::Http(error) => error.is_retryable(),
            Self::RetryableProtocol(_) | Self::Timeout { .. } => true,
            Self::UnsupportedEncoding(_)
            | Self::Decode(_)
            | Self::TooManyRedirects(_)
            | Self::Security(_)
            | Self::Protocol(_) => false,
        }
    }

    /// Whether this failure is the signature of a connection that was already
    /// dead when the request was written to it — the fate of a pooled socket the
    /// peer discarded while it sat idle.
    ///
    /// The predicate is deliberately about *where* the failure happened, not
    /// merely which error type surfaced, because one physical event (a peer
    /// closing an idle socket) reaches this crate through several shapes
    /// depending on how politely the peer closed:
    ///
    /// - a bare `FIN` makes rustls report `UnexpectedEof`, which arrives as
    ///   [`NetError::Io`];
    /// - a courteous `close_notify` makes the codec see a clean end-of-stream,
    ///   which arrives as [`NetError::Http`] with [`HttpError::Incomplete`];
    /// - a `RST` makes the first write fail with `BrokenPipe` or
    ///   `ConnectionReset`.
    ///
    /// All three mean "this socket was gone before the request reached the
    /// peer", so a fresh connection can be tried without the caller ever
    /// observing a failure. Callers must only treat this as safe *before a
    /// response head has been parsed*: past that point the request provably
    /// reached the origin, and re-sending is a policy decision, not a transport
    /// one.
    pub fn is_stale_connection(&self) -> bool {
        fn transient_io(kind: std::io::ErrorKind) -> bool {
            use std::io::ErrorKind::*;
            matches!(
                kind,
                ConnectionReset
                    | ConnectionAborted
                    | ConnectionRefused
                    | BrokenPipe
                    | UnexpectedEof
                    | NotConnected
                    | TimedOut
            )
        }
        match self {
            Self::Io(error) => transient_io(error.kind()),
            Self::Http(HttpError::Io(error)) => transient_io(error.kind()),
            // A stream that ended before a single response byte arrived. The
            // codec reports this the same way whether the peer was courteous
            // (`close_notify`, a clean end-of-stream) or abrupt (`FIN`/`RST`,
            // which rustls turns into `UnexpectedEof`) — both are handled here
            // so one physical event cannot be treated differently depending on
            // which shape it surfaced as.
            Self::Http(HttpError::Incomplete(_)) => true,
            // A peer that refuses the stream before processing it is telling us
            // replay is safe; the socket itself is alive, but a fresh connection
            // is the only way to make progress.
            Self::RetryableProtocol(_) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(what) => write!(f, "resolve failed: {what}"),
            Self::Connect(what) => write!(f, "connect failed: {what}"),
            Self::Http(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "transport error: {error}"),
            Self::UnsupportedEncoding(encoding) => {
                write!(f, "unsupported content-encoding: {encoding}")
            }
            Self::Decode(what) => write!(f, "could not decode response body: {what}"),
            Self::TooManyRedirects(limit) => write!(f, "more than {limit} redirects"),
            Self::Security(what) => write!(f, "security policy: {what}"),
            Self::Protocol(what) => write!(f, "protocol error: {what}"),
            Self::RetryableProtocol(what) => write!(f, "retryable protocol error: {what}"),
            Self::Timeout {
                waiting_for, limit, ..
            } => write!(
                f,
                "timed out after {} ms waiting for the {waiting_for}",
                limit.as_millis()
            ),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve(error) => Some(error),
            Self::Connect(error) => Some(error),
            Self::Http(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl Diagnose for NetError {
    fn diagnostic(&self) -> DiagnosticRecord {
        let (code, phase) = match self {
            Self::Resolve(error) => (error.diagnostic_code(), DiagnosticPhase::Dns),
            Self::Connect(error) => (error.diagnostic_code(), error.phase),
            Self::Http(error) => match error.class() {
                "protocol" => (
                    DiagnosticCode::EGRESS_HTTP1_PROTOCOL,
                    DiagnosticPhase::Http1,
                ),
                "limit" => (DiagnosticCode::EGRESS_HTTP1_LIMIT, DiagnosticPhase::Http1),
                "incomplete" => (
                    DiagnosticCode::EGRESS_HTTP1_INCOMPLETE,
                    DiagnosticPhase::Http1,
                ),
                _ => (DiagnosticCode::EGRESS_HTTP1_IO, DiagnosticPhase::Http1),
            },
            Self::Io(error) => {
                if error.kind() == std::io::ErrorKind::TimedOut {
                    (DiagnosticCode::EGRESS_TIMEOUT, DiagnosticPhase::Unknown)
                } else {
                    (DiagnosticCode::EGRESS_IO, DiagnosticPhase::Unknown)
                }
            }
            Self::UnsupportedEncoding(_) => (
                DiagnosticCode::EGRESS_UNSUPPORTED_ENCODING,
                DiagnosticPhase::Response,
            ),
            Self::Decode(_) => (DiagnosticCode::EGRESS_DECODE, DiagnosticPhase::Response),
            Self::TooManyRedirects(_) => (
                DiagnosticCode::EGRESS_REDIRECT_LIMIT,
                DiagnosticPhase::Response,
            ),
            Self::Security(_) => (DiagnosticCode::EGRESS_SECURITY, DiagnosticPhase::Tcp),
            Self::Protocol(_) => (DiagnosticCode::EGRESS_PROTOCOL, DiagnosticPhase::Unknown),
            Self::RetryableProtocol(_) => {
                (DiagnosticCode::EGRESS_HTTP2_REFUSED, DiagnosticPhase::Http2)
            }
            Self::Timeout { phase, .. } => (DiagnosticCode::EGRESS_TIMEOUT, *phase),
        };
        DiagnosticRecord::new(code)
            .with_phase(phase)
            .with_retry(if self.is_retryable() {
                RetryVerdict::Retryable
            } else {
                RetryVerdict::Terminal
            })
            .with_message(self.to_string())
            .with_field("class", self.class())
    }
}

impl NetError {
    /// The registered diagnostic for this failure.
    pub fn diagnostic(&self) -> DiagnosticRecord {
        <Self as Diagnose>::diagnostic(self)
    }
}

/// A failed public attempt: the narrow error plus the evidence it produced.
///
/// The snapshot is captured at the orchestrator boundary, after every internal
/// producer has finished. It is populated even when the caller selected
/// `Observation::Off`, because failure narration is independent of byte-path
/// measurement cost.
#[derive(Debug)]
pub struct AttemptError {
    error: NetError,
    trace: TraceSnapshot,
    report: DiagnosticRecord,
}

impl AttemptError {
    /// Wrap `error` with the attempt's evidence.
    ///
    /// If no error-level diagnostic was recorded internally, the error's own
    /// classification is appended. If one was recorded, it wins: it is the
    /// producer's more specific account.
    pub fn new(error: NetError, mut trace: TraceSnapshot) -> Self {
        if trace.diagnostics.last_error().is_none() {
            trace.diagnostics.push(error.diagnostic());
        }
        let report = trace
            .diagnostics
            .last_error()
            .cloned()
            .unwrap_or_else(|| error.diagnostic());
        Self {
            error,
            trace,
            report,
        }
    }

    /// Borrow the underlying transport error.
    pub fn error(&self) -> &NetError {
        &self.error
    }

    /// Borrow the attempt trace snapshot captured up to the failure.
    pub fn trace(&self) -> &TraceSnapshot {
        &self.trace
    }

    /// Borrow the primary terminal diagnostic record.
    pub fn diagnostic(&self) -> &DiagnosticRecord {
        &self.report
    }

    /// Derive a structured [`netune_trace::Diagnosis`] from the failure trace.
    pub fn diagnosis(&self) -> netune_trace::Diagnosis {
        self.trace.diagnose()
    }

    /// Consume the attempt error into its `(NetError, TraceSnapshot)` parts.
    pub fn into_parts(self) -> (NetError, TraceSnapshot) {
        (self.error, self.trace)
    }

    /// Wrap an error that happened before any attempt recorder existed.
    ///
    /// The snapshot is still real: it carries the error's diagnostic and a
    /// generated trace id, so a caller never has to treat a configuration
    /// failure as an evidence-free special case.
    pub fn without_evidence(error: NetError) -> Self {
        let snapshot =
            netune_trace::TraceCollector::disabled().snapshot(netune_trace::Fidelity::none());
        Self::new(error, snapshot)
    }
}

impl Deref for AttemptError {
    type Target = NetError;

    fn deref(&self) -> &Self::Target {
        &self.error
    }
}

impl std::fmt::Display for AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for AttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<HttpError> for NetError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

impl From<std::io::Error> for NetError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn connect_error_preserves_phase_timeout_io_kind_and_source() {
        let err = NetError::Connect(ConnectError::timeout(
            DiagnosticPhase::Tls,
            "example.com:443",
            "TLS handshake",
            Duration::from_secs(5),
        ));
        assert!(err.is_timeout());
        assert!(err.is_retryable());
        assert_eq!(err.class(), "connect");
        let diag = err.diagnostic();
        assert_eq!(diag.code, DiagnosticCode::EGRESS_TIMEOUT);
        assert_eq!(diag.phase, DiagnosticPhase::Tls);

        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let err = NetError::Connect(ConnectError::io(
            DiagnosticPhase::Tcp,
            "127.0.0.1:8080",
            refused,
        ));
        assert!(!err.is_timeout());
        assert!(err.is_retryable());
        assert_eq!(
            err.io_error_kind(),
            Some(std::io::ErrorKind::ConnectionRefused)
        );
        let src = err.source().expect("ConnectError source");
        assert!(
            src.source().is_some(),
            "underlying io::Error source preserved"
        );
        assert_eq!(err.diagnostic().code, DiagnosticCode::EGRESS_TCP_FAILED);
    }

    #[test]
    fn config_and_tls_connect_errors_are_non_retryable() {
        let cfg = NetError::Connect(ConnectError::config(DiagnosticPhase::Tls, "bad profile"));
        assert!(!cfg.is_retryable());
        assert_eq!(cfg.diagnostic().code, DiagnosticCode::EGRESS_CONFIG);

        let tls = NetError::Connect(ConnectError::tls("example.com", "bad cert"));
        assert!(!tls.is_retryable());
        assert_eq!(tls.diagnostic().code, DiagnosticCode::EGRESS_TLS_FAILED);

        let resolve_cfg = NetError::Resolve(ResolveError::invalid_authority("bad:port", "bad"));
        assert!(!resolve_cfg.is_retryable());
        assert_eq!(resolve_cfg.diagnostic().code, DiagnosticCode::EGRESS_CONFIG);

        let resolve_timeout = NetError::Resolve(ResolveError::timeout(
            "slow.example",
            Duration::from_secs(2),
        ));
        assert!(resolve_timeout.is_timeout());
        assert!(resolve_timeout.is_retryable());
        assert_eq!(
            resolve_timeout.diagnostic().code,
            DiagnosticCode::EGRESS_TIMEOUT
        );
    }
}
