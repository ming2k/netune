//! Typed transport failures with an explicit retry verdict.
//!
//! The enum is the narrow error vocabulary. The public attempt boundary wraps it
//! in [`AttemptError`], which carries the trace snapshot that proves what the
//! transport recorded. A failure without evidence is not a reviewable failure.

use std::ops::Deref;

use netune_http1::HttpError;
use netune_trace::{
    Diagnose, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, RetryVerdict, TraceSnapshot,
};

/// Why a request could not be completed at the transport layer.
#[derive(Debug)]
pub enum NetError {
    /// The authority could not be resolved.
    Resolve(String),
    /// TCP (or TLS) could not be established.
    Connect(String),
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
}

impl NetError {
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
        }
    }

    /// Whether another attempt could plausibly succeed.
    ///
    /// A broken HTTP peer will speak the same broken HTTP again, a corrupt body
    /// will decode to garbage again, and an unsupported encoding will stay
    /// unsupported: only resolution, connect and transport failures are worth
    /// retrying. This mirrors the retry discipline the previous client derived
    /// from `reqwest`'s error kinds.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Resolve(_) | Self::Connect(_) | Self::Io(_) => true,
            Self::Http(error) => error.is_retryable(),
            Self::RetryableProtocol(_) => true,
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
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl Diagnose for NetError {
    fn diagnostic(&self) -> DiagnosticRecord {
        let (code, phase) = match self {
            Self::Resolve(_) => (DiagnosticCode::EGRESS_DNS_FAILED, DiagnosticPhase::Dns),
            Self::Connect(_) => (DiagnosticCode::EGRESS_TCP_FAILED, DiagnosticPhase::Tcp),
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

    pub fn error(&self) -> &NetError {
        &self.error
    }

    pub fn trace(&self) -> &TraceSnapshot {
        &self.trace
    }

    pub fn diagnostic(&self) -> &DiagnosticRecord {
        &self.report
    }

    pub fn diagnosis(&self) -> netune_trace::Diagnosis {
        self.trace.diagnose()
    }

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
