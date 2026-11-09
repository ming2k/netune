//! Listener configuration: the bounds an operator grants.
//!
//! Every field here is a *bound*, never a policy. "No request may spend more than 15 s
//! producing its head" is a bound this transport enforces without knowing anything about
//! the application; "paths starting with `/admin` require authorization" is policy and
//! belongs above this crate.
//!
//! # Why the defaults are hostile
//!
//! A listener is addressed by anyone who can reach the port, so an unbounded default is not
//! a neutral choice — it is a promise to be exhausted. Every default here is chosen for a
//! public port: tight codec limits, a finite connection cap, a finite reuse count, four
//! separate phase timeouts and a bounded trace ring.
//!
//! # Why every timeout is separate
//!
//! The phases of an exchange fail for different reasons and demand different responses. A
//! peer that will not produce a head (slow loris) is hostile and cheap to give up on; a peer
//! that will not finish a body may be uploading legitimately on a bad link; a handler that
//! will not return is our own bug; a peer that will not read our response is a slow-read
//! attack. Collapsing them into one number makes the transport unable to tell an operator
//! which of the four happened.

use std::sync::Arc;
use std::time::Duration;

use netune_http1::Limits;
use netune_trace::{Event, EventLog, TraceSink};

#[cfg(feature = "tls")]
use tokio_rustls::rustls as netune_rustls;

use crate::service::IngressTrace;

/// Which application protocols the listener speaks.
///
/// Both are bounded by the same admission control and the same trace contract; the
/// difference is the wire and the concurrency model. A listener that offers HTTP/2 to a
/// client that asked for it does not also offer HTTP/1.1 on the same connection: the
/// protocol is decided once, at the preface or at ALPN, and never upgraded in place — an
/// in-place upgrade is a request-smuggling surface and a second parser on one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocols {
    /// Serve HTTP/1.1 (plaintext, and over TLS when the ALPN offer permits it).
    pub http1: bool,
    /// Serve HTTP/2 (over TLS via ALPN, or plaintext as a prior-knowledge connection).
    pub http2: bool,
}

impl Protocols {
    /// Both protocols, which is what a public listener should offer.
    pub const BOTH: Self = Self {
        http1: true,
        http2: true,
    };
    /// HTTP/1.1 only.
    pub const HTTP1: Self = Self {
        http1: true,
        http2: false,
    };
    /// HTTP/2 only.
    pub const HTTP2: Self = Self {
        http1: false,
        http2: true,
    };

    /// What this build can actually serve.
    ///
    /// The default is `BOTH` when the `http2` feature is compiled in and `HTTP1` otherwise, because a
    /// default that cannot bind is not a default. Asking for `HTTP2` explicitly in a build that omits
    /// the codec is still a hard error at bind time — that is a configuration asking for something the
    /// artifact cannot do, and failing loudly beats accepting connections and closing them.
    pub const fn available() -> Self {
        if cfg!(feature = "http2") {
            Self::BOTH
        } else {
            Self::HTTP1
        }
    }

    /// The ALPN wire identifiers this configuration offers, in preference order.
    ///
    /// Public because a TLS terminator in front of this listener needs exactly this list, and because
    /// the order *is* the preference: `h2` first is what makes a browser pick HTTP/2, and reversing it
    /// would silently keep every client on HTTP/1.1.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.http2 {
            out.push(b"h2".to_vec());
        }
        if self.http1 {
            out.push(b"http/1.1".to_vec());
        }
        out
    }

    pub(crate) fn validate(&self) -> Result<(), crate::service::BindError> {
        if !self.http1 && !self.http2 {
            return Err(crate::service::BindError::Invalid(
                "no protocol is enabled: the listener would accept and immediately close",
            ));
        }
        Ok(())
    }
}

impl Default for Protocols {
    fn default() -> Self {
        Self::available()
    }
}

/// How the transport bounds one connection, and where its trace goes.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Codec bounds: head bytes, header count, chunk and body size.
    pub limits: Limits,
    /// Upper bound on simultaneously served connections.
    ///
    /// A connection that cannot be admitted is closed immediately rather than queued
    /// without limit: an unbounded accept queue converts a burst into memory exhaustion,
    /// and a client told "no" quickly can retry while one queued silently cannot.
    pub max_connections: usize,
    /// Upper bound on requests served on one connection before it is closed.
    ///
    /// Keep-alive is not a promise of indefinite reuse: a connection that has served its
    /// quota gets `Connection: close` on the last response. This is what stops a long-lived
    /// client from pinning a slot forever, and it gives a slow configuration rollout a
    /// natural drain.
    pub max_requests_per_connection: u32,
    /// Time allowed between accept and a complete request head (the slow-loris bound).
    pub head_timeout: Duration,
    /// Time allowed between a complete head and a fully consumed request body.
    pub body_timeout: Duration,
    /// Time allowed for the handler plus the response it produces.
    pub handler_timeout: Duration,
    /// Time allowed for one write of the response to make progress.
    ///
    /// This is the slow-*read* bound: a peer that opens its receive window one byte at a
    /// time must not be able to hold a worker slot for `handler_timeout` per response. Each
    /// write gets this long, which bounds a stalled peer without punishing a slow link.
    pub write_timeout: Duration,
    /// How long a shutdown waits for in-flight requests before closing their sockets.
    pub drain_timeout: Duration,
    /// Whether a connection may serve more than one request.
    pub keep_alive: bool,
    /// Whether an HTTP/1.1 request without exactly one valid `Host` is refused.
    ///
    /// `true` by default, because RFC 9112 §3.2 makes it mandatory and because a request
    /// with no `Host` (or two, or one that disagrees with an absolute-form target) is what
    /// lets two hops route it to different origins. A listener that turns this off is
    /// opting out of a protocol requirement, which is why it is a named switch rather than
    /// a silent tolerance.
    pub require_host: bool,
    /// Whether `Expect: 100-continue` is honoured.
    ///
    /// When set, a request carrying that expectation gets an interim `100 Continue` before
    /// its body is read, so a client does not stall waiting for permission it will never
    /// receive. Turning this off is correct only for a listener that expects no
    /// expectation-bearing clients; a client that sends one and waits would then time out.
    pub expect_continue: bool,
    /// Which application protocols the listener serves.
    pub protocols: Protocols,
    /// TLS termination, when the listener terminates it itself.
    ///
    /// `None` means plaintext: the listener speaks HTTP directly and something else must terminate TLS
    /// if the deployment needs it. `Some` moves the handshake inside the trace, which is the only way
    /// the handshake's cost and the ALPN decision can be reported rather than assumed.
    #[cfg(feature = "tls")]
    pub tls: Option<TlsTermination>,
    /// HTTP/2 codec bounds, used only when `protocols.http2`.
    pub http2: crate::config::H2Ingress,
    /// Capacity of each connection's trace ring.
    pub trace_capacity: usize,
    /// Where each connection's trace is delivered when the connection ends (`ADR-0010`).
    ///
    /// `None` by default, so a server nobody observes pays nothing. Install one and every
    /// finished connection arrives as a complete [`IngressTrace`].
    pub trace_sink: Option<Arc<dyn TraceObserver>>,
}

/// HTTP/2-specific ingress bounds.
///
/// These mirror the SETTINGS this listener advertises, so the number an operator sets is
/// the number the peer is *told*, rather than a number enforced after the fact. A bound the
/// peer was not told about is a bound that shows up as a mid-request failure instead of as
/// a limit the peer could have respected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Ingress {
    /// Concurrent streams one connection may have open (advertised
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`).
    pub max_concurrent_streams: u32,
    /// Per-stream receive window this listener advertises
    /// (`SETTINGS_INITIAL_WINDOW_SIZE`).
    ///
    /// Also the per-stream request-body ceiling: the peer cannot send more than this until
    /// the handler consumes bytes and a `WINDOW_UPDATE` replenishes it, so memory is bounded
    /// by the window rather than by trust.
    pub initial_window_size: u32,
    /// Connection-level receive window.
    pub connection_window_size: u32,
    /// Largest frame this listener accepts (`SETTINGS_MAX_FRAME_SIZE`).
    pub max_frame_size: u32,
    /// Header table size advertised to the peer's HPACK encoder
    /// (`SETTINGS_HEADER_TABLE_SIZE`).
    pub header_table_size: u32,
    /// Advertised `SETTINGS_MAX_HEADER_LIST_SIZE`, in bytes.
    pub max_header_list_size: u32,
}

impl H2Ingress {
    /// Bounds sized for a public port: 128 streams, 1 MiB windows, 16 KiB frames.
    pub const fn for_ingress() -> Self {
        Self {
            max_concurrent_streams: 128,
            initial_window_size: 1024 * 1024,
            connection_window_size: 4 * 1024 * 1024,
            max_frame_size: 16 * 1024,
            header_table_size: 4096,
            max_header_list_size: 32 * 1024,
        }
    }

    /// The SETTINGS parameter list this configuration advertises, in wire order.
    ///
    /// Order is a fingerprint (§6.5), and the values are the bounds the *peer* must respect, so they
    /// come from the same struct that validates them.
    ///
    /// Absent when the build does not include the HTTP/2 codec at all, which is the only case where
    /// there is no SETTINGS to advertise.
    #[cfg(feature = "http2")]
    pub(crate) fn parameters(&self) -> Vec<(u16, u32)> {
        self.local_settings().parameters()
    }

    /// The codec-level bounds matching this configuration.
    #[cfg(feature = "http2")]
    pub(crate) fn local_settings(&self) -> netune_http2::LocalSettings {
        netune_http2::LocalSettings {
            header_table_size: self.header_table_size,
            max_concurrent_streams: self.max_concurrent_streams,
            initial_window_size: self.initial_window_size,
            max_frame_size: self.max_frame_size,
            max_header_list_size: self.max_header_list_size,
            enable_push: false,
        }
    }

    /// Reject values RFC 9113 §6.5.2 forbids.
    #[cfg_attr(not(feature = "http2"), allow(dead_code))]
    pub(crate) fn validate(&self) -> Result<(), crate::service::BindError> {
        if self.max_concurrent_streams == 0 {
            return Err(crate::service::BindError::Invalid(
                "http2.max_concurrent_streams must be at least 1",
            ));
        }
        if self.initial_window_size > 0x7FFF_FFFF {
            return Err(crate::service::BindError::Invalid(
                "http2.initial_window_size exceeds 2^31-1",
            ));
        }
        if self.connection_window_size <= 65_535 {
            return Err(crate::service::BindError::Invalid(
                "http2.connection_window_size must exceed the protocol default 65535",
            ));
        }
        if !(16_384..=16_777_215).contains(&self.max_frame_size) {
            return Err(crate::service::BindError::Invalid(
                "http2.max_frame_size must be within 16384..=16777215",
            ));
        }
        Ok(())
    }
}

impl Default for H2Ingress {
    fn default() -> Self {
        Self::for_ingress()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            limits: Limits::for_ingress(),
            max_connections: 512,
            max_requests_per_connection: 1_000,
            head_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(60),
            handler_timeout: Duration::from_secs(120),
            write_timeout: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(30),
            keep_alive: true,
            require_host: true,
            expect_continue: true,
            protocols: Protocols::available(),
            #[cfg(feature = "tls")]
            tls: None,
            http2: H2Ingress::for_ingress(),
            trace_capacity: 1024,
            trace_sink: None,
        }
    }
}

impl ServerConfig {
    /// A configuration sized for a test: short timeouts, no long-lived reuse.
    ///
    /// Present so tests do not each invent their own timings and drift apart. The bounds it
    /// tightens are exactly the ones a test would otherwise wait on; nothing about the wire
    /// behaviour changes.
    pub const fn for_tests() -> Self {
        Self {
            limits: Limits::for_ingress(),
            max_connections: 8,
            max_requests_per_connection: 8,
            head_timeout: Duration::from_secs(2),
            body_timeout: Duration::from_secs(2),
            handler_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            drain_timeout: Duration::from_secs(2),
            keep_alive: true,
            require_host: true,
            expect_continue: true,
            protocols: Protocols::available(),
            #[cfg(feature = "tls")]
            tls: None,
            http2: H2Ingress::for_ingress(),
            trace_capacity: 128,
            trace_sink: None,
        }
    }

    /// Deliver every finished connection's trace to `observer`.
    #[must_use]
    pub fn with_trace_sink(mut self, observer: Arc<dyn TraceObserver>) -> Self {
        self.trace_sink = Some(observer);
        self
    }

    /// The codec limits, named separately for a caller that only wants to tighten them.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Cap simultaneous connections.
    #[must_use]
    pub const fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Cap how many requests one connection serves before it is closed.
    #[must_use]
    pub const fn with_max_requests_per_connection(mut self, max: u32) -> Self {
        self.max_requests_per_connection = max;
        self
    }

    /// Set the slow-peer head bound.
    #[must_use]
    pub const fn with_head_timeout(mut self, timeout: Duration) -> Self {
        self.head_timeout = timeout;
        self
    }

    /// Set the body-read bound.
    #[must_use]
    pub const fn with_body_timeout(mut self, timeout: Duration) -> Self {
        self.body_timeout = timeout;
        self
    }

    /// Set the handler bound.
    #[must_use]
    pub const fn with_handler_timeout(mut self, timeout: Duration) -> Self {
        self.handler_timeout = timeout;
        self
    }

    /// Set the slow-read bound, per write.
    #[must_use]
    pub const fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// Set the shutdown drain bound.
    #[must_use]
    pub const fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Terminate TLS with `tls`.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls(mut self, tls: TlsTermination) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Serve only the protocols in `protocols`.
    #[must_use]
    pub const fn with_protocols(mut self, protocols: Protocols) -> Self {
        self.protocols = protocols;
        self
    }

    /// Replace the HTTP/2 ingress bounds.
    #[must_use]
    pub const fn with_http2(mut self, http2: H2Ingress) -> Self {
        self.http2 = http2;
        self
    }

    /// Refuse (or accept) an HTTP/1.1 request without a usable `Host`.
    #[must_use]
    pub const fn with_host_requirement(mut self, required: bool) -> Self {
        self.require_host = required;
        self
    }

    /// Honour (or ignore) `Expect: 100-continue`.
    #[must_use]
    pub const fn with_expect_continue(mut self, honour: bool) -> Self {
        self.expect_continue = honour;
        self
    }

    /// Reject any value that would make a bound useless.
    ///
    /// Zero is refused rather than silently treated as one: a listener that accepts nothing
    /// or bounds nothing is a configuration error, and reporting it at bind time is cheaper
    /// than discovering it as a hang.
    pub(crate) fn validate(&self) -> Result<(), crate::service::BindError> {
        if self.max_connections == 0 {
            return Err(crate::service::BindError::Invalid(
                "max_connections must be at least 1",
            ));
        }
        if self.max_requests_per_connection == 0 {
            return Err(crate::service::BindError::Invalid(
                "max_requests_per_connection must be at least 1",
            ));
        }
        if self.limits.max_head_bytes == 0 || self.limits.max_headers == 0 {
            return Err(crate::service::BindError::Invalid(
                "codec limits must be non-zero",
            ));
        }
        if self.limits.max_body_bytes == 0 || self.limits.max_chunk_bytes == 0 {
            return Err(crate::service::BindError::Invalid(
                "body and chunk bounds must be non-zero",
            ));
        }
        for (name, timeout) in [
            ("head_timeout", self.head_timeout),
            ("body_timeout", self.body_timeout),
            ("handler_timeout", self.handler_timeout),
            ("write_timeout", self.write_timeout),
            ("drain_timeout", self.drain_timeout),
        ] {
            if timeout.is_zero() {
                return Err(crate::service::BindError::Invalid(match name {
                    "head_timeout" => "head_timeout must be non-zero",
                    "body_timeout" => "body_timeout must be non-zero",
                    "handler_timeout" => "handler_timeout must be non-zero",
                    "write_timeout" => "write_timeout must be non-zero",
                    _ => "drain_timeout must be non-zero",
                }));
            }
        }
        if self.trace_capacity == 0 {
            return Err(crate::service::BindError::Invalid(
                "trace_capacity must be at least 1",
            ));
        }
        self.protocols.validate()?;
        #[cfg(feature = "tls")]
        if let Some(tls) = &self.tls {
            if self.protocols.alpn().is_empty() {
                return Err(crate::service::BindError::Invalid(
                    "a TLS listener must offer at least one ALPN protocol",
                ));
            }
            // The configuration must actually advertise what the listener claims to serve, or ALPN
            // would select something the dispatcher then refuses.
            let advertised: Vec<&[u8]> = tls
                .configured_alpn
                .iter()
                .map(std::vec::Vec::as_slice)
                .collect();
            for protocol in self.protocols.alpn() {
                if !advertised.contains(&protocol.as_slice()) {
                    return Err(crate::service::BindError::Invalid(
                        "the TLS configuration's ALPN list does not advertise every protocol `protocols` serves",
                    ));
                }
            }
        }
        #[cfg(feature = "http2")]
        if self.protocols.http2 {
            self.http2.validate()?;
        }
        // A configuration that asks for a protocol the build cannot speak must fail at bind time.
        // Accepting and then closing every such connection would look like a network fault to the
        // operator and like a broken server to the client.
        #[cfg(not(feature = "http2"))]
        if self.protocols.http2 {
            return Err(crate::service::BindError::Invalid(
                "protocols.http2 is enabled but this build omits the `http2` feature",
            ));
        }
        Ok(())
    }
}

/// Chooses a `rustls` configuration for one connection from the SNI name the peer sent.
///
/// A named alias rather than an inline type: the signature appears in two public places, and a closure
/// type spelled twice is one place for them to disagree.
#[cfg(feature = "tls")]
pub type ConfigSelector =
    Arc<dyn Fn(Option<&str>) -> Arc<netune_rustls::ServerConfig> + Send + Sync>;

/// TLS termination for the listener.
///
/// The configuration is selected per connection from the SNI the peer sent, because a listener may hold
/// several certificates and serving the wrong one to the wrong name is a silent security failure. The
/// closure form is what lets a deployment resolve a certificate from a store this crate knows nothing
/// about.
#[cfg(feature = "tls")]
pub struct TlsTermination {
    /// Chooses the `rustls` configuration for a connection, given the SNI name it asked for.
    pub select: ConfigSelector,
    /// The ALPN protocols the selected configurations advertise, for the bind-time consistency check.
    ///
    /// Declared rather than introspected: `rustls::ServerConfig` exposes its ALPN list, but a listener
    /// may build a *different* configuration per SNI, and a check that read only one of them would pass
    /// while another served the wrong set.
    pub configured_alpn: Vec<Vec<u8>>,
}

#[cfg(feature = "tls")]
impl Clone for TlsTermination {
    fn clone(&self) -> Self {
        Self {
            select: Arc::clone(&self.select),
            configured_alpn: self.configured_alpn.clone(),
        }
    }
}

#[cfg(feature = "tls")]
impl std::fmt::Debug for TlsTermination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTermination")
            .field("alpn", &self.configured_alpn)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "tls")]
impl TlsTermination {
    /// One configuration for every SNI, which is the common single-certificate case.
    pub fn single(config: Arc<netune_rustls::ServerConfig>) -> Self {
        let configured_alpn = config
            .alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        Self {
            select: Arc::new(move |_name| Arc::clone(&config)),
            configured_alpn,
        }
    }

    /// One configuration per SNI name, with a fallback for a name no rule matched.
    ///
    /// The fallback is required rather than optional: a client that sends no SNI (an IP address, an old
    /// client) must still be answered, and refusing it would break the case a certificate's SAN covers
    /// an address.
    pub fn per_name(
        rules: Vec<(String, Arc<netune_rustls::ServerConfig>)>,
        fallback: Arc<netune_rustls::ServerConfig>,
    ) -> Self {
        let mut configured_alpn: Vec<Vec<u8>> = Vec::new();
        for (_, config) in &rules {
            for protocol in &config.alpn_protocols {
                if !configured_alpn.contains(protocol) {
                    configured_alpn.push(protocol.clone());
                }
            }
        }
        for protocol in &fallback.alpn_protocols {
            if !configured_alpn.contains(protocol) {
                configured_alpn.push(protocol.clone());
            }
        }
        Self {
            select: Arc::new(move |name| {
                name.and_then(|name| {
                    rules
                        .iter()
                        .find(|(rule, _)| rule.eq_ignore_ascii_case(name))
                        .map(|(_, config)| Arc::clone(config))
                })
                .unwrap_or_else(|| Arc::clone(&fallback))
            }),
            configured_alpn,
        }
    }
}

/// Receives each finished connection's ingress trace.
///
/// Implemented by the transport's consumer, never by the transport. The unit is the
/// **connection**, not the event: an ingress trace spans a socket's whole life, and a
/// consumer that wants per-request numbers derives them from the exchanges inside.
pub trait TraceObserver: Send + Sync + std::fmt::Debug {
    /// Deliver one finished connection's trace.
    ///
    /// Called after the connection task ends, so nothing is still writing to the recorder.
    /// It must not block: it runs on the connection's task.
    fn connection_finished(&self, trace: IngressTrace);
}

/// A [`TraceObserver`] that forwards a connection's events to a [`TraceSink`].
///
/// The bridge for a consumer that already has one sink collecting both directions: it
/// replays the finished trace's events into that sink, so an ingress connection and an
/// egress attempt land in the same place without the consumer holding two types.
#[derive(Debug)]
pub struct SinkObserver {
    sink: Arc<dyn TraceSink>,
}

impl SinkObserver {
    /// Wrap `sink` so finished ingress connections are replayed into it.
    pub fn new(sink: Arc<dyn TraceSink>) -> Self {
        Self { sink }
    }
}

impl TraceObserver for SinkObserver {
    fn connection_finished(&self, trace: IngressTrace) {
        for event in trace.log.iter() {
            let _ = self.sink.event(event);
        }
    }
}

/// A [`TraceObserver`] that keeps every finished trace.
///
/// Useful for a test or an operator's diagnostic endpoint; unbounded by design, so a
/// production consumer should prefer [`SinkObserver`] or its own bounded store.
#[derive(Debug, Default)]
pub struct CollectingObserver(pub std::sync::Mutex<Vec<IngressTrace>>);

impl TraceObserver for CollectingObserver {
    fn connection_finished(&self, trace: IngressTrace) {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(trace);
    }
}

impl CollectingObserver {
    /// Take every trace collected so far.
    pub fn take(&self) -> Vec<IngressTrace> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|error| error.into_inner()))
    }

    /// Borrow the collected traces.
    pub fn peek(&self) -> Vec<IngressTrace> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

/// Rebuild an [`EventLog`] from a streamed event, for an observer that buffers events itself.
///
/// Exposed because a consumer writing its own observer needs exactly this and nothing else;
/// leaving it to each consumer invites them to get `push_at` wrong.
pub fn log_from_events(events: impl IntoIterator<Item = Event>) -> EventLog {
    let events: Vec<Event> = events.into_iter().collect();
    let mut log = EventLog::with_capacity(events.len().max(1));
    for event in events {
        log.push_at(event.at_ns, event.kind, event.a, event.b);
    }
    log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_without_a_sink_is_the_default() {
        assert!(ServerConfig::default().trace_sink.is_none());
        assert!(ServerConfig::for_tests().trace_sink.is_none());
    }

    #[test]
    fn defaults_are_safe_on_a_public_port() {
        let config = ServerConfig::default();
        assert_eq!(config.limits, Limits::for_ingress());
        assert!(config.require_host, "the RFC makes Host mandatory");
        assert!(config.expect_continue);
        assert!(config.max_connections > 0);
        assert!(config.max_requests_per_connection > 0);
        assert!(config.head_timeout < config.body_timeout);
    }

    #[test]
    fn a_zero_connection_cap_is_refused_at_bind_time() {
        let config = ServerConfig::default().with_max_connections(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_codec_bounds_are_refused() {
        let config = ServerConfig::default().with_limits(Limits {
            max_head_bytes: 0,
            ..Limits::for_ingress()
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_zero_trace_ring_is_refused() {
        let config = ServerConfig {
            trace_capacity: 0,
            ..ServerConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_zero_timeout_is_refused() {
        for config in [
            ServerConfig::default().with_head_timeout(Duration::ZERO),
            ServerConfig::default().with_body_timeout(Duration::ZERO),
            ServerConfig::default().with_handler_timeout(Duration::ZERO),
            ServerConfig::default().with_write_timeout(Duration::ZERO),
            ServerConfig::default().with_drain_timeout(Duration::ZERO),
        ] {
            assert!(config.validate().is_err(), "a zero bound is not a bound");
        }
    }

    #[test]
    fn the_default_protocols_are_ones_this_build_can_serve() {
        assert!(
            ServerConfig::default().validate().is_ok(),
            "a default configuration that cannot bind is not a default"
        );
        assert_eq!(Protocols::default(), Protocols::available());
        assert_eq!(
            Protocols::available().http2,
            cfg!(feature = "http2"),
            "the default offers h2 exactly when the codec is compiled in"
        );
    }

    #[cfg(not(feature = "http2"))]
    #[test]
    fn asking_for_http2_in_a_build_that_omits_it_is_refused_at_bind_time() {
        let config = ServerConfig::default().with_protocols(Protocols::HTTP2);
        let error = config.validate().expect_err("must refuse");
        assert!(format!("{error}").contains("http2"), "{error}");
    }

    #[test]
    fn a_listener_with_no_protocol_is_refused() {
        let config = ServerConfig::default().with_protocols(Protocols {
            http1: false,
            http2: false,
        });
        assert!(config.validate().is_err());
    }

    #[cfg(feature = "http2")]
    #[test]
    fn http2_frame_sizes_outside_the_rfc_range_are_refused() {
        for max_frame_size in [1024, 16 * 1024 * 1024] {
            let config = ServerConfig::default().with_http2(H2Ingress {
                max_frame_size,
                ..H2Ingress::for_ingress()
            });
            assert!(config.validate().is_err(), "{max_frame_size} is not legal");
        }
        let config = ServerConfig::default().with_http2(H2Ingress {
            connection_window_size: 65_535,
            ..H2Ingress::for_ingress()
        });
        assert!(
            config.validate().is_err(),
            "the default window is not an upgrade"
        );
    }

    #[test]
    fn alpn_offers_h2_before_http11_when_both_are_served() {
        assert_eq!(
            Protocols::BOTH.alpn(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(Protocols::HTTP1.alpn(), vec![b"http/1.1".to_vec()]);
        assert_eq!(Protocols::HTTP2.alpn(), vec![b"h2".to_vec()]);
    }
}
