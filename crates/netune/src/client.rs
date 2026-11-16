//! The client: one request, planned, carried, observed.
//!
//! [`Client`] owns what is true of every request regardless of how it
//! travels: resolving the plan before anything is opened, the trace-id
//! header, the redirect chain, the response's decoding and bounds, and the
//! attempt's evidence. It does not own a connection, a pool or a protocol.
//! Those sit behind [`RoundTrip`], so the same client drives real connections
//! ([`Wire`]) and scripted ones ([`crate::mock::Mock`]) through identical
//! code, and a mocked attempt leaves the same kind of trace a real one does.
//!
//! It owns no retry policy either: the transport absorbs a dead pooled socket
//! where that is provably safe, and every other retry is the caller's call.
//!
//! Redirects are followed here rather than by a wrapper because a redirect is
//! a property of the *attempt*: the trace must show the hops, and only the
//! final response may mark `HeadComplete`, or time-to-first-byte would be
//! measured against a 302.

use std::sync::Arc;
use std::time::Duration;

use http::Method;
use netune_http1::{IncomingResponse, Limits, RequestHead};
use netune_trace::{
    DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EventKind, Fidelity, TraceCollector,
    TracePropagation, TraceSink, TraceSnapshot,
};

use crate::body::{Body, BodyContext};
use crate::connect::{Connector, EgressConfinement, HttpProtocol, Target, TcpConnector};
use crate::decompress::Decoder;
use crate::error::{AttemptError, NetError};
use crate::exchange::{Attempt, ObservationLevel, Request, RequestBody, RoundTrip};
use crate::pool::{Pool, PoolConfig, PoolKey};
use crate::profile::{ConnectionPlan, H1Registry, H1WireProfile, Http2Mode, PlannedTransport};
#[cfg(any(feature = "http2", feature = "http3"))]
use crate::profile::ProfileId;
#[cfg(feature = "http2")]
use crate::profile::{H2Registry, H2RequestRegistry};
use crate::proxy::{Proxy, ProxyConnector};
use crate::redirect::{redirect_location, redirect_to_get, resolve_location};
use crate::socket::SocketConfig;
use crate::tls::TlsRouterConnector;
use crate::tls_profile::TlsProfile;
use crate::wire::Wire;
#[cfg(feature = "http2")]
use netune_http2::H2Fingerprint;

/// How the next attempt observes its byte path.
///
/// The value selects one of three monomorphized taps; the byte path itself never
/// sees this enum. `Counters` is the default because a production client must be
/// debuggable at L0 without paying for a ring, a clock or a lock.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub enum Observation {
    /// No clock, no allocation, no event. The pure mode.
    Off,
    /// Allocated-free byte and call counters; no clock.
    #[default]
    Counters,
    /// A bounded event ring, optionally streamed to a sink.
    Traced(TraceConfig),
}

/// Bounds and delivery for a traced attempt.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Maximum events retained in the attempt's ring buffer.
    pub capacity: usize,
    /// Optional streaming trace sink for live event delivery.
    pub sink: Option<Arc<dyn TraceSink>>,
    /// Whether this attempt's trace id travels on the wire.
    pub propagation: TracePropagation,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            capacity: crate::DEFAULT_TRACE_CAPACITY,
            sink: None,
            propagation: TracePropagation::Off,
        }
    }
}

impl TraceConfig {
    /// Create a trace configuration with ring buffer `capacity`.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            sink: None,
            propagation: TracePropagation::Off,
        }
    }

    /// Stream recorded events to `sink`.
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn TraceSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Configure outbound trace-id propagation.
    #[must_use]
    pub fn with_propagation(mut self, propagation: TracePropagation) -> Self {
        self.propagation = propagation;
        self
    }
}

impl Observation {
    /// A traced attempt with the default capacity.
    pub fn traced() -> Self {
        Self::Traced(TraceConfig::default())
    }

    /// A traced attempt with an explicit capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::Traced(TraceConfig::new(capacity))
    }

    /// The level a transport is asked to observe at.
    pub const fn level(&self) -> ObservationLevel {
        match self {
            Self::Off => ObservationLevel::Off,
            Self::Counters => ObservationLevel::Counters,
            Self::Traced(_) => ObservationLevel::Traced,
        }
    }
}

/// Client policy.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// HTTP/1.1 parser and decoded-body size limits.
    pub limits: Limits,
    /// Sent as `user-agent` when the caller did not supply one.
    pub user_agent: String,
    /// Redirect hops followed before giving up.
    pub max_redirects: u8,
    /// Whether to automatically upgrade to HTTP/2 when ALPN negotiates `h2`.
    pub enable_http2: bool,
    /// Bound on a newly dialed HTTP/2 connection's preface and SETTINGS
    /// exchange.
    ///
    /// The TLS handshake proves the peer holds the certificate, not that it
    /// speaks HTTP/2: a peer can stop after `TlsEnd` and never answer SETTINGS,
    /// which would otherwise hold a streaming attempt until an outer watchdog
    /// fires. This bound covers the whole exchange (preface, SETTINGS and the
    /// peer's ACK) and produces a retryable `connect` failure when it expires.
    ///
    /// Default 10 s. `None` removes the bound for a caller whose own deadline
    /// reports the stall as a connection failure. Ignored on a pooled
    /// connection, which already completed the exchange.
    pub h2_handshake_timeout: Option<Duration>,
    /// Bound on the wait between the request being written and the response
    /// head arriving.
    ///
    /// This is the one phase of an exchange nothing else bounds: the
    /// connection is up, the request is sent, and the peer simply does not
    /// answer. Expiry is a [`NetError::Timeout`] returned with the attempt's
    /// trace, which an outer `tokio::time::timeout` cannot give: cancelling
    /// the future discards the evidence along with it.
    ///
    /// Default 30 s. A peer that accepts the request and never answers must
    /// not hold the attempt forever. Set this to `None` only when an outer
    /// deadline reports the stall with equivalent evidence.
    pub response_head_timeout: Option<Duration>,
    /// Bound on the silence between two reads of a response body.
    ///
    /// An idle bound rather than a total one: a long stream is never cut for
    /// being long, only for going quiet. Default 60 s.
    pub body_idle_timeout: Option<Duration>,
    /// Total bound on one attempt, from dispatch through the terminal body
    /// state, including redirects.
    ///
    /// The per-phase bounds catch a silent peer; this one also catches a
    /// peer that trickles forever. Default 300 s. Set it to `None` only for
    /// a caller-owned deadline that covers both the head and the body.
    pub request_timeout: Option<Duration>,
    /// The default observation policy for [`Client::request`].
    pub observation: Observation,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            user_agent: format!("netune/{}", env!("CARGO_PKG_VERSION")),
            max_redirects: 5,
            enable_http2: false,
            h2_handshake_timeout: Some(crate::handshake::DEFAULT_HANDSHAKE_TIMEOUT),
            response_head_timeout: Some(Duration::from_secs(30)),
            body_idle_timeout: Some(Duration::from_secs(60)),
            request_timeout: Some(Duration::from_secs(300)),
            observation: Observation::Counters,
        }
    }
}

impl ClientConfig {
    /// Set HTTP/1.1 parser and body limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the default `user-agent` header.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Set the maximum redirect hops followed per attempt.
    #[must_use]
    pub fn with_max_redirects(mut self, max_redirects: u8) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Enable or disable automatic HTTP/2 upgrade when ALPN negotiates `h2`.
    #[must_use]
    pub fn with_enable_http2(mut self, enable_http2: bool) -> Self {
        self.enable_http2 = enable_http2;
        self
    }

    /// Set the HTTP/2 preface and SETTINGS handshake timeout.
    #[must_use]
    pub fn with_h2_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.h2_handshake_timeout = timeout;
        self
    }

    /// Set the response-head timeout.
    #[must_use]
    pub fn with_response_head_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.response_head_timeout = timeout;
        self
    }

    /// Set the body-idle timeout.
    #[must_use]
    pub fn with_body_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.body_idle_timeout = timeout;
        self
    }

    /// Set the total per-attempt timeout.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set the default observation policy for [`Client::request`].
    #[must_use]
    pub fn with_observation(mut self, observation: Observation) -> Self {
        self.observation = observation;
        self
    }
}

/// A parsed response: head plus a decoded, observed body stream.
#[non_exhaustive]
#[derive(Debug)]
pub struct Response {
    /// Parsed response status line and headers.
    pub head: IncomingResponse,
    /// Streaming decoded response body and attempt trace handle.
    pub body: Body,
}

#[derive(Clone)]
enum BuilderTls {
    RustlsDefault,
    RustlsConfig(Box<rustls::ClientConfig>),
    Owned(netune_tls::Verifier),
    Disabled,
}

/// Fluent builder for a production [`Client`].
///
/// Defaults to [`TcpConnector`] wrapped in [`TlsRouterConnector::platform_default`]
/// (rustls with the platform certificate verifier), [`Pool::default`], and
/// [`ClientConfig::default`]. Calling [`Self::http2(true)`] automatically
/// configures rustls ALPN `["h2", "http/1.1"]` alongside `enable_http2`.
pub struct ClientBuilder {
    config: ClientConfig,
    pool: Option<Pool>,
    pool_config: PoolConfig,
    confinement: EgressConfinement,
    socket_config: SocketConfig,
    connect_timeout: Option<Duration>,
    proxy: Option<Proxy>,
    tls: BuilderTls,
    tls_handshake_timeout: Option<Duration>,
    custom_tls_profiles: Vec<(String, TlsProfile)>,
    h1_profiles: H1Registry,
    #[cfg(feature = "http2")]
    h2_profiles: H2Registry,
    #[cfg(feature = "http2")]
    h2_request_profiles: H2RequestRegistry,
    #[cfg(feature = "http3")]
    quic_connector: Option<netune_quic::QuicConnector>,
    #[cfg(feature = "http3")]
    quic_profiles: netune_quic::profile::QuicProfileRegistry,
    #[cfg(feature = "http3")]
    h3_settings_profiles: netune_http3::H3SettingsRegistry,
    #[cfg(feature = "http3")]
    h3_request_profiles: netune_http3::H3RequestRegistry,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Create a new builder with safe production defaults.
    pub fn new() -> Self {
        Self {
            config: ClientConfig::default(),
            pool: None,
            pool_config: PoolConfig::default(),
            confinement: EgressConfinement::Unrestricted,
            socket_config: SocketConfig::default(),
            connect_timeout: Some(crate::connect::CONNECT_TIMEOUT),
            proxy: None,
            tls: BuilderTls::RustlsDefault,
            tls_handshake_timeout: Some(crate::handshake::DEFAULT_HANDSHAKE_TIMEOUT),
            custom_tls_profiles: Vec::new(),
            h1_profiles: H1Registry::default(),
            #[cfg(feature = "http2")]
            h2_profiles: H2Registry::default(),
            #[cfg(feature = "http2")]
            h2_request_profiles: H2RequestRegistry::default(),
            #[cfg(feature = "http3")]
            quic_connector: None,
            #[cfg(feature = "http3")]
            quic_profiles: netune_quic::profile::QuicProfileRegistry::default(),
            #[cfg(feature = "http3")]
            h3_settings_profiles: netune_http3::H3SettingsRegistry::default(),
            #[cfg(feature = "http3")]
            h3_request_profiles: netune_http3::H3RequestRegistry::default(),
        }
    }

    /// Replace the full [`ClientConfig`].
    #[must_use]
    pub fn config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }

    /// Enable or disable automatic HTTP/2 negotiation via ALPN (and align the
    /// default rustls ALPN offer accordingly).
    #[must_use]
    pub fn http2(mut self, enable: bool) -> Self {
        self.config.enable_http2 = enable;
        self
    }

    /// Set the redirect limit.
    #[must_use]
    pub fn max_redirects(mut self, max_redirects: u8) -> Self {
        self.config.max_redirects = max_redirects;
        self
    }

    /// Set the default `user-agent` header.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.config.user_agent = user_agent.into();
        self
    }

    /// Set the default [`Observation`] policy for [`Client::request`].
    #[must_use]
    pub fn observation(mut self, observation: Observation) -> Self {
        self.config.observation = observation;
        self
    }

    /// Set HTTP/1.1 parser and body limits.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.config.limits = limits;
        self
    }

    /// Set the overall per-attempt deadline.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    /// Set the response-head timeout.
    #[must_use]
    pub fn response_head_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.config.response_head_timeout = timeout;
        self
    }

    /// Set the body-idle timeout.
    #[must_use]
    pub fn body_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.config.body_idle_timeout = timeout;
        self
    }

    /// Set the HTTP/2 preface + SETTINGS handshake timeout.
    #[must_use]
    pub fn h2_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.config.h2_handshake_timeout = timeout;
        self
    }

    /// Share an existing [`Pool`].
    #[must_use]
    pub fn pool(mut self, pool: Pool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Configure a fresh [`Pool`] using `config` (ignored if [`Self::pool`] is set).
    #[must_use]
    pub fn pool_config(mut self, config: PoolConfig) -> Self {
        self.pool_config = config;
        self
    }

    /// Set the egress confinement policy (e.g. [`EgressConfinement::StrictPublic`]).
    #[must_use]
    pub fn confinement(mut self, confinement: EgressConfinement) -> Self {
        self.confinement = confinement;
        self
    }

    /// Configure TCP socket options.
    #[must_use]
    pub fn socket_config(mut self, socket_config: SocketConfig) -> Self {
        self.socket_config = socket_config;
        self
    }

    /// Set the DNS + TCP connect timeout.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Route outbound TCP/TLS connections through an HTTP `CONNECT` or SOCKS5 proxy.
    #[must_use]
    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Use the default audited rustls + platform verifier TLS path.
    #[must_use]
    pub fn tls_rustls(mut self) -> Self {
        self.tls = BuilderTls::RustlsDefault;
        self
    }

    /// Use a caller-supplied [`rustls::ClientConfig`] for plain TLS targets.
    #[must_use]
    pub fn tls_rustls_config(mut self, config: rustls::ClientConfig) -> Self {
        self.tls = BuilderTls::RustlsConfig(Box::new(config));
        self
    }

    /// Select the owned `netune-tls` engine with the given verifier.
    #[must_use]
    pub fn tls_owned(mut self, verifier: netune_tls::Verifier) -> Self {
        self.tls = BuilderTls::Owned(verifier);
        self
    }

    /// Disable TLS termination on the connector (plaintext TCP / proxy only).
    #[must_use]
    pub fn no_tls(mut self) -> Self {
        self.tls = BuilderTls::Disabled;
        self
    }

    /// Set the TLS handshake timeout.
    #[must_use]
    pub fn tls_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.tls_handshake_timeout = timeout;
        self
    }

    /// Register or override a named [`TlsProfile`] on the TLS router.
    #[must_use]
    pub fn tls_profile(mut self, name: impl Into<String>, profile: TlsProfile) -> Self {
        self.custom_tls_profiles.push((name.into(), profile));
        self
    }

    /// Register or replace an HTTP/1 request-header wire profile.
    #[must_use]
    pub fn h1_profile(mut self, profile: H1WireProfile) -> Self {
        self.h1_profiles = self.h1_profiles.with_profile(profile);
        self
    }

    /// Register or replace an HTTP/2 connection profile.
    #[cfg(feature = "http2")]
    #[must_use]
    pub fn h2_profile(mut self, id: impl Into<ProfileId>, profile: H2Fingerprint) -> Self {
        self.h2_profiles = self.h2_profiles.with_profile(id, profile);
        self
    }

    /// Register or replace an HTTP/2 request-header profile.
    #[cfg(feature = "http2")]
    #[must_use]
    pub fn h2_request_profile(
        mut self,
        id: impl Into<ProfileId>,
        profile: netune_http2::H2RequestProfile,
    ) -> Self {
        self.h2_request_profiles = self.h2_request_profiles.with_profile(id, profile);
        self
    }

    /// Supply a custom [`netune_quic::QuicConnector`] for HTTP/3 targets.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn quic(mut self, quic: netune_quic::QuicConnector) -> Self {
        self.quic_connector = Some(quic);
        self
    }

    /// Register or replace a QUIC transport profile for HTTP/3 requests.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn quic_profile(mut self, profile: netune_quic::profile::QuicProfile) -> Self {
        self.quic_profiles = self.quic_profiles.with_profile(profile);
        self
    }

    /// Register or replace an HTTP/3 connection SETTINGS profile.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn h3_settings_profile(mut self, profile: netune_http3::H3SettingsProfile) -> Self {
        self.h3_settings_profiles = self.h3_settings_profiles.with_profile(profile);
        self
    }

    /// Register or replace an HTTP/3 request-header profile.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn h3_request_profile(mut self, profile: netune_http3::H3RequestProfile) -> Self {
        self.h3_request_profiles = self.h3_request_profiles.with_profile(profile);
        self
    }

    fn finish_tls<C: Connector + 'static>(self, connector: C, pool: Pool) -> Client {
        let alpn = if self.config.enable_http2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let client = match self.tls {
            BuilderTls::Disabled => {
                #[allow(unused_mut)]
                let mut wire = Wire::new(connector, pool);
                #[cfg(feature = "http3")]
                if let Some(quic) = self.quic_connector {
                    wire = wire.with_quic(quic);
                }
                Client::with_transport(wire, self.config)
            }
            tls => {
                let mut router = TlsRouterConnector::platform_default(connector)
                    .with_handshake_timeout(self.tls_handshake_timeout)
                    .with_rustls_alpn(alpn);
                match tls {
                    BuilderTls::RustlsDefault => {}
                    BuilderTls::RustlsConfig(cfg) => {
                        router = router.with_rustls_config(*cfg);
                    }
                    BuilderTls::Owned(verifier) => {
                        router = router.with_verifier(verifier);
                    }
                    BuilderTls::Disabled => unreachable!(),
                }
                for (name, profile) in self.custom_tls_profiles {
                    router = router.with_profile_named(name, profile);
                }
                #[allow(unused_mut)]
                let mut wire = Wire::new(router, pool);
                #[cfg(feature = "http3")]
                if let Some(quic) = self.quic_connector {
                    wire = wire.with_quic(quic);
                }
                Client::with_transport(wire, self.config)
            }
        };
        let mut client = client;
        client.h1_profiles = self.h1_profiles;
        #[cfg(feature = "http2")]
        {
            client.h2_profiles = self.h2_profiles;
            client.h2_request_profiles = self.h2_request_profiles;
        }
        #[cfg(feature = "http3")]
        {
            client.quic_profiles = self.quic_profiles;
            client.h3_settings_profiles = self.h3_settings_profiles;
            client.h3_request_profiles = self.h3_request_profiles;
        }
        client
    }

    /// Assemble the configured [`Client`].
    pub fn build(mut self) -> Client {
        let pool = self
            .pool
            .take()
            .unwrap_or_else(|| Pool::new(self.pool_config));
        let mut tcp = match self.confinement {
            EgressConfinement::Unrestricted => TcpConnector::new(),
            EgressConfinement::StrictPublic => TcpConnector::strict_public(),
        };
        tcp = tcp
            .with_socket_config(self.socket_config.clone())
            .with_connect_timeout(self.connect_timeout);

        if let Some(proxy) = self.proxy.take() {
            let proxied = ProxyConnector::new(tcp, proxy);
            self.finish_tls(proxied, pool)
        } else {
            self.finish_tls(tcp, pool)
        }
    }
}

/// An HTTP client over any [`RoundTrip`].
#[derive(Clone)]
pub struct Client {
    transport: Arc<dyn RoundTrip>,
    config: ClientConfig,
    h1_profiles: H1Registry,
    #[cfg(feature = "http2")]
    h2_profiles: H2Registry,
    #[cfg(feature = "http2")]
    h2_request_profiles: H2RequestRegistry,
    #[cfg(feature = "http3")]
    quic_profiles: netune_quic::profile::QuicProfileRegistry,
    #[cfg(feature = "http3")]
    h3_settings_profiles: netune_http3::H3SettingsRegistry,
    #[cfg(feature = "http3")]
    h3_request_profiles: netune_http3::H3RequestRegistry,
}

impl Client {
    /// Start building a production-configured [`Client`] with TLS enabled via
    /// the audited rustls platform verifier.
    ///
    /// Enabling [`ClientBuilder::http2`] automatically aligns the rustls ALPN
    /// offer (`["h2", "http/1.1"]`) with `ClientConfig::enable_http2`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// A client over real connections: `connector` opens them, `pool` keeps
    /// them.
    pub fn new<C: Connector + 'static>(connector: C, pool: Pool, config: ClientConfig) -> Self {
        Self::with_transport(Wire::new(connector, pool), config)
    }

    /// A client over any transport: [`Wire`], a [`crate::mock::Mock`], or a
    /// caller's own [`RoundTrip`].
    pub fn with_transport(transport: impl RoundTrip, config: ClientConfig) -> Self {
        Self {
            transport: Arc::new(transport),
            config,
            h1_profiles: H1Registry::default(),
            #[cfg(feature = "http2")]
            h2_profiles: H2Registry::default(),
            #[cfg(feature = "http2")]
            h2_request_profiles: H2RequestRegistry::default(),
            #[cfg(feature = "http3")]
            quic_profiles: netune_quic::profile::QuicProfileRegistry::default(),
            #[cfg(feature = "http3")]
            h3_settings_profiles: netune_http3::H3SettingsRegistry::default(),
            #[cfg(feature = "http3")]
            h3_request_profiles: netune_http3::H3RequestRegistry::default(),
        }
    }

    /// The client's policy.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Whether this target selects HTTP/3 (explicitly or via H3/QUIC profiles).
    fn wants_http3(target: &Target) -> bool {
        target.protocol == HttpProtocol::Http3
            || (target.protocol == HttpProtocol::Auto
                && (target.identity.h3_profile.is_some()
                    || target.identity.h3_settings_profile.is_some()
                    || target.h3_request_profile.is_some()))
    }

    /// How this target relates to HTTP/2 when using TCP.
    ///
    /// A mandate or a named HTTP/2 profile is prior knowledge, independent of
    /// ALPN: a named profile is an assertion that the request speaks HTTP/2.
    /// `enable_http2` alone only upgrades when ALPN actually negotiates `h2`.
    fn http2_mode(&self, target: &Target) -> Http2Mode {
        match target.protocol {
            HttpProtocol::Http1 => Http2Mode::Off,
            HttpProtocol::Http2 => Http2Mode::Force,
            HttpProtocol::Http3 => Http2Mode::Off,
            HttpProtocol::Auto => {
                if target.identity.h2_profile.is_some() || target.h2_request_profile.is_some() {
                    Http2Mode::Force
                } else if self.config.enable_http2 {
                    Http2Mode::Negotiate
                } else {
                    Http2Mode::Off
                }
            }
        }
    }

    /// Register or replace an HTTP/1 request-header wire profile.
    #[must_use]
    pub fn with_h1_profile(mut self, profile: H1WireProfile) -> Self {
        self.h1_profiles = self.h1_profiles.with_profile(profile);
        self
    }

    /// Register or replace an HTTP/2 connection profile.
    #[cfg(feature = "http2")]
    #[must_use]
    pub fn with_h2_profile(mut self, id: impl Into<ProfileId>, profile: H2Fingerprint) -> Self {
        self.h2_profiles = self.h2_profiles.with_profile(id, profile);
        self
    }

    /// Register or replace an HTTP/2 request-header profile.
    #[cfg(feature = "http2")]
    #[must_use]
    pub fn with_h2_request_profile(
        mut self,
        id: impl Into<ProfileId>,
        profile: netune_http2::H2RequestProfile,
    ) -> Self {
        self.h2_request_profiles = self.h2_request_profiles.with_profile(id, profile);
        self
    }

    /// Register or replace a QUIC transport profile for HTTP/3 requests.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn with_quic_profile(mut self, profile: netune_quic::profile::QuicProfile) -> Self {
        self.quic_profiles = self.quic_profiles.with_profile(profile);
        self
    }

    /// Register or replace an HTTP/3 connection SETTINGS profile.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn with_h3_settings_profile(mut self, profile: netune_http3::H3SettingsProfile) -> Self {
        self.h3_settings_profiles = self.h3_settings_profiles.with_profile(profile);
        self
    }

    /// Register or replace an HTTP/3 request-header profile.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn with_h3_request_profile(mut self, profile: netune_http3::H3RequestProfile) -> Self {
        self.h3_request_profiles = self.h3_request_profiles.with_profile(profile);
        self
    }

    /// Resolve every choice for one request before anything is opened.
    ///
    /// The returned plan separates connection identity (pool key) from the
    /// per-request wire profiles (H1 header order, H2 pseudo-header order, H3
    /// header order). Unknown profile names fail here, not after a handshake.
    pub fn plan(&self, target: &Target) -> Result<ConnectionPlan, NetError> {
        // The authority is written into a `Host` header (HTTP/1.1) and a
        // `:authority` field (HTTP/2 and HTTP/3), and a proxy CONNECT writes it
        // into a request line. Validate it here, at the one choke point every
        // request and every redirect hop passes through, so no
        // target-construction path can smuggle a control byte onto the wire.
        netune_http1::validate_host_field(target.authority.as_bytes()).map_err(|error| {
            NetError::Connect(crate::error::ConnectError::config(
                DiagnosticPhase::Request,
                format!("invalid target authority {:?}: {error}", target.authority),
            ))
        })?;

        let h1_id = target
            .h1_profile
            .as_ref()
            .unwrap_or_else(|| self.h1_profiles.default_profile().id());
        let h1 = self.h1_profiles.resolve(h1_id)?.clone();

        let mut identity = target.identity.clone();
        if identity.socket_shape.is_none() {
            identity.socket_shape = self.transport.socket_shape();
        }
        if identity.route.is_none() {
            identity.route = self.transport.route_shape();
        }

        if Self::wants_http3(target) {
            if target.identity.h2_profile.is_some() || target.h2_request_profile.is_some() {
                return Err(NetError::Connect(crate::error::ConnectError::config(
                    DiagnosticPhase::Dispatch,
                    "cannot combine HTTP/3 with HTTP/2 profiles on one Target",
                )));
            }
            if target.tls_server_name().is_none() {
                return Err(NetError::Connect(crate::error::ConnectError::config(
                    DiagnosticPhase::Dispatch,
                    "HTTP/3 requires a TLS server name on Target",
                )));
            }
            #[cfg(not(feature = "http3"))]
            {
                return Err(NetError::Protocol(
                    "HTTP/3 was requested but the `http3` feature is not compiled in".into(),
                ));
            }
            #[cfg(feature = "http3")]
            {
                let quic_name = identity
                    .h3_profile
                    .as_deref()
                    .unwrap_or("quic-default")
                    .to_string();
                let quic = self
                    .quic_profiles
                    .resolve(&quic_name)
                    .map_err(|err| {
                        NetError::Connect(crate::error::ConnectError::config(
                            DiagnosticPhase::Dispatch,
                            err.to_string(),
                        ))
                    })?
                    .clone();
                identity.h3_profile = Some(quic.name.to_string());

                let settings_name = identity
                    .h3_settings_profile
                    .as_deref()
                    .unwrap_or("default")
                    .to_string();
                let settings = self
                    .h3_settings_profiles
                    .resolve(&settings_name)
                    .map_err(|err| {
                        NetError::Connect(crate::error::ConnectError::config(
                            DiagnosticPhase::Dispatch,
                            err.to_string(),
                        ))
                    })?
                    .clone();
                settings.validate().map_err(|reason| {
                    NetError::Connect(crate::error::ConnectError::config(
                        DiagnosticPhase::Dispatch,
                        reason,
                    ))
                })?;
                identity.h3_settings_profile = Some(settings.name.clone());

                let request_name = target
                    .h3_request_profile
                    .as_ref()
                    .map_or("default", ProfileId::as_str);
                let request = self
                    .h3_request_profiles
                    .resolve(request_name)
                    .map_err(|err| {
                        NetError::Connect(crate::error::ConnectError::config(
                            DiagnosticPhase::Dispatch,
                            err.to_string(),
                        ))
                    })?
                    .clone();

                return Ok(ConnectionPlan {
                    target: target.clone(),
                    identity,
                    h1,
                    transport: PlannedTransport::Http3 {
                        quic,
                        settings,
                        request,
                    },
                });
            }
        }

        if target.identity.h3_profile.is_some()
            || target.identity.h3_settings_profile.is_some()
            || target.h3_request_profile.is_some()
        {
            return Err(NetError::Connect(crate::error::ConnectError::config(
                DiagnosticPhase::Dispatch,
                "HTTP/3/QUIC profiles cannot be set on a non-HTTP/3 Target",
            )));
        }
        if target.protocol == HttpProtocol::Http1
            && (target.identity.h2_profile.is_some() || target.h2_request_profile.is_some())
        {
            return Err(NetError::Connect(crate::error::ConnectError::config(
                DiagnosticPhase::Dispatch,
                "HTTP/2 profiles cannot be set when Target requires HTTP/1.1",
            )));
        }

        let http2 = self.http2_mode(target);

        #[cfg(feature = "http2")]
        let h2 = if http2 == Http2Mode::Off {
            None
        } else {
            match &identity.h2_profile {
                Some(id) => Some(
                    self.h2_profiles
                        .resolve(&ProfileId::new(id.as_str()))?
                        .clone(),
                ),
                None => {
                    let (id, fingerprint) = self
                        .h2_profiles
                        .default_for_tls(target.tls_profile())
                        .ok_or_else(|| {
                            NetError::Connect(crate::error::ConnectError::config(
                                DiagnosticPhase::Dispatch,
                                "no built-in HTTP/2 profile is registered; register one with \
                                 Client::with_h2_profile",
                            ))
                        })?;
                    if http2 == Http2Mode::Force {
                        identity.h2_profile = Some(id.to_string());
                    }
                    Some(fingerprint.clone())
                }
            }
        };

        #[cfg(not(feature = "http2"))]
        if http2 != Http2Mode::Off {
            return Err(NetError::Protocol(
                "HTTP/2 was requested but the `http2` feature is not compiled in".into(),
            ));
        }

        #[cfg(feature = "http2")]
        let h2_request = match &h2 {
            Some(pair) => Some(match &target.h2_request_profile {
                Some(id) => *self.h2_request_profiles.resolve(id)?,
                None => pair.request,
            }),
            None => None,
        };

        Ok(ConnectionPlan {
            target: target.clone(),
            identity,
            h1,
            transport: PlannedTransport::Tcp {
                http2,
                #[cfg(feature = "http2")]
                h2,
                #[cfg(feature = "http2")]
                h2_request,
            },
        })
    }

    /// Establish a connection for `target` ahead of need, if the transport
    /// keeps connections and has none idle for it.
    ///
    /// Returns `true` if a connection was opened. A transport with nothing to
    /// warm (a mock) answers `false`.
    pub async fn prewarm(&self, target: &Target) -> Result<bool, NetError> {
        let plan = self.plan(target)?;
        // Pre-warming is a pool operation, not an attempt: there is no consumer
        // for a trace of it, so it must not allocate one.
        let recorder = TraceCollector::disabled();
        self.transport
            .prewarm(Attempt {
                plan: &plan,
                recorder: &recorder,
                observation: ObservationLevel::Off,
                config: &self.config,
                deadline: None,
            })
            .await
    }

    /// The pool key for a target: authority plus the whole connection identity.
    ///
    /// The identity carries the TLS profile, the verified server name, the
    /// evasion policy and every other handshake-fixed axis. A connection
    /// established under one identity must never serve a request that asked for
    /// another; making the key a type is what prevents a future axis from being
    /// silently omitted.
    pub fn pool_key(&self, target: &Target) -> Result<PoolKey, NetError> {
        Ok(self.plan(target)?.pool_key())
    }

    /// Send one request under the client's configured observation policy.
    ///
    /// The default is [`Observation::Counters`]: L0 byte and call counters, no
    /// clock and no allocation on the byte path. Call [`Client::request_traced`]
    /// for an event timeline or [`Client::request_untraced`] for the pure mode.
    pub async fn request(
        &self,
        target: &Target,
        head: RequestHead,
        body: impl Into<RequestBody>,
    ) -> Result<Response, AttemptError> {
        self.send(target, head, body, self.config.observation.clone())
            .await
    }

    /// Send one request with no byte-path observation.
    pub async fn request_untraced(
        &self,
        target: &Target,
        head: RequestHead,
        body: impl Into<RequestBody>,
    ) -> Result<Response, AttemptError> {
        self.send(target, head, body, Observation::Off).await
    }

    /// Send one request with an event timeline.
    pub async fn request_traced(
        &self,
        target: &Target,
        head: RequestHead,
        body: impl Into<RequestBody>,
        config: TraceConfig,
    ) -> Result<Response, AttemptError> {
        self.send(target, head, body, Observation::Traced(config))
            .await
    }

    /// Send one request, following redirects, and return the final response.
    pub async fn send(
        &self,
        target: &Target,
        head: RequestHead,
        body: impl Into<RequestBody>,
        observation: Observation,
    ) -> Result<Response, AttemptError> {
        let (recorder, propagation) = match &observation {
            Observation::Traced(config) => {
                let mut recorder = TraceCollector::start(config.capacity);
                if let Some(sink) = &config.sink {
                    recorder = recorder.with_sink(Arc::clone(sink));
                }
                // Propagation changes the wire, so it is opt-in.
                (recorder, config.propagation.header())
            }
            Observation::Off | Observation::Counters => (TraceCollector::disabled(), None),
        };
        self.attempt(
            target,
            recorder,
            Request::new(head, body),
            observation.level(),
            propagation,
        )
        .await
    }

    /// Send one request with an explicitly supplied attempt recorder.
    ///
    /// This is for a consumer that already owns the control recorder (tests, a
    /// relay, a caller that streams trace events). Socket events are merged
    /// into the supplied recorder when the body reaches a terminal state.
    pub async fn send_traced(
        &self,
        target: &Target,
        recorder: TraceCollector,
        head: RequestHead,
        body: impl Into<RequestBody>,
    ) -> Result<Response, AttemptError> {
        self.attempt(
            target,
            recorder,
            Request::new(head, body),
            ObservationLevel::Traced,
            None,
        )
        .await
    }

    /// Run one attempt and attach its evidence to a failure.
    async fn attempt(
        &self,
        target: &Target,
        recorder: TraceCollector,
        mut request: Request,
        level: ObservationLevel,
        propagation: Option<&'static str>,
    ) -> Result<Response, AttemptError> {
        let deadline = self
            .config
            .request_timeout
            .map(|limit| tokio::time::Instant::now() + limit);
        let outcome = async {
            match propagate(&mut request, propagation, &recorder) {
                Ok(()) => {
                    self.follow(target, &recorder, request, level, deadline)
                        .await
                }
                Err(error) => Err(error),
            }
        };
        let outcome = match (self.config.request_timeout, deadline) {
            (Some(limit), Some(deadline)) => {
                match tokio::time::timeout_at(deadline, outcome).await {
                    Ok(result) => result,
                    Err(_) => Err(NetError::Timeout {
                        phase: DiagnosticPhase::Request,
                        waiting_for: "request attempt",
                        limit,
                    }),
                }
            }
            _ => outcome.await,
        };
        outcome.map_err(|error| AttemptError::new(error, evidence(&recorder, level)))
    }

    /// Carry the request, following redirects to the final response.
    async fn follow(
        &self,
        target: &Target,
        recorder: &TraceCollector,
        mut request: Request,
        level: ObservationLevel,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Response, NetError> {
        if !request.head.headers.contains_key(http::header::USER_AGENT) {
            request.head.headers.insert(
                http::header::USER_AGENT,
                http::HeaderValue::from_str(&self.config.user_agent)
                    .unwrap_or_else(|_| http::HeaderValue::from_static("netune")),
            );
        }
        let origin = (target.tls_server_name().is_some(), target.authority.clone());
        let mut target = target.clone();
        let mut hops: u8 = 0;

        loop {
            let plan = self.plan(&target)?;
            let response = self.hop(&plan, recorder, &request, level, deadline).await?;
            let Some(location) = redirect_location(&response.head) else {
                // Only the final head marks completion: a redirect's head must
                // not become the anchor time-to-first-byte is measured against.
                recorder.mark(EventKind::HeadComplete, 0, 0);
                return Ok(response);
            };
            if hops >= self.config.max_redirects {
                return Err(NetError::TooManyRedirects(self.config.max_redirects));
            }
            let status = response.head.status;
            // The hop's connection is not reused: its body was never drained,
            // so reusing it could desynchronise the stream.
            drop(response);
            recorder.mark(EventKind::Redirect, u32::from(status.as_u16()), 0);

            let (next_target, next_path) =
                resolve_location(&target, &request.head.target, &location)?;
            let next_origin = (
                next_target.tls_server_name().is_some(),
                next_target.authority.clone(),
            );
            if next_origin != origin {
                // Credentials never follow a redirect off the original origin.
                // A scheme change is an origin change even when the authority
                // is byte-identical: an `https -> http` redirect would
                // otherwise put the same bearer token on the wire in clear.
                for header in ["authorization", "cookie", "proxy-authorization"] {
                    remove_header(&mut request.head, header);
                }
            }
            if redirect_to_get(status) && request.head.method != Method::HEAD {
                request.head.method = Method::GET;
                remove_header(&mut request.head, "content-type");
                remove_header(&mut request.head, "content-length");
                request.body = RequestBody::Empty;
            } else if !request.body.can_replay() {
                return Err(NetError::Protocol(
                    "cannot replay a streaming request body across a redirect".into(),
                ));
            }
            request.head.target = next_path;
            target = next_target;
            hops += 1;
        }
    }

    /// One round trip, wrapped into a decoded, bounded, observed response.
    async fn hop(
        &self,
        plan: &ConnectionPlan,
        recorder: &TraceCollector,
        request: &Request,
        level: ObservationLevel,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Response, NetError> {
        let exchange = self
            .transport
            .round_trip(
                Attempt {
                    plan,
                    recorder,
                    observation: level,
                    config: &self.config,
                    deadline,
                },
                request,
            )
            .await?;
        let mut head = exchange.head;
        let decoder = Decoder::from_encoding(
            head.headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
        )?;
        // A `Content-Encoding` this client decodes must not be decoded again
        // by anyone downstream.
        if !matches!(decoder, Decoder::Identity) {
            head.headers.remove(http::header::CONTENT_ENCODING);
        }
        Ok(Response {
            head,
            body: Body::new(
                exchange.body,
                BodyContext {
                    recorder: recorder.clone(),
                    observation: level,
                    identity: plan.identity.clone(),
                    authority: plan.target.authority.clone(),
                    connection: exchange.connection,
                    decoder,
                    max_decoded: self.config.limits.max_body_bytes,
                    idle_timeout: self.config.body_idle_timeout,
                    deadline,
                },
            ),
        })
    }
}

/// Remove a header from both the normalized map and the raw wire form.
///
/// A request that set `raw_headers` is serialized from that vector, so
/// removing only from `headers` would leave the credential on the wire.
fn remove_header(head: &mut RequestHead, name: &str) {
    head.headers.remove(name);
    if let Some(raw) = head.raw_headers.as_mut() {
        raw.retain(|(candidate, _)| !candidate.eq_ignore_ascii_case(name));
    }
}

/// Add the trace-id header when propagation was asked for.
///
/// The header is inserted before any request bytes are written and after the
/// trace id exists. A caller-supplied header of the same name wins.
fn propagate(
    request: &mut Request,
    propagation: Option<&'static str>,
    recorder: &TraceCollector,
) -> Result<(), NetError> {
    let Some(name) = propagation else {
        return Ok(());
    };
    let refuse = |message: String| {
        recorder.record_error(
            DiagnosticRecord::new(DiagnosticCode::EGRESS_CONFIG)
                .with_phase(DiagnosticPhase::Request)
                .with_message(message.clone()),
        );
        NetError::Protocol(message)
    };
    let header = http::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
        refuse(format!(
            "invalid trace propagation header {name:?}: {error}"
        ))
    })?;
    let present = match request.head.raw_headers.as_ref() {
        Some(raw) => raw
            .iter()
            .any(|(candidate, _)| candidate.eq_ignore_ascii_case(header.as_str())),
        None => request.head.headers.contains_key(&header),
    };
    if !present {
        let id = recorder.meta().id.as_str().to_owned();
        let value = http::HeaderValue::from_str(&id)
            .map_err(|error| refuse(format!("invalid trace id header value: {error}")))?;
        // A raw head is serialized from `raw_headers`, and HTTP/2/3 take
        // their fields from it too; insert into both forms so propagation
        // survives every wire writer.
        if let Some(raw) = request.head.raw_headers.as_mut() {
            raw.push((header.as_str().to_owned(), id));
        }
        request.head.headers.insert(header, value);
    }
    Ok(())
}

/// The evidence a failed attempt carries, at the fidelity it can prove.
///
/// A traced attempt is L1 only if socket events were actually recorded: a
/// failure before any byte crossed a socket, or over a transport that has no
/// socket, is protocol evidence and says so.
pub(crate) fn evidence(recorder: &TraceCollector, level: ObservationLevel) -> TraceSnapshot {
    match level {
        ObservationLevel::Off => recorder.snapshot(Fidelity::none()),
        ObservationLevel::Counters => recorder.snapshot(Fidelity::l0()),
        ObservationLevel::Traced => {
            let mut snapshot = recorder.snapshot(Fidelity::l0());
            if snapshot.log.iter().any(|event| event.kind.is_byte_path()) {
                snapshot.fidelity = Fidelity::l1();
            }
            snapshot
        }
    }
}

#[cfg(feature = "ws")]
mod upgrade {
    use bytes::BytesMut;
    use http::{Method, StatusCode};
    use netune_http1::{Http1Reader, RequestHead, write_request};
    use netune_trace::{
        DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EventKind, TraceCollector,
    };

    use super::{Client, evidence};
    use crate::connect::Target;
    use crate::error::{AttemptError, NetError};
    use crate::exchange::{Attempt, ObservationLevel};
    use crate::ws::{WsHandshake, WsIo, WsStream};

    impl Client {
        /// Establish an upgraded, untraced client WebSocket stream to `target`.
        ///
        /// Call [`Client::connect_ws_traced`] with a recorder when the caller
        /// wants control, frame and socket events.
        pub async fn connect_ws(
            &self,
            target: &Target,
            path: &str,
        ) -> Result<WsStream<WsIo>, AttemptError> {
            let recorder = TraceCollector::disabled();
            self.upgrade(target, path, &recorder, None, WsHandshake::default())
                .await
                .map_err(|error| {
                    AttemptError::new(error, evidence(&recorder, ObservationLevel::Off))
                })
        }

        /// Establish an upgraded client WebSocket stream with an explicit
        /// trace recorder and negotiation knobs (`Sec-WebSocket-Protocol`
        /// selection, extra request headers, size limits).
        pub async fn connect_ws_traced(
            &self,
            target: &Target,
            path: &str,
            recorder: TraceCollector,
            handshake: WsHandshake,
        ) -> Result<WsStream<WsIo>, AttemptError> {
            self.upgrade(target, path, &recorder, Some(recorder.clone()), handshake)
                .await
                .map_err(|error| {
                    AttemptError::new(error, evidence(&recorder, ObservationLevel::Traced))
                })
        }

        async fn upgrade(
            &self,
            target: &Target,
            path: &str,
            recorder: &TraceCollector,
            stream_recorder: Option<TraceCollector>,
            handshake: WsHandshake,
        ) -> Result<WsStream<WsIo>, NetError> {
            // Every terminal failure inside this function must close out the
            // attempt's trace with an `Error` event: the trace must never end
            // without an explanation.
            let fail = |message: String| -> NetError {
                recorder.record_error(
                    DiagnosticRecord::new(DiagnosticCode::EGRESS_WS_FAILED)
                        .with_phase(DiagnosticPhase::WebSocket)
                        .with_message(message.clone()),
                );
                NetError::Protocol(message)
            };

            let plan = self.plan(target)?;
            let observation = if stream_recorder.is_some() {
                ObservationLevel::Traced
            } else {
                ObservationLevel::Off
            };
            let established = match self
                .transport
                .open_stream(Attempt {
                    plan: &plan,
                    recorder,
                    observation,
                    config: &self.config,
                    deadline: None,
                })
                .await
            {
                Ok(established) => established,
                Err(error) => {
                    recorder.record_error(error.diagnostic());
                    return Err(error);
                }
            };
            // From here the stream returns its socket events to the recorder
            // however it ends: a failed upgrade and a closed session alike.
            let mut io = WsIo::new(established.stream, stream_recorder.clone());

            let sec_key = netune_ws::generate_key();
            let mut head = RequestHead::new(Method::GET, path)
                .with_header(http::header::HOST, &target.authority)
                .with_header(http::header::UPGRADE, "websocket")
                .with_header(http::header::CONNECTION, "Upgrade")
                .with_header("sec-websocket-key", &sec_key)
                .with_header("sec-websocket-version", "13");

            if !handshake.subprotocols.is_empty() {
                // RFC 6455 §4.1: the client offers its preferences in order;
                // the server picks one and echoes it, or none.
                let offered = handshake.subprotocols.join(", ");
                head.headers.insert(
                    http::HeaderName::from_static("sec-websocket-protocol"),
                    http::HeaderValue::from_str(&offered)
                        .map_err(|e| fail(format!("Invalid subprotocol list: {e}")))?,
                );
            }
            for (name, value) in &handshake.extra_headers {
                let name = http::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| fail(format!("Invalid extra header name {name:?}: {e}")))?;
                let value = http::HeaderValue::from_str(value)
                    .map_err(|e| fail(format!("Invalid extra header value {value:?}: {e}")))?;
                head.headers.insert(name, value);
            }

            if !head.headers.contains_key(http::header::USER_AGENT) {
                head.headers.insert(
                    http::header::USER_AGENT,
                    http::HeaderValue::from_str(&self.config.user_agent)
                        .unwrap_or_else(|_| http::HeaderValue::from_static("netune")),
                );
            }
            if !head.headers.contains_key(http::header::CONTENT_LENGTH)
                && let Ok(value) = http::HeaderValue::from_str("0")
            {
                head.headers.insert(http::header::CONTENT_LENGTH, value);
            }
            plan.h1.apply(&mut head);

            recorder.mark(EventKind::RequestWriteStart, 0, 0);
            if let Err(error) = write_request(&mut io, &head, None).await {
                return Err(fail(format!("WebSocket request write: {error}")));
            }
            recorder.mark(EventKind::RequestWriteEnd, 0, 0);

            let mut reader =
                Http1Reader::with_limits_and_buffer(io, self.config.limits, BytesMut::new());
            let response_head = match crate::handshake::bound(
                handshake.handshake_timeout,
                DiagnosticPhase::WebSocket,
                "WebSocket handshake",
                &target.authority,
                recorder,
                reader.read_response_head(&Method::GET),
            )
            .await
            {
                Ok(Ok(head)) => head,
                Ok(Err(error)) => {
                    return Err(fail(format!("WebSocket upgrade response read: {error}")));
                }
                Err(error) => return Err(error),
            };

            if response_head.status != StatusCode::SWITCHING_PROTOCOLS {
                return Err(fail(format!(
                    "WebSocket upgrade rejected with status {}",
                    response_head.status
                )));
            }

            let is_upgrade = response_head
                .headers
                .get(http::header::UPGRADE)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false);
            if !is_upgrade {
                return Err(fail(
                    "Missing or invalid Upgrade header in WebSocket handshake response".to_string(),
                ));
            }

            let accept_header = response_head
                .headers
                .get("sec-websocket-accept")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            if let Err(error) = netune_ws::verify_handshake(&sec_key, accept_header) {
                return Err(fail(error.to_string()));
            }

            // If we offered subprotocols, the server must echo exactly one of
            // them back — or none, declining the negotiation.
            if !handshake.subprotocols.is_empty() {
                let echoed = response_head
                    .headers
                    .get("sec-websocket-protocol")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !echoed.is_empty()
                    && !handshake
                        .subprotocols
                        .iter()
                        .any(|offered| offered == echoed)
                {
                    return Err(fail(format!(
                        "Server selected subprotocol {echoed:?}, which was not offered"
                    )));
                }
            }

            recorder.mark(EventKind::HeadComplete, 0, 0);

            let (io, residual_buf) = reader.into_inner();
            Ok(WsStream::new(
                io,
                residual_buf,
                stream_recorder,
                handshake.limits,
            ))
        }
    }
}

#[cfg(not(feature = "ws"))]
impl Client {
    /// WebSocket support was compiled out.
    ///
    /// Returns an error rather than a silent fallback: a caller that asked for
    /// an upgraded stream must be told the capability is absent, not handed a
    /// plain HTTP response it will misread.
    pub async fn connect_ws(&self, _target: &Target, _path: &str) -> Result<(), AttemptError> {
        Err(AttemptError::without_evidence(NetError::Protocol(
            "WebSocket support was not compiled in: enable the `ws` feature".into(),
        )))
    }

    /// WebSocket support was compiled out.
    pub async fn connect_ws_traced(
        &self,
        _target: &Target,
        _path: &str,
        _recorder: TraceCollector,
        _handshake: (),
    ) -> Result<(), AttemptError> {
        Err(AttemptError::without_evidence(NetError::Protocol(
            "WebSocket support was not compiled in: enable the `ws` feature".into(),
        )))
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use crate::connect::TcpConnector;
    use crate::socket::SocketConfig;
    use netune_trace::EvasionPolicy;

    fn keyed_client() -> Client {
        Client::new(
            TcpConnector::new(),
            Pool::default(),
            ClientConfig::default(),
        )
    }

    #[test]
    fn inv_custom_04_pool_key_separates_server_names() {
        let client = keyed_client();
        let a = Target::tls("203.0.113.10:443", "a.example");
        let b = Target::tls("203.0.113.10:443", "b.example");
        assert_ne!(
            client.pool_key(&a).expect("plan"),
            client.pool_key(&b).expect("plan"),
            "the verified server name is part of the connection identity"
        );
    }

    #[test]
    fn inv_custom_04_pool_key_separates_evasion_policies() {
        let client = keyed_client();
        let plain = Target::tls("203.0.113.10:443", "a.example");
        let split = plain.clone().with_evasion(EvasionPolicy::sni_split());
        assert_ne!(
            client.pool_key(&plain).expect("plan"),
            client.pool_key(&split).expect("plan"),
            "a request that asked for wire shaping must not reuse an unshaped socket"
        );
    }

    #[cfg(feature = "http2")]
    #[test]
    fn inv_custom_04_pool_key_records_the_h2_profile() {
        let client = Client::new(
            TcpConnector::new(),
            Pool::default(),
            ClientConfig {
                enable_http2: true,
                ..ClientConfig::default()
            },
        );
        let target = Target::plain("203.0.113.10:80").with_protocol(HttpProtocol::Http2);
        assert_eq!(
            client
                .pool_key(&target)
                .expect("plan")
                .identity
                .h2_profile
                .as_deref(),
            Some("chrome-130")
        );
        let safari = target.with_tls_profile("safari-current");
        assert_eq!(
            client
                .pool_key(&safari)
                .expect("plan")
                .identity
                .h2_profile
                .as_deref(),
            Some("safari-18")
        );
    }

    #[test]
    fn a_target_authority_with_control_bytes_is_refused_while_planning() {
        let client = keyed_client();
        let target = Target::plain("evil.example\r\nX-Injected: 1:80");
        let error = client
            .plan(&target)
            .expect_err("control bytes must not reach a request line or Host header");
        assert!(
            error.to_string().contains("invalid target authority"),
            "{error}"
        );
    }

    #[test]
    fn an_unknown_h1_profile_fails_while_planning() {
        let client = keyed_client();
        let target = Target::plain("203.0.113.10:80").with_h1_profile("does-not-exist");
        let error = client
            .plan(&target)
            .expect_err("unknown H1 profile must fail");
        assert!(error.to_string().contains("unknown HTTP/1 wire profile"));
    }

    #[cfg(feature = "http2")]
    #[test]
    fn a_custom_h2_profile_is_resolved_and_recorded() {
        let client = keyed_client().with_h2_profile("my-chrome", H2Fingerprint::chrome());
        let target = Target::plain("203.0.113.10:80")
            .with_protocol(HttpProtocol::Http2)
            .with_h2_profile("my-chrome");
        let plan = client.plan(&target).expect("custom H2 plan");
        assert_eq!(plan.identity.h2_profile.as_deref(), Some("my-chrome"));
        assert!(plan.h2_fingerprint().is_some());
    }

    #[cfg(feature = "http2")]
    #[test]
    fn a_custom_h2_request_profile_is_resolved_without_changing_the_pool_key() {
        let client = keyed_client().with_h2_request_profile(
            "my-order",
            netune_http2::H2RequestProfile {
                name: "my-order",
                pseudo_headers_order: netune_http2::PseudoHeaderOrder::AuthorityMethodPathScheme,
                regular_header_order: netune_http2::RegularHeaderOrder::CallerOrder,
            },
        );
        let target = Target::plain("203.0.113.10:80")
            .with_protocol(HttpProtocol::Http2)
            .with_h2_request_profile("my-order");
        let plan = client.plan(&target).expect("plan");
        assert_eq!(plan.h2_request().expect("request profile").name, "my-order");
        let baseline = client
            .plan(&Target::plain("203.0.113.10:80").with_protocol(HttpProtocol::Http2))
            .expect("baseline plan");
        assert_eq!(plan.pool_key(), baseline.pool_key());
    }

    #[cfg(feature = "http2")]
    #[test]
    fn an_unknown_h2_request_profile_fails_while_planning() {
        let client = keyed_client();
        let target = Target::plain("203.0.113.10:80")
            .with_protocol(HttpProtocol::Http2)
            .with_h2_request_profile("does-not-exist");
        let error = client
            .plan(&target)
            .expect_err("unknown H2 request profile must fail");
        assert!(error.to_string().contains("unknown HTTP/2 request profile"));
    }

    #[cfg(feature = "http2")]
    #[test]
    fn an_unknown_h2_profile_fails_while_planning() {
        let client = keyed_client();
        let target = Target::plain("203.0.113.10:80")
            .with_protocol(HttpProtocol::Http2)
            .with_h2_profile("does-not-exist");
        let error = client
            .plan(&target)
            .expect_err("unknown H2 profile must fail");
        assert!(error.to_string().contains("unknown HTTP/2 profile"));
    }

    #[test]
    fn production_defaults_are_bounded() {
        let config = ClientConfig::default();
        assert_eq!(config.response_head_timeout, Some(Duration::from_secs(30)));
        assert_eq!(config.body_idle_timeout, Some(Duration::from_secs(60)));
        assert_eq!(config.request_timeout, Some(Duration::from_secs(300)));
    }

    #[test]
    fn trace_propagation_reaches_a_raw_head() {
        let recorder = TraceCollector::start(8);
        let mut request = Request::new(
            RequestHead::new(Method::GET, "/").with_raw_header("X-Keep", "yes"),
            RequestBody::Empty,
        );
        propagate(&mut request, Some("traceparent"), &recorder).expect("propagate");
        assert!(request.head.headers.contains_key("traceparent"));
        let raw = request.head.raw_headers.as_ref().expect("raw head");
        assert!(
            raw.iter()
                .any(|(name, value)| name == "traceparent" && value == recorder.meta().id.as_str())
        );
    }

    #[test]
    fn removing_a_header_strips_its_raw_wire_form_too() {
        let mut head = RequestHead::new(Method::GET, "/")
            .with_raw_header("Authorization", "Bearer secret")
            .with_raw_header("X-Keep", "yes");
        remove_header(&mut head, "authorization");
        assert!(!head.headers.contains_key("authorization"));
        let raw = head.raw_headers.as_ref().expect("raw head");
        assert!(
            raw.iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("authorization"))
        );
        assert!(
            raw.iter()
                .any(|(name, value)| name == "X-Keep" && value == "yes")
        );
    }

    #[test]
    fn inv_custom_04_pool_key_separates_socket_shapes() {
        let target = Target::plain("203.0.113.10:80");
        let first = Client::new(
            TcpConnector::new(),
            Pool::default(),
            ClientConfig::default(),
        );
        let second = Client::new(
            TcpConnector::new().with_socket_config(SocketConfig::windows_baseline()),
            Pool::default(),
            ClientConfig::default(),
        );
        assert_ne!(
            first.pool_key(&target).expect("plan"),
            second.pool_key(&target).expect("plan"),
            "a shared pool must not cross socket shapes"
        );
    }
}
