//! The client: one request, fully traced, policy applied.
//!
//! `Client::send` owns the request lifecycle — take a pooled connection or
//! establish one, write the request, parse the head, follow redirects, then
//! stream a decoded body — marking each milestone in the attempt's
//! [`TraceCollector`]. It owns no provider knowledge and no retry policy: those live
//! above (the harness).
//!
//! Redirects are followed here rather than by a wrapper because a redirect is a
//! property of the *attempt*: the trace must show the hops, and only the final
//! response may mark `HeadComplete`, or TTFT would be measured against a 302.

use std::sync::Arc;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
#[cfg(feature = "http2")]
use http::HeaderMap;
use http::{Method, StatusCode};
use netune_http1::{BodyKind, Http1Reader, IncomingResponse, Limits, RequestHead, write_request};
#[cfg(feature = "http2")]
use netune_http2::{H2ClientConnection, H2Fingerprint, H2ResponseEvent, H2ResponseStream};
use netune_trace::{
    Alpn, ConnectionIdentity, Counters, EventKind, Fidelity, NoTap, Ring, TRACE_SCHEMA_VERSION,
    Tap, TraceCollector, TraceSink,
};

use crate::connect::{Connector, Target};
use crate::decompress::Decoder;
use crate::error::NetError;
use crate::pool::{IdleConnection, Pool, PoolKey, Protocol};
use crate::profile::{ConnectionPlan, H1Registry, H1WireProfile, ProfileId};
#[cfg(feature = "http2")]
use crate::profile::{H2Registry, H2RequestRegistry};
use crate::tcp_info::{SAMPLE_INTERVAL, Sampler, start as start_sampler};
#[cfg(feature = "ws")]
use netune_io::RingIo;
use netune_io::TimedIo;

/// Split a request head into the HTTP/2 authority and its regular headers.
///
/// HTTP/2 carries the target authority in `:authority`; a client that generates
/// HTTP/2 requests directly SHOULD use that instead of `Host` (RFC 9113
/// §8.3.1). Some origins enforce the reading strictly: Google's frontend
/// answers a request carrying both with `RST_STREAM(PROTOCOL_ERROR)` (error
/// code 1), which surfaces as a request failure before a response exists. A
/// caller that set `Host` chose an authority, so it is promoted into
/// `:authority` rather than forwarded.
///
/// Regular header names are lowercased because HTTP/2 requires lowercase
/// names, even when `raw_headers` preserved caller casing for an HTTP/1.1
/// fingerprint.
#[cfg(feature = "http2")]
fn h2_request_parts(
    head: &RequestHead,
    fallback_authority: &str,
) -> (String, Vec<(String, String)>) {
    let mut authority: Option<String> = None;
    let mut headers = Vec::new();
    match &head.raw_headers {
        Some(raw) => {
            for (name, value) in raw {
                if name.eq_ignore_ascii_case("host") {
                    authority.get_or_insert_with(|| value.clone());
                } else {
                    headers.push((name.to_ascii_lowercase(), value.clone()));
                }
            }
        }
        None => {
            for (name, value) in head.headers.iter() {
                if name == http::header::HOST {
                    if let Ok(value) = value.to_str() {
                        authority.get_or_insert_with(|| value.to_string());
                    }
                } else {
                    headers.push((
                        name.as_str().to_string(),
                        value.to_str().unwrap_or_default().to_string(),
                    ));
                }
            }
        }
    }
    (
        authority.unwrap_or_else(|| fallback_authority.to_string()),
        headers,
    )
}

/// Map an HTTP/2 codec failure onto the transport's error taxonomy.
///
/// The distinction matters: a socket that died while no response head existed
/// yet is a *stale pooled connection*, and [`NetError::is_stale_connection`]
/// decides whether the attempt may be safely replayed. Reporting every codec
/// failure as [`NetError::Protocol`] would turn a recycled-but-dead HTTP/2
/// connection into a user-visible provider failure.
#[cfg(feature = "http2")]
fn h2_error(context: &str, error: netune_http2::H2Error) -> NetError {
    use netune_http2::error_code;
    match error {
        netune_http2::H2Error::Io(error) => NetError::Io(error),
        netune_http2::H2Error::UnexpectedEof => {
            NetError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        // Before the response head, both of these say the peer did not process
        // this stream: a fresh connection may replay it safely. They are not
        // `Protocol`: a pooled HTTP/2 connection that starts draining must not
        // turn into a user-visible generation failure.
        netune_http2::H2Error::GoAway { error_code, .. } if context == "request" => {
            NetError::RetryableProtocol(format!(
                "HTTP/2 {context}: peer closed with GOAWAY (error code {error_code})"
            ))
        }
        netune_http2::H2Error::StreamReset {
            stream_id,
            error_code,
        } if context == "request" && error_code == error_code::REFUSED_STREAM => {
            NetError::RetryableProtocol(format!("HTTP/2 {context}: stream {stream_id} was refused"))
        }
        other => NetError::Protocol(format!("HTTP/2 {context}: {other}")),
    }
}

/// How the next attempt observes its byte path.
///
/// The value selects one of three monomorphized taps; the byte path itself never
/// sees this enum. `Counters` is the default because a production client must be
/// debuggable at L0 without paying for a ring, a clock or a lock.
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
#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub capacity: usize,
    pub sink: Option<Arc<dyn TraceSink>>,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            capacity: crate::DEFAULT_TRACE_CAPACITY,
            sink: None,
        }
    }
}

impl TraceConfig {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            sink: None,
        }
    }

    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn TraceSink>) -> Self {
        self.sink = Some(sink);
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
}

/// Client policy.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub limits: Limits,
    /// Sent as `user-agent` when the caller did not supply one.
    pub user_agent: String,
    /// Redirect hops followed before giving up.
    pub max_redirects: u8,
    /// Whether to automatically upgrade to HTTP/2 when ALPN negotiates `h2`.
    pub enable_http2: bool,
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
            observation: Observation::Counters,
        }
    }
}

/// HTTP/1.1 body reader variants, one per monomorphized tap type.
///
/// The enum exists only at the body boundary; `TimedIo` and the codec inside
/// each variant are monomorphized and carry no trait object.
enum Http1Body {
    Off(Http1Reader<TimedIo<Box<dyn crate::connect::Transport>, NoTap>>),
    Counters(Http1Reader<TimedIo<Box<dyn crate::connect::Transport>, Counters>>),
    Traced(Http1Reader<TimedIo<Box<dyn crate::connect::Transport>, Ring>>),
}

/// The observation artifact attached to a response body.
#[derive(Debug, Clone, Copy)]
enum BodyObservation {
    Off,
    Counters(Option<Counters>),
    /// A traced body, with the fidelity its actual tap produced. HTTP/1 owns a
    /// `Ring` syscall tap; HTTP/2 currently records control/frame events only,
    /// so it reports L0 rather than claiming a byte timeline it does not have.
    Traced(Fidelity),
}

/// The internal bridge between the runtime policy and a concrete tap type.
///
/// This is deliberately private: a caller selects [`Observation`], and the
/// compiler monomorphizes one of three implementations. There is no public
/// `Box<dyn Tap>` seam.
trait ClientTap: Tap + Sized {
    fn create(observation: &Observation, origin: Instant) -> Self;
    fn wrap(reader: Http1Reader<TimedIo<Box<dyn crate::connect::Transport>, Self>>) -> Http1Body;
    fn initial() -> BodyObservation;
}

impl ClientTap for NoTap {
    fn create(_observation: &Observation, _origin: Instant) -> Self {
        NoTap
    }

    fn wrap(reader: Http1Reader<TimedIo<Box<dyn crate::connect::Transport>, Self>>) -> Http1Body {
        Http1Body::Off(reader)
    }

    fn initial() -> BodyObservation {
        BodyObservation::Off
    }
}

impl ClientTap for Counters {
    fn create(_observation: &Observation, _origin: Instant) -> Self {
        Counters::default()
    }

    fn wrap(reader: Http1Reader<TimedIo<Box<dyn crate::connect::Transport>, Self>>) -> Http1Body {
        Http1Body::Counters(reader)
    }

    fn initial() -> BodyObservation {
        BodyObservation::Counters(None)
    }
}

impl ClientTap for Ring {
    fn create(observation: &Observation, origin: Instant) -> Self {
        match observation {
            Observation::Traced(config) => Ring::new(origin, config.capacity, config.sink.clone()),
            _ => Ring::new(origin, crate::DEFAULT_TRACE_CAPACITY, None),
        }
    }

    fn wrap(reader: Http1Reader<TimedIo<Box<dyn crate::connect::Transport>, Self>>) -> Http1Body {
        Http1Body::Traced(reader)
    }

    fn initial() -> BodyObservation {
        BodyObservation::Traced(Fidelity::l1())
    }
}

/// An HTTP/1.1 client over a connector and a pool.
pub struct Client<C: Connector> {
    connector: C,
    pool: Pool,
    config: ClientConfig,
    h1_profiles: H1Registry,
    #[cfg(feature = "http2")]
    h2_profiles: H2Registry,
    #[cfg(feature = "http2")]
    h2_request_profiles: H2RequestRegistry,
}

impl<C: Connector> Client<C> {
    pub fn new(connector: C, pool: Pool, config: ClientConfig) -> Self {
        Self {
            connector,
            pool,
            config,
            h1_profiles: H1Registry::default(),
            #[cfg(feature = "http2")]
            h2_profiles: H2Registry::default(),
            #[cfg(feature = "http2")]
            h2_request_profiles: H2RequestRegistry::default(),
        }
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Whether this target selects HTTP/2, explicitly or by naming an H2
    /// profile. A named H2 profile is an assertion that the request speaks H2.
    fn wants_http2(&self, target: &Target) -> bool {
        self.config.enable_http2 || self.forces_h2(target)
    }

    /// Prior-knowledge H2: a mandate or an explicit H2 profile, independent of
    /// ALPN. `enable_http2` alone only upgrades when ALPN actually negotiates h2.
    fn forces_h2(&self, target: &Target) -> bool {
        target.force_h2
            || target.identity.h2_profile.is_some()
            || target.h2_request_profile.is_some()
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

    /// Resolve every choice for one request before a socket is opened.
    ///
    /// The returned plan separates connection identity (pool key) from the
    /// per-request wire profiles (H1 header order, H2 pseudo-header order).
    /// Unknown profile names fail here, not after a handshake.
    pub fn plan(&self, target: &Target) -> Result<ConnectionPlan, NetError> {
        let h1_id = target
            .h1_profile
            .as_ref()
            .unwrap_or_else(|| self.h1_profiles.default_profile().id());
        let h1 = self.h1_profiles.resolve(h1_id)?.clone();

        let mut identity = target.identity.clone();
        if identity.socket_shape.is_none() {
            identity.socket_shape = self.connector.socket_shape();
        }
        if identity.route.is_none() {
            identity.route = self.connector.route_shape();
        }

        #[cfg(feature = "http2")]
        let h2 = if self.wants_http2(target) {
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
                            NetError::Connect(
                                "no built-in HTTP/2 profile is registered; register one with \
                                 Client::with_h2_profile"
                                    .into(),
                            )
                        })?;
                    if self.forces_h2(target) {
                        identity.h2_profile = Some(id.to_string());
                    }
                    Some(fingerprint.clone())
                }
            }
        } else {
            None
        };

        #[cfg(not(feature = "http2"))]
        if self.wants_http2(target) {
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
            #[cfg(feature = "http2")]
            h2,
            #[cfg(feature = "http2")]
            h2_request,
        })
    }

    /// Pre-warm a connection for `target` into the idle pool if none exists.
    ///
    /// Runs DNS + TCP + TLS in advance so the next user request can start with
    /// zero connection overhead (instant warm-pool hit). Returns `true` if a fresh
    /// connection was opened, or `false` if an idle connection was already available.
    pub async fn prewarm(&self, target: &Target) -> Result<bool, NetError> {
        let plan = self.plan(target)?;
        let key = plan.pool_key();
        if self.pool.idle_count(&key) > 0 {
            return Ok(false);
        }
        // Pre-warming is a pool operation, not an attempt: there is no consumer
        // for a trace of it, so it must not allocate one.
        let recorder = TraceCollector::disabled();
        let established = self.connector.connect(target, &recorder).await?;

        // Warm the connection in the protocol the next request will actually
        // use; pooling an already-negotiated HTTP/2 socket as if it were
        // HTTP/1.1 would hand it to the wrong writer.
        #[cfg(feature = "http2")]
        if self.forces_h2(target)
            || (self.config.enable_http2 && established.alpn == Some(Alpn::H2))
        {
            let fp = plan.h2.ok_or_else(|| {
                NetError::Protocol("HTTP/2 prewarm has no resolved H2 profile".into())
            })?;
            let h2 = H2ClientConnection::handshake(established.stream, fp)
                .await
                .map_err(|error| h2_error("handshake", error))?;
            self.pool
                .put_http2(&key, h2, established.local_port, established.socket);
            return Ok(true);
        }

        self.pool.put_http1(
            &key,
            established.stream,
            BytesMut::new(),
            established.local_port,
            established.socket,
        );
        Ok(true)
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
        body: Option<Bytes>,
    ) -> Result<Response, NetError> {
        self.send(target, head, body, self.config.observation.clone())
            .await
    }

    /// Send one request with no byte-path observation.
    pub async fn request_untraced(
        &self,
        target: &Target,
        head: RequestHead,
        body: Option<Bytes>,
    ) -> Result<Response, NetError> {
        self.send(target, head, body, Observation::Off).await
    }

    /// Send one request with an event-ring byte timeline.
    pub async fn request_traced(
        &self,
        target: &Target,
        head: RequestHead,
        body: Option<Bytes>,
        config: TraceConfig,
    ) -> Result<Response, NetError> {
        self.send(target, head, body, Observation::Traced(config))
            .await
    }

    /// Establish an upgraded, untraced client WebSocket stream to `target`.
    ///
    /// Pass an explicit recorder through [`Client::connect_ws_traced`] when the
    /// caller wants control and frame events.
    #[cfg(feature = "ws")]
    pub async fn connect_ws(
        &self,
        target: &Target,
        path: &str,
    ) -> Result<crate::ws::WsStream<TimedIo<Box<dyn crate::connect::Transport>, NoTap>>, NetError>
    {
        let recorder = TraceCollector::disabled();
        self.connect_ws_with(
            target,
            path,
            recorder,
            |stream| TimedIo::new(stream, NoTap),
            None,
            crate::ws::WsHandshake::default(),
        )
        .await
    }

    /// WebSocket support was compiled out.
    ///
    /// Returns an error rather than a silent fallback: a caller that asked for
    /// an upgraded stream must be told the capability is absent, not handed a
    /// plain HTTP response it will misread.
    #[cfg(not(feature = "ws"))]
    pub async fn connect_ws(&self, _target: &Target, _path: &str) -> Result<(), NetError> {
        Err(NetError::Protocol(
            "WebSocket support was not compiled in: enable the `ws` feature".into(),
        ))
    }

    /// Establish an upgraded client WebSocket stream with explicit trace recorder and limits.
    ///
    /// `handshake` carries the optional negotiation knobs (`Sec-WebSocket-Protocol`
    /// selection, extra request headers, size limits).
    #[cfg(feature = "ws")]
    pub async fn connect_ws_traced(
        &self,
        target: &Target,
        path: &str,
        recorder: TraceCollector,
        handshake: crate::ws::WsHandshake,
    ) -> Result<crate::ws::WsStream<RingIo<Box<dyn crate::connect::Transport>>>, NetError> {
        let (origin, capacity, sink) = (recorder.origin(), recorder.capacity(), recorder.sink());
        let ring = Ring::new(origin, capacity, sink);
        let recorder_for_io = recorder.clone();
        self.connect_ws_with(
            target,
            path,
            recorder.clone(),
            move |stream| RingIo::new(stream, ring, recorder_for_io),
            Some(recorder),
            handshake,
        )
        .await
    }

    #[cfg(feature = "ws")]
    #[allow(clippy::too_many_arguments)]
    async fn connect_ws_with<S, F>(
        &self,
        target: &Target,
        path: &str,
        recorder: TraceCollector,
        make_stream: F,
        stream_recorder: Option<TraceCollector>,
        handshake: crate::ws::WsHandshake,
    ) -> Result<crate::ws::WsStream<S>, NetError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        F: FnOnce(Box<dyn crate::connect::Transport>) -> S,
    {
        // Every terminal failure inside this function must close out the
        // attempt's trace with an `Error` event: the trace must never end as
        // an unexplained headless corpse.
        let fail = |recorder: &TraceCollector, message: String| -> NetError {
            recorder.mark(EventKind::Error, 0, 0);
            NetError::Protocol(message)
        };

        let established = match self.connector.connect(target, &recorder).await {
            Ok(established) => established,
            Err(error) => {
                recorder.mark(EventKind::Error, 0, 0);
                return Err(error);
            }
        };
        let mut io = make_stream(established.stream);

        let sec_key = netune_ws::generate_key();
        let mut head = RequestHead::new(Method::GET, path)
            .with_header(http::header::HOST, &target.authority)
            .with_header(http::header::UPGRADE, "websocket")
            .with_header(http::header::CONNECTION, "Upgrade")
            .with_header("sec-websocket-key", &sec_key)
            .with_header("sec-websocket-version", "13");

        if !handshake.subprotocols.is_empty() {
            // RFC 6455 §4.1: the client offers its preferences in order; the
            // server picks one and echoes it, or none.
            let offered = handshake.subprotocols.join(", ");
            head.headers.insert(
                http::HeaderName::from_static("sec-websocket-protocol"),
                http::HeaderValue::from_str(&offered)
                    .map_err(|e| fail(&recorder, format!("Invalid subprotocol list: {e}")))?,
            );
        }
        for (name, value) in &handshake.extra_headers {
            let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                fail(
                    &recorder,
                    format!("Invalid extra header name {name:?}: {e}"),
                )
            })?;
            let value = http::HeaderValue::from_str(value).map_err(|e| {
                fail(
                    &recorder,
                    format!("Invalid extra header value {value:?}: {e}"),
                )
            })?;
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
        self.plan(target)?.h1.apply(&mut head);

        recorder.mark(EventKind::RequestWriteStart, 0, 0);
        if let Err(error) = write_request(&mut io, &head, None).await {
            return Err(fail(&recorder, format!("WebSocket request write: {error}")));
        }
        recorder.mark(EventKind::RequestWriteEnd, 0, 0);

        let mut reader =
            Http1Reader::with_limits_and_buffer(io, self.config.limits, BytesMut::new());
        let response_head = match reader.read_response_head(&Method::GET).await {
            Ok(head) => head,
            Err(error) => {
                return Err(fail(
                    &recorder,
                    format!("WebSocket upgrade response read: {error}"),
                ));
            }
        };

        if response_head.status != StatusCode::SWITCHING_PROTOCOLS {
            return Err(fail(
                &recorder,
                format!(
                    "WebSocket upgrade rejected with status {}",
                    response_head.status
                ),
            ));
        }

        let is_upgrade = response_head
            .headers
            .get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        if !is_upgrade {
            return Err(fail(
                &recorder,
                "Missing or invalid Upgrade header in WebSocket handshake response".to_string(),
            ));
        }

        let accept_header = response_head
            .headers
            .get("sec-websocket-accept")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();

        if let Err(error) = netune_ws::verify_handshake(&sec_key, accept_header) {
            return Err(fail(&recorder, error.to_string()));
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
                return Err(fail(
                    &recorder,
                    format!("Server selected subprotocol {echoed:?}, which was not offered"),
                ));
            }
        }

        recorder.mark(EventKind::HeadComplete, 0, 0);

        let (io, residual_buf) = reader.into_inner();
        Ok(crate::ws::WsStream::new(
            io,
            residual_buf,
            stream_recorder,
            handshake.limits,
        ))
    }

    /// WebSocket support was compiled out.
    #[cfg(not(feature = "ws"))]
    pub async fn connect_ws_traced(
        &self,
        _target: &Target,
        _path: &str,
        _recorder: TraceCollector,
        _handshake: (),
    ) -> Result<(), NetError> {
        Err(NetError::Protocol(
            "WebSocket support was not compiled in: enable the `ws` feature".into(),
        ))
    }

    /// Send one request, following redirects, and return the final response.
    ///
    /// The observation policy is selected once at this boundary; the byte path
    /// is monomorphized for the corresponding tap type.
    pub async fn send(
        &self,
        target: &Target,
        head: RequestHead,
        body: Option<Bytes>,
        observation: Observation,
    ) -> Result<Response, NetError> {
        let recorder = match &observation {
            Observation::Traced(config) => {
                let mut recorder = TraceCollector::start(config.capacity);
                if let Some(sink) = &config.sink {
                    recorder = recorder.with_sink(Arc::clone(sink));
                }
                recorder
            }
            Observation::Off | Observation::Counters => TraceCollector::disabled(),
        };

        match &observation {
            Observation::Off => {
                self.send_with::<NoTap>(target, recorder, head, body, &observation)
                    .await
            }
            Observation::Counters => {
                self.send_with::<Counters>(target, recorder, head, body, &observation)
                    .await
            }
            Observation::Traced(_) => {
                self.send_with::<Ring>(target, recorder, head, body, &observation)
                    .await
            }
        }
    }

    /// Send one request with an explicitly supplied attempt recorder.
    ///
    /// This is the escape hatch for a consumer that already owns the control
    /// recorder (tests, a relay, a harness that wants to stream trace events).
    /// The byte-path tap is still owned by `TimedIo`; its log is merged into the
    /// supplied recorder when the body is released.
    pub async fn send_traced(
        &self,
        target: &Target,
        recorder: TraceCollector,
        head: RequestHead,
        body: Option<Bytes>,
    ) -> Result<Response, NetError> {
        let observation = Observation::Traced(TraceConfig {
            capacity: recorder.capacity(),
            sink: recorder.sink(),
        });
        self.send_with::<Ring>(target, recorder, head, body, &observation)
            .await
    }

    async fn send_with<T: ClientTap>(
        &self,
        target: &Target,
        recorder: TraceCollector,
        head: RequestHead,
        body: Option<Bytes>,
        observation: &Observation,
    ) -> Result<Response, NetError> {
        let origin = target.authority.clone();
        let mut target = target.clone();
        let mut head = head;
        let mut body = body;
        let mut hops: u8 = 0;

        loop {
            let plan = self.plan(&target)?;
            let response = self
                .send_once::<T>(
                    &plan,
                    recorder.clone(),
                    head.clone(),
                    body.clone(),
                    observation,
                )
                .await?;
            let Some(location) = redirect_location(&response.head) else {
                // Only the final head marks completion: a redirect's head must
                // not become the anchor TTFT is measured against.
                recorder.mark(EventKind::HeadComplete, 0, 0);
                return Ok(response);
            };
            if hops >= self.config.max_redirects {
                return Err(NetError::TooManyRedirects(self.config.max_redirects));
            }
            let status = response.head.status;
            // The hop's connection is not pooled: its body was never drained, so
            // reusing it could desynchronise the stream.
            drop(response);
            recorder.mark(EventKind::Redirect, u32::from(status.as_u16()), 0);

            let (next_target, next_path) = resolve_location(&target, &head.target, &location)?;
            if next_target.authority != origin {
                // Credentials never follow a redirect off the original origin.
                for header in [
                    http::header::AUTHORIZATION,
                    http::header::COOKIE,
                    http::header::PROXY_AUTHORIZATION,
                ] {
                    head.headers.remove(header);
                }
            }
            if redirect_to_get(status) && head.method != Method::HEAD {
                head.method = Method::GET;
                head.headers.remove(http::header::CONTENT_TYPE);
                head.headers.remove(http::header::CONTENT_LENGTH);
                body = None;
            }
            head.target = next_path;
            target = next_target;
            hops += 1;
        }
    }

    async fn send_once<T: ClientTap>(
        &self,
        plan: &ConnectionPlan,
        recorder: TraceCollector,
        head: RequestHead,
        body: Option<Bytes>,
        observation: &Observation,
    ) -> Result<Response, NetError> {
        let target = &plan.target;
        // A pooled socket may have been discarded by the peer while it sat idle,
        // and virtually every HTTP peer does this without a `close_notify`. That
        // is a normal way for a connection to end, not a failure of the request,
        // so the transport absorbs it instead of asking the user to re-select a
        // model to get a fresh pool. The retry is only ever taken *before* a
        // response head was parsed, on a connection this attempt took from the
        // pool: the request provably had not reached the origin, so re-sending
        // it cannot duplicate a side effect.
        // Prefer a pooled connection already speaking the protocol this client
        // wants, and never hand an HTTP/2 connection to the HTTP/1.1 writer (or
        // a keep-alive socket to a request that mandates HTTP/2).
        let key = plan.pool_key();
        #[cfg(feature = "http2")]
        let prefer_http2 = self.wants_http2(target);

        #[cfg(feature = "http2")]
        let mut recycled = if prefer_http2 {
            self.pool
                .take_matching(&key, |protocol| protocol == Protocol::Http2)
        } else {
            None
        };
        #[cfg(not(feature = "http2"))]
        let mut recycled = None;

        if recycled.is_none() && !self.forces_h2(target) {
            recycled = self
                .pool
                .take_matching(&key, |protocol| protocol == Protocol::Http1);
        }
        loop {
            let reused = recycled.is_some();
            let attempt = self
                .send_on_connection::<T>(
                    plan,
                    recorder.clone(),
                    &head,
                    &body,
                    recycled.take(),
                    observation,
                )
                .await;
            match attempt {
                Err(error) if reused && error.is_stale_connection() => {
                    // The socket died before the peer answered. Record the
                    // revocation so the trace explains both the decision and the
                    // cost: the reuse claim is withdrawn and the handshake this
                    // attempt is about to pay is measured rather than reported
                    // as `ConnectionReused`.
                    recorder.mark(EventKind::ConnectStaleDiscarded, 0, 0);
                    continue;
                }
                other => return other,
            }
        }
    }

    /// Write `head`/`body` on `recycled` (or a fresh connection) and return the
    /// response, with no recovery of its own.
    async fn send_on_connection<T: ClientTap>(
        &self,
        plan: &ConnectionPlan,
        recorder: TraceCollector,
        head: &RequestHead,
        body: &Option<Bytes>,
        recycled: Option<IdleConnection>,
        observation: &Observation,
    ) -> Result<Response, NetError> {
        let target = &plan.target;
        let mut head = head.clone();
        if !head.headers.contains_key(http::header::USER_AGENT) {
            head.headers.insert(
                http::header::USER_AGENT,
                http::HeaderValue::from_str(&self.config.user_agent)
                    .unwrap_or_else(|_| http::HeaderValue::from_static("netune")),
            );
        }

        // A pooled connection already speaks a protocol. Drive it with the role
        // that protocol requires; a connection the request cannot use is dropped
        // and a fresh one is dialled.
        if let Some(recycled) = recycled {
            match recycled {
                IdleConnection::Http1(idle) if !self.forces_h2(target) => {
                    // One event, carrying the idle age: `derive` and every
                    // surface read reuse through `first_of(ConnectReused)`.
                    recorder.mark(EventKind::ConnectReused, idle.age.as_millis() as u32, 0);
                    return self
                        .send_http1::<T>(
                            idle.stream,
                            idle.buffered,
                            idle.local_port,
                            idle.socket,
                            recorder,
                            head,
                            body,
                            plan,
                            observation,
                        )
                        .await;
                }
                #[cfg(feature = "http2")]
                IdleConnection::Http2(idle) if self.wants_http2(target) => {
                    recorder.mark(EventKind::ConnectReused, idle.age.as_millis() as u32, 0);
                    return self
                        .send_http2(
                            *idle.connection,
                            idle.local_port,
                            idle.socket,
                            recorder,
                            head,
                            body,
                            plan,
                            T::initial(),
                        )
                        .await;
                }
                // A protocol this request cannot drive: discard it and dial.
                IdleConnection::Http1(_) => {}
                #[cfg(feature = "http2")]
                IdleConnection::Http2(_) => {}
            }
        }

        let established = self.connector.connect(target, &recorder).await?;

        // Without the `http2` feature this fails closed instead of falling back
        // to HTTP/1.1: a caller that mandated H2, or an upstream that only
        // negotiated `h2` over ALPN, must not be handed a downgraded request.
        #[cfg(not(feature = "http2"))]
        if target.force_h2 || established.alpn == Some(Alpn::H2) {
            return Err(NetError::Protocol(
                "HTTP/2 was requested but the `http2` feature is not compiled in".into(),
            ));
        }

        #[cfg(feature = "http2")]
        if self.forces_h2(target)
            || (self.config.enable_http2 && established.alpn == Some(Alpn::H2))
        {
            let fp = plan.h2.clone().ok_or_else(|| {
                NetError::Protocol("HTTP/2 was selected but no H2 profile was resolved".into())
            })?;
            let h2 = H2ClientConnection::handshake(established.stream, fp)
                .await
                .map_err(|error| h2_error("handshake", error))?;
            return self
                .send_http2(
                    h2,
                    established.local_port,
                    established.socket,
                    recorder,
                    head,
                    body,
                    plan,
                    T::initial(),
                )
                .await;
        }

        self.send_http1::<T>(
            established.stream,
            BytesMut::new(),
            established.local_port,
            established.socket,
            recorder,
            head,
            body,
            plan,
            observation,
        )
        .await
    }

    /// Write the request over HTTP/1.1 and return its streaming response.
    #[allow(clippy::too_many_arguments)]
    async fn send_http1<T: ClientTap>(
        &self,
        stream: Box<dyn crate::connect::Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
        recorder: TraceCollector,
        mut head: RequestHead,
        body: &Option<Bytes>,
        plan: &ConnectionPlan,
        observation: &Observation,
    ) -> Result<Response, NetError> {
        let target = &plan.target;
        let pool_key = plan.pool_key();
        if !head.headers.contains_key(http::header::HOST)
            && let Ok(value) = http::HeaderValue::from_str(&target.authority)
        {
            head.headers.insert(http::header::HOST, value);
        }
        // Materialize Content-Length before the profile so the profile controls
        // its casing and position too; `write_request` only auto-adds one when
        // the head is not raw.
        if !head.headers.contains_key(http::header::CONTENT_LENGTH) {
            let length = body.as_ref().map_or(0, |body| body.len());
            if let Ok(value) = http::HeaderValue::from_str(&length.to_string()) {
                head.headers.insert(http::header::CONTENT_LENGTH, value);
            }
        }
        plan.h1.apply(&mut head);

        // Sample the socket for as long as this request is in flight. The
        // sampler gets its own duplicate handle; `socket` travels with the body
        // stream so the pool can be handed a live handle when it is released.
        let sampler = socket.as_ref().and_then(|socket| {
            crate::tcp_info::duplicate(socket)
                .map(|clone| start_sampler(clone, recorder.clone(), SAMPLE_INTERVAL))
        });

        let tap = T::create(observation, recorder.origin());
        let mut io = TimedIo::new(stream, tap);
        recorder.mark(EventKind::RequestWriteStart, 0, 0);
        write_request(&mut io, &head, body.as_deref()).await?;
        let written = body.as_ref().map_or(0, |body| body.len()) as u32;
        recorder.mark(EventKind::RequestWriteEnd, written, 0);

        let mut reader = Http1Reader::with_limits_and_buffer(io, self.config.limits, buffered);
        let response_head = reader.read_response_head(&head.method).await?;
        let reusable = is_reusable(&response_head);
        let decoder = Decoder::from_encoding(
            response_head
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
        )?;
        // A `Content-Encoding` we just decoded must not be re-decoded by anyone
        // downstream.
        let mut response_head = response_head;
        if !matches!(decoder, Decoder::Identity) {
            response_head.headers.remove(http::header::CONTENT_ENCODING);
        }
        Ok(Response {
            head: response_head,
            body: BodyStream {
                reader: Some(T::wrap(reader)),
                #[cfg(feature = "http2")]
                h2: None,
                recorder,
                observation: T::initial(),
                identity: pool_key.identity.clone(),
                pool: self.pool.clone(),
                pool_key,
                authority: target.authority.clone(),
                local_port,
                reusable,
                started: false,
                finished: false,
                sampler,
                socket,
                decoder,
                decoded: 0,
                max_decoded: self.config.limits.max_body_bytes,
            },
        })
    }

    /// Write the request over HTTP/2 and return its streaming response.
    #[cfg(feature = "http2")]
    #[allow(clippy::too_many_arguments)]
    async fn send_http2(
        &self,
        mut h2: H2ClientConnection<Box<dyn crate::connect::Transport>>,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
        recorder: TraceCollector,
        head: RequestHead,
        body: &Option<Bytes>,
        plan: &ConnectionPlan,
        observation: BodyObservation,
    ) -> Result<Response, NetError> {
        let target = &plan.target;
        let pool_key = plan.pool_key();
        let mut identity = plan.identity.clone();
        if identity.h2_profile.is_none()
            && let Some(fingerprint) = &plan.h2
        {
            identity.h2_profile = Some(fingerprint.connection.name.to_string());
        }
        let observation = match observation {
            BodyObservation::Traced(_) => BodyObservation::Traced(Fidelity::l0()),
            other => other,
        };
        let scheme = if target.tls_server_name().is_some() {
            "https"
        } else {
            "http"
        };
        let (authority, extra_headers) = h2_request_parts(&head, &target.authority);

        recorder.mark(EventKind::RequestWriteStart, 0, 0);
        let request_profile = plan.h2_request.unwrap_or(*h2.request_profile());
        let stream_id = h2
            .start_request_with_profile(
                head.method.as_str(),
                &authority,
                scheme,
                &head.target,
                &extra_headers,
                body.as_deref(),
                &request_profile,
            )
            .await
            .map_err(|error| h2_error("request", error))?;
        let written = body.as_ref().map_or(0, |body| body.len()) as u32;
        recorder.mark(EventKind::RequestWriteEnd, written, 0);

        let response = h2
            .read_response_head(stream_id)
            .await
            .map_err(|error| h2_error("request", error))?;
        let stream = h2.into_response_stream(stream_id, &response);

        let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK);
        let mut headers = HeaderMap::new();
        for (name, value) in response.headers {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::try_from(name.as_str()),
                http::header::HeaderValue::try_from(value.as_str()),
            ) {
                headers.append(name, value);
            }
        }

        let decoder = Decoder::from_encoding(
            headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
        )?;
        if !matches!(decoder, Decoder::Identity) {
            headers.remove(http::header::CONTENT_ENCODING);
        }
        let body_kind = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map_or(BodyKind::Chunked, BodyKind::Length);

        let sampler = socket.as_ref().and_then(|socket| {
            crate::tcp_info::duplicate(socket)
                .map(|clone| start_sampler(clone, recorder.clone(), SAMPLE_INTERVAL))
        });

        Ok(Response {
            head: IncomingResponse {
                version: http::Version::HTTP_2,
                status,
                headers,
                body: body_kind,
            },
            body: BodyStream {
                reader: None,
                h2: Some(stream),
                recorder,
                observation,
                identity,
                pool: self.pool.clone(),
                pool_key,
                authority: target.authority.clone(),
                local_port,
                reusable: true,
                started: false,
                finished: false,
                sampler,
                socket,
                decoder,
                decoded: 0,
                max_decoded: self.config.limits.max_body_bytes,
            },
        })
    }
}

/// The `Location` of a redirecting response, if any.
fn redirect_location(head: &IncomingResponse) -> Option<String> {
    match head.status.as_u16() {
        301 | 302 | 303 | 307 | 308 => head
            .headers
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        _ => None,
    }
}

/// Whether this status turns a non-`HEAD` request into a `GET` with no body.
fn redirect_to_get(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301..=303)
}

/// Whether the peer's framing allows the connection to be pooled.
///
/// A close-delimited body cannot be reused (its end is the connection's end),
/// and an explicit `connection: close` or an HTTP/1.0 response without
/// `keep-alive` ends the connection by contract.
fn is_reusable(head: &IncomingResponse) -> bool {
    let mut close = false;
    let mut keep_alive = false;
    for value in head.headers.get_all(http::header::CONNECTION) {
        if let Ok(value) = value.to_str() {
            for token in value.split(',') {
                let token = token.trim();
                close |= token.eq_ignore_ascii_case("close");
                keep_alive |= token.eq_ignore_ascii_case("keep-alive");
            }
        }
    }
    if close {
        return false;
    }
    if head.version == http::Version::HTTP_10 && !keep_alive {
        return false;
    }
    !matches!(head.body, BodyKind::UntilClose)
}

/// Resolve a `Location` against the request that produced it.
fn resolve_location(
    current: &Target,
    current_path: &str,
    location: &str,
) -> Result<(Target, String), NetError> {
    if let Some(rest) = location.strip_prefix("https://") {
        let (authority, path) = split_authority(rest, 443);
        let name = authority
            .rsplit_once(':')
            .map_or(authority.as_str(), |(host, _)| host)
            .to_string();
        let mut target = Target::tls(authority, name);
        // A redirect changes the destination, not the identity the caller
        // selected. Only the authority and the verified server name follow the
        // new location.
        target.identity.tls_profile = current.identity.tls_profile.clone();
        target.identity.evasion = current.identity.evasion;
        target.identity.h2_profile = current.identity.h2_profile.clone();
        target.force_h2 = current.force_h2;
        target.h1_profile = current.h1_profile.clone();
        target.h2_request_profile = current.h2_request_profile.clone();
        return Ok((target, path));
    }
    if let Some(rest) = location.strip_prefix("http://") {
        let (authority, path) = split_authority(rest, 80);
        let mut target = Target::plain(authority);
        target.identity.evasion = current.identity.evasion;
        target.h1_profile = current.h1_profile.clone();
        target.h2_request_profile = current.h2_request_profile.clone();
        return Ok((target, path));
    }
    if let Some(rest) = location.strip_prefix("//") {
        let (authority, path) = split_authority(rest, default_port(current));
        let mut target = current.clone();
        target.authority = authority;
        if target.identity.tls_server_name.is_some() {
            target.identity.tls_server_name = Some(
                target
                    .authority
                    .rsplit_once(':')
                    .map_or(target.authority.as_str(), |(host, _)| host)
                    .to_string(),
            );
        }
        return Ok((target, path));
    }
    if location.starts_with('/') {
        return Ok((current.clone(), location.to_string()));
    }
    // Relative reference: replace the last path segment.
    let base = current_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    Ok((current.clone(), format!("{base}/{location}")))
}

fn default_port(target: &Target) -> u16 {
    if target.tls_server_name().is_some() {
        443
    } else {
        80
    }
}

/// Split `host[:port][/path]` into `(host:port, path)`.
fn split_authority(rest: &str, default_port: u16) -> (String, String) {
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let has_port = authority
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.chars().all(|character| character.is_ascii_digit()));
    let authority = if has_port {
        authority.to_string()
    } else {
        format!("{authority}:{default_port}")
    };
    (authority, path.to_string())
}

/// A parsed response: head plus a decoded, traced body stream.
pub struct Response {
    pub head: IncomingResponse,
    pub body: BodyStream,
}

/// Streams the response body, decoding `Content-Encoding` and marking chunk
/// boundaries and completion.
pub struct BodyStream {
    reader: Option<Http1Body>,
    #[cfg(feature = "http2")]
    h2: Option<H2ResponseStream<Box<dyn crate::connect::Transport>>>,
    recorder: TraceCollector,
    observation: BodyObservation,
    identity: ConnectionIdentity,
    pool: Pool,
    pool_key: PoolKey,
    authority: String,
    local_port: Option<u16>,
    reusable: bool,
    started: bool,
    finished: bool,
    sampler: Option<Sampler>,
    /// Duplicate socket descriptor, handed back to the pool on release so the
    /// next request can sample the same socket.
    socket: Option<std::net::TcpStream>,
    decoder: Decoder,
    /// Decoded bytes emitted so far, bounded so a compression bomb cannot
    /// exhaust memory.
    decoded: u64,
    max_decoded: u64,
}

impl Drop for BodyStream {
    fn drop(&mut self) {
        // A redirect hop or an abandoned response never reaches `release`, but
        // its byte tap still belongs to the attempt trace. Merge it here; the
        // connection itself is deliberately not pooled because its body was not
        // drained.
        if let Some(Http1Body::Traced(reader)) = self.reader.take() {
            let (io, _buffered) = reader.into_inner();
            let (_stream, tap) = io.into_parts();
            self.recorder.merge(tap.finish());
        }
    }
}

impl BodyStream {
    /// Read the next decoded body bytes, or `None` at the end of the body.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, NetError> {
        loop {
            let Some(raw) = self.read_raw_chunk().await? else {
                let mut tail = Vec::new();
                self.decoder.finish(&mut tail)?;
                self.recorder.mark(EventKind::BodyEnd, 0, 0);
                self.finished = true;
                self.release();
                return Ok(if tail.is_empty() {
                    None
                } else {
                    Some(Bytes::from(tail))
                });
            };

            let mut decoded = Vec::new();
            self.decoder.push(&raw, &mut decoded)?;
            self.decoded = self.decoded.saturating_add(decoded.len() as u64);
            if self.decoded > self.max_decoded {
                return Err(NetError::Decode(
                    "decoded body exceeded the configured limit".into(),
                ));
            }
            if !self.started {
                self.recorder.mark(EventKind::BodyStart, 0, 0);
                self.started = true;
            }
            if !decoded.is_empty() {
                self.recorder
                    .mark(EventKind::ChunkBoundary, decoded.len() as u32, 0);
            }
            if !decoded.is_empty() {
                return Ok(Some(Bytes::from(decoded)));
            }
            // The decoder consumed the raw bytes without producing output (a
            // header, or a partial frame): keep reading.
        }
    }

    /// Read the next raw (still `Content-Encoding`-encoded) body chunk.
    async fn read_raw_chunk(&mut self) -> Result<Option<Bytes>, NetError> {
        match self.reader.as_mut() {
            Some(Http1Body::Off(reader)) => {
                return reader.read_body_chunk().await.map_err(NetError::from);
            }
            Some(Http1Body::Counters(reader)) => {
                return reader.read_body_chunk().await.map_err(NetError::from);
            }
            Some(Http1Body::Traced(reader)) => {
                return reader.read_body_chunk().await.map_err(NetError::from);
            }
            None => {}
        }
        #[cfg(feature = "http2")]
        if let Some(h2) = self.h2.as_mut() {
            loop {
                match h2
                    .next_event()
                    .await
                    .map_err(|error| h2_error("body", error))?
                {
                    H2ResponseEvent::Data { payload, .. } => {
                        if payload.is_empty() {
                            continue;
                        }
                        return Ok(Some(payload));
                    }
                    // The trailer block ends the stream; the next call returns
                    // `End`, which is where the body is released.
                    H2ResponseEvent::Trailers(_) => continue,
                    H2ResponseEvent::End => return Ok(None),
                }
            }
        }
        Ok(None)
    }

    /// Drain the body.
    pub async fn read_to_end(&mut self) -> Result<Bytes, NetError> {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.next_chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Whether the body has been fully consumed.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// The L0 counters, when this attempt was observed with `Counters`.
    ///
    /// The counters are available once the body has been released. `None` for
    /// `Off` and `Traced`: an untraced attempt has nothing to count, and a traced
    /// attempt reports its evidence as an event log instead.
    pub fn counters(&self) -> Option<Counters> {
        match self.observation {
            BodyObservation::Counters(counters) => counters,
            BodyObservation::Off | BodyObservation::Traced(_) => None,
        }
    }

    /// The attempt's trace, once the body has been fully consumed.
    ///
    /// `None` while the body is still open, and `None` when the attempt was not
    /// traced. A trace cannot claim syscall fidelity that no tap produced.
    pub fn trace(&self) -> Option<netune_trace::RequestTrace> {
        let BodyObservation::Traced(fidelity) = self.observation else {
            return None;
        };
        if !self.finished {
            return None;
        }
        if !self.recorder.is_enabled() {
            return None;
        }
        let log = self.recorder.log();
        Some(netune_trace::RequestTrace {
            id: netune_trace::TraceId::new("egress"),
            attempt: netune_trace::AttemptRef {
                round: 0,
                turn: 0,
                attempt: 0,
            },
            endpoint: netune_trace::EndpointRef {
                provider: String::new(),
                model: String::new(),
                authority: self.authority.clone(),
            },
            connection: netune_trace::ConnectionInfo::default(),
            identity: self.identity.clone(),
            schema_version: TRACE_SCHEMA_VERSION,
            fidelity,
            log,
        })
    }

    /// Return the connection to the pool when the body is done and the peer
    /// allows reuse. Idempotent.
    pub fn release(&mut self) {
        if let Some(reader) = self.reader.take() {
            let (stream, buffered) = match reader {
                Http1Body::Off(reader) => {
                    let (io, buffered) = reader.into_inner();
                    let (stream, tap) = io.into_parts();
                    tap.finish();
                    (stream, buffered)
                }
                Http1Body::Counters(reader) => {
                    let (io, buffered) = reader.into_inner();
                    let (stream, tap) = io.into_parts();
                    self.observation = BodyObservation::Counters(Some(tap.finish()));
                    (stream, buffered)
                }
                Http1Body::Traced(reader) => {
                    let (io, buffered) = reader.into_inner();
                    let (stream, tap) = io.into_parts();
                    self.recorder.merge(tap.finish());
                    (stream, buffered)
                }
            };
            // Stop sampling before the connection goes idle.
            drop(self.sampler.take());
            if self.finished && self.reusable {
                self.pool.put_http1(
                    &self.pool_key,
                    stream,
                    buffered,
                    self.local_port,
                    self.socket.take(),
                );
            }
        }
        #[cfg(feature = "http2")]
        if let Some(h2) = self.h2.take() {
            drop(self.sampler.take());
            // `into_connection` reports whether the stream ended cleanly and the
            // peer did not send GOAWAY: only then may the connection be reused.
            if let Some((connection, reusable)) = h2.into_connection()
                && self.finished
                && reusable
            {
                self.pool.put_http2(
                    &self.pool_key,
                    connection,
                    self.local_port,
                    self.socket.take(),
                );
            }
        }
    }
}

#[cfg(all(test, feature = "http2"))]
mod h2_tests {
    use super::*;

    #[test]
    fn a_host_header_becomes_the_authority_instead_of_a_regular_field() {
        let head = RequestHead::new(Method::GET, "/v1").with_header("host", "override.example");
        let (authority, headers) = h2_request_parts(&head, "target.example");
        assert_eq!(authority, "override.example");
        assert!(headers.iter().all(|(name, _)| name != "host"));
    }

    #[test]
    fn without_a_host_header_the_target_authority_is_used() {
        let head = RequestHead::new(Method::GET, "/v1");
        let (authority, headers) = h2_request_parts(&head, "target.example");
        assert_eq!(authority, "target.example");
        assert!(headers.iter().all(|(name, _)| name != "host"));
    }

    #[test]
    fn raw_header_casing_is_lowered_for_http2() {
        let head = RequestHead::new(Method::GET, "/v1").with_raw_header("X-Trace-Id", "abc");
        let (_, headers) = h2_request_parts(&head, "target.example");
        assert_eq!(headers, vec![("x-trace-id".to_string(), "abc".to_string())]);
    }

    #[test]
    fn a_refusal_before_the_head_is_replayable_on_a_fresh_connection() {
        let goaway = h2_error(
            "request",
            netune_http2::H2Error::GoAway {
                error_code: 0,
                debug_data: Vec::new(),
            },
        );
        assert!(goaway.is_stale_connection());
        assert!(goaway.is_retryable());

        let refused = h2_error(
            "request",
            netune_http2::H2Error::StreamReset {
                stream_id: 1,
                error_code: netune_http2::error_code::REFUSED_STREAM,
            },
        );
        assert!(refused.is_stale_connection());
        assert!(refused.is_retryable());

        // A reset or GOAWAY after the response head belongs to a stream the peer
        // may already have processed; it must not be replayed transparently.
        let after_head = h2_error(
            "body",
            netune_http2::H2Error::StreamReset {
                stream_id: 1,
                error_code: netune_http2::error_code::REFUSED_STREAM,
            },
        );
        assert!(!after_head.is_stale_connection());
        assert!(!after_head.is_retryable());
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use crate::connect::TcpConnector;
    use crate::socket::SocketConfig;
    use netune_trace::EvasionPolicy;

    fn keyed_client() -> Client<TcpConnector> {
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
        let target = Target::plain("203.0.113.10:80").with_force_h2(true);
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
            .with_force_h2(true)
            .with_h2_profile("my-chrome");
        let plan = client.plan(&target).expect("custom H2 plan");
        assert_eq!(plan.identity.h2_profile.as_deref(), Some("my-chrome"));
        assert!(plan.h2.is_some());
    }

    #[cfg(feature = "http2")]
    #[test]
    fn a_custom_h2_request_profile_is_resolved_without_changing_the_pool_key() {
        let client = keyed_client().with_h2_request_profile(
            "my-order",
            netune_http2::H2RequestProfile {
                name: "my-order",
                pseudo_headers_order: netune_http2::PseudoHeaderOrder::AuthorityMethodPathScheme,
            },
        );
        let target = Target::plain("203.0.113.10:80")
            .with_force_h2(true)
            .with_h2_request_profile("my-order");
        let plan = client.plan(&target).expect("plan");
        assert_eq!(plan.h2_request.expect("request profile").name, "my-order");
        let baseline = client
            .plan(&Target::plain("203.0.113.10:80").with_force_h2(true))
            .expect("baseline plan");
        assert_eq!(plan.pool_key(), baseline.pool_key());
    }

    #[cfg(feature = "http2")]
    #[test]
    fn an_unknown_h2_request_profile_fails_while_planning() {
        let client = keyed_client();
        let target = Target::plain("203.0.113.10:80")
            .with_force_h2(true)
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
            .with_force_h2(true)
            .with_h2_profile("does-not-exist");
        let error = client
            .plan(&target)
            .expect_err("unknown H2 profile must fail");
        assert!(error.to_string().contains("unknown HTTP/2 profile"));
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

    #[test]
    fn inv_custom_05_absolute_redirect_preserves_the_identity() {
        let original = Target::tls("a.example:443", "a.example")
            .with_tls_profile("chrome-current")
            .with_evasion(EvasionPolicy::sni_split())
            .with_force_h2(true);

        let (next, path) = resolve_location(&original, "/start", "https://b.example/next")
            .expect("resolve absolute redirect");

        assert_eq!(path, "/next");
        assert_eq!(next.authority, "b.example:443");
        assert_eq!(next.identity.tls_profile.as_deref(), Some("chrome-current"));
        assert_eq!(next.identity.tls_server_name.as_deref(), Some("b.example"));
        assert_eq!(next.identity.evasion, EvasionPolicy::sni_split());
        assert!(next.force_h2);
    }

    #[test]
    fn an_absolute_downgrade_drops_tls_but_keeps_evasion() {
        let original =
            Target::tls("a.example:443", "a.example").with_evasion(EvasionPolicy::sni_split());

        let (next, path) = resolve_location(&original, "/start", "http://b.example/next")
            .expect("resolve absolute downgrade");

        assert_eq!(path, "/next");
        assert!(next.tls_server_name().is_none());
        assert_eq!(next.identity.evasion, EvasionPolicy::sni_split());
    }
}
