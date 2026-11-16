// SPDX-License-Identifier: MIT

//! HTTP/3 client session and request execution (RFC 9114).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use netune_trace::{
    ConnectionIdentity, ConnectionInfo, EventKind, Fidelity, RequestTrace, TRACE_SCHEMA_VERSION,
    TraceCollector,
};

use crate::connection::{Connection, H3Stream, Role};
use crate::error::H3Error;
use crate::profile::{H3RequestProfile, H3SettingsProfile};
use crate::proto::headers::{encode_request, encode_trailers};

/// Bounds and trace identity for one HTTP/3 session.
#[derive(Debug, Clone)]
pub struct H3ClientConfig {
    /// Bound on sending the request head, body and finish.
    pub request_timeout: Duration,
    /// Bound on waiting for the response head.
    pub response_head_timeout: Duration,
    /// Bound on waiting for one response-body chunk.
    pub body_chunk_timeout: Duration,
    /// Maximum response body bytes buffered by [`H3Client::execute`].
    pub max_body_bytes: usize,
}

impl Default for H3ClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            response_head_timeout: Duration::from_secs(30),
            body_chunk_timeout: Duration::from_secs(30),
            max_body_bytes: 16 * 1024 * 1024,
        }
    }
}

/// The connection identity of an H3 session.
///
/// HTTP/3 has no second handshake: [`Self::identity`] carries the resolved
/// QUIC profile as `h3_profile`, plus the TLS server name.
#[derive(Debug, Clone)]
pub struct H3TraceContext {
    pub authority: String,
    pub server_name: String,
    pub identity: ConnectionIdentity,
}

/// The result of a buffered HTTP/3 exchange.
#[derive(Debug)]
pub struct H3Response {
    pub head: http::Response<()>,
    pub body: Bytes,
    /// Present when the session was created through [`H3Client::connect`] and
    /// the body was observed to completion.
    pub trace: Option<RequestTrace>,
}

impl H3Response {
    pub fn status(&self) -> http::StatusCode {
        self.head.status()
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }
}

/// A streaming HTTP/3 request body.
///
/// Created by [`H3Client::open_request`]. The request head has already been
/// encoded and written when this value exists; body chunks are written one at
/// a time, so an upload never has to be buffered in full.
pub struct H3RequestBody {
    stream: H3Stream,
    recorder: Option<TraceCollector>,
    context: Option<H3TraceContext>,
    config: H3ClientConfig,
    exchange: u32,
    permit: Option<H3StreamPermit>,
}

impl std::fmt::Debug for H3RequestBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3RequestBody")
            .field("exchange", &self.exchange)
            .finish_non_exhaustive()
    }
}

impl H3RequestBody {
    /// The exchange id carried in `Event::stream`.
    pub const fn exchange(&self) -> u32 {
        self.exchange
    }

    /// Write the next request-body chunk.
    ///
    /// An empty chunk is a no-op: HTTP/3 DATA frames may be empty, but there is
    /// no reason to spend a frame on one.
    pub async fn send_data(&mut self, bytes: Bytes) -> Result<(), H3Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        deadline(
            "request body",
            self.config.request_timeout,
            self.stream.send_data(&bytes),
        )
        .await
    }

    /// Send one HTTP/3 datagram associated with this request stream.
    pub async fn send_datagram(&mut self, data: &[u8]) -> Result<(), H3Error> {
        self.stream.send_datagram(data).await
    }

    /// Send one RFC 9297 capsule in the request body.
    pub async fn send_capsule(&mut self, capsule: &crate::Capsule) -> Result<(), H3Error> {
        self.stream.send_capsule(capsule).await
    }

    /// Split the request into a write-only sender and a response-head future.
    ///
    /// The returned [`H3SplitSender`] can only send body data, trailers, or
    /// close the send side; it does not expose datagrams or `into_duplex`,
    /// which belong exclusively to an unsplit [`H3RequestBody`] /
    /// [`H3ResponseStream`]. The response future owns the receive half and
    /// shares the stream permit, so dropping either half waits for the other
    /// before releasing the session slot.
    pub fn split(mut self) -> (H3SplitSender, H3ResponseFuture) {
        let view = self.stream.response_view();
        self.stream.release_read_ownership();
        let response = H3ResponseFuture {
            stream: view,
            recorder: self.recorder.clone(),
            context: self.context.take(),
            config: self.config.clone(),
            exchange: self.exchange,
            permit: self.permit.clone(),
        };
        let sender = H3SplitSender {
            stream: self.stream,
            config: self.config,
            exchange: self.exchange,
            _permit: self.permit,
        };
        (sender, response)
    }

    /// Read the response head while keeping the request body open.
    ///
    /// This is the full-duplex form used by CONNECT and WebTransport-style
    /// sessions: the returned response stream retains both directions.
    pub async fn into_duplex(self) -> Result<H3ResponseStream, H3Error> {
        await_response(
            self.stream,
            self.recorder,
            self.context,
            self.config,
            self.exchange,
            self.permit,
        )
        .await
    }

    /// Close only the request send side without yet awaiting response headers.
    pub async fn close_send(&mut self) -> Result<(), H3Error> {
        deadline(
            "request finish",
            self.config.request_timeout,
            self.stream.finish_send(),
        )
        .await
    }

    /// Finish the request without trailers and wait for the response head.
    pub async fn finish(mut self) -> Result<H3ResponseStream, H3Error> {
        self.close_send().await?;
        self.into_duplex().await
    }

    /// Send request trailers, which also finish the request, then wait for the
    /// response head.
    pub async fn send_trailers(
        self,
        trailers: http::HeaderMap,
    ) -> Result<H3ResponseStream, H3Error> {
        let fields = encode_trailers(&trailers)?;
        let mut stream = self.stream;
        deadline(
            "request trailers",
            self.config.request_timeout,
            stream.send_trailers(&fields),
        )
        .await?;
        await_response(
            stream,
            self.recorder,
            self.context,
            self.config,
            self.exchange,
            self.permit,
        )
        .await
    }
}

/// The write-only request-body half returned by [`H3RequestBody::split`].
///
/// Unlike [`H3RequestBody`], this type cannot read the response or send HTTP/3
/// datagrams; use [`H3RequestBody::into_duplex`] for full-duplex CONNECT /
/// WebTransport streams with datagrams.
pub struct H3SplitSender {
    stream: H3Stream,
    config: H3ClientConfig,
    exchange: u32,
    _permit: Option<H3StreamPermit>,
}

impl std::fmt::Debug for H3SplitSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3SplitSender")
            .field("exchange", &self.exchange)
            .finish_non_exhaustive()
    }
}

impl H3SplitSender {
    /// The exchange id carried in `Event::stream`.
    pub const fn exchange(&self) -> u32 {
        self.exchange
    }

    /// Write the next request-body chunk.
    pub async fn send_data(&mut self, bytes: Bytes) -> Result<(), H3Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        deadline(
            "request body",
            self.config.request_timeout,
            self.stream.send_data(&bytes),
        )
        .await
    }

    /// Close the request send side without waiting for response headers.
    pub async fn close_send(&mut self) -> Result<(), H3Error> {
        deadline(
            "request finish",
            self.config.request_timeout,
            self.stream.finish_send(),
        )
        .await
    }

    /// Send request trailers and finish the send side.
    pub async fn send_trailers(mut self, trailers: http::HeaderMap) -> Result<(), H3Error> {
        let fields = encode_trailers(&trailers)?;
        deadline(
            "request trailers",
            self.config.request_timeout,
            self.stream.send_trailers(&fields),
        )
        .await
    }
}

/// The response-head half of a split HTTP/3 request.
///
/// Created by [`H3RequestBody::split`]. Awaiting it does not wait for the
/// request sender; the two halves use separate QUIC send/receive handles.
pub struct H3ResponseFuture {
    stream: H3Stream,
    recorder: Option<TraceCollector>,
    context: Option<H3TraceContext>,
    config: H3ClientConfig,
    exchange: u32,
    permit: Option<H3StreamPermit>,
}

impl std::fmt::Debug for H3ResponseFuture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3ResponseFuture")
            .field("exchange", &self.exchange)
            .finish_non_exhaustive()
    }
}

impl H3ResponseFuture {
    /// Wait for the response head, retaining the response stream.
    pub async fn await_head(self) -> Result<H3ResponseStream, H3Error> {
        await_response(
            self.stream,
            self.recorder,
            self.context,
            self.config,
            self.exchange,
            self.permit,
        )
        .await
    }
}

/// A streaming HTTP/3 response.
pub struct H3ResponseStream {
    stream: H3Stream,
    head: http::Response<()>,
    recorder: Option<TraceCollector>,
    context: Option<H3TraceContext>,
    config: H3ClientConfig,
    exchange: u32,
    received: usize,
    finished: bool,
    permit: Option<H3StreamPermit>,
}

impl std::fmt::Debug for H3ResponseStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3ResponseStream")
            .field("status", &self.head.status())
            .field("exchange", &self.exchange)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl H3ResponseStream {
    pub fn head(&self) -> &http::Response<()> {
        &self.head
    }

    /// The wire CONNECT/request stream id.
    pub fn id(&self) -> u64 {
        self.stream.id()
    }

    /// The underlying owned QUIC connection.
    pub fn quic_connection(&self) -> &netune_quic::owned::Connection {
        &self.stream.shared().connection
    }

    /// Finish the send side of a duplex CONNECT session.
    pub async fn finish(&mut self) -> Result<(), H3Error> {
        self.stream.finish_send().await
    }

    /// The exchange id carried in `Event::stream`.
    pub const fn exchange(&self) -> u32 {
        self.exchange
    }

    /// Receive one already-queued HTTP/3 datagram associated with this request stream.
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        self.stream.recv_datagram()
    }

    /// Wait for the next HTTP/3 datagram associated with this request stream.
    pub async fn next_datagram(&mut self) -> Option<Bytes> {
        self.stream.next_datagram().await
    }

    /// Send one HTTP/3 datagram associated with this request stream.
    pub async fn send_datagram(&mut self, data: &[u8]) -> Result<(), H3Error> {
        self.stream.send_datagram(data).await
    }

    /// Send one RFC 9297 capsule on the retained request/response body.
    pub async fn send_capsule(&mut self, capsule: &crate::Capsule) -> Result<(), H3Error> {
        self.stream.send_capsule(capsule).await
    }

    /// Read the next RFC 9297 capsule from the response body.
    pub async fn next_capsule(&mut self) -> Result<Option<crate::Capsule>, H3Error> {
        self.stream.next_capsule().await
    }

    /// Read the next decoded body chunk, or `None` at the end.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, H3Error> {
        if self.finished {
            return Ok(None);
        }
        let next = deadline(
            "response body",
            self.config.body_chunk_timeout,
            self.stream.next_chunk(64 * 1024),
        )
        .await?;
        match next {
            Some(bytes) => {
                self.received = self.received.saturating_add(bytes.len());
                if self.received > self.config.max_body_bytes {
                    return Err(H3Error::BodyTooLarge {
                        limit: self.config.max_body_bytes,
                    });
                }
                Ok(Some(bytes))
            }
            None => {
                if let Some(rec) = &self.recorder {
                    let bytes = self.received.min(u32::MAX as usize) as u32;
                    rec.mark_stream(self.exchange, EventKind::H3Finished, bytes, 0);
                }
                self.finished = true;
                self.permit.take();
                Ok(None)
            }
        }
    }

    /// Read response trailers after the body has ended, if any.
    pub async fn trailers(&mut self) -> Result<Option<http::HeaderMap>, H3Error> {
        deadline(
            "response trailers",
            self.config.body_chunk_timeout,
            self.stream.read_trailers(),
        )
        .await
    }

    /// Drain the response body, bounded by `max_body_bytes`.
    pub async fn read_to_end(&mut self) -> Result<Bytes, H3Error> {
        let mut body = BytesMut::new();
        while let Some(chunk) = self.next_chunk().await? {
            body.extend_from_slice(&chunk);
        }
        Ok(body.freeze())
    }

    /// The per-exchange trace, once the body is complete.
    pub fn trace(&self) -> Option<RequestTrace> {
        if !self.finished {
            return None;
        }
        let recorder = self.recorder.as_ref()?;
        let context = self.context.as_ref()?;
        let snapshot = recorder.snapshot(Fidelity::l0());
        Some(RequestTrace {
            meta: snapshot.meta,
            authority: context.authority.clone(),
            connection: ConnectionInfo::default(),
            identity: context.identity.clone(),
            schema_version: TRACE_SCHEMA_VERSION,
            fidelity: Fidelity::l0(),
            log: snapshot.log.for_exchange(self.exchange),
            diagnostics: snapshot.diagnostics,
        })
    }
}

#[derive(Clone)]
struct H3StreamPermit {
    /// The field exists solely to keep the shared permit alive; the decrement
    /// lives in `H3StreamPermitInner::drop`, so no method reads it.
    #[allow(dead_code)]
    inner: Arc<H3StreamPermitInner>,
}

struct H3StreamPermitInner {
    session: Arc<H3SessionInner>,
}

impl Drop for H3StreamPermitInner {
    fn drop(&mut self) {
        if self.session.active_streams.fetch_sub(1, Ordering::AcqRel) == 1 {
            let ms = u64::try_from(self.session.created.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.session.idle_since_ms.store(ms, Ordering::Release);
        }
    }
}

struct H3SessionInner {
    connection: Connection,
    /// Keeps the QUIC endpoint + UDP socket alive as long as the session lives.
    quic: Option<netune_quic::QuicConnection>,
    settings_profile: H3SettingsProfile,
    active_streams: AtomicUsize,
    next_exchange: AtomicU32,
    created: Instant,
    idle_since_ms: AtomicU64,
}

/// Shareable, cloneable handle onto a multiplexed HTTP/3 client session.
#[derive(Clone)]
pub struct H3Session {
    inner: Arc<H3SessionInner>,
}

impl std::fmt::Debug for H3Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Session")
            .field("active_streams", &self.active_streams())
            .field("usable", &self.is_usable())
            .finish_non_exhaustive()
    }
}

impl H3Session {
    /// Start an HTTP/3 session over an established QUIC connection.
    pub async fn new_with_settings(
        connection: &netune_quic::owned::Connection,
        settings: H3SettingsProfile,
    ) -> Result<Self, H3Error> {
        settings
            .validate()
            .map_err(|reason| H3Error::Profile(reason.to_string()))?;
        let connection = Connection::start(connection.clone(), &settings, Role::Client).await?;
        Ok(Self::from_parts(connection, None, settings))
    }

    /// Start an HTTP/3 session taking ownership of `quic` and keeping its
    /// endpoint alive while any session handle or stream exists.
    pub async fn from_quic(
        quic: netune_quic::QuicConnection,
        settings: H3SettingsProfile,
    ) -> Result<Self, H3Error> {
        settings
            .validate()
            .map_err(|reason| H3Error::Profile(reason.to_string()))?;
        let connection =
            Connection::start(quic.connection().clone(), &settings, Role::Client).await?;
        Ok(Self::from_parts(connection, Some(quic), settings))
    }

    fn from_parts(
        connection: Connection,
        quic: Option<netune_quic::QuicConnection>,
        settings_profile: H3SettingsProfile,
    ) -> Self {
        Self {
            inner: Arc::new(H3SessionInner {
                connection,
                quic,
                settings_profile,
                active_streams: AtomicUsize::new(0),
                next_exchange: AtomicU32::new(1),
                created: Instant::now(),
                idle_since_ms: AtomicU64::new(0),
            }),
        }
    }

    /// Whether the session can open another request stream (alive, open QUIC
    /// connection, and no peer `GOAWAY`).
    pub fn is_usable(&self) -> bool {
        let shared = self.inner.connection.shared();
        shared.check_error().is_ok() && shared.goaway().is_none() && !shared.connection.is_closed()
    }

    /// Number of currently open request/response streams on this connection.
    pub fn active_streams(&self) -> usize {
        self.inner.active_streams.load(Ordering::Acquire)
    }

    /// Elapsed duration since this session last had zero active streams (`None`
    /// while streams remain active).
    pub fn idle_duration(&self) -> Option<Duration> {
        if self.active_streams() > 0 {
            return None;
        }
        let since_ms = self.inner.idle_since_ms.load(Ordering::Acquire);
        let now_ms = u64::try_from(self.inner.created.elapsed().as_millis()).unwrap_or(u64::MAX);
        Some(Duration::from_millis(now_ms.saturating_sub(since_ms)))
    }

    /// Local UDP port backing the QUIC endpoint, when this session owns it.
    pub fn local_port(&self) -> Option<u16> {
        self.inner
            .quic
            .as_ref()
            .map(|quic| quic.endpoint().local_addr().port())
    }

    /// The underlying owned QUIC connection, when this session owns one.
    pub fn quic_connection(&self) -> Option<&netune_quic::owned::Connection> {
        self.inner
            .quic
            .as_ref()
            .map(netune_quic::QuicConnection::connection)
    }

    /// The HTTP/3 SETTINGS profile in force for this connection.
    pub fn settings_profile(&self) -> &H3SettingsProfile {
        &self.inner.settings_profile
    }

    /// Wait until the peer SETTINGS frame has been observed.
    pub async fn wait_settings(&self) {
        self.inner.connection.shared().wait_settings().await;
    }

    /// Look up a peer SETTINGS identifier, including extension settings.
    pub fn peer_setting(&self, id: u64) -> Option<u64> {
        self.inner.connection.shared().peer_extra_setting(id)
    }

    /// Install a protocol-neutral stream extension router.
    pub fn enable_stream_extension(
        &self,
        uni_types: Vec<u64>,
        bidi_signal: u64,
    ) -> tokio::sync::mpsc::UnboundedReceiver<crate::H3ExtensionStream> {
        self.inner
            .connection
            .shared()
            .enable_extension(uni_types, bidi_signal)
    }

    /// Install an extension router with a protocol-supplied identifier
    /// validator.
    pub fn enable_stream_extension_with_validator(
        &self,
        uni_types: Vec<u64>,
        bidi_signal: u64,
        validator: impl Fn(u64) -> bool + Send + Sync + 'static,
    ) -> tokio::sync::mpsc::UnboundedReceiver<crate::H3ExtensionStream> {
        self.inner
            .connection
            .shared()
            .enable_extension_with_validator(uni_types, bidi_signal, validator)
    }

    /// Open a request stream on this shared session using caller-supplied
    /// per-request headers policy, bounds, and trace recorder.
    pub async fn open_request(
        &self,
        request: http::Request<()>,
        request_profile: &H3RequestProfile,
        config: &H3ClientConfig,
        recorder: Option<TraceCollector>,
        context: Option<H3TraceContext>,
    ) -> Result<H3RequestBody, H3Error> {
        self.inner.active_streams.fetch_add(1, Ordering::AcqRel);
        let permit = H3StreamPermit {
            inner: Arc::new(H3StreamPermitInner {
                session: Arc::clone(&self.inner),
            }),
        };
        let exchange = self.inner.next_exchange.fetch_add(1, Ordering::AcqRel);

        if let Some(rec) = &recorder {
            rec.mark_stream(exchange, EventKind::H3StreamStart, 0, 0);
        }

        if request
            .extensions()
            .get::<crate::proto::ExtendedConnectProtocol>()
            .is_some()
            && !self
                .inner
                .connection
                .shared()
                .peer_extended_connect_enabled()
        {
            self.inner.connection.shared().wait_settings().await;
            if !self
                .inner
                .connection
                .shared()
                .peer_extended_connect_enabled()
            {
                return Err(H3Error::H3(
                    "extended CONNECT was not negotiated".to_string(),
                ));
            }
        }

        let fields = encode_request(&request, &request_profile.order)?;
        let mut stream = deadline(
            "request head",
            config.request_timeout,
            self.inner.connection.open_bi(),
        )
        .await?;
        deadline(
            "request head",
            config.request_timeout,
            stream.send_head(&fields),
        )
        .await?;

        Ok(H3RequestBody {
            stream,
            recorder,
            context,
            config: config.clone(),
            exchange,
            permit: Some(permit),
        })
    }
}

/// An active HTTP/3 client session driving a QUIC connection.
pub struct H3Client {
    session: H3Session,
    recorder: Option<TraceCollector>,
    /// The resolved QUIC profile that shapes this H3 connection.
    quic_profile: Option<&'static str>,
    trace_context: Option<H3TraceContext>,
    request_profile: H3RequestProfile,
    config: H3ClientConfig,
}

impl std::fmt::Debug for H3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Client")
            .field("quic_profile", &self.quic_profile)
            .field("trace_context", &self.trace_context)
            .field("settings_profile", self.session.settings_profile())
            .field("request_profile", &self.request_profile)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl H3Client {
    /// Creates a new HTTP/3 client session over an established QUIC connection.
    pub async fn new(
        connection: &netune_quic::owned::Connection,
        recorder: Option<TraceCollector>,
    ) -> Result<Self, H3Error> {
        Self::new_with_config(connection, recorder, H3ClientConfig::default()).await
    }

    /// Creates a session with explicit bounds and the default SETTINGS.
    pub async fn new_with_config(
        connection: &netune_quic::owned::Connection,
        recorder: Option<TraceCollector>,
        config: H3ClientConfig,
    ) -> Result<Self, H3Error> {
        Self::new_with_settings_and_config(
            connection,
            recorder,
            H3SettingsProfile::default(),
            config,
        )
        .await
    }

    /// Creates a session with an explicit SETTINGS profile and default bounds.
    pub async fn new_with_settings(
        connection: &netune_quic::owned::Connection,
        recorder: Option<TraceCollector>,
        settings: H3SettingsProfile,
    ) -> Result<Self, H3Error> {
        Self::new_with_settings_and_config(
            connection,
            recorder,
            settings,
            H3ClientConfig::default(),
        )
        .await
    }

    /// Creates a session with explicit SETTINGS and bounds.
    pub async fn new_with_settings_and_config(
        connection: &netune_quic::owned::Connection,
        recorder: Option<TraceCollector>,
        settings: H3SettingsProfile,
        config: H3ClientConfig,
    ) -> Result<Self, H3Error> {
        let session = H3Session::new_with_settings(connection, settings).await?;
        Ok(Self {
            session,
            recorder,
            quic_profile: None,
            trace_context: None,
            request_profile: H3RequestProfile::default(),
            config,
        })
    }

    fn from_quic_session(
        session: H3Session,
        recorder: Option<TraceCollector>,
        quic_profile: &'static str,
        target: SocketAddr,
        server_name: &str,
        settings_name: String,
        config: H3ClientConfig,
    ) -> Self {
        Self {
            session,
            recorder,
            quic_profile: Some(quic_profile),
            trace_context: Some(H3TraceContext {
                authority: target.to_string(),
                server_name: server_name.to_string(),
                identity: ConnectionIdentity::default()
                    .with_tls_server_name(server_name)
                    .with_h3_profile(quic_profile)
                    .with_h3_settings_profile(settings_name),
            }),
            request_profile: H3RequestProfile::default(),
            config,
        }
    }

    /// Connect a QUIC transport through `connector`, then start HTTP/3 on it.
    ///
    /// The connector's resolved profile is retained on the H3 session; it is the
    /// connection identity for this transport.
    pub async fn connect(
        connector: &netune_quic::QuicConnector,
        target: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
    ) -> Result<Self, crate::error::H3AttemptError> {
        Self::connect_with_config(
            connector,
            target,
            server_name,
            recorder,
            H3ClientConfig::default(),
        )
        .await
    }

    /// Connect with explicit bounds.
    pub async fn connect_with_config(
        connector: &netune_quic::QuicConnector,
        target: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
        config: H3ClientConfig,
    ) -> Result<Self, crate::error::H3AttemptError> {
        Self::connect_with_settings_and_config(
            connector,
            target,
            server_name,
            recorder,
            H3SettingsProfile::default(),
            config,
        )
        .await
    }

    /// Connect with an explicit HTTP/3 SETTINGS profile and default bounds.
    pub async fn connect_with_settings(
        connector: &netune_quic::QuicConnector,
        target: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
        settings: H3SettingsProfile,
    ) -> Result<Self, crate::error::H3AttemptError> {
        Self::connect_with_settings_and_config(
            connector,
            target,
            server_name,
            recorder,
            settings,
            H3ClientConfig::default(),
        )
        .await
    }

    /// Connect with explicit SETTINGS and bounds.
    pub async fn connect_with_settings_and_config(
        connector: &netune_quic::QuicConnector,
        target: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
        settings: H3SettingsProfile,
        config: H3ClientConfig,
    ) -> Result<Self, crate::error::H3AttemptError> {
        let evidence = recorder.clone().unwrap_or_else(TraceCollector::disabled);
        let result: Result<Self, H3Error> = async {
            settings
                .validate()
                .map_err(|reason| H3Error::Profile(reason.to_string()))?;
            let profile = connector.profile_name();
            let quic = connector
                .connect(target, server_name, recorder.clone())
                .await
                .map_err(H3Error::from)?;
            let settings_name = settings.name.clone();
            let session = H3Session::from_quic(quic, settings).await?;
            Ok(Self::from_quic_session(
                session,
                recorder,
                profile,
                target,
                server_name,
                settings_name,
                config,
            ))
        }
        .await;
        match result {
            Ok(client) => Ok(client),
            Err(error) => Err(crate::error::H3AttemptError::new(
                error,
                evidence.snapshot(Fidelity::l0()),
            )),
        }
    }

    /// Connect without waiting for the QUIC handshake.
    ///
    /// This is only faster than [`H3Client::connect`] when the connector has a
    /// resumed session and cached peer transport parameters; otherwise the
    /// call waits for the handshake before starting H3. The returned client may
    /// send early requests; if the server rejects 0-RTT, the QUIC core replays
    /// the early stream frames after the handshake.
    pub async fn connect_early(
        connector: &netune_quic::QuicConnector,
        target: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
    ) -> Result<Self, crate::error::H3AttemptError> {
        Self::connect_early_with_settings_and_config(
            connector,
            target,
            server_name,
            recorder,
            H3SettingsProfile::default(),
            H3ClientConfig::default(),
        )
        .await
    }

    /// Connect early with an explicit HTTP/3 SETTINGS profile.
    pub async fn connect_early_with_settings(
        connector: &netune_quic::QuicConnector,
        target: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
        settings: H3SettingsProfile,
    ) -> Result<Self, crate::error::H3AttemptError> {
        Self::connect_early_with_settings_and_config(
            connector,
            target,
            server_name,
            recorder,
            settings,
            H3ClientConfig::default(),
        )
        .await
    }

    /// Connect early with explicit SETTINGS and bounds.
    pub async fn connect_early_with_settings_and_config(
        connector: &netune_quic::QuicConnector,
        target: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
        settings: H3SettingsProfile,
        config: H3ClientConfig,
    ) -> Result<Self, crate::error::H3AttemptError> {
        let evidence = recorder.clone().unwrap_or_else(TraceCollector::disabled);
        let result: Result<Self, H3Error> = async {
            settings
                .validate()
                .map_err(|reason| H3Error::Profile(reason.to_string()))?;
            let profile = connector.profile_name();
            let quic = connector
                .connect_early(target, server_name, recorder.clone())
                .await
                .map_err(H3Error::from)?;
            if !quic.connection().early_data_available() {
                quic.connection()
                    .wait_established()
                    .await
                    .map_err(H3Error::from)?;
            }
            let settings_name = settings.name.clone();
            let session = H3Session::from_quic(quic, settings).await?;
            Ok(Self::from_quic_session(
                session,
                recorder,
                profile,
                target,
                server_name,
                settings_name,
                config,
            ))
        }
        .await;
        match result {
            Ok(client) => Ok(client),
            Err(error) => Err(crate::error::H3AttemptError::new(
                error,
                evidence.snapshot(Fidelity::l0()),
            )),
        }
    }

    /// Borrow the underlying shareable HTTP/3 session.
    pub fn session(&self) -> &H3Session {
        &self.session
    }

    /// Consume this client wrapper and return the shareable HTTP/3 session.
    pub fn into_session(self) -> H3Session {
        self.session
    }

    /// The underlying QUIC connection, when this client owns one.
    pub fn quic_connection(&self) -> Option<&netune_quic::owned::Connection> {
        self.session.quic_connection()
    }

    /// Wait for the underlying QUIC handshake to complete.
    pub async fn wait_handshake(&self) -> Result<(), H3Error> {
        if let Some(quic) = self.session.quic_connection() {
            quic.wait_established().await?;
        }
        Ok(())
    }

    /// Whether the server accepted this session's 0-RTT data.
    pub fn early_data_accepted(&self) -> bool {
        self.session
            .quic_connection()
            .is_some_and(netune_quic::owned::Connection::early_data_accepted)
    }

    /// Open an RFC 9220 extended CONNECT and return a full-duplex session.
    ///
    /// Capsules are read/written through the returned stream; datagrams remain
    /// available through `send_datagram`/`next_datagram`.
    pub async fn connect_extended(
        &mut self,
        protocol: &str,
        uri: &str,
    ) -> Result<H3ResponseStream, H3Error> {
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .body(())
            .map_err(H3Error::Http)?;
        request
            .extensions_mut()
            .insert(crate::ExtendedConnectProtocol(protocol.to_string()));
        let body = self.open_request(request).await?;
        body.into_duplex().await
    }

    /// Install a protocol-neutral stream extension router.
    pub fn enable_stream_extension(
        &self,
        uni_types: Vec<u64>,
        bidi_signal: u64,
    ) -> tokio::sync::mpsc::UnboundedReceiver<crate::H3ExtensionStream> {
        self.session.enable_stream_extension(uni_types, bidi_signal)
    }

    /// Install an extension router with a protocol-supplied identifier
    /// validator. Invalid identifiers close the H3 connection with
    /// `H3_ID_ERROR` instead of being queued for an application session.
    pub fn enable_stream_extension_with_validator(
        &self,
        uni_types: Vec<u64>,
        bidi_signal: u64,
        validator: impl Fn(u64) -> bool + Send + Sync + 'static,
    ) -> tokio::sync::mpsc::UnboundedReceiver<crate::H3ExtensionStream> {
        self.session
            .enable_stream_extension_with_validator(uni_types, bidi_signal, validator)
    }

    /// Wait until the peer SETTINGS frame has been observed.
    pub async fn wait_settings(&self) {
        self.session.wait_settings().await;
    }

    /// Look up a peer SETTINGS identifier, including extension settings.
    pub fn peer_setting(&self, id: u64) -> Option<u64> {
        self.session.peer_setting(id)
    }

    /// The resolved QUIC profile that shapes this H3 connection.
    pub const fn quic_profile(&self) -> Option<&'static str> {
        self.quic_profile
    }

    /// The HTTP/3 SETTINGS profile used when this connection was opened.
    pub fn settings_profile(&self) -> &H3SettingsProfile {
        self.session.settings_profile()
    }

    /// Attach an identity context when the session was built from a raw
    /// connection. `connect` does this automatically.
    #[must_use]
    pub fn with_trace_context(mut self, context: H3TraceContext) -> Self {
        self.trace_context = Some(context);
        self
    }

    /// Replace the session bounds without reconnecting.
    #[must_use]
    pub fn with_config(mut self, config: H3ClientConfig) -> Self {
        self.config = config;
        self
    }

    /// Select the request-header order for subsequent exchanges.
    ///
    /// This changes the QPACK header-block order only; it never changes the
    /// QUIC connection identity or opens a socket.
    #[must_use]
    pub fn with_request_profile(mut self, profile: H3RequestProfile) -> Self {
        self.request_profile = profile;
        self
    }

    /// The H3 request-header profile in force.
    pub fn request_profile(&self) -> &H3RequestProfile {
        &self.request_profile
    }

    /// The identity context used for per-exchange trace envelopes.
    pub fn trace_context(&self) -> Option<&H3TraceContext> {
        self.trace_context.as_ref()
    }

    /// The active bounds.
    pub fn config(&self) -> &H3ClientConfig {
        &self.config
    }

    /// Send a request whose body is already buffered and return its streaming
    /// response.
    ///
    /// For a body that arrives in pieces, use [`H3Client::open_request`].
    pub async fn send(
        &mut self,
        request: http::Request<Bytes>,
    ) -> Result<H3ResponseStream, H3Error> {
        let (parts, body) = request.into_parts();
        let mut request_body = self
            .open_request(http::Request::from_parts(parts, ()))
            .await?;
        request_body.send_data(body).await?;
        request_body.finish().await
    }

    /// Open a request stream and write its head.
    ///
    /// The returned [`H3RequestBody`] writes body chunks and then transitions to
    /// the streaming response. The request head is bounded by
    /// [`H3ClientConfig::request_timeout`].
    pub async fn open_request(
        &mut self,
        request: http::Request<()>,
    ) -> Result<H3RequestBody, H3Error> {
        self.session
            .open_request(
                request,
                &self.request_profile,
                &self.config,
                self.recorder.clone(),
                self.trace_context.clone(),
            )
            .await
    }

    /// Execute an HTTP/3 request to completion, buffering the response body.
    ///
    /// Use [`H3Client::send`] when the body must be streamed. A failure carries
    /// the H3 trace snapshot, including the QUIC and QPACK diagnostics recorded
    /// before the request returned.
    pub async fn execute(
        &mut self,
        request: http::Request<Bytes>,
    ) -> Result<H3Response, crate::error::H3AttemptError> {
        let evidence = self
            .recorder
            .clone()
            .unwrap_or_else(TraceCollector::disabled);
        let result = async {
            let mut stream = self.send(request).await?;
            let body = stream.read_to_end().await?;
            let trace = stream.trace();
            Ok(H3Response {
                head: stream.head().clone(),
                body,
                trace,
            })
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(error) => Err(crate::error::H3AttemptError::new(
                error,
                evidence.snapshot(Fidelity::l0()),
            )),
        }
    }
}

async fn await_response(
    mut stream: H3Stream,
    recorder: Option<TraceCollector>,
    context: Option<H3TraceContext>,
    config: H3ClientConfig,
    exchange: u32,
    permit: Option<H3StreamPermit>,
) -> Result<H3ResponseStream, H3Error> {
    loop {
        let response = deadline(
            "response head",
            config.response_head_timeout,
            stream.read_response_head(),
        )
        .await?;

        if response.status().is_informational() {
            continue;
        }

        if let Some(rec) = &recorder {
            rec.mark_stream(
                exchange,
                EventKind::H3HeadComplete,
                response.status().as_u16() as u32,
                0,
            );
        }

        return Ok(H3ResponseStream {
            stream,
            head: response,
            recorder,
            context,
            config,
            exchange,
            received: 0,
            finished: false,
            permit,
        });
    }
}

async fn deadline<T, E, F>(phase: &'static str, duration: Duration, future: F) -> Result<T, H3Error>
where
    F: Future<Output = Result<T, E>>,
    E: Into<H3Error>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(H3Error::Timeout(phase)),
    }
}
