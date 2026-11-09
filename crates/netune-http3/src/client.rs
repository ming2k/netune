// SPDX-License-Identifier: MIT

//! HTTP/3 client session and request execution (RFC 9114).

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use netune_trace::{
    AttemptRef, ConnectionIdentity, ConnectionInfo, EndpointRef, EventKind, Fidelity, RequestTrace,
    TRACE_SCHEMA_VERSION, TraceCollector, TraceId,
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

    /// Finish the request without trailers and wait for the response head.
    pub async fn finish(self) -> Result<H3ResponseStream, H3Error> {
        let mut stream = self.stream;
        deadline("request finish", self.config.request_timeout, async {
            stream.finish_send().await
        })
        .await?;
        await_response(
            stream,
            self.recorder,
            self.context,
            self.config,
            self.exchange,
        )
        .await
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

    /// The exchange id carried in `Event::stream`.
    pub const fn exchange(&self) -> u32 {
        self.exchange
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
        Some(RequestTrace {
            id: TraceId::new("h3"),
            attempt: AttemptRef {
                round: 0,
                turn: 0,
                attempt: 0,
            },
            endpoint: EndpointRef {
                provider: String::new(),
                model: String::new(),
                authority: context.authority.clone(),
            },
            connection: ConnectionInfo::default(),
            identity: context.identity.clone(),
            schema_version: TRACE_SCHEMA_VERSION,
            fidelity: Fidelity::l0(),
            log: recorder.log().for_exchange(self.exchange),
        })
    }
}

/// An active HTTP/3 client session driving a QUIC connection.
pub struct H3Client {
    connection: Connection,
    recorder: Option<TraceCollector>,
    /// The QUIC connection that owns the endpoint. Present when the client was
    /// built through [`H3Client::connect`]; dropping it would tear down the
    /// transport under the H3 session.
    quic: Option<netune_quic::QuicConnection>,
    /// The resolved QUIC profile that shapes this H3 connection.
    quic_profile: Option<&'static str>,
    trace_context: Option<H3TraceContext>,
    settings_profile: H3SettingsProfile,
    request_profile: H3RequestProfile,
    config: H3ClientConfig,
    next_exchange: u32,
}

impl std::fmt::Debug for H3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Client")
            .field("quic_profile", &self.quic_profile)
            .field("trace_context", &self.trace_context)
            .field("settings_profile", &self.settings_profile)
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
        settings
            .validate()
            .map_err(|reason| H3Error::Profile(reason.to_string()))?;
        let connection = Connection::start(connection.clone(), &settings, Role::Client).await?;
        Ok(Self {
            connection,
            recorder,
            quic: None,
            quic_profile: None,
            trace_context: None,
            settings_profile: settings,
            request_profile: H3RequestProfile::default(),
            config,
            next_exchange: 1,
        })
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
    ) -> Result<Self, H3Error> {
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
    ) -> Result<Self, H3Error> {
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
    ) -> Result<Self, H3Error> {
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
    ) -> Result<Self, H3Error> {
        settings
            .validate()
            .map_err(|reason| H3Error::Profile(reason.to_string()))?;
        let profile = connector.profile_name();
        let quic = connector
            .connect(target, server_name, recorder.clone())
            .await?;
        let settings_name = settings.name.clone();
        let mut client =
            Self::new_with_settings_and_config(quic.connection(), recorder, settings, config)
                .await?;
        client.quic = Some(quic);
        client.quic_profile = Some(profile);
        client.trace_context = Some(H3TraceContext {
            authority: target.to_string(),
            server_name: server_name.to_string(),
            identity: ConnectionIdentity {
                tls_server_name: Some(server_name.to_string()),
                h3_profile: Some(profile.to_string()),
                h3_settings_profile: Some(settings_name),
                ..ConnectionIdentity::default()
            },
        });
        Ok(client)
    }

    /// The resolved QUIC profile that shapes this H3 connection.
    pub const fn quic_profile(&self) -> Option<&'static str> {
        self.quic_profile
    }

    /// The HTTP/3 SETTINGS profile used when this connection was opened.
    pub fn settings_profile(&self) -> &H3SettingsProfile {
        &self.settings_profile
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
        let exchange = self.next_exchange;
        self.next_exchange = self.next_exchange.saturating_add(1);

        if let Some(rec) = &self.recorder {
            rec.mark_stream(exchange, EventKind::H3StreamStart, 0, 0);
        }

        let fields = encode_request(&request, &self.request_profile.order)?;
        let mut stream = deadline(
            "request head",
            self.config.request_timeout,
            self.connection.open_bi(),
        )
        .await?;
        deadline(
            "request head",
            self.config.request_timeout,
            stream.send_head(&fields),
        )
        .await?;

        Ok(H3RequestBody {
            stream,
            recorder: self.recorder.clone(),
            context: self.trace_context.clone(),
            config: self.config.clone(),
            exchange,
        })
    }

    /// Execute an HTTP/3 request to completion, buffering the response body.
    ///
    /// Use [`H3Client::send`] when the body must be streamed.
    pub async fn execute(&mut self, request: http::Request<Bytes>) -> Result<H3Response, H3Error> {
        let mut stream = self.send(request).await?;
        let body = stream.read_to_end().await?;
        let trace = stream.trace();
        Ok(H3Response {
            head: stream.head().clone(),
            body,
            trace,
        })
    }
}

async fn await_response(
    mut stream: H3Stream,
    recorder: Option<TraceCollector>,
    context: Option<H3TraceContext>,
    config: H3ClientConfig,
    exchange: u32,
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
        });
    }
}

async fn deadline<T, E, F>(phase: &'static str, duration: Duration, future: F) -> Result<T, H3Error>
where
    F: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    match tokio::time::timeout(duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(H3Error::H3(format!("{phase}: {error}"))),
        Err(_) => Err(H3Error::Timeout(phase)),
    }
}
