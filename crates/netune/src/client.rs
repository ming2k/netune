//! The client: one request, fully traced, policy applied.
//!
//! `Client::send` owns the request lifecycle — take a pooled connection or
//! establish one, write the request, parse the head, follow redirects, then
//! stream a decoded body — marking each milestone in the attempt's
//! [`Recorder`]. It owns no provider knowledge and no retry policy: those live
//! above (the harness).
//!
//! Redirects are followed here rather than by a wrapper because a redirect is a
//! property of the *attempt*: the trace must show the hops, and only the final
//! response may mark `HeadComplete`, or TTFT would be measured against a 302.

use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
#[cfg(feature = "http2")]
use http::HeaderMap;
use http::{Method, StatusCode};
use netune_http1::{BodyKind, Http1Reader, IncomingResponse, Limits, RequestHead, write_request};
#[cfg(feature = "http2")]
use netune_http2::{H2ClientConnection, H2Fingerprint, H2ResponseEvent, H2ResponseStream};
use netune_trace::{Alpn, EventKind, Recorder};

use crate::connect::{Connector, Target};
use crate::decompress::Decoder;
use crate::error::NetError;
use crate::pool::{IdleConnection, Pool, Protocol};
use crate::tcp_info::{SAMPLE_INTERVAL, Sampler, start as start_sampler};
use netune_io::TimedIo;

/// The HTTP/2 framing identity that pairs with a TLS profile name.
///
/// One name selects both halves of an identity, because a client that presents
/// a Go hello and then frames like Chrome is *more* distinctive than either
/// choice alone. Names with no declared HTTP/2 pairing fall back to the
/// Chromium baseline — the most common framing on the public web — rather than
/// to something that would look like a hand-assembled hybrid.
#[cfg(feature = "http2")]
fn h2_fingerprint_for(profile: Option<&str>) -> H2Fingerprint {
    match profile {
        Some("safari-current") => H2Fingerprint::safari(),
        Some("firefox-current") => H2Fingerprint::firefox(),
        Some("antigravity-cli") => H2Fingerprint::go(),
        _ => H2Fingerprint::chrome(),
    }
}

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
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            user_agent: format!("netune/{}", env!("CARGO_PKG_VERSION")),
            max_redirects: 5,
            enable_http2: false,
        }
    }
}

/// An HTTP/1.1 client over a connector and a pool.
pub struct Client<C: Connector> {
    connector: C,
    pool: Pool,
    config: ClientConfig,
}

impl<C: Connector> Client<C> {
    pub fn new(connector: C, pool: Pool, config: ClientConfig) -> Self {
        Self {
            connector,
            pool,
            config,
        }
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Pre-warm a connection for `target` into the idle pool if none exists.
    ///
    /// Runs DNS + TCP + TLS in advance so the next user request can start with
    /// zero connection overhead (instant warm-pool hit). Returns `true` if a fresh
    /// connection was opened, or `false` if an idle connection was already available.
    pub async fn prewarm(&self, target: &Target) -> Result<bool, NetError> {
        let key = Self::pool_key(target);
        if self.pool.idle_count(&key) > 0 {
            return Ok(false);
        }
        let recorder = Arc::new(Mutex::new(Recorder::start(crate::DEFAULT_TRACE_CAPACITY)));
        let established = self.connector.connect(target, &recorder).await?;

        // Warm the connection in the protocol the next request will actually
        // use; pooling an already-negotiated HTTP/2 socket as if it were
        // HTTP/1.1 would hand it to the wrong writer.
        #[cfg(feature = "http2")]
        if target.force_h2 || (self.config.enable_http2 && established.alpn == Some(Alpn::H2)) {
            let fp = h2_fingerprint_for(target.tls_profile.as_deref());
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

    /// The pool key for a target: authority plus the requested TLS identity.
    ///
    /// A connection handshook under one fingerprint must never serve a request
    /// that asked for another — the hello is already on the wire, and any
    /// resumption ticket belongs to that identity. Keying on both keeps each
    /// identity's connections in their own slice of the pool. Requests without
    /// a selection keep the bare-authority key and never collide with
    /// profiled ones.
    fn pool_key(target: &Target) -> String {
        match &target.tls_profile {
            Some(profile) => format!("{}#{}", target.authority, profile),
            None => target.authority.clone(),
        }
    }

    /// Send one request without installing a trace consumer.
    ///
    /// Convenience for call sites that are not model attempts (catalog fetches,
    /// token exchanges, MCP): they get the owned transport's behaviour without
    /// plumbing a [`Recorder`] they will never read.
    pub async fn request(
        &self,
        target: &Target,
        head: RequestHead,
        body: Option<Bytes>,
    ) -> Result<Response, NetError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(crate::DEFAULT_TRACE_CAPACITY)));
        self.send(target, recorder, head, body).await
    }

    /// Establish an upgraded, traced client WebSocket stream to `target`.
    ///
    /// The attempt's trace lives in the returned stream's `Recorder`; pass a
    /// recorder explicitly via [`Client::connect_ws_traced`] when the caller
    /// wants to derive timings afterwards.
    #[cfg(feature = "ws")]
    pub async fn connect_ws(
        &self,
        target: &Target,
        path: &str,
    ) -> Result<crate::ws::WsStream<TimedIo<Box<dyn crate::connect::Transport>>>, NetError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(crate::DEFAULT_TRACE_CAPACITY)));
        self.connect_ws_traced(target, path, recorder, crate::ws::WsHandshake::default())
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
        recorder: Arc<Mutex<Recorder>>,
        handshake: crate::ws::WsHandshake,
    ) -> Result<crate::ws::WsStream<TimedIo<Box<dyn crate::connect::Transport>>>, NetError> {
        // Every terminal failure inside this function must close out the
        // attempt's trace with an `Error` event: the trace must never end as
        // an unexplained headless corpse.
        let fail = |recorder: &Mutex<Recorder>, message: String| -> NetError {
            recorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .mark(EventKind::Error, 0, 0);
            NetError::Protocol(message)
        };

        let established = match self.connector.connect(target, &recorder).await {
            Ok(established) => established,
            Err(error) => {
                let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
                rec.mark(EventKind::Error, 0, 0);
                return Err(error);
            }
        };
        let mut io = TimedIo::new(established.stream, Arc::clone(&recorder));

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

        {
            let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
            rec.mark(EventKind::RequestWriteStart, 0, 0);
        }
        if let Err(error) = write_request(&mut io, &head, None).await {
            return Err(fail(&recorder, format!("WebSocket request write: {error}")));
        }
        {
            let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
            rec.mark(EventKind::RequestWriteEnd, 0, 0);
        }

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

        {
            let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
            rec.mark(EventKind::HeadComplete, 0, 0);
        }

        let (io, residual_buf) = reader.into_inner();
        Ok(crate::ws::WsStream::new(
            io,
            residual_buf,
            Some(recorder),
            handshake.limits,
        ))
    }

    /// WebSocket support was compiled out.
    #[cfg(not(feature = "ws"))]
    pub async fn connect_ws_traced(
        &self,
        _target: &Target,
        _path: &str,
        _recorder: Arc<Mutex<Recorder>>,
        _handshake: (),
    ) -> Result<(), NetError> {
        Err(NetError::Protocol(
            "WebSocket support was not compiled in: enable the `ws` feature".into(),
        ))
    }

    /// Send one request, following redirects, and return the final response.
    pub async fn send(
        &self,
        target: &Target,
        recorder: Arc<Mutex<Recorder>>,
        head: RequestHead,
        body: Option<Bytes>,
    ) -> Result<Response, NetError> {
        let origin = target.authority.clone();
        let mut target = target.clone();
        let mut head = head;
        let mut body = body;
        let mut hops: u8 = 0;

        loop {
            let response = self
                .send_once(&target, Arc::clone(&recorder), head.clone(), body.clone())
                .await?;
            let Some(location) = redirect_location(&response.head) else {
                // Only the final head marks completion: a redirect's head must
                // not become the anchor TTFT is measured against.
                recorder
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .mark(EventKind::HeadComplete, 0, 0);
                return Ok(response);
            };
            if hops >= self.config.max_redirects {
                return Err(NetError::TooManyRedirects(self.config.max_redirects));
            }
            let status = response.head.status;
            // The hop's connection is not pooled: its body was never drained, so
            // reusing it could desynchronise the stream.
            drop(response);
            recorder
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .mark(EventKind::Redirect, u32::from(status.as_u16()), 0);

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

    async fn send_once(
        &self,
        target: &Target,
        recorder: Arc<Mutex<Recorder>>,
        head: RequestHead,
        body: Option<Bytes>,
    ) -> Result<Response, NetError> {
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
        let key = Self::pool_key(target);
        #[cfg(feature = "http2")]
        let prefer_http2 = self.config.enable_http2 || target.force_h2;

        #[cfg(feature = "http2")]
        let mut recycled = if prefer_http2 {
            self.pool
                .take_matching(&key, |protocol| protocol == Protocol::Http2)
        } else {
            None
        };
        #[cfg(not(feature = "http2"))]
        let mut recycled = None;

        if recycled.is_none() && !target.force_h2 {
            recycled = self
                .pool
                .take_matching(&key, |protocol| protocol == Protocol::Http1);
        }
        loop {
            let reused = recycled.is_some();
            let attempt = self
                .send_on_connection(target, Arc::clone(&recorder), &head, &body, recycled.take())
                .await;
            match attempt {
                Err(error) if reused && error.is_stale_connection() => {
                    // The socket died before the peer answered. Record the
                    // revocation so the trace explains both the decision and the
                    // cost: the reuse claim is withdrawn and the handshake this
                    // attempt is about to pay is measured rather than reported
                    // as `ConnectionReused`.
                    let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
                    recorder.mark(EventKind::ConnectStaleDiscarded, 0, 0);
                    drop(recorder);
                    continue;
                }
                other => return other,
            }
        }
    }

    /// Write `head`/`body` on `recycled` (or a fresh connection) and return the
    /// response, with no recovery of its own.
    async fn send_on_connection(
        &self,
        target: &Target,
        recorder: Arc<Mutex<Recorder>>,
        head: &RequestHead,
        body: &Option<Bytes>,
        recycled: Option<IdleConnection>,
    ) -> Result<Response, NetError> {
        let mut head = head.clone();
        if !head.headers.contains_key(http::header::USER_AGENT) {
            head.headers.insert(
                http::header::USER_AGENT,
                http::HeaderValue::from_str(&self.config.user_agent)
                    .unwrap_or_else(|_| http::HeaderValue::from_static("netune")),
            );
        }

        let pool_key = Self::pool_key(target);

        // A pooled connection already speaks a protocol. Drive it with the role
        // that protocol requires; a connection the request cannot use is dropped
        // and a fresh one is dialled.
        if let Some(recycled) = recycled {
            match recycled {
                IdleConnection::Http1(idle) if !target.force_h2 => {
                    {
                        let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
                        // One event, carrying the idle age: `derive` and every
                        // surface read reuse through `first_of(ConnectReused)`.
                        rec.mark(EventKind::ConnectReused, idle.age.as_millis() as u32, 0);
                    }
                    return self
                        .send_http1(
                            idle.stream,
                            idle.buffered,
                            idle.local_port,
                            idle.socket,
                            recorder,
                            head,
                            body,
                            target,
                            pool_key,
                        )
                        .await;
                }
                #[cfg(feature = "http2")]
                IdleConnection::Http2(idle) if self.config.enable_http2 || target.force_h2 => {
                    {
                        let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
                        rec.mark(EventKind::ConnectReused, idle.age.as_millis() as u32, 0);
                    }
                    return self
                        .send_http2(
                            *idle.connection,
                            idle.local_port,
                            idle.socket,
                            recorder,
                            head,
                            body,
                            target,
                            pool_key,
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
        if target.force_h2 || (self.config.enable_http2 && established.alpn == Some(Alpn::H2)) {
            let fp = h2_fingerprint_for(target.tls_profile.as_deref());
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
                    target,
                    pool_key,
                )
                .await;
        }

        self.send_http1(
            established.stream,
            BytesMut::new(),
            established.local_port,
            established.socket,
            recorder,
            head,
            body,
            target,
            pool_key,
        )
        .await
    }

    /// Write the request over HTTP/1.1 and return its streaming response.
    #[allow(clippy::too_many_arguments)]
    async fn send_http1(
        &self,
        stream: Box<dyn crate::connect::Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
        recorder: Arc<Mutex<Recorder>>,
        mut head: RequestHead,
        body: &Option<Bytes>,
        target: &Target,
        pool_key: String,
    ) -> Result<Response, NetError> {
        if !head.headers.contains_key(http::header::HOST)
            && let Ok(value) = http::HeaderValue::from_str(&target.authority)
        {
            head.headers.insert(http::header::HOST, value);
        }

        // Sample the socket for as long as this request is in flight. The
        // sampler gets its own duplicate handle; `socket` travels with the body
        // stream so the pool can be handed a live handle when it is released.
        let sampler = socket.as_ref().and_then(|socket| {
            crate::tcp_info::duplicate(socket)
                .map(|clone| start_sampler(clone, Arc::clone(&recorder), SAMPLE_INTERVAL))
        });

        let mut io = TimedIo::new(stream, Arc::clone(&recorder));
        {
            let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
            recorder.mark(EventKind::RequestWriteStart, 0, 0);
        }
        write_request(&mut io, &head, body.as_deref()).await?;
        {
            let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
            let written = body.as_ref().map_or(0, |body| body.len()) as u32;
            recorder.mark(EventKind::RequestWriteEnd, written, 0);
        }

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
                reader: Some(reader),
                #[cfg(feature = "http2")]
                h2: None,
                recorder,
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
        recorder: Arc<Mutex<Recorder>>,
        head: RequestHead,
        body: &Option<Bytes>,
        target: &Target,
        pool_key: String,
    ) -> Result<Response, NetError> {
        let scheme = if target.tls_server_name.is_some() {
            "https"
        } else {
            "http"
        };
        let (authority, extra_headers) = h2_request_parts(&head, &target.authority);

        {
            let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
            rec.mark(EventKind::RequestWriteStart, 0, 0);
        }
        let stream_id = h2
            .start_request(
                head.method.as_str(),
                &authority,
                scheme,
                &head.target,
                &extra_headers,
                body.as_deref(),
            )
            .await
            .map_err(|error| h2_error("request", error))?;
        {
            let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
            let written = body.as_ref().map_or(0, |body| body.len()) as u32;
            rec.mark(EventKind::RequestWriteEnd, written, 0);
        }

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
                .map(|clone| start_sampler(clone, Arc::clone(&recorder), SAMPLE_INTERVAL))
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
        return Ok((Target::tls(authority, name), path));
    }
    if let Some(rest) = location.strip_prefix("http://") {
        let (authority, path) = split_authority(rest, 80);
        return Ok((Target::plain(authority), path));
    }
    if let Some(rest) = location.strip_prefix("//") {
        let (authority, path) = split_authority(rest, default_port(current));
        let mut target = current.clone();
        target.authority = authority;
        if target.tls_server_name.is_some() {
            target.tls_server_name = Some(
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
    if target.tls_server_name.is_some() {
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
    reader: Option<Http1Reader<TimedIo<Box<dyn crate::connect::Transport>>>>,
    #[cfg(feature = "http2")]
    h2: Option<H2ResponseStream<Box<dyn crate::connect::Transport>>>,
    recorder: Arc<Mutex<Recorder>>,
    pool: Pool,
    pool_key: String,
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

impl BodyStream {
    /// Read the next decoded body bytes, or `None` at the end of the body.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, NetError> {
        loop {
            let Some(raw) = self.read_raw_chunk().await? else {
                let mut tail = Vec::new();
                self.decoder.finish(&mut tail)?;
                {
                    let mut recorder = self.recorder.lock().unwrap_or_else(|e| e.into_inner());
                    recorder.mark(EventKind::BodyEnd, 0, 0);
                }
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
            let mut recorder = self.recorder.lock().unwrap_or_else(|e| e.into_inner());
            if !self.started {
                recorder.mark(EventKind::BodyStart, 0, 0);
                self.started = true;
            }
            if !decoded.is_empty() {
                recorder.mark(EventKind::ChunkBoundary, decoded.len() as u32, 0);
            }
            drop(recorder);
            if !decoded.is_empty() {
                return Ok(Some(Bytes::from(decoded)));
            }
            // The decoder consumed the raw bytes without producing output (a
            // header, or a partial frame): keep reading.
        }
    }

    /// Read the next raw (still `Content-Encoding`-encoded) body chunk.
    async fn read_raw_chunk(&mut self) -> Result<Option<Bytes>, NetError> {
        if let Some(reader) = self.reader.as_mut() {
            return reader.read_body_chunk().await.map_err(NetError::from);
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

    /// The attempt's trace, once the body has been fully consumed.
    ///
    /// `None` while the body is still open: a partial trace would report
    /// missing stages as if they had not happened.
    pub fn trace(&self) -> Option<netune_trace::RequestTrace> {
        if !self.finished {
            return None;
        }
        let log = self
            .recorder
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .log()
            .clone();
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
            fidelity: netune_trace::Fidelity::l1(),
            log,
        })
    }

    /// Return the connection to the pool when the body is done and the peer
    /// allows reuse. Idempotent.
    pub fn release(&mut self) {
        if let Some(reader) = self.reader.take() {
            let (io, buffered) = reader.into_inner();
            let stream = io.into_inner();
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
