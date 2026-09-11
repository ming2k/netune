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
use http::{Method, StatusCode};
use netune_http1::{BodyKind, Http1Reader, Limits, RequestHead, ResponseHead, write_request};
use netune_trace::{EventKind, Recorder};

use crate::connect::{Connector, Target};
use crate::decompress::Decoder;
use crate::error::NetError;
use crate::io::TimedIo;
use crate::pool::Pool;
use crate::tcp_info::{SAMPLE_INTERVAL, Sampler, start as start_sampler};

/// Client policy.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub limits: Limits,
    /// Sent as `user-agent` when the caller did not supply one.
    pub user_agent: String,
    /// Redirect hops followed before giving up.
    pub max_redirects: u8,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            user_agent: format!("netune/{}", env!("CARGO_PKG_VERSION")),
            max_redirects: 5,
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
        if self.pool.idle_count(&Self::pool_key(target)) > 0 {
            return Ok(false);
        }
        let recorder = Arc::new(Mutex::new(Recorder::start(crate::DEFAULT_TRACE_CAPACITY)));
        let established = self.connector.connect(target, &recorder).await?;
        self.pool.put(
            &Self::pool_key(target),
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
        mut head: RequestHead,
        body: Option<Bytes>,
    ) -> Result<Response, NetError> {
        if !head.headers.contains_key(http::header::USER_AGENT) {
            head.headers.insert(
                http::header::USER_AGENT,
                http::HeaderValue::from_str(&self.config.user_agent)
                    .unwrap_or_else(|_| http::HeaderValue::from_static("netune")),
            );
        }
        if !head.headers.contains_key(http::header::HOST)
            && let Ok(value) = http::HeaderValue::from_str(&target.authority)
        {
            head.headers.insert(http::header::HOST, value);
        }

        let pool_key = Self::pool_key(target);
        let (stream, buffered, local_port, socket) = match self.pool.take(&pool_key) {
            Some(idle) => {
                let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
                recorder.reused_connection();
                recorder.mark(EventKind::ConnectReused, idle.age.as_millis() as u32, 0);
                (idle.stream, idle.buffered, idle.local_port, idle.socket)
            }
            None => {
                let established = self.connector.connect(target, &recorder).await?;
                (
                    established.stream,
                    BytesMut::new(),
                    established.local_port,
                    established.socket,
                )
            }
        };
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
}

/// The `Location` of a redirecting response, if any.
fn redirect_location(head: &ResponseHead) -> Option<String> {
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
fn is_reusable(head: &ResponseHead) -> bool {
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
    pub head: ResponseHead,
    pub body: BodyStream,
}

/// Streams the response body, decoding `Content-Encoding` and marking chunk
/// boundaries and completion.
pub struct BodyStream {
    reader: Option<Http1Reader<TimedIo<Box<dyn crate::connect::Transport>>>>,
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
            let Some(reader) = self.reader.as_mut() else {
                return Ok(None);
            };
            match reader.read_body_chunk().await? {
                Some(raw) => {
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
                    // The decoder consumed the raw bytes without producing
                    // output (a header, or a partial frame): keep reading.
                }
                None => {
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
                }
            }
        }
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
        let Some(reader) = self.reader.take() else {
            return;
        };
        let (io, buffered) = reader.into_inner();
        let stream = io.into_inner();
        // Stop sampling before the connection goes idle.
        drop(self.sampler.take());
        if self.finished && self.reusable {
            self.pool.put(
                &self.pool_key,
                stream,
                buffered,
                self.local_port,
                self.socket.take(),
            );
        }
    }
}
