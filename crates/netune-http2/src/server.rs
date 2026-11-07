//! HTTP/2 *server* role: accept a connection and serve multiplexed request streams.
//!
//! The connection layer ([`crate::connection`]) owns framing, `SETTINGS`, `PING`, `GOAWAY` and
//! HPACK. This module owns the three things that are the server's alone:
//!
//! 1. **The stream table** — which peer-originated streams are open, cancelled or refused. A server
//!    that could not answer "is stream 7 still live" would either accept `DATA` for a closed stream
//!    (a protocol error, §5.1) or lose the state per-stream flow control needs.
//! 2. **The receive window** — credit is replenished as the *handler* consumes bytes, so a peer can
//!    never have more than the advertised window in flight. Memory is bounded by a number the peer
//!    was told, not by trust.
//! 3. **The response direction** — one `HEADERS`, then zero or more `DATA` frames; `END_STREAM` is
//!    the only terminator there is, and unlike HTTP/1.1 there is no chunked encoding to get wrong.
//!
//! # Concurrency model: one writer, many producers
//!
//! One task owns the connection and its write half. Handlers run as *separate* tasks, but they never
//! touch the socket: a handler returns a head and, for a streamed response, hands back a channel of
//! chunks. The session writes every frame.
//!
//! That is not a stylistic preference. HTTP/2 frames from different streams must interleave at
//! *frame* granularity; two tasks writing to one socket would interleave at *byte* granularity —
//! producing a frame whose header belongs to stream 3 and whose payload is the tail of stream 5's
//! header block. Single writer, always.
//!
//! # Why the loop wakes on two things, not one
//!
//! A session that only awaited the socket would sit in `read_frame` while a handler finished, which
//! is the difference between a server and a deadlock: the client is waiting for a response that is
//! already computed. The loop therefore awaits the socket *and* a wake-up channel that carries
//! handler completions and streamed-body chunks. Both are cheap to poll and neither can lose an
//! event, because a wake-up is a message rather than a level.
//!
//! # What the server will not do
//!
//! - **No push.** `PUSH_PROMISE` is never sent and `ENABLE_PUSH=0` is advertised: a pushed resource
//!   is a cache hint no handler here can opt into.
//! - **No `h2c` upgrade.** A plaintext connection is prior-knowledge HTTP/2 or HTTP/1.1, decided by
//!   the first bytes. An in-place upgrade is a smuggling surface and a second parser on one socket.
//! - **No priority scheduling.** `PRIORITY` frames are accepted and ignored (§5.3.1 permits it); a
//!   scheduler is policy and this is a transport.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::connection::{CLIENT_PREFACE, DEFAULT_WINDOW, H2Connection, LocalSettings, error_code};
use crate::error::H2Error;
use crate::frame::{Frame, SETTING_INITIAL_WINDOW_SIZE};

/// The bounds and advertised values one HTTP/2 session uses.
///
/// Passed by value so the role holds no policy: an orchestrator that wants different limits builds
/// a different config, and the numbers it sets are the numbers the peer is *told*.
#[derive(Debug, Clone)]
pub struct ServerSessionConfig {
    /// The SETTINGS to advertise, in wire order.
    pub settings: Vec<(u16, u32)>,
    /// The local bounds those settings reflect (frame size, window, table size).
    pub local: LocalSettings,
    /// Connection-level receive window to advertise.
    pub connection_window: u32,
    /// How many request chunks may be buffered for a handler before the read loop applies
    /// back-pressure.
    ///
    /// This channel is the only place request bytes are held, so the effective ceiling per stream is
    /// the advertised window; a peer that ignores flow control stalls itself rather than growing our
    /// memory.
    pub body_channel_capacity: usize,
    /// Bound on any single frame write.
    ///
    /// The slow-*read* defence: a peer that opens its receive window one byte at a time must not hold
    /// a stream slot for the length of a handler timeout. Each frame write gets this long, which bounds
    /// a stalled peer without punishing a slow link.
    pub write_timeout: std::time::Duration,
}

impl Default for ServerSessionConfig {
    fn default() -> Self {
        Self::for_ingress()
    }
}

impl ServerSessionConfig {
    /// Production defaults matching [`LocalSettings::for_ingress`].
    pub fn for_ingress() -> Self {
        let local = LocalSettings::for_ingress();
        Self {
            settings: local.parameters(),
            local,
            connection_window: 4 * 1024 * 1024,
            body_channel_capacity: 4,
            write_timeout: std::time::Duration::from_secs(30),
        }
    }

    /// A configuration whose windows are obviously small, for tests that exercise flow control
    /// without moving a megabyte.
    pub fn for_tests() -> Self {
        let local = LocalSettings {
            initial_window_size: 64 * 1024,
            max_concurrent_streams: 8,
            ..LocalSettings::for_ingress()
        };
        Self {
            settings: local.parameters(),
            local,
            connection_window: 65_535,
            body_channel_capacity: 2,
            write_timeout: std::time::Duration::from_secs(2),
        }
    }
}

/// One request, as the server role hands it to the orchestrator.
#[derive(Debug)]
pub struct H2Request {
    /// The stream this request arrived on. It is the exchange identity a trace records.
    pub stream_id: u32,
    pub method: http::Method,
    /// `:path` as bytes; empty for `CONNECT`.
    pub path: Bytes,
    /// `:authority`, or empty when the peer sent none.
    pub authority: String,
    /// `:scheme`, or empty for `CONNECT`.
    pub scheme: String,
    /// The regular headers, with `host` synthesised from `:authority` when the peer sent no `host`
    /// of its own — so a handler reads one field to learn the authority regardless of protocol.
    pub headers: http::HeaderMap,
    /// The request body.
    pub body: H2Body,
}

impl H2Request {
    /// The target in the absolute form an HTTP/1.1 handler would have received behind a proxy.
    ///
    /// A translation, not an interpretation: the path bytes are untouched.
    pub fn absolute_target(&self) -> Bytes {
        if self.scheme.is_empty() || self.authority.is_empty() {
            return self.path.clone();
        }
        let mut out = bytes::BytesMut::with_capacity(
            self.scheme.len() + self.authority.len() + self.path.len() + 3,
        );
        out.extend_from_slice(self.scheme.as_bytes());
        out.extend_from_slice(b"://");
        out.extend_from_slice(self.authority.as_bytes());
        out.extend_from_slice(&self.path);
        out.freeze()
    }
}

/// The request body of one HTTP/2 stream.
///
/// Delivers `DATA` payloads in order and reports the end exactly once. A `DATA` frame that arrives
/// after the handler stopped reading is drained by the session, so the connection's flow-control
/// window never stalls behind an abandoned body.
#[derive(Debug)]
pub struct H2Body {
    rx: mpsc::Receiver<Bytes>,
    finished: bool,
    read: u64,
}

impl H2Body {
    fn new(rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            rx,
            finished: false,
            read: 0,
        }
    }

    /// A body that is already complete, which is the common case for a small request.
    pub fn complete(bytes: Bytes) -> Self {
        let (tx, rx) = mpsc::channel(1);
        if !bytes.is_empty() {
            let _ = tx.try_send(bytes);
        }
        drop(tx);
        Self {
            rx,
            finished: false,
            read: 0,
        }
    }

    /// A body that never has content.
    pub fn empty() -> Self {
        Self::complete(Bytes::new())
    }

    /// The next chunk, or `None` at the end of the body.
    pub async fn next_chunk(&mut self) -> Option<Bytes> {
        if self.finished {
            return None;
        }
        match self.rx.recv().await {
            Some(chunk) => {
                self.read += chunk.len() as u64;
                Some(chunk)
            }
            None => {
                self.finished = true;
                None
            }
        }
    }

    /// Drain the body into one buffer.
    pub async fn read_to_end(&mut self) -> Bytes {
        let mut out = bytes::BytesMut::new();
        while let Some(chunk) = self.next_chunk().await {
            out.extend_from_slice(&chunk);
        }
        out.freeze()
    }

    /// Whether the body has been read to its end.
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Bytes handed to the handler so far.
    pub const fn bytes_read(&self) -> u64 {
        self.read
    }
}

/// The response a handler produces for one stream.
#[derive(Debug)]
pub struct H2Response {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    /// The body: bytes for a one-shot answer, a channel for a streamed one.
    pub body: H2ResponseBody,
}

/// How a response body is delivered.
#[derive(Debug)]
pub enum H2ResponseBody {
    /// No body; the head carries `END_STREAM`.
    Empty,
    /// The whole body in memory.
    Bytes(Bytes),
    /// Chunks produced while the response is written. Dropping the sender ends the body.
    Stream(mpsc::Receiver<Bytes>),
}

impl H2Response {
    /// A `200` with the given bytes.
    pub fn ok(body: impl Into<Bytes>) -> Self {
        Self {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: H2ResponseBody::Bytes(body.into()),
        }
    }

    /// A response with an explicit status and no body.
    pub fn with_status(status: http::StatusCode) -> Self {
        Self {
            status,
            headers: http::HeaderMap::new(),
            body: H2ResponseBody::Empty,
        }
    }

    /// A streaming response: the head is written first, then each chunk as it arrives.
    pub fn stream(status: http::StatusCode, rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            status,
            headers: http::HeaderMap::new(),
            body: H2ResponseBody::Stream(rx),
        }
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_ref().as_bytes()),
            http::header::HeaderValue::from_str(value.as_ref()),
        ) {
            self.headers.insert(name, value);
        }
        self
    }
}

/// The future an [`H2Handler`] returns.
pub type ResponseFuture<'a> = std::pin::Pin<Box<dyn Future<Output = H2Response> + Send + 'a>>;

/// The application boundary for HTTP/2 ingress.
///
/// One method, object-safe, called once per stream — deliberately the same shape as the HTTP/1.1
/// handler in `netune-server`, so the orchestration above this crate implements both for one
/// application function. A protocol-specific handler trait would force every application to write
/// its routing twice.
pub trait H2Handler: Send + Sync + 'static {
    /// Answer one request.
    fn handle(&self, request: H2Request) -> ResponseFuture<'_>;
}

/// Why a session ended.
#[derive(Debug)]
pub enum SessionEnd {
    /// The peer closed the connection.
    PeerClosed,
    /// The peer sent `GOAWAY` with this error code.
    PeerGoAway(u32),
    /// A protocol violation ended the connection; `GOAWAY(code)` was sent.
    Protocol(H2Error, u32),
    /// The caller's shutdown future resolved; open streams finished, then `GOAWAY` was sent.
    Drained,
}

/// A fact observed on one stream, as the session reports it.
///
/// The events are this crate's own vocabulary rather than `netune-trace`'s because a codec must not
/// depend on the trace model (it is a leaf, ADR-0003). The orchestrator adapts these to `EventKind`
/// and attaches the exchange identity the trace needs — which is exactly the translation that
/// belongs in the crate that owns the recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEvent {
    /// A request head was decoded; `payload` bytes.
    RequestHeadComplete { payload: u32 },
    /// `payload` bytes of request body were delivered to the handler.
    RequestBodyChunk { payload: u32 },
    /// The request body ended.
    RequestBodyEnd,
    /// The handler returned `status`.
    HandlerEnd { status: u16 },
    /// The response head was written.
    ResponseHeadSent,
    /// `payload` bytes of response body were written.
    ResponseBodyChunk { payload: u32 },
    /// The response ended.
    ResponseEnd,
    /// A stream-level failure, classified by `code`.
    Failed { code: u32 },
}

/// Receives the facts a session observes, tagged with the stream they belong to.
///
/// Implemented by the orchestrator, never by this crate: a session that wrote into a `Recorder`
/// itself would need the trace model, and a codec that depends on a trace model is no longer a codec.
pub trait SessionObserver: Send + Sync + std::fmt::Debug {
    /// One fact on `stream_id`.
    fn observed(&self, stream_id: u32, event: StreamEvent);
}

/// An observer that discards everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoObserver;

impl SessionObserver for NoObserver {
    fn observed(&self, _stream_id: u32, _event: StreamEvent) {}
}

/// Sends a wake-up when its task ends, whether it returned, panicked or was cancelled.
struct WakeGuard {
    tx: mpsc::UnboundedSender<Wake>,
}

impl Drop for WakeGuard {
    fn drop(&mut self) {
        let _ = self.tx.send(Wake::HandlerDone);
    }
}

/// What wakes the session loop besides the socket.
enum Wake {
    /// A handler finished; its response is ready to be collected by the reap pass.
    HandlerDone,
    /// Stream `0` produced one body chunk.
    Chunk(u32, Bytes),
    /// Stream `0` closed its body channel; the terminator is owed once the queue drains.
    BodyEnd(u32),
}

/// Serves one HTTP/2 connection.
pub struct ServerSession<H> {
    handler: Arc<H>,
    config: ServerSessionConfig,
    observer: Arc<dyn SessionObserver>,
}

impl<H: H2Handler> ServerSession<H> {
    /// Prepare a session that reports every stream's facts to `observer`.
    pub fn new(
        handler: Arc<H>,
        config: ServerSessionConfig,
        observer: Arc<dyn SessionObserver>,
    ) -> Self {
        Self {
            handler,
            config,
            observer,
        }
    }

    /// Serve the connection until it closes or `shutdown` resolves.
    ///
    /// `preface_already_read` says whether the caller consumed the 24-octet client preface while
    /// deciding this connection was HTTP/2. A TLS connection with ALPN `h2` has not read it (the
    /// bytes are still in the stream); a plaintext prior-knowledge connection usually has, because
    /// that is how the listener recognised it.
    ///
    /// Never returns an error: a fatal protocol condition becomes [`SessionEnd::Protocol`] after a
    /// `GOAWAY` is attempted, so the caller can count it as a connection failure without
    /// distinguishing "we closed" from "they closed".
    pub async fn run<T>(
        self,
        stream: T,
        preface_already_read: bool,
        shutdown: impl Future<Output = ()>,
    ) -> SessionEnd
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut connection = match H2Connection::server_handshake(
            stream,
            self.config.local.clone(),
            self.config.settings.clone(),
            self.config.connection_window,
        )
        .await
        {
            Ok(connection) => connection,
            Err(error) => return SessionEnd::Protocol(error, error_code::INTERNAL_ERROR),
        };

        if !preface_already_read && let Err(error) = read_client_preface(&mut connection).await {
            return SessionEnd::Protocol(error, error_code::PROTOCOL_ERROR);
        }

        connection.set_write_deadline(Some(self.config.write_timeout));
        let mut state = SessionState::new(&self.config);
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => {
                    state.drain(&mut connection, &self).await;
                    return SessionEnd::Drained;
                }
                ended = state.step(&mut connection, &self) => {
                    if let Some(end) = ended {
                        if let SessionEnd::Protocol(_, code) = &end {
                            // One choke point for the whole session: RFC 9113 §6.8 makes `GOAWAY`
                            // the only way to tell a peer the connection is over for a protocol
                            // reason. A session that returned without one would leave the peer
                            // waiting on streams it believes are still open, which reads as a hang
                            // rather than as a failure.
                            let _ = connection.send_goaway(state.highest, *code, b"").await;
                        }
                        return end;
                    }
                }
            }
        }
    }

    /// Report one stream's fact.
    fn mark(&self, stream_id: u32, event: StreamEvent) {
        self.observer.observed(stream_id, event);
    }
}

/// Read the client preface after our own SETTINGS, for a connection recognised some other way than
/// by its first bytes (ALPN).
async fn read_client_preface<T>(connection: &mut H2Connection<T>) -> Result<(), H2Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut preface = vec![0u8; CLIENT_PREFACE.len()];
    connection.read_preface_bytes(&mut preface).await
}

/// One connection's stream bookkeeping.
struct SessionState {
    streams: HashMap<u32, StreamState>,
    /// The highest stream id the peer has opened.
    highest: u32,
    /// Body chunks the session owes the peer, in arrival order.
    outbound: VecDeque<(u32, Bytes)>,
    /// Body channel capacity, from the config.
    body_capacity: usize,
    /// The sending half of the wake-up channel, cloned into every handler task.
    wake_tx: mpsc::UnboundedSender<Wake>,
    /// The receiving half, awaited alongside the socket.
    wake_rx: mpsc::UnboundedReceiver<Wake>,
}

/// What one stream is doing.
struct StreamState {
    /// The channel of request-body chunks handed to the handler. `None` once the body ended or the
    /// handler dropped it.
    body_tx: Option<mpsc::Sender<Bytes>>,
    /// The handler's task, until it produces a response.
    handler: Option<JoinHandle<H2Response>>,
    /// Credit this stream has for sending, from the peer's `INITIAL_WINDOW_SIZE`.
    send_window: i64,
    /// Whether the response head has been written, so a body may follow.
    head_sent: bool,
    /// Whether the body channel has closed: the terminator is owed after `outbound` drains.
    body_ending: bool,
    /// Whether this stream is closed and its id retired.
    finished: bool,
    /// Receive credit for this stream, as advertised in `SETTINGS_INITIAL_WINDOW_SIZE`.
    ///
    /// Tracked per stream because RFC 9113 §6.9 has two windows, not one: a peer may not send past
    /// either, and credit returned for one does not restore the other. A server that only tracked the
    /// connection window would stall the first upload larger than a stream window — a hang, not an
    /// error.
    recv_window: i64,
}

impl SessionState {
    fn new(config: &ServerSessionConfig) -> Self {
        let (wake_tx, wake_rx) = mpsc::unbounded_channel();
        Self {
            streams: HashMap::new(),
            highest: 0,
            outbound: VecDeque::new(),
            body_capacity: config.body_channel_capacity,
            wake_tx,
            wake_rx,
        }
    }

    /// One iteration: write what is owed, then wait for the socket or a handler.
    async fn step<T, H>(
        &mut self,
        connection: &mut H2Connection<T>,
        session: &ServerSession<H>,
    ) -> Option<SessionEnd>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        H: H2Handler,
    {
        self.reap(connection, session).await;
        if let Some(end) = self.flush_pending(connection, session).await {
            return Some(end);
        }

        // Concurrency-minimising choice: when nothing is owed and nothing is running, block on the
        // socket alone. Otherwise the handler side must be able to wake us, or a finished response
        // would wait for the peer's next frame — which is exactly the deadlock a client sees as a
        // hang.
        let frame = tokio::select! {
            biased;
            Some(wake) = self.wake_rx.recv() => {
                self.on_wake(wake);
                return None;
            }
            frame = connection.read_frame() => match frame {
                Ok(frame) => frame,
                Err(H2Error::UnexpectedEof) => return Some(SessionEnd::PeerClosed),
                Err(error) => {
                    return Some(SessionEnd::Protocol(error, error_code::PROTOCOL_ERROR));
                }
            },
        };

        match frame {
            Frame::Headers {
                stream_id,
                end_stream,
                end_headers,
                header_block,
            } => {
                if let Some(end) = self
                    .open_stream(
                        connection,
                        session,
                        stream_id,
                        end_stream,
                        end_headers,
                        header_block,
                    )
                    .await
                {
                    return Some(end);
                }
            }
            Frame::Data {
                stream_id,
                end_stream,
                payload,
            } => {
                let len = payload.len() as u32;
                // The window we advertised is the memory we promised to hold. Refusing an overrun here
                // is what makes the promise real: a peer that ignores it is failed rather than believed.
                if let Err(error) = connection.consume_inbound(len) {
                    return Some(SessionEnd::Protocol(error, error_code::FLOW_CONTROL_ERROR));
                }
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.recv_window -= i64::from(len);
                    if state.recv_window < 0 {
                        return Some(SessionEnd::Protocol(
                            H2Error::Protocol("the peer exceeded a stream receive window".into()),
                            error_code::FLOW_CONTROL_ERROR,
                        ));
                    }
                }
                match self.streams.get_mut(&stream_id) {
                    Some(state) => {
                        let mut delivered = false;
                        if let Some(tx) = state.body_tx.clone() {
                            // Delivering into a bounded channel *is* the flow-control policy: when
                            // the handler is behind, `send` waits, no read happens, the peer's
                            // window fills, and it must stop.
                            if tx.send(payload).await.is_ok() {
                                delivered = true;
                            } else {
                                // The handler dropped its body: drain the rest so the connection's
                                // window does not stall behind an abandoned request.
                                state.body_tx = None;
                            }
                        }
                        if delivered {
                            session.mark(stream_id, StreamEvent::RequestBodyChunk { payload: len });
                            // Credit returns as the *handler* consumes, which is what bounds memory by
                            // the advertised window instead of by trust.
                            state.recv_window += i64::from(len);
                            if state.recv_window > 0x7FFF_FFFF {
                                return Some(SessionEnd::Protocol(
                                    H2Error::Protocol("stream receive window overflowed".into()),
                                    error_code::FLOW_CONTROL_ERROR,
                                ));
                            }
                            let _ = connection.replenish(stream_id, len).await;
                        }
                        // The connection window is restored either way: bytes that reached a stream we
                        // are still tracking consumed connection credit, whether or not a handler
                        // wanted them.
                        let _ = connection.replenish_connection(len).await;
                        let _ = connection.flush().await;
                        if end_stream {
                            state.body_tx = None;
                            session.mark(stream_id, StreamEvent::RequestBodyEnd);
                        }
                    }
                    None => {
                        // §5.1: DATA on a stream that is not open. Replenish the connection window
                        // so one hostile stream cannot stall every other stream on the connection;
                        // there is no stream window left to credit.
                        let _ = connection.replenish_connection(len).await;
                        let _ = connection
                            .reset_stream(stream_id, error_code::STREAM_CLOSED)
                            .await;
                        let _ = connection.flush().await;
                    }
                }
            }
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                if let Some(state) = self.streams.remove(&stream_id)
                    && let Some(task) = state.handler
                {
                    task.abort();
                }
                // A cancellation is the peer saying the work is unwanted. Recorded rather than
                // swallowed: it is the difference between "the handler was slow" and "nobody was
                // waiting".
                session.mark(stream_id, StreamEvent::Failed { code: error_code });
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                if stream_id == 0 {
                    if let Err(error) = connection.apply_connection_window_update(increment) {
                        return Some(SessionEnd::Protocol(error, error_code::FLOW_CONTROL_ERROR));
                    }
                } else if let Some(state) = self.streams.get_mut(&stream_id) {
                    if increment == 0 {
                        return Some(SessionEnd::Protocol(
                            H2Error::Protocol("a zero WINDOW_UPDATE increment".into()),
                            error_code::PROTOCOL_ERROR,
                        ));
                    }
                    state.send_window += i64::from(increment);
                    if state.send_window > 0x7FFF_FFFF {
                        let _ = connection
                            .reset_stream(stream_id, error_code::FLOW_CONTROL_ERROR)
                            .await;
                        self.streams.remove(&stream_id);
                    }
                }
            }
            Frame::Settings {
                ack: false,
                settings,
            } => {
                if let Err(error) = connection.apply_peer_settings(&settings) {
                    return Some(SessionEnd::Protocol(error, error_code::PROTOCOL_ERROR));
                }
                if let Some(value) = settings
                    .iter()
                    .find(|(id, _)| *id == SETTING_INITIAL_WINDOW_SIZE)
                    .map(|(_, value)| *value as i64)
                {
                    // §6.5.2: the peer's INITIAL_WINDOW_SIZE change adjusts every open stream's
                    // send window by the delta, retroactively.
                    let delta = value - DEFAULT_WINDOW;
                    for state in self.streams.values_mut() {
                        state.send_window += delta;
                    }
                }
                if let Err(error) = connection
                    .write_frame(&Frame::Settings {
                        ack: true,
                        settings: Vec::new(),
                    })
                    .await
                {
                    return Some(SessionEnd::Protocol(error, error_code::INTERNAL_ERROR));
                }
                let _ = connection.flush().await;
            }
            Frame::GoAway {
                last_stream_id,
                error_code: code,
                ..
            } => {
                let _ = connection
                    .send_goaway(last_stream_id.min(self.highest), code, b"")
                    .await;
                return Some(SessionEnd::PeerGoAway(code));
            }
            other => {
                if let Err(error) = connection.handle_housekeeping(other).await {
                    return Some(SessionEnd::Protocol(error, error_code::PROTOCOL_ERROR));
                }
            }
        }

        self.reap(connection, session).await;
        self.flush_pending(connection, session).await
    }

    /// Act on a wake-up from a handler task.
    fn on_wake(&mut self, wake: Wake) {
        match wake {
            // Nothing to do here: the reap pass reads whatever finished.
            Wake::HandlerDone => {}
            Wake::Chunk(id, chunk) => self.outbound.push_back((id, chunk)),
            Wake::BodyEnd(id) => {
                if let Some(state) = self.streams.get_mut(&id) {
                    state.body_ending = true;
                }
            }
        }
    }

    /// Open a peer stream from its decoded header block.
    async fn open_stream<T, H>(
        &mut self,
        connection: &mut H2Connection<T>,
        session: &ServerSession<H>,
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        header_block: Bytes,
    ) -> Option<SessionEnd>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        H: H2Handler,
    {
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return Some(SessionEnd::Protocol(
                H2Error::Protocol("a client opened an even or zero stream id".into()),
                error_code::PROTOCOL_ERROR,
            ));
        }
        if stream_id <= self.highest && !self.streams.contains_key(&stream_id) {
            return Some(SessionEnd::Protocol(
                H2Error::Protocol("a stream id was reused or went backwards".into()),
                error_code::PROTOCOL_ERROR,
            ));
        }
        self.highest = self.highest.max(stream_id);

        let max = connection.local.max_concurrent_streams;
        if self.streams.len() as u32 >= max {
            // Over the advertised concurrency. Refusing the stream keeps the connection (and every
            // other live stream) alive — the only legal shed in HTTP/2.
            let _ = connection
                .reset_stream(stream_id, error_code::REFUSED_STREAM)
                .await;
            let _ = connection.flush().await;
            session.mark(
                stream_id,
                StreamEvent::Failed {
                    code: error_code::REFUSED_STREAM,
                },
            );
            return None;
        }

        let block = if end_headers {
            header_block
        } else {
            match connection.read_header_block(header_block).await {
                Ok(block) => block,
                Err(error) => {
                    return Some(SessionEnd::Protocol(error, error_code::COMPRESSION_ERROR));
                }
            }
        };

        let request = match decode_request(connection, stream_id, &block) {
            Ok(request) => request,
            Err(_) => {
                let _ = connection
                    .reset_stream(stream_id, error_code::PROTOCOL_ERROR)
                    .await;
                let _ = connection.flush().await;
                session.mark(
                    stream_id,
                    StreamEvent::Failed {
                        code: error_code::PROTOCOL_ERROR,
                    },
                );
                return None;
            }
        };
        session.mark(
            stream_id,
            StreamEvent::RequestHeadComplete {
                payload: block.len() as u32,
            },
        );

        let (body_tx, body_rx) = mpsc::channel(self.body_capacity);
        let request = H2Request {
            body: H2Body::new(body_rx),
            ..request
        };
        let wake_tx = self.wake_tx.clone();
        let handler = Arc::clone(&session.handler);
        let task = tokio::spawn(async move {
            // The wake-up is sent from a drop guard, not after the `await`, so it survives a
            // panicking handler. Without that, a handler bug would leave the session blocked in
            // `read_frame` believing a response is still coming — the peer would hang rather than
            // see the `500` the panic deserves.
            let _wake = WakeGuard {
                tx: wake_tx.clone(),
            };
            handler.handle(request).await
        });

        self.streams.insert(
            stream_id,
            StreamState {
                body_tx: if end_stream { None } else { Some(body_tx) },
                handler: Some(task),
                send_window: i64::from(connection.peer.initial_window_size),
                head_sent: false,
                body_ending: false,
                finished: false,
                recv_window: i64::from(connection.local.initial_window_size),
            },
        );
        if end_stream {
            session.mark(stream_id, StreamEvent::RequestBodyEnd);
        }
        None
    }

    /// Collect handler results whose future has completed, and write their heads.
    async fn reap<T, H>(&mut self, connection: &mut H2Connection<T>, session: &ServerSession<H>)
    where
        T: AsyncRead + AsyncWrite + Unpin,
        H: H2Handler,
    {
        loop {
            let ready = self
                .streams
                .iter()
                .find(|(_, state)| {
                    state
                        .handler
                        .as_ref()
                        .is_some_and(tokio::task::JoinHandle::is_finished)
                })
                .map(|(id, _)| *id);
            let Some(id) = ready else { break };
            let Some(state) = self.streams.get_mut(&id) else {
                break;
            };
            let Some(task) = state.handler.take() else {
                break;
            };
            let response = match task.await {
                Ok(response) => response,
                Err(_) => {
                    // A panicking handler is a 500 for that stream, not a dead connection: every
                    // other stream on this connection is still making progress.
                    session.mark(
                        id,
                        StreamEvent::Failed {
                            code: error_code::INTERNAL_ERROR,
                        },
                    );
                    H2Response::with_status(http::StatusCode::INTERNAL_SERVER_ERROR)
                }
            };
            session.mark(
                id,
                StreamEvent::HandlerEnd {
                    status: response.status.as_u16(),
                },
            );

            let (body, end_stream) = match response.body {
                H2ResponseBody::Empty => (BodySource::None, true),
                H2ResponseBody::Bytes(bytes) if bytes.is_empty() => (BodySource::None, true),
                H2ResponseBody::Bytes(bytes) => (BodySource::Buffered(bytes), false),
                H2ResponseBody::Stream(rx) => {
                    // Forward the handler's chunks into the session's own wake channel, so one
                    // await covers every streaming response on the connection.
                    let wake = self.wake_tx.clone();
                    tokio::spawn(async move {
                        let mut rx = rx;
                        while let Some(chunk) = rx.recv().await {
                            if wake.send(Wake::Chunk(id, chunk)).is_err() {
                                return;
                            }
                        }
                        let _ = wake.send(Wake::BodyEnd(id));
                    });
                    (BodySource::Streamed, false)
                }
            };

            if write_head(
                connection,
                id,
                response.status,
                &response.headers,
                end_stream,
            )
            .await
            .is_err()
            {
                // The transport is gone: the next read or write reports it, and the session ends
                // through the one choke point that sends `GOAWAY`.
                self.streams.remove(&id);
                continue;
            }
            session.mark(id, StreamEvent::ResponseHeadSent);

            let Some(state) = self.streams.get_mut(&id) else {
                continue;
            };
            state.head_sent = true;
            if end_stream {
                state.finished = true;
                session.mark(id, StreamEvent::ResponseEnd);
                self.streams.remove(&id);
                continue;
            }
            if let BodySource::Buffered(bytes) = body {
                let len = bytes.len() as u32;
                // A buffered body is one write; the terminator rides on it.
                self.outbound.push_back((id, bytes));
                if let Some(state) = self.streams.get_mut(&id) {
                    state.body_ending = true;
                }
                session.mark(id, StreamEvent::ResponseBodyChunk { payload: len });
            }
        }
    }

    /// Write whatever body chunks are owed, as far as the windows allow.
    ///
    /// One chunk per stream per pass, in id order: that is fair without a scheduler, and it keeps a
    /// stream that produces faster than the peer reads from starving the others.
    async fn flush_pending<T, H>(
        &mut self,
        connection: &mut H2Connection<T>,
        session: &ServerSession<H>,
    ) -> Option<SessionEnd>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        H: H2Handler,
    {
        loop {
            // Find the first queued chunk whose stream still has credit.
            let mut progress = false;
            let mut index = None;
            for (offset, (id, bytes)) in self.outbound.iter().enumerate() {
                let Some(state) = self.streams.get(id) else {
                    // The stream was reset: drop whatever it still owed.
                    index = Some((offset, false));
                    break;
                };
                if state.send_window > 0 || bytes.is_empty() {
                    index = Some((offset, true));
                    break;
                }
            }
            let Some((offset, sendable)) = index else {
                // Nothing queued, or nothing sendable until a WINDOW_UPDATE arrives.
                break;
            };
            let Some((id, bytes)) = self.outbound.remove(offset) else {
                // The queue changed between the scan and the removal; the next pass rescans.
                break;
            };
            if !sendable {
                continue;
            }
            let last = {
                let Some(state) = self.streams.get(&id) else {
                    continue;
                };
                state.body_ending && self.outbound.iter().all(|(other, _)| *other != id)
            };
            let window = self
                .streams
                .get(&id)
                .map(|state| state.send_window)
                .unwrap_or(0);
            match connection.write_data(id, &bytes, last, window).await {
                Ok(window) => {
                    progress = true;
                    if let Some(state) = self.streams.get_mut(&id) {
                        state.send_window = window;
                        if !bytes.is_empty() {
                            session.mark(
                                id,
                                StreamEvent::ResponseBodyChunk {
                                    payload: bytes.len() as u32,
                                },
                            );
                        }
                        if last {
                            state.finished = true;
                            session.mark(id, StreamEvent::ResponseEnd);
                        }
                    }
                    if last {
                        self.streams.remove(&id);
                    }
                }
                Err(H2Error::StreamReset { .. }) => {
                    self.streams.remove(&id);
                }
                Err(error) => {
                    return Some(SessionEnd::Protocol(error, error_code::INTERNAL_ERROR));
                }
            }
            if !progress {
                break;
            }
        }

        // A stream whose body channel closed and whose queue drained still owes a terminator when
        // the final chunk was non-empty; `write_data` sends it on the last chunk above, so the only
        // case left is a body that produced nothing at all.
        let empty_ended: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, state)| state.head_sent && state.body_ending && !state.finished)
            .filter(|(id, _)| !self.outbound.iter().any(|(other, _)| other == *id))
            .map(|(id, _)| *id)
            .collect();
        for id in empty_ended {
            let window = self
                .streams
                .get(&id)
                .map(|state| state.send_window)
                .unwrap_or(0);
            match connection.write_data(id, b"", true, window).await {
                Ok(_) => {
                    session.mark(id, StreamEvent::ResponseEnd);
                    self.streams.remove(&id);
                }
                Err(H2Error::StreamReset { .. }) => {
                    self.streams.remove(&id);
                }
                Err(error) => {
                    return Some(SessionEnd::Protocol(error, error_code::INTERNAL_ERROR));
                }
            }
        }

        if let Err(error) = connection.flush().await {
            return Some(SessionEnd::Protocol(error, error_code::INTERNAL_ERROR));
        }
        None
    }

    /// Finish every stream that is already under way, then send `GOAWAY`.
    ///
    /// A drain is *not* an abort. `GOAWAY` tells the peer which streams will complete, and a stream
    /// below that id must still be answered — a server that announced a stream and then closed it
    /// would be worse than one that never accepted it, because the client has already committed to
    /// waiting. So this collects the handlers that finish (bounded by the caller's deadline, which is
    /// `drain_timeout`), writes their responses as far as the window allows, and only then announces.
    ///
    /// A handler still running at the deadline is cancelled and reported, which is the honest outcome:
    /// its stream is one the peer will see closed without a response, and the trace says why.
    async fn drain<T, H>(&mut self, connection: &mut H2Connection<T>, session: &ServerSession<H>)
    where
        T: AsyncRead + AsyncWrite + Unpin,
        H: H2Handler,
    {
        // Let every in-flight handler run to completion. The caller bounds this with `drain_timeout`
        // by aborting the task, so an unbounded wait cannot happen here; but a handler that has
        // already finished is written *now* rather than abandoned.
        while self.streams.values().any(|state| state.handler.is_some()) {
            self.reap(connection, session).await;
            if let Some(end) = self.flush_pending(connection, session).await {
                let _ = end;
                break;
            }
            if !self.streams.values().any(|state| state.handler.is_some()) {
                break;
            }
            // Wake on whichever handler finishes next, so a drain does not spin.
            if self.wake_rx.recv().await.is_none() {
                break;
            }
        }

        self.reap(connection, session).await;
        let _ = self.flush_pending(connection, session).await;

        // Whatever is still open at this point had no response to write. Report it as cancelled rather
        // than closing silently over it.
        for (id, state) in self.streams.iter() {
            if !state.finished {
                session.mark(
                    *id,
                    StreamEvent::Failed {
                        code: error_code::CANCEL,
                    },
                );
            }
        }

        let _ = connection
            .send_goaway(self.highest, error_code::NO_ERROR, b"draining")
            .await;
    }
}

/// What a response's body is, once its head has been written.
enum BodySource {
    /// No body.
    None,
    /// One buffer, already known.
    Buffered(Bytes),
    /// Chunks arrive through the wake channel.
    Streamed,
}

/// Write one response head, dropping the headers HTTP/2 forbids.
async fn write_head<T>(
    connection: &mut H2Connection<T>,
    stream_id: u32,
    status: http::StatusCode,
    headers: &http::HeaderMap,
    end_stream: bool,
) -> Result<(), H2Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut fields: Vec<(String, String)> = Vec::with_capacity(headers.len() + 1);
    fields.push((":status".to_owned(), status.as_str().to_owned()));
    for (name, value) in headers {
        // A connection-specific header has no meaning in HTTP/2 (§8.2.2) and a peer must reject a
        // message that carries one, so they are dropped rather than forwarded.
        if is_connection_specific(name.as_str()) {
            continue;
        }
        let Ok(value) = value.to_str() else { continue };
        fields.push((name.as_str().to_owned(), value.to_owned()));
    }
    let block = connection.encode_header_block(
        fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    connection
        .write_header_block(stream_id, &block, end_stream)
        .await
}

/// Whether a header is connection-specific and therefore illegal in HTTP/2 (§8.2.2).
fn is_connection_specific(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

/// Turn a decoded header list into a request, refusing the shapes RFC 9113 §8.3 forbids.
fn decode_request<T>(
    connection: &mut H2Connection<T>,
    stream_id: u32,
    block: &Bytes,
) -> Result<H2Request, H2Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let fields = connection.decoder().decode(block)?;
    let mut method: Option<String> = None;
    let mut scheme = String::new();
    let mut authority = String::new();
    let mut path: Option<Bytes> = None;
    let mut headers = http::HeaderMap::new();
    let mut saw_regular = false;

    for (name, value) in fields {
        if let Some(pseudo) = name.strip_prefix(':') {
            // §8.3.1: pseudo-headers must precede regular fields, because a decoder that allowed
            // them after would accept a request whose meaning depends on field order.
            if saw_regular {
                return Err(H2Error::Protocol(
                    "a pseudo-header followed a regular header field".into(),
                ));
            }
            match pseudo {
                "method" => method = Some(value),
                "scheme" => scheme = value,
                "authority" => authority = value,
                "path" => path = Some(Bytes::from(value.into_bytes())),
                other => {
                    return Err(H2Error::Protocol(format!(
                        "unknown pseudo-header `:{other}` in a request"
                    )));
                }
            }
            continue;
        }
        saw_regular = true;
        if is_connection_specific(&name) {
            return Err(H2Error::Protocol(format!(
                "HTTP/2 forbids the connection-specific header `{name}`"
            )));
        }
        // A field name that is not a token cannot be represented at all; refusing it keeps the
        // `HeaderMap` from silently dropping a header the peer believes it sent.
        let Ok(name) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
            return Err(H2Error::Protocol(format!(
                "invalid header field name `{name}`"
            )));
        };
        let Ok(value) = http::header::HeaderValue::from_str(&value) else {
            return Err(H2Error::Protocol("invalid header field value".into()));
        };
        headers.append(name, value);
    }

    let method = method.ok_or_else(|| H2Error::Protocol("a request has no :method".into()))?;
    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|_| H2Error::Protocol("invalid :method".into()))?;
    let path = match path {
        Some(path) => path,
        // §8.3.1: `CONNECT` omits `:scheme` and `:path`; every other method requires `:path`.
        None if method == http::Method::CONNECT => Bytes::new(),
        None => return Err(H2Error::Protocol("a request has no :path".into())),
    };
    if method != http::Method::CONNECT && path.is_empty() {
        return Err(H2Error::Protocol("an empty :path".into()));
    }
    // §8.3.1: every request *except* `CONNECT` carries `:scheme` and `:authority`. A request without
    // them cannot be routed at all, and a proxy that filled them in from the connection would be
    // inventing an origin the peer never named.
    if method != http::Method::CONNECT && (scheme.is_empty() || authority.is_empty()) {
        return Err(H2Error::Protocol(
            "a request must carry :scheme and :authority".into(),
        ));
    }
    // Synthesise `host` from `:authority` so one handler reads one field for both protocols.
    if !authority.is_empty()
        && !headers.contains_key(http::header::HOST)
        && let Ok(value) = http::header::HeaderValue::from_str(&authority)
    {
        headers.insert(http::header::HOST, value);
    }

    Ok(H2Request {
        stream_id,
        method,
        path,
        authority,
        scheme,
        headers,
        body: H2Body::empty(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_specific_header_is_never_forwarded() {
        for name in [
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
        ] {
            assert!(is_connection_specific(name), "{name} must not be forwarded");
        }
        assert!(!is_connection_specific("content-type"));
    }

    #[test]
    fn an_absolute_target_is_rebuilt_for_an_http11_shaped_handler() {
        let request = H2Request {
            stream_id: 1,
            method: http::Method::GET,
            path: Bytes::from_static(b"/v1/models?x=1"),
            authority: "example.com".to_owned(),
            scheme: "https".to_owned(),
            headers: http::HeaderMap::new(),
            body: H2Body::empty(),
        };
        assert_eq!(
            &request.absolute_target()[..],
            b"https://example.com/v1/models?x=1",
            "the path bytes are untouched"
        );
    }

    #[tokio::test]
    async fn a_complete_body_is_delivered_then_end() {
        let mut body = H2Body::complete(Bytes::from_static(b"hello"));
        assert_eq!(body.next_chunk().await.expect("chunk").as_ref(), b"hello");
        assert!(body.next_chunk().await.is_none());
        assert!(body.is_finished());
        assert_eq!(body.bytes_read(), 5);
    }

    #[tokio::test]
    async fn an_empty_body_ends_immediately() {
        let mut body = H2Body::empty();
        assert!(body.next_chunk().await.is_none());
        assert!(body.is_finished());
    }
}
