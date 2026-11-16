//! Multiplexed HTTP/2 client session and background connection driver (RFC 9113).
//!
//! One background task owns the [`H2Connection`] exclusively so multiple
//! concurrent request streams share a single TCP/TLS socket without
//! frame-interleaving corruption, while idle housekeeping (`PING`, `SETTINGS`,
//! `WINDOW_UPDATE`, `GOAWAY`) runs continuously even when no streams are open.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc, oneshot};

use crate::client::{
    H2ClientConnection, H2ResponseEvent, H2ResponseHead, REPLENISH_THRESHOLD,
    encode_request_headers, split_response,
};
use crate::connection::{H2Connection, error_code};
use crate::error::H2Error;
use crate::fingerprint::{H2ConnectionProfile, H2RequestProfile};
use crate::frame::Frame;

const OUTBOUND_CHUNK_CREDITS: usize = 8;
const MAX_RECENTLY_RESET: usize = 1024;

/// Shared atomic view of connection health and stream concurrency.
#[derive(Debug)]
struct SessionView {
    closed: AtomicBool,
    goaway: AtomicBool,
    active_streams: AtomicUsize,
    max_concurrent_streams: AtomicU32,
    created: Instant,
    idle_since_ms: AtomicU64,
}

impl SessionView {
    fn new(max_concurrent_streams: u32) -> Self {
        Self {
            closed: AtomicBool::new(false),
            goaway: AtomicBool::new(false),
            active_streams: AtomicUsize::new(0),
            max_concurrent_streams: AtomicU32::new(max_concurrent_streams),
            created: Instant::now(),
            idle_since_ms: AtomicU64::new(0),
        }
    }

    fn is_usable(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && !self.goaway.load(Ordering::Acquire)
    }
}

/// RAII reservation of one concurrent stream slot on an [`H2ClientSession`].
///
/// Prevents concurrent callers from racing past the peer's
/// `SETTINGS_MAX_CONCURRENT_STREAMS`. Decrements `active_streams` on drop.
#[derive(Debug)]
pub struct H2StreamPermit {
    view: Arc<SessionView>,
}

impl Drop for H2StreamPermit {
    fn drop(&mut self) {
        if self.view.active_streams.fetch_sub(1, Ordering::AcqRel) == 1 {
            let ms = u64::try_from(self.view.created.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.view.idle_since_ms.store(ms, Ordering::Release);
        }
    }
}

/// A cloneable, thread-safe handle onto a multiplexed HTTP/2 client connection.
#[derive(Clone, Debug)]
pub struct H2ClientSession {
    cmd_tx: mpsc::UnboundedSender<ClientCmd>,
    view: Arc<SessionView>,
    connection_profile: H2ConnectionProfile,
    request_profile: H2RequestProfile,
}

impl H2ClientSession {
    /// Spawn the background driver task taking ownership of `connection`.
    pub fn spawn<T>(connection: H2ClientConnection<T>) -> Self
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let connection_profile = connection.connection_profile().clone();
        let request_profile = *connection.request_profile();
        let max_streams = connection
            .connection
            .peer_max_concurrent_streams()
            .unwrap_or(u32::MAX);
        let view = Arc::new(SessionView::new(max_streams));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        tokio::spawn(drive_client(connection, Arc::clone(&view), cmd_rx));
        Self {
            cmd_tx,
            view,
            connection_profile,
            request_profile,
        }
    }

    /// The connection-fixed half of the fingerprint in force.
    pub const fn connection_profile(&self) -> &H2ConnectionProfile {
        &self.connection_profile
    }

    /// The default request-fixed half of the fingerprint for this connection.
    pub const fn request_profile(&self) -> &H2RequestProfile {
        &self.request_profile
    }

    /// Whether the session can still open new streams (alive and no `GOAWAY`).
    pub fn is_usable(&self) -> bool {
        self.view.is_usable() && !self.cmd_tx.is_closed()
    }

    /// Currently active (open) request streams on this connection.
    pub fn active_streams(&self) -> usize {
        self.view.active_streams.load(Ordering::Acquire)
    }

    /// Elapsed time since this session last had zero active streams (`None` if
    /// one or more streams are currently active).
    pub fn idle_duration(&self) -> Option<Duration> {
        if self.active_streams() > 0 {
            return None;
        }
        let since_ms = self.view.idle_since_ms.load(Ordering::Acquire);
        let now_ms = u64::try_from(self.view.created.elapsed().as_millis()).unwrap_or(u64::MAX);
        Some(Duration::from_millis(now_ms.saturating_sub(since_ms)))
    }

    /// Peer's advertised `SETTINGS_MAX_CONCURRENT_STREAMS` (or `u32::MAX`).
    pub fn max_concurrent_streams(&self) -> u32 {
        self.view.max_concurrent_streams.load(Ordering::Acquire)
    }

    /// Atomically reserve one stream slot if the session is usable and below
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    pub fn try_reserve_stream(&self) -> Option<H2StreamPermit> {
        if !self.is_usable() {
            return None;
        }
        loop {
            let max = self.view.max_concurrent_streams.load(Ordering::Acquire) as usize;
            let current = self.view.active_streams.load(Ordering::Acquire);
            if current >= max || !self.is_usable() {
                return None;
            }
            if self
                .view
                .active_streams
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(H2StreamPermit {
                    view: Arc::clone(&self.view),
                });
            }
        }
    }

    /// Open a new HTTP/2 stream, writing its request `HEADERS` (and optional
    /// buffered body) through the connection driver.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_request(
        &self,
        permit: Option<H2StreamPermit>,
        method: &str,
        authority: &str,
        scheme: &str,
        path: &str,
        extra_headers: &[(String, String)],
        initial_body: Option<Bytes>,
        streaming_body: bool,
        request_profile: &H2RequestProfile,
    ) -> Result<(Option<H2RequestSender>, H2HeadFuture, H2StreamReader), H2Error> {
        let permit = match permit {
            Some(permit) => permit,
            None => self.try_reserve_stream().ok_or_else(|| {
                H2Error::Protocol("HTTP/2 connection cannot accept another stream".into())
            })?,
        };
        let (opened_tx, opened_rx) = oneshot::channel();
        let (head_tx, head_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();
        let outbound_permits = Arc::new(Semaphore::new(OUTBOUND_CHUNK_CREDITS));

        let cmd = ClientCmd::OpenRequest(Box::new(OpenRequestCmd {
            permit,
            method: method.to_owned(),
            authority: authority.to_owned(),
            scheme: scheme.to_owned(),
            path: path.to_owned(),
            extra_headers: extra_headers.to_vec(),
            initial_body,
            streaming_body,
            request_profile: *request_profile,
            outbound_permits: Arc::clone(&outbound_permits),
            head_tx,
            body_tx,
            opened_tx,
        }));

        self.cmd_tx.send(cmd).map_err(|_| H2Error::UnexpectedEof)?;

        let stream_id = opened_rx.await.map_err(|_| H2Error::UnexpectedEof)??;

        let sender = streaming_body.then(|| H2RequestSender {
            stream_id,
            cmd_tx: self.cmd_tx.clone(),
            permits: outbound_permits,
            finished: false,
        });
        let reader = H2StreamReader {
            stream_id,
            body_rx,
            cmd_tx: self.cmd_tx.clone(),
            finished: false,
            cancelled: false,
        };
        Ok((sender, H2HeadFuture { rx: head_rx }, reader))
    }
}

/// Future resolving to the final response head of a stream.
pub struct H2HeadFuture {
    rx: oneshot::Receiver<Result<H2ResponseHead, H2Error>>,
}

impl H2HeadFuture {
    /// Wait for the stream's response head.
    pub async fn await_head(self) -> Result<H2ResponseHead, H2Error> {
        self.rx.await.map_err(|_| H2Error::UnexpectedEof)?
    }
}

/// Streaming request-body writer for one open HTTP/2 stream.
///
/// Dropping without calling [`Self::finish`] cancels the stream with
/// `RST_STREAM(CANCEL)` so the peer never waits on an aborted upload.
pub struct H2RequestSender {
    stream_id: u32,
    cmd_tx: mpsc::UnboundedSender<ClientCmd>,
    permits: Arc<Semaphore>,
    finished: bool,
}

impl H2RequestSender {
    /// Send the next body chunk, waiting on outbound queue backpressure.
    pub async fn send_data(&mut self, chunk: Bytes) -> Result<(), H2Error> {
        if self.finished {
            return Err(H2Error::Protocol(
                "HTTP/2 request body chunk sent after finish".into(),
            ));
        }
        if chunk.is_empty() {
            return Ok(());
        }
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| H2Error::UnexpectedEof)?;
        self.cmd_tx
            .send(ClientCmd::SendData {
                stream_id: self.stream_id,
                chunk,
                _permit: permit,
            })
            .map_err(|_| H2Error::UnexpectedEof)
    }

    /// Finish the request body (`END_STREAM`).
    pub fn finish(mut self) -> Result<(), H2Error> {
        self.finished = true;
        self.cmd_tx
            .send(ClientCmd::EndSend {
                stream_id: self.stream_id,
            })
            .map_err(|_| H2Error::UnexpectedEof)
    }
}

impl Drop for H2RequestSender {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cmd_tx.send(ClientCmd::CancelStream {
                stream_id: self.stream_id,
            });
        }
    }
}

/// Streaming response-body reader for one HTTP/2 stream.
///
/// Dropping before reading the stream to completion cancels *only* this stream
/// via `RST_STREAM(CANCEL)`, leaving the underlying HTTP/2 connection alive for
/// sibling and subsequent requests.
pub struct H2StreamReader {
    stream_id: u32,
    body_rx: mpsc::UnboundedReceiver<Result<H2ResponseEvent, H2Error>>,
    cmd_tx: mpsc::UnboundedSender<ClientCmd>,
    finished: bool,
    cancelled: bool,
}

impl H2StreamReader {
    /// The HTTP/2 stream id.
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Mark the body finished immediately when the response head had `end_stream`.
    pub fn mark_empty(&mut self) {
        self.finished = true;
    }

    /// Read the next response body event, returning flow-control credit as
    /// payload bytes are consumed.
    pub async fn next_event(&mut self) -> Result<H2ResponseEvent, H2Error> {
        if self.finished {
            return Ok(H2ResponseEvent::End);
        }
        let Some(item) = self.body_rx.recv().await else {
            self.finished = true;
            return Ok(H2ResponseEvent::End);
        };
        match item {
            Ok(H2ResponseEvent::Data {
                payload,
                end_stream,
            }) => {
                if end_stream {
                    self.finished = true;
                }
                let _ = self.cmd_tx.send(ClientCmd::Consumed {
                    stream_id: self.stream_id,
                    bytes: payload.len() as u32,
                    end_stream,
                });
                Ok(H2ResponseEvent::Data {
                    payload,
                    end_stream,
                })
            }
            Ok(H2ResponseEvent::Trailers(fields)) => {
                self.finished = true;
                let _ = self.cmd_tx.send(ClientCmd::Consumed {
                    stream_id: self.stream_id,
                    bytes: 0,
                    end_stream: true,
                });
                Ok(H2ResponseEvent::Trailers(fields))
            }
            Ok(H2ResponseEvent::End) => {
                self.finished = true;
                let _ = self.cmd_tx.send(ClientCmd::Consumed {
                    stream_id: self.stream_id,
                    bytes: 0,
                    end_stream: true,
                });
                Ok(H2ResponseEvent::End)
            }
            Err(error) => {
                self.finished = true;
                Err(error)
            }
        }
    }

    /// Explicitly cancel or finish consumption without keeping the stream open.
    pub fn release(mut self, complete: bool) {
        if complete {
            self.finished = true;
        } else if !self.finished && !self.cancelled {
            self.cancelled = true;
            let _ = self.cmd_tx.send(ClientCmd::CancelStream {
                stream_id: self.stream_id,
            });
        }
    }
}

impl Drop for H2StreamReader {
    fn drop(&mut self) {
        if !self.finished && !self.cancelled {
            self.cancelled = true;
            let _ = self.cmd_tx.send(ClientCmd::CancelStream {
                stream_id: self.stream_id,
            });
        }
    }
}

struct OpenRequestCmd {
    permit: H2StreamPermit,
    method: String,
    authority: String,
    scheme: String,
    path: String,
    extra_headers: Vec<(String, String)>,
    initial_body: Option<Bytes>,
    streaming_body: bool,
    request_profile: H2RequestProfile,
    outbound_permits: Arc<Semaphore>,
    head_tx: oneshot::Sender<Result<H2ResponseHead, H2Error>>,
    body_tx: mpsc::UnboundedSender<Result<H2ResponseEvent, H2Error>>,
    opened_tx: oneshot::Sender<Result<u32, H2Error>>,
}

enum ClientCmd {
    OpenRequest(Box<OpenRequestCmd>),
    SendData {
        stream_id: u32,
        chunk: Bytes,
        _permit: tokio::sync::OwnedSemaphorePermit,
    },
    EndSend {
        stream_id: u32,
    },
    Consumed {
        stream_id: u32,
        bytes: u32,
        end_stream: bool,
    },
    CancelStream {
        stream_id: u32,
    },
}

struct PendingHeaderBlock {
    stream_id: u32,
    end_stream: bool,
    block: BytesMut,
}

struct ActiveStream {
    head_tx: Option<oneshot::Sender<Result<H2ResponseHead, H2Error>>>,
    body_tx: mpsc::UnboundedSender<Result<H2ResponseEvent, H2Error>>,
    send_window: i64,
    outbound: VecDeque<(Bytes, Option<tokio::sync::OwnedSemaphorePermit>)>,
    send_ended: bool,
    end_stream_written: bool,
    outbound_permits: Arc<Semaphore>,
    recv_window: i64,
    unacked_recv: u32,
    buffered_unread: u32,
    head_received: bool,
    peer_closed: bool,
    permit: Option<H2StreamPermit>,
}

impl ActiveStream {
    fn release_if_wire_closed(&mut self) {
        if self.peer_closed && self.end_stream_written {
            self.permit.take();
        }
    }
}

struct DriverState {
    streams: HashMap<u32, ActiveStream>,
    outbound_order: VecDeque<u32>,
    recently_reset: HashSet<u32>,
    recently_reset_order: VecDeque<u32>,
    pending_headers: Option<PendingHeaderBlock>,
}

impl DriverState {
    fn new() -> Self {
        Self {
            streams: HashMap::new(),
            outbound_order: VecDeque::new(),
            recently_reset: HashSet::new(),
            recently_reset_order: VecDeque::new(),
            pending_headers: None,
        }
    }

    fn mark_recently_reset(&mut self, stream_id: u32) {
        if self.recently_reset.insert(stream_id) {
            self.recently_reset_order.push_back(stream_id);
            while self.recently_reset_order.len() > MAX_RECENTLY_RESET {
                if let Some(oldest) = self.recently_reset_order.pop_front() {
                    self.recently_reset.remove(&oldest);
                }
            }
        }
    }

    fn queue_outbound(&mut self, stream_id: u32) {
        if !self.outbound_order.contains(&stream_id) {
            self.outbound_order.push_back(stream_id);
        }
    }

    fn fail_stream(&mut self, stream_id: u32, error: H2Error) {
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            stream.outbound_permits.close();
            let head_tx = stream.head_tx.take();
            let body_tx = stream.body_tx.clone();
            drop(stream);
            if let Some(head_tx) = head_tx {
                let _ = head_tx.send(Err(error));
            } else {
                let _ = body_tx.send(Err(error));
            }
        }
    }

    fn fail_all(&mut self, error: &H2Error) {
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            let cloned = clone_h2_error(error);
            self.fail_stream(id, cloned);
        }
    }
}

fn clone_h2_error(error: &H2Error) -> H2Error {
    match error {
        H2Error::Io(io_err) => H2Error::Io(std::io::Error::new(io_err.kind(), io_err.to_string())),
        H2Error::UnexpectedEof => H2Error::UnexpectedEof,
        H2Error::Protocol(msg) => H2Error::Protocol(msg.clone()),
        H2Error::FrameSize(msg) => H2Error::FrameSize(msg.clone()),
        H2Error::Hpack(err) => H2Error::Protocol(err.to_string()),
        H2Error::StreamReset {
            stream_id,
            error_code,
        } => H2Error::StreamReset {
            stream_id: *stream_id,
            error_code: *error_code,
        },
        H2Error::GoAway {
            error_code,
            debug_data,
        } => H2Error::GoAway {
            error_code: *error_code,
            debug_data: debug_data.clone(),
        },
    }
}

async fn drive_client<T: AsyncRead + AsyncWrite + Send + Unpin>(
    mut client: H2ClientConnection<T>,
    view: Arc<SessionView>,
    mut cmd_rx: mpsc::UnboundedReceiver<ClientCmd>,
) {
    let mut state = DriverState::new();
    let mut cmds_closed = false;

    loop {
        if let Err(error) = flush_outbound(&mut client.connection, &mut state).await {
            view.closed.store(true, Ordering::Release);
            state.fail_all(&error);
            break;
        }

        if client.connection.goaway_last_stream().is_some() && state.streams.is_empty() {
            view.closed.store(true, Ordering::Release);
            break;
        }

        tokio::select! {
            biased;
            cmd = cmd_rx.recv(), if !cmds_closed => {
                match cmd {
                    Some(first) => {
                        if let Err(error) = handle_cmd(first, &mut client, &view, &mut state).await {
                            view.closed.store(true, Ordering::Release);
                            state.fail_all(&error);
                            break;
                        }
                        while let Ok(more) = cmd_rx.try_recv() {
                            if let Err(error) = handle_cmd(more, &mut client, &view, &mut state).await {
                                view.closed.store(true, Ordering::Release);
                                state.fail_all(&error);
                                return;
                            }
                        }
                    }
                    None => {
                        // All session handles and active stream readers/writers were dropped.
                        cmds_closed = true;
                        if state.streams.is_empty() {
                            view.closed.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
            }
            frame = client.connection.read_frame() => {
                match frame {
                    Ok(frame) => {
                        if let Err(error) = handle_frame(frame, &mut client.connection, &view, &mut state).await {
                            view.closed.store(true, Ordering::Release);
                            state.fail_all(&error);
                            break;
                        }
                    }
                    Err(error) => {
                        view.closed.store(true, Ordering::Release);
                        state.fail_all(&error);
                        break;
                    }
                }
            }
        }
    }

    view.closed.store(true, Ordering::Release);
}

async fn handle_cmd<T: AsyncRead + AsyncWrite + Unpin>(
    cmd: ClientCmd,
    client: &mut H2ClientConnection<T>,
    view: &SessionView,
    state: &mut DriverState,
) -> Result<(), H2Error> {
    match cmd {
        ClientCmd::OpenRequest(req) => {
            let OpenRequestCmd {
                permit,
                method,
                authority,
                scheme,
                path,
                extra_headers,
                initial_body,
                streaming_body,
                request_profile,
                outbound_permits,
                head_tx,
                body_tx,
                opened_tx,
            } = *req;
            if !view.is_usable() {
                let _ = opened_tx.send(Err(H2Error::GoAway {
                    error_code: error_code::NO_ERROR,
                    debug_data: Vec::new(),
                }));
                return Ok(());
            }
            let Some(stream_id) = client.connection.allocate_stream_id() else {
                let _ = opened_tx.send(Err(H2Error::Protocol(
                    "no stream id remains on this connection".into(),
                )));
                return Ok(());
            };

            let block = encode_request_headers(
                &mut client.connection,
                &method,
                &authority,
                &scheme,
                &path,
                &extra_headers,
                &request_profile,
                client.header_order_seed,
                stream_id,
            );
            let has_initial = initial_body.as_ref().is_some_and(|b| !b.is_empty());
            let end_on_headers = !has_initial && !streaming_body;

            client
                .connection
                .write_header_block(stream_id, &block, end_on_headers)
                .await?;
            client.connection.flush().await?;

            let mut outbound = VecDeque::new();
            if let Some(body) = initial_body
                && !body.is_empty()
            {
                outbound.push_back((body, None));
            }

            let stream = ActiveStream {
                head_tx: Some(head_tx),
                body_tx,
                send_window: i64::from(client.connection.peer.initial_window_size),
                outbound,
                send_ended: !streaming_body,
                end_stream_written: end_on_headers,
                outbound_permits,
                recv_window: i64::from(client.connection.local.initial_window_size),
                unacked_recv: 0,
                buffered_unread: 0,
                head_received: false,
                peer_closed: false,
                permit: Some(permit),
            };
            state.streams.insert(stream_id, stream);
            if has_initial {
                state.queue_outbound(stream_id);
            }
            let _ = opened_tx.send(Ok(stream_id));
        }
        ClientCmd::SendData {
            stream_id,
            chunk,
            _permit,
        } => {
            if let Some(stream) = state.streams.get_mut(&stream_id)
                && !stream.send_ended
            {
                stream.outbound.push_back((chunk, Some(_permit)));
                state.queue_outbound(stream_id);
            }
        }
        ClientCmd::EndSend { stream_id } => {
            if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.send_ended = true;
                if !stream.end_stream_written {
                    state.queue_outbound(stream_id);
                }
            }
        }
        ClientCmd::Consumed {
            stream_id,
            bytes,
            end_stream,
        } => {
            if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.buffered_unread = stream.buffered_unread.saturating_sub(bytes);
                stream.unacked_recv = stream.unacked_recv.saturating_add(bytes);
                if stream.unacked_recv >= REPLENISH_THRESHOLD || end_stream {
                    let credit = std::mem::take(&mut stream.unacked_recv);
                    if credit > 0 {
                        stream.recv_window += i64::from(credit);
                        if end_stream {
                            if client
                                .connection
                                .replenish_connection(credit)
                                .await
                                .is_err()
                                || client.connection.flush().await.is_err()
                            {
                                client.unusable = true;
                            }
                        } else {
                            client.connection.replenish(stream_id, credit).await?;
                            client.connection.replenish_connection(credit).await?;
                            client.connection.flush().await?;
                        }
                    }
                }
                if end_stream && stream.peer_closed && stream.end_stream_written {
                    state.streams.remove(&stream_id);
                }
            }
        }
        ClientCmd::CancelStream { stream_id } => {
            if let Some(stream) = state.streams.remove(&stream_id) {
                stream.outbound_permits.close();
                let credit = stream.buffered_unread.saturating_add(stream.unacked_recv);
                if credit > 0 {
                    let _ = client.connection.replenish_connection(credit).await;
                }
                if !stream.peer_closed || !stream.end_stream_written {
                    let _ = client
                        .connection
                        .reset_stream(stream_id, error_code::CANCEL)
                        .await;
                    let _ = client.connection.flush().await;
                    if !stream.peer_closed {
                        state.mark_recently_reset(stream_id);
                    }
                } else if credit > 0 {
                    let _ = client.connection.flush().await;
                }
            }
        }
    }
    Ok(())
}

async fn flush_outbound<T: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut H2Connection<T>,
    state: &mut DriverState,
) -> Result<(), H2Error> {
    let mut wrote = false;
    let max_frame = connection.peer.max_frame_size as usize;
    let count = state.outbound_order.len();
    let mut deferred = VecDeque::new();

    for _ in 0..count {
        let Some(stream_id) = state.outbound_order.pop_front() else {
            break;
        };
        let Some(stream) = state.streams.get_mut(&stream_id) else {
            continue;
        };

        if stream.end_stream_written {
            continue;
        }

        if stream.outbound.is_empty() && stream.send_ended {
            connection
                .write_frame(&Frame::Data {
                    stream_id,
                    end_stream: true,
                    payload: Bytes::new(),
                })
                .await?;
            stream.end_stream_written = true;
            stream.release_if_wire_closed();
            wrote = true;
            if stream.peer_closed && stream.buffered_unread == 0 && stream.unacked_recv == 0 {
                state.streams.remove(&stream_id);
            }
            continue;
        }

        while let Some((front, permit)) = stream.outbound.pop_front() {
            if front.is_empty() {
                drop(permit);
                continue;
            }
            if connection.connection_send_window <= 0 || stream.send_window <= 0 {
                stream.outbound.push_front((front, permit));
                deferred.push_back(stream_id);
                break;
            }
            let allowed = usize::try_from(connection.connection_send_window)
                .unwrap_or(usize::MAX)
                .min(usize::try_from(stream.send_window).unwrap_or(usize::MAX))
                .min(max_frame);
            if allowed == 0 {
                stream.outbound.push_front((front, permit));
                deferred.push_back(stream_id);
                break;
            }
            let take = front.len().min(allowed);
            let chunk = front.slice(..take);
            let rest = front.slice(take..);
            let is_last_of_chunk = rest.is_empty();
            let is_final = is_last_of_chunk && stream.outbound.is_empty() && stream.send_ended;

            connection
                .write_frame(&Frame::Data {
                    stream_id,
                    end_stream: is_final,
                    payload: chunk,
                })
                .await?;
            connection.connection_send_window -= take as i64;
            stream.send_window -= take as i64;
            wrote = true;

            if is_last_of_chunk {
                drop(permit);
            } else {
                stream.outbound.push_front((rest, permit));
                // Yield to sibling streams if we hit frame/window granularity.
                deferred.push_back(stream_id);
                break;
            }

            if is_final {
                stream.end_stream_written = true;
                stream.release_if_wire_closed();
                if stream.peer_closed && stream.buffered_unread == 0 && stream.unacked_recv == 0 {
                    state.streams.remove(&stream_id);
                }
                break;
            }
        }
    }

    while let Some(id) = deferred.pop_front() {
        state.queue_outbound(id);
    }

    if wrote {
        connection.flush().await?;
    }
    Ok(())
}

async fn handle_frame<T: AsyncRead + AsyncWrite + Unpin>(
    frame: Frame,
    connection: &mut H2Connection<T>,
    view: &SessionView,
    state: &mut DriverState,
) -> Result<(), H2Error> {
    if let Some(pending) = state.pending_headers.take() {
        match frame {
            Frame::Continuation {
                stream_id,
                end_headers,
                header_block,
            } if stream_id == pending.stream_id => {
                let mut block = pending.block;
                block.extend_from_slice(&header_block);
                let limit = connection.local.max_header_list_size as usize;
                if block.len() > limit {
                    return Err(H2Error::Protocol(format!(
                        "a header block of at least {} bytes exceeds the advertised {limit} byte limit",
                        block.len()
                    )));
                }
                if end_headers {
                    finish_header_block(
                        connection,
                        state,
                        stream_id,
                        pending.end_stream,
                        block.freeze(),
                    )
                    .await?;
                } else {
                    state.pending_headers = Some(PendingHeaderBlock {
                        stream_id,
                        end_stream: pending.end_stream,
                        block,
                    });
                }
                return Ok(());
            }
            other => {
                return Err(H2Error::Protocol(format!(
                    "expected CONTINUATION inside a header block, got {other:?}"
                )));
            }
        }
    }

    match frame {
        Frame::Headers {
            stream_id,
            end_stream,
            end_headers,
            header_block,
        } => {
            let limit = connection.local.max_header_list_size as usize;
            if header_block.len() > limit {
                return Err(H2Error::Protocol(format!(
                    "a header block of at least {} bytes exceeds the advertised {limit} byte limit",
                    header_block.len()
                )));
            }
            if end_headers {
                finish_header_block(connection, state, stream_id, end_stream, header_block).await?;
            } else {
                state.pending_headers = Some(PendingHeaderBlock {
                    stream_id,
                    end_stream,
                    block: BytesMut::from(&header_block[..]),
                });
            }
        }
        Frame::Data {
            stream_id,
            end_stream,
            payload,
        } => {
            let len = payload.len() as u32;
            connection.consume_inbound(len)?;

            if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.recv_window -= i64::from(len);
                if stream.recv_window < 0 {
                    return Err(H2Error::Protocol(
                        "the peer exceeded the stream receive window".into(),
                    ));
                }
                if !stream.head_received {
                    let _ = connection.replenish_connection(len).await;
                    let _ = connection
                        .reset_stream(stream_id, error_code::PROTOCOL_ERROR)
                        .await;
                    let _ = connection.flush().await;
                    state.fail_stream(
                        stream_id,
                        H2Error::Protocol("response DATA arrived before its HEADERS".into()),
                    );
                    if !end_stream {
                        state.mark_recently_reset(stream_id);
                    }
                    return Ok(());
                }

                if end_stream {
                    stream.peer_closed = true;
                    stream.release_if_wire_closed();
                }

                let mut delivered = true;
                if !payload.is_empty() {
                    stream.buffered_unread = stream.buffered_unread.saturating_add(len);
                    if stream
                        .body_tx
                        .send(Ok(H2ResponseEvent::Data {
                            payload,
                            end_stream,
                        }))
                        .is_err()
                    {
                        delivered = false;
                    }
                } else if end_stream && stream.body_tx.send(Ok(H2ResponseEvent::End)).is_err() {
                    delivered = false;
                }

                if !delivered {
                    // Consumer already dropped the reader; cancel cleanly and return credit.
                    if let Some(removed) = state.streams.remove(&stream_id) {
                        removed.outbound_permits.close();
                        let credit = removed.buffered_unread.saturating_add(removed.unacked_recv);
                        if credit > 0 {
                            let _ = connection.replenish_connection(credit).await;
                        }
                        if !end_stream {
                            let _ = connection.reset_stream(stream_id, error_code::CANCEL).await;
                            state.mark_recently_reset(stream_id);
                        }
                        let _ = connection.flush().await;
                    }
                }
            } else if state.recently_reset.contains(&stream_id) {
                if len > 0 {
                    connection.replenish_connection(len).await?;
                    connection.flush().await?;
                }
                if end_stream {
                    state.recently_reset.remove(&stream_id);
                }
            } else {
                if len > 0 {
                    connection.replenish_connection(len).await?;
                }
                connection
                    .reset_stream(stream_id, error_code::STREAM_CLOSED)
                    .await?;
                connection.flush().await?;
            }
        }
        Frame::RstStream {
            stream_id,
            error_code,
        } => {
            if let Some(stream) = state.streams.get(&stream_id) {
                let credit = stream.buffered_unread.saturating_add(stream.unacked_recv);
                if credit > 0 {
                    let _ = connection.replenish_connection(credit).await;
                    let _ = connection.flush().await;
                }
            }
            state.fail_stream(
                stream_id,
                H2Error::StreamReset {
                    stream_id,
                    error_code,
                },
            );
            state.recently_reset.remove(&stream_id);
        }
        Frame::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } => {
            view.goaway.store(true, Ordering::Release);
            connection.goaway_last_stream = Some(last_stream_id);
            let rejected: Vec<u32> = state
                .streams
                .keys()
                .copied()
                .filter(|id| *id > last_stream_id)
                .collect();
            for id in rejected {
                if let Some(stream) = state.streams.get(&id) {
                    let credit = stream.buffered_unread.saturating_add(stream.unacked_recv);
                    if credit > 0 {
                        let _ = connection.replenish_connection(credit).await;
                    }
                }
                state.fail_stream(
                    id,
                    H2Error::GoAway {
                        error_code,
                        debug_data: debug_data.to_vec(),
                    },
                );
            }
            let _ = connection.flush().await;
        }
        Frame::Settings {
            ack: false,
            settings,
        } => {
            let old_initial = i64::from(connection.peer.initial_window_size);
            connection.apply_peer_settings(&settings)?;
            if let Some(max) = connection.peer.max_concurrent_streams {
                view.max_concurrent_streams.store(max, Ordering::Release);
            }
            let new_initial = i64::from(connection.peer.initial_window_size);
            let delta = new_initial - old_initial;
            if delta != 0 {
                for (&stream_id, stream) in &mut state.streams {
                    stream.send_window += delta;
                    if stream.send_window > 0x7FFF_FFFF {
                        let _ = connection
                            .reset_stream(stream_id, error_code::FLOW_CONTROL_ERROR)
                            .await;
                    } else if stream.send_window > 0
                        && !stream.outbound.is_empty()
                        && !state.outbound_order.contains(&stream_id)
                    {
                        state.outbound_order.push_back(stream_id);
                    }
                }
            }
            connection
                .write_frame(&Frame::Settings {
                    ack: true,
                    settings: Vec::new(),
                })
                .await?;
            connection.flush().await?;
        }
        Frame::WindowUpdate {
            stream_id,
            increment,
        } => {
            if increment == 0 {
                if stream_id == 0 {
                    return Err(H2Error::Protocol(
                        "a zero WINDOW_UPDATE increment is a connection error".into(),
                    ));
                }
                connection
                    .reset_stream(stream_id, error_code::PROTOCOL_ERROR)
                    .await?;
                connection.flush().await?;
                state.fail_stream(
                    stream_id,
                    H2Error::Protocol("a zero WINDOW_UPDATE increment".into()),
                );
                return Ok(());
            }
            if stream_id == 0 {
                connection.apply_connection_window_update(increment)?;
            } else if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.send_window += i64::from(increment);
                if stream.send_window > 0x7FFF_FFFF {
                    connection
                        .reset_stream(stream_id, error_code::FLOW_CONTROL_ERROR)
                        .await?;
                    connection.flush().await?;
                    state.fail_stream(
                        stream_id,
                        H2Error::Protocol("stream send window overflowed".into()),
                    );
                    return Ok(());
                }
                if !stream.outbound.is_empty() || stream.send_ended {
                    state.queue_outbound(stream_id);
                }
            }
        }
        Frame::PushPromise { .. } => {
            return Err(H2Error::Protocol(
                "PUSH_PROMISE is not legal from this peer".into(),
            ));
        }
        Frame::Continuation { .. } => {
            return Err(H2Error::Protocol(
                "CONTINUATION outside a header block".into(),
            ));
        }
        other => {
            connection.handle_housekeeping(other).await?;
        }
    }

    Ok(())
}

async fn finish_header_block<T: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut H2Connection<T>,
    state: &mut DriverState,
    stream_id: u32,
    end_stream: bool,
    block: Bytes,
) -> Result<(), H2Error> {
    let limit = connection.local.max_header_list_size as usize;
    let fields = connection.decoder().decode_with_limit(&block, limit)?;

    if state.recently_reset.contains(&stream_id) {
        if end_stream {
            state.recently_reset.remove(&stream_id);
        }
        return Ok(());
    }

    let Some(stream) = state.streams.get_mut(&stream_id) else {
        return Ok(());
    };

    if !stream.head_received {
        let (status, headers) = split_response(fields);
        if (100..200).contains(&status) {
            if end_stream {
                state.fail_stream(
                    stream_id,
                    H2Error::Protocol("informational 1xx response cannot end the stream".into()),
                );
            }
            return Ok(());
        }
        stream.head_received = true;
        if end_stream {
            stream.peer_closed = true;
            stream.release_if_wire_closed();
        }
        let head = H2ResponseHead {
            status,
            headers,
            end_stream,
        };
        let head_tx = stream.head_tx.take();
        if end_stream && stream.end_stream_written {
            state.streams.remove(&stream_id);
        }
        if let Some(head_tx) = head_tx {
            let _ = head_tx.send(Ok(head));
        }
        return Ok(());
    }

    if !end_stream {
        return Err(H2Error::Protocol(
            "a response trailer block must end the stream".into(),
        ));
    }
    stream.peer_closed = true;
    stream.release_if_wire_closed();
    let _ = stream.body_tx.send(Ok(H2ResponseEvent::Trailers(fields)));
    Ok(())
}
