//! HTTP/1.1 over one exclusively held connection.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use netune_http1::{BodyKind, Http1Reader, IncomingResponse, RequestWriter, write_request};
use netune_trace::{
    ConnectionInfo, Counters, DiagnosticPhase, EventKind, SocketTap, Tap, TapArtifact,
    TraceCollector,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::ClientConfig;
use crate::connect::{Transport, dial_tap};
use crate::error::NetError;
use crate::exchange::{
    Attempt, BodySource, BoxFuture, Exchange, ObservationLevel, Released, Request, RequestBody,
};
use crate::pool::{Pool, PoolInFlightPermit, PoolKey};
use crate::profile::ConnectionPlan;
use crate::tcp_info::{SAMPLE_INTERVAL, Sampler, start as start_sampler};

/// One underlying transport shared by an HTTP/1.1 read half and write half.
///
/// The socket tap stays inside the transport, so both directions record the
/// same byte path. The last reference to this value hands the transport back
/// to the pool or merges a partial tap if an early response abandoned the
/// upload.
struct SplitShared {
    transport: Mutex<Option<Box<dyn Transport>>>,
    recorder: TraceCollector,
}

impl SplitShared {
    fn with_transport(transport: Box<dyn Transport>, recorder: TraceCollector) -> Self {
        Self {
            transport: Mutex::new(Some(transport)),
            recorder,
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Box<dyn Transport>) -> R) -> Option<R> {
        let mut transport = self.transport.lock().unwrap_or_else(|e| e.into_inner());
        transport.as_mut().map(f)
    }
}

impl Drop for SplitShared {
    fn drop(&mut self) {
        let Some(mut transport) = self
            .transport
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            return;
        };
        if let Some(artifact) = transport.swap_tap(SocketTap::Off).map(Tap::finish)
            && let TapArtifact::Log(log) = artifact
        {
            self.recorder.merge(log);
        }
    }
}

/// The read half of an HTTP/1.1 transport.
struct SplitRead {
    shared: Arc<SplitShared>,
}

impl AsyncRead for SplitRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self
            .shared
            .with(|transport| Pin::new(&mut **transport).poll_read(cx, buf))
        {
            Some(result) => result,
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HTTP/1.1 transport was already detached",
            ))),
        }
    }
}

/// The write half of an HTTP/1.1 transport.
struct SplitWrite {
    shared: Arc<SplitShared>,
}

impl AsyncWrite for SplitWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self
            .shared
            .with(|transport| Pin::new(&mut **transport).poll_write(cx, buf))
        {
            Some(result) => result,
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HTTP/1.1 transport was already detached",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self
            .shared
            .with(|transport| Pin::new(&mut **transport).poll_flush(cx))
        {
            Some(result) => result,
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HTTP/1.1 transport was already detached",
            ))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self
            .shared
            .with(|transport| Pin::new(&mut **transport).poll_shutdown(cx))
        {
            Some(result) => result,
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HTTP/1.1 transport was already detached",
            ))),
        }
    }
}

/// Owner handle for a split HTTP/1.1 transport.
struct SplitHandle {
    shared: Arc<SplitShared>,
}

impl SplitHandle {
    /// Release the split transport, synchronously extracting its tap artifact.
    ///
    /// When `try_keep` is `true` and every half (`SplitRead`/`SplitWrite`) has
    /// already been dropped, this returns `Some(transport)` so the caller can
    /// pool it. Otherwise it takes and drops the underlying transport
    /// immediately (closing any abandoned upload socket) while still returning
    /// the recorded `TapArtifact` synchronously.
    fn release(self, try_keep: bool) -> (Option<Box<dyn Transport>>, TapArtifact) {
        if try_keep {
            match Arc::try_unwrap(self.shared) {
                Ok(mut shared) => {
                    let Some(mut transport) = shared
                        .transport
                        .get_mut()
                        .unwrap_or_else(|e| e.into_inner())
                        .take()
                    else {
                        return (None, TapArtifact::None);
                    };
                    let artifact = transport
                        .swap_tap(SocketTap::Off)
                        .map_or(TapArtifact::None, Tap::finish);
                    return (Some(transport), artifact);
                }
                Err(shared) => {
                    return (None, take_transport_tap(&shared));
                }
            }
        }
        (None, take_transport_tap(&self.shared))
    }
}

fn take_transport_tap(shared: &SplitShared) -> TapArtifact {
    let Some(mut transport) = shared
        .transport
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    else {
        return TapArtifact::None;
    };
    transport
        .swap_tap(SocketTap::Off)
        .map_or(TapArtifact::None, Tap::finish)
}

fn split_transport(
    transport: Box<dyn Transport>,
    recorder: TraceCollector,
) -> (SplitRead, SplitWrite, SplitHandle) {
    let shared = Arc::new(SplitShared::with_transport(transport, recorder));
    (
        SplitRead {
            shared: Arc::clone(&shared),
        },
        SplitWrite {
            shared: Arc::clone(&shared),
        },
        SplitHandle { shared },
    )
}

/// Abort a request-body upload if the response is abandoned before it finishes.
struct AbortOnDrop(Option<AbortHandle>);

impl AbortOnDrop {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

struct ExchangeCleanup {
    handle: Option<SplitHandle>,
    upload_abort: Option<AbortOnDrop>,
    sampler: Option<Sampler>,
    recorder: TraceCollector,
}

impl Drop for ExchangeCleanup {
    fn drop(&mut self) {
        drop(self.upload_abort.take());
        drop(self.sampler.take());
        if let Some(handle) = self.handle.take() {
            let (_, artifact) = handle.release(false);
            if let TapArtifact::Log(log) = artifact {
                self.recorder.merge(log);
            }
        }
    }
}
/// A connection ready to carry one HTTP/1.1 exchange.
pub(super) struct Connection {
    pub stream: Box<dyn Transport>,
    /// Bytes the peer sent after the previous response on this connection.
    pub buffered: BytesMut,
    pub local_port: Option<u16>,
    pub socket: Option<std::net::TcpStream>,
    pub info: ConnectionInfo,
}

/// Materialize the transport-stamped HTTP/1.1 headers into `head` — the ones
/// the exchange, not the caller, owns: `host`, the automatic
/// `content-length` (or `transfer-encoding: chunked` for an unknown-length
/// upload), and — when the client adopts the Go transport's identity —
/// `accept-encoding: gzip`.
///
/// Stamping happens **before** the wire profile so the profile controls the
/// casing and position of these headers like any other; `write_request`
/// only auto-adds a `content-length` when the head is not raw, and a caller
/// that supplied `raw_headers` keeps its exact bytes (the gzip offer steps
/// aside for them too).
pub(super) fn stamp_transport_headers(
    head: &mut netune_http1::RequestHead,
    plan: &ConnectionPlan,
    config: &ClientConfig,
    body: &RequestBody,
) {
    if !head.headers.contains_key(http::header::HOST)
        && let Ok(value) = http::HeaderValue::from_str(super::host_field_value(&plan.target))
    {
        head.headers.insert(http::header::HOST, value);
    }
    let is_stream = body.known_len().is_none();
    if is_stream {
        if !head.headers.contains_key(http::header::CONTENT_LENGTH)
            && !head.headers.contains_key(http::header::TRANSFER_ENCODING)
        {
            head.headers.insert(
                http::header::TRANSFER_ENCODING,
                http::HeaderValue::from_static("chunked"),
            );
        }
    } else if !head.headers.contains_key(http::header::CONTENT_LENGTH)
        && let Some(len) = body.known_len()
        && let Ok(value) = http::HeaderValue::from_str(&len.to_string())
    {
        // Materialize Content-Length before the profile so the profile controls
        // its casing and position too; `write_request` only auto-adds one when
        // the head is not raw.
        head.headers.insert(http::header::CONTENT_LENGTH, value);
    }
    // The Go `net/http` transport offers gzip when the caller did not name an
    // encoding, and decodes what it offered. Offered before the profile so a
    // profile pins the header's position like every transport-stamped header.
    if config.accept_encoding_gzip
        && !head.headers.contains_key(http::header::ACCEPT_ENCODING)
        && head.raw_headers.is_none()
    {
        head.headers.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
    }
}

pub(super) async fn exchange(
    pool: &Pool,
    key: PoolKey,
    connection: Connection,
    attempt: Attempt<'_>,
    request: &Request,
    in_flight: &mut Option<PoolInFlightPermit>,
) -> Result<Exchange, NetError> {
    let plan = attempt.plan;
    let recorder = attempt.recorder;
    let Connection {
        mut stream,
        buffered,
        local_port,
        socket,
        info,
    } = connection;

    let mut head = request.head.clone();
    stamp_transport_headers(&mut head, plan, attempt.config, &request.body);
    plan.h1.apply(&mut head);

    // The socket tap for this exchange. A fresh, traced connection already
    // carries the ring its dial installed, so the handshake stays in the
    // timeline; a pooled one was left untapped when it was released.
    match (attempt.observation, info.reused) {
        (ObservationLevel::Traced, false) | (ObservationLevel::Off, _) => {}
        (ObservationLevel::Traced, true) => {
            let _ = stream.swap_tap(dial_tap(recorder));
        }
        (ObservationLevel::Counters, _) => {
            let _ = stream.swap_tap(SocketTap::Counters(Counters::default()));
        }
    }

    // Sample the socket for as long as this exchange is in flight. The sampler
    // gets its own duplicate handle; `socket` travels with the body so the
    // pool can be handed a live handle when the connection is released.
    let sampler = socket.as_ref().and_then(|socket| {
        crate::tcp_info::duplicate(socket)
            .map(|clone| start_sampler(clone, recorder.clone(), SAMPLE_INTERVAL))
    });

    // From here `cleanup` owns the connection until `Body` is returned: any
    // early error or cancellation synchronously extracts and merges the socket
    // tap into `recorder` before returning to the caller.
    let (read, write, handle) = split_transport(stream, recorder.clone());
    let mut reader = Http1Reader::with_limits_and_buffer(read, attempt.config.limits, buffered);

    recorder.mark(EventKind::RequestWriteStart, 0, 0);
    let stream_source = request.body.take_stream()?;
    let buffered_body = request.body.as_bytes().map(Bytes::copy_from_slice);
    let body_len = request.body.known_len().unwrap_or(0);
    let head_for_write = head.clone();
    let recorder_for_write = recorder.clone();
    let (upload_tx, mut upload_rx) = oneshot::channel();
    let upload = tokio::spawn(async move {
        let mut write = write;
        let result: Result<SplitWrite, NetError> = async {
            let written = if let Some(mut source) = stream_source {
                let mut writer = RequestWriter::start(write, &head_for_write).await?;
                while let Some(chunk) = source.next_chunk().await? {
                    writer.write(&chunk).await?;
                }
                let written = writer.written() as u32;
                write = writer.finish().await?;
                written
            } else {
                write_request(&mut write, &head_for_write, buffered_body.as_deref()).await?;
                u32::try_from(body_len).unwrap_or(u32::MAX)
            };
            recorder_for_write.mark(EventKind::RequestWriteEnd, written, 0);
            Ok(write)
        }
        .await;
        let _ = upload_tx.send(result);
    });
    let mut cleanup = ExchangeCleanup {
        handle: Some(handle),
        upload_abort: Some(AbortOnDrop(Some(upload.abort_handle()))),
        sampler,
        recorder: recorder.clone(),
    };

    // The response head and the upload run concurrently. If the head wins, the
    // body keeps the upload task until the response stream ends or is dropped;
    // if the upload wins, its split write half is retained for pooling.
    let (response_head, upload_rx, write_half) = {
        let mut head_fut = std::pin::pin!(bounded(
            attempt.config.response_head_timeout,
            reader.read_response_head(&head.method),
        ));
        tokio::select! {
            head = &mut head_fut => (head??, Some(upload_rx), None),
            uploaded = &mut upload_rx => {
                let write = match uploaded {
                    Ok(Ok(write)) => write,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(NetError::Protocol(
                        "HTTP/1.1 upload task aborted".into(),
                    )),
                };
                if let Some(abort) = cleanup.upload_abort.as_mut() {
                    abort.disarm();
                }
                (head_fut.as_mut().await??, None, Some(write))
            }
        }
    };

    let upload_done = upload_rx.is_none();
    let body = Body {
        reader: Some(reader),
        write_half,
        handle: cleanup.handle.take(),
        upload_abort: if upload_done {
            None
        } else {
            cleanup.upload_abort.take()
        },
        upload_rx,
        upload_done,
        upload_error: None,
        recorder: recorder.clone(),
        pool: pool.clone(),
        key,
        local_port,
        socket,
        sampler: cleanup.sampler.take(),
        reusable: is_reusable(&response_head),
        _in_flight: in_flight.take(),
    };

    Ok(Exchange {
        head: response_head,
        body: Box::new(body),
        connection: info,
    })
}

/// Run `future` under the response-head bound.
pub(super) async fn bounded<F: Future>(
    limit: Option<Duration>,
    future: F,
) -> Result<F::Output, NetError> {
    match limit {
        Some(limit) => tokio::time::timeout(limit, future)
            .await
            .map_err(|_| NetError::Timeout {
                phase: DiagnosticPhase::Response,
                waiting_for: "response head",
                limit,
            }),
        None => Ok(future.await),
    }
}

/// The unread body of an HTTP/1.1 response, and the connection under it.
struct Body {
    reader: Option<Http1Reader<SplitRead>>,
    /// Returned by the writer task once the full request has been written.
    write_half: Option<SplitWrite>,
    handle: Option<SplitHandle>,
    upload_abort: Option<AbortOnDrop>,
    upload_rx: Option<oneshot::Receiver<Result<SplitWrite, NetError>>>,
    upload_done: bool,
    upload_error: Option<NetError>,
    recorder: TraceCollector,
    pool: Pool,
    key: PoolKey,
    local_port: Option<u16>,
    /// Duplicate socket descriptor, handed back to the pool on release so the
    /// next exchange can sample the same socket.
    socket: Option<std::net::TcpStream>,
    sampler: Option<Sampler>,
    reusable: bool,
    _in_flight: Option<PoolInFlightPermit>,
}

impl Body {
    fn reader(&mut self) -> Result<&mut Http1Reader<SplitRead>, NetError> {
        self.reader
            .as_mut()
            .ok_or_else(|| NetError::Protocol("the HTTP/1.1 connection was released".into()))
    }

    /// Collect a writer half that completed while the response body is being
    /// read. A writer error is surfaced on the next body poll, not lost.
    fn poll_upload(&mut self) {
        let Some(rx) = self.upload_rx.as_mut() else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(write)) => {
                self.write_half = Some(write);
                self.upload_done = true;
                self.upload_rx = None;
                if let Some(abort) = self.upload_abort.as_mut() {
                    abort.disarm();
                }
            }
            Ok(Err(error)) => {
                self.upload_error = Some(error);
                self.upload_done = true;
                self.upload_rx = None;
                if let Some(abort) = self.upload_abort.as_mut() {
                    abort.disarm();
                }
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                self.upload_done = true;
                self.upload_rx = None;
                if let Some(abort) = self.upload_abort.as_mut() {
                    abort.disarm();
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
    }

    /// Detach the connection and synchronously extract what its tap recorded.
    fn detach(&mut self, try_keep: bool) -> (Option<Box<dyn Transport>>, BytesMut, TapArtifact) {
        let buffered = match self.reader.take() {
            Some(reader) => {
                let (read, buffered) = reader.into_inner();
                drop(read);
                buffered
            }
            None => BytesMut::new(),
        };
        drop(self.write_half.take());
        drop(self.upload_abort.take());
        self.poll_upload();
        drop(self.upload_rx.take());
        drop(self.write_half.take());
        // Stop sampling before the connection goes idle.
        drop(self.sampler.take());
        let Some(handle) = self.handle.take() else {
            return (None, buffered, TapArtifact::None);
        };
        let (stream, artifact) = handle.release(try_keep);
        (stream, buffered, artifact)
    }
}

impl BodySource for Body {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>> {
        Box::pin(async move {
            self.poll_upload();
            if let Some(error) = self.upload_error.take() {
                return Err(error);
            }
            let next = self
                .reader()?
                .read_body_chunk()
                .await
                .map_err(NetError::from)?;
            if next.is_none() {
                // The response ended before the upload. Keep reading is
                // impossible: stop the writer and leave the connection
                // unpooled.
                drop(self.upload_abort.take());
                self.poll_upload();
                if let Some(error) = self.upload_error.take() {
                    return Err(error);
                }
            }
            Ok(next)
        })
    }

    fn release(mut self: Box<Self>, complete: bool) -> Released {
        self.poll_upload();
        let can_pool = complete && self.reusable && self.upload_done;
        let (stream, buffered, artifact) = self.detach(can_pool);
        if can_pool && let Some(stream) = stream {
            self.pool.put_http1(
                &self.key,
                stream,
                buffered,
                self.local_port,
                self.socket.take(),
            );
        }
        Released { artifact }
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        // Reached when the exchange failed or was dropped without calling
        // `release`: any bytes that crossed the socket are merged synchronously
        // so `Body::trace()` / `AttemptError::trace()` always see them.
        let (_stream, _buffered, artifact) = self.detach(false);
        if let TapArtifact::Log(log) = artifact {
            self.recorder.merge(log);
        }
    }
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

#[cfg(test)]
mod stamp_tests {
    use super::*;
    use crate::connect::Target;
    use crate::profile::H1WireProfile;
    use bytes::Bytes;
    use http::Method;
    use netune_http1::RequestHead;

    fn antigravity_plan() -> ConnectionPlan {
        let client = crate::Client::builder().build();
        let target = Target::plain("daily-cloudcode-pa.googleapis.com:80")
            .with_h1_profile("antigravity-cli");
        client.plan(&target).expect("the pairing resolves")
    }

    /// The Go transport's gzip offer, as the shipped `agy` 1.5.12 puts it on
    /// the wire (live capture 2026-11-19): a request with no
    /// `accept-encoding` gains one, a request that names its own encoding
    /// keeps it, and an exact raw head is never rewritten.
    #[test]
    fn gzip_offer_matches_the_go_transport() {
        let plan = antigravity_plan();
        let config = ClientConfig::default().with_accept_encoding_gzip(true);
        let body = RequestBody::Full(Bytes::from_static(b"{}"));

        let mut plain_head = RequestHead::new(Method::POST, "/v1internal:loadCodeAssist")
            .with_header("authorization", "Bearer t");
        stamp_transport_headers(&mut plain_head, &plan, &config, &body);
        assert_eq!(
            plain_head
                .headers
                .get(http::header::ACCEPT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            Some("gzip"),
            "the transport offers what it can decode"
        );

        let mut caller_set =
            RequestHead::new(Method::POST, "/x").with_header("accept-encoding", "identity");
        stamp_transport_headers(&mut caller_set, &plan, &config, &body);
        assert_eq!(
            caller_set
                .headers
                .get(http::header::ACCEPT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            Some("identity"),
            "a caller-named encoding is the caller's final word"
        );

        let mut raw = RequestHead::new(Method::POST, "/x").with_raw_header("X-Exact", "yes");
        stamp_transport_headers(&mut raw, &plan, &config, &body);
        assert!(
            raw.headers.get(http::header::ACCEPT_ENCODING).is_none(),
            "an exact raw head is never rewritten"
        );
    }

    /// Stamping plus the `antigravity-cli` wire profile reproduces the
    /// captured `agy` 1.5.12 head exactly: `Host`, `User-Agent`,
    /// `Content-Length`, the caller's headers, `Accept-Encoding` last.
    #[test]
    fn stamped_antigravity_head_matches_the_captured_order() {
        let plan = antigravity_plan();
        let config = ClientConfig::default().with_accept_encoding_gzip(true);
        let body = RequestBody::Full(Bytes::from_static(
            b"{\"metadata\":{\"ideType\":\"ANTIGRAVITY\"}}",
        ));

        let mut head = RequestHead::new(Method::POST, "/v1internal:loadCodeAssist")
            .with_header("authorization", "Bearer t")
            .with_header("content-type", "application/json")
            .with_header(
                "user-agent",
                "antigravity/cli/1.5.12 (aidev_client; os_type=linux; \
                 arch=amd64; cl=1024904911; auth_method=consumer)",
            );
        stamp_transport_headers(&mut head, &plan, &config, &body);
        H1WireProfile::antigravity_cli().apply(&mut head);
        let raw = head.raw_headers.expect("raw head");
        let names: Vec<&str> = raw.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Host",
                "User-Agent",
                "Content-Length",
                "Authorization",
                "Content-Type",
                "Accept-Encoding",
            ],
            "the 1.5.12 captured order, gzip offer last"
        );
    }
}
