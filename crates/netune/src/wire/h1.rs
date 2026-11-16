//! HTTP/1.1 over one exclusively held connection.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use netune_http1::{BodyKind, Http1Reader, IncomingResponse, RequestWriter, write_request};
use netune_trace::{
    ConnectionInfo, Counters, DiagnosticPhase, EventKind, SocketTap, Tap, TapArtifact,
    TraceCollector,
};

use crate::connect::{Transport, dial_tap};
use crate::error::NetError;
use crate::exchange::{
    Attempt, BodySource, BoxFuture, Exchange, ObservationLevel, Released, Request,
};
use crate::pool::{Pool, PoolInFlightPermit, PoolKey};
use crate::tcp_info::{SAMPLE_INTERVAL, Sampler, start as start_sampler};

/// A connection ready to carry one HTTP/1.1 exchange.
pub(super) struct Connection {
    pub stream: Box<dyn Transport>,
    /// Bytes the peer sent after the previous response on this connection.
    pub buffered: BytesMut,
    pub local_port: Option<u16>,
    pub socket: Option<std::net::TcpStream>,
    pub info: ConnectionInfo,
}

/// Write the request, read the head, and hand back the unread body.
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
    if !head.headers.contains_key(http::header::HOST)
        && let Ok(value) = http::HeaderValue::from_str(&plan.target.authority)
    {
        head.headers.insert(http::header::HOST, value);
    }
    let is_stream = request.body.known_len().is_none();
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
        && let Some(len) = request.body.known_len()
        && let Ok(value) = http::HeaderValue::from_str(&len.to_string())
    {
        // Materialize Content-Length before the profile so the profile controls
        // its casing and position too; `write_request` only auto-adds one when the
        // head is not raw.
        head.headers.insert(http::header::CONTENT_LENGTH, value);
    }
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

    // From here the body owns the connection: any early return drops it, and
    // its `Drop` still merges what the socket tap saw into the trace.
    let mut body = Body {
        reader: Some(Http1Reader::with_limits_and_buffer(
            stream,
            attempt.config.limits,
            buffered,
        )),
        recorder: recorder.clone(),
        pool: pool.clone(),
        key,
        local_port,
        socket,
        sampler,
        reusable: false,
        _in_flight: None,
    };

    recorder.mark(EventKind::RequestWriteStart, 0, 0);
    let written = if let Some(mut source) = request.body.take_stream()? {
        let mut writer = RequestWriter::start(body.io()?, &head).await?;
        while let Some(chunk) = source.next_chunk().await? {
            writer.write(&chunk).await?;
        }
        let written = writer.written() as u32;
        writer.finish().await?;
        written
    } else {
        write_request(body.io()?, &head, request.body.as_bytes()).await?;
        request.body.known_len().unwrap_or(0) as u32
    };
    recorder.mark(EventKind::RequestWriteEnd, written, 0);

    let response_head = bounded(
        attempt.config.response_head_timeout,
        body.reader()?.read_response_head(&head.method),
    )
    .await??;
    body.reusable = is_reusable(&response_head);
    body._in_flight = in_flight.take();

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
    reader: Option<Http1Reader<Box<dyn Transport>>>,
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
    fn reader(&mut self) -> Result<&mut Http1Reader<Box<dyn Transport>>, NetError> {
        self.reader
            .as_mut()
            .ok_or_else(|| NetError::Protocol("the HTTP/1.1 connection was released".into()))
    }

    fn io(&mut self) -> Result<&mut Box<dyn Transport>, NetError> {
        Ok(self.reader()?.transport_mut())
    }

    /// Detach the connection and what its tap recorded.
    fn detach(&mut self) -> Option<(Box<dyn Transport>, BytesMut, TapArtifact)> {
        let (mut stream, buffered) = self.reader.take()?.into_inner();
        // Stop sampling before the connection goes idle.
        drop(self.sampler.take());
        let artifact = stream
            .swap_tap(SocketTap::Off)
            .map_or(TapArtifact::None, Tap::finish);
        Some((stream, buffered, artifact))
    }
}

impl BodySource for Body {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>> {
        Box::pin(async move {
            self.reader()?
                .read_body_chunk()
                .await
                .map_err(NetError::from)
        })
    }

    fn release(mut self: Box<Self>, complete: bool) -> Released {
        let Some((stream, buffered, artifact)) = self.detach() else {
            return Released::untapped();
        };
        if complete && self.reusable {
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
        // Reached only when the exchange failed before it produced a response:
        // nobody will call `release`, but the bytes that did cross the socket
        // are part of the failure's evidence.
        if let Some((_stream, _buffered, TapArtifact::Log(log))) = self.detach() {
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
