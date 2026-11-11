//! The HTTP/1.1 connection: framing, keep-alive, and the ordering of an exchange.
//!
//! One connection at a time, one exchange at a time — that is what HTTP/1.1 *is*, and the code here
//! is arranged so the absence of multiplexing is a fact of the protocol rather than an omission of
//! the implementation. (HTTP/2 is served by [`crate::h2`], through the same handler.)
//!
//! # The order of operations, and why it is that order
//!
//! ```text
//! head (bounded) ─► validate ─► 100-continue? ─► handler ─► drain ─► response ─► reuse?
//!      │               │             │             │         │         │
//!      │               │             │             │         │         └── framing enforced by the writer
//!      │               │             │             │         └── a body the handler ignored
//!      │               │             │             └── bounded by handler_timeout, panic contained
//!      │               │             └── so a client does not stall waiting for permission
//!      │               └── Host, target form, framing — all before application code
//!      └── bounded by head_timeout, so slow loris costs the holder
//! ```
//!
//! # Why every response goes through a writer object
//!
//! A response that declares `Content-Length: 5` and writes 4 bytes hangs the peer; one that writes a
//! body under `204` shifts every later response on a keep-alive connection. Both are enforced by
//! [`netune_http1::ResponseWriter`] rather than by convention here, so a streaming handler and a
//! one-shot handler are equally unable to produce them.

use std::sync::Arc;
use std::time::Duration;

use netune_http1::{
    BodyKind, Http1ServerReader, HttpError, IncomingRequest, ResponseWriter, TargetForm,
    write_interim,
};
use netune_io::{RingIo, TimedIo};
use netune_trace::{
    DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EventKind, NoTap, Ring, TraceCollector,
};
use tokio::io::AsyncWrite;

use crate::body::{BodySource, RequestBody};
use crate::config::ServerConfig;
use crate::handler::{Handler, Response, ResponseBody};
use crate::panic::CatchPanic;

/// Serve requests on one accepted connection until it closes or becomes unusable.
///
/// Returns the number of exchanges completed, which the caller reports in the connection's trace —
/// a connection that closed before serving anything is a fact worth counting, and a connection that
/// served forty is a fact worth *not* treating as one exchange.
pub(crate) async fn serve_http1<T>(
    stream: T,
    config: Arc<ServerConfig>,
    handler: Arc<dyn Handler>,
    recorder: TraceCollector,
) -> u32
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (observed, origin, capacity) = (
        recorder.is_enabled(),
        recorder.origin(),
        recorder.capacity(),
    );
    let stream: Box<dyn crate::body::AsyncIo> = if observed {
        Box::new(RingIo::new(
            stream,
            Ring::new(origin, capacity, None),
            recorder.clone(),
        ))
    } else {
        // No observer was installed: the byte path must not take a lock or
        // read a clock just to feed a disabled recorder.
        Box::new(TimedIo::new(stream, NoTap))
    };
    let mut reader: Reader = Http1ServerReader::with_limits(stream, config.limits);
    let mut exchanges = 0u32;

    loop {
        // -- head, bounded ---------------------------------------------------
        let head = match tokio::time::timeout(config.head_timeout, reader.read_request_head()).await
        {
            Ok(Ok(head)) => head,
            Ok(Err(error)) => {
                record_read_failure(&recorder, &error);
                // A head that failed to parse is still a request the peer is waiting for an answer
                // to. A `400` costs one write and tells the client to stop; a bare close is
                // indistinguishable from the network dropping the connection, so the client cannot
                // tell its own framing bug from our failure.
                if let Some(response) = rejection_for(&error) {
                    let _ = tokio::time::timeout(
                        config.write_timeout,
                        write_failure(
                            &mut reader,
                            &http::Method::GET,
                            response,
                            config.write_timeout,
                        ),
                    )
                    .await;
                }
                return exchanges;
            }
            Err(_) => {
                // The peer did not produce a head in time: slow loris. An attempt is made to tell it
                // why, but the connection is closed either way because its framing position is
                // unknown.
                record_error(
                    &recorder,
                    DiagnosticCode::SERVER_HEAD_TIMEOUT,
                    DiagnosticPhase::Http1,
                    "request head exceeded the configured bound",
                );
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    // No head was parsed, so no method is known: `GET` is the only method whose
                    // response framing a rejection may safely assume, and every rejection this path
                    // writes is body-less anyway.
                    write_failure(
                        &mut reader,
                        &http::Method::GET,
                        Response::timeout(),
                        config.write_timeout,
                    ),
                )
                .await;
                return exchanges;
            }
        };

        crate::config::adopt_trace_id(&config, &recorder, &head.headers);
        mark(
            &recorder,
            EventKind::RequestHeadComplete,
            head.target.len() as u32,
        );

        // -- validate before application code --------------------------------
        if let Some(rejection) = validate(&head, &config) {
            record_error(
                &recorder,
                DiagnosticCode::SERVER_INVALID_REQUEST,
                DiagnosticPhase::Http1,
                "request validation refused the head",
            );
            let _ = write_failure(&mut reader, &head.method, rejection, config.write_timeout).await;
            return exchanges;
        }

        let close_after =
            wants_close(&head, &config) || exchanges + 1 >= config.max_requests_per_connection;
        let body_kind = head.body;
        // An HTTP/1.0 peer that opted in must be *told* the connection is staying open, or it will
        // close after the response and the keep-alive it asked for costs a round trip for nothing.
        // HTTP/1.1 needs no announcement: persistence is its default.
        let keep_alive_1_0 =
            !close_after && head.version == http::Version::HTTP_10 && config.keep_alive;
        let expects_continue = config.expect_continue && expects_continue(&head);

        if expects_continue {
            // The peer is waiting for permission before sending its body. Answering is what turns a
            // 1 s stall into no stall at all; a listener that stays silent makes every large upload
            // pay a timeout.
            let mut io = reader_io(&mut reader);
            if write_interim(&mut io, http::StatusCode::CONTINUE, &http::HeaderMap::new())
                .await
                .is_err()
            {
                return exchanges;
            }
            mark(&recorder, EventKind::HandlerStart, 0);
        }

        // -- handler, bounded and contained ----------------------------------
        let method = head.method.clone();
        let response = {
            let mut source = Http1BodySource {
                reader: &mut reader,
                config: &config,
            };
            let body = RequestBody::new(&mut source, recorder.clone());
            if !expects_continue {
                mark(&recorder, EventKind::HandlerStart, 0);
            }
            let outcome = tokio::time::timeout(
                config.handler_timeout,
                handler.handle(head, body).catch_panic(),
            )
            .await;
            match outcome {
                Ok(Ok(response)) => {
                    mark(
                        &recorder,
                        EventKind::HandlerEnd,
                        response.head.status.as_u16() as u32,
                    );
                    response
                }
                Ok(Err(payload)) => {
                    // A panicking handler is answered, not dropped: a peer that receives a status
                    // line can retry or report, while a reset socket is indistinguishable from a
                    // network failure. The payload travels in the diagnostic side table, so a
                    // review can see what panicked without putting a string in every event.
                    record_error(
                        &recorder,
                        DiagnosticCode::SERVER_HANDLER_PANIC,
                        DiagnosticPhase::Server,
                        crate::panic::describe(payload.as_ref()),
                    );
                    Response::internal_error()
                }
                Err(_) => {
                    // A handler that never returns would hold the connection forever and make
                    // draining impossible.
                    record_error(
                        &recorder,
                        DiagnosticCode::SERVER_HANDLER_TIMEOUT,
                        DiagnosticPhase::Server,
                        "handler did not return within the configured bound",
                    );
                    Response::internal_error()
                }
            }
        };

        // -- drain what the handler left behind ------------------------------
        // A body the handler ignored is still in the stream; reusing the connection without draining
        // it would hand the next request the wrong bytes.
        let drained = drain_body(&mut reader, body_kind, &config).await;
        if !drained {
            record_error(
                &recorder,
                DiagnosticCode::SERVER_BODY_TIMEOUT,
                DiagnosticPhase::Http1,
                "request body did not finish within the configured bound",
            );
            return exchanges;
        }

        // -- response --------------------------------------------------------
        let wrote = write_exchange(
            &mut reader,
            &recorder,
            &method,
            response,
            ConnectionDirective {
                close: close_after,
                announce_keep_alive: keep_alive_1_0,
            },
            config.write_timeout,
        )
        .await;
        if !wrote {
            return exchanges;
        }
        exchanges += 1;
        if close_after {
            return exchanges;
        }
    }
}

/// The concrete reader this orchestrator uses: the codec over the erasure boundary.
type Reader = Http1ServerReader<Box<dyn crate::body::AsyncIo>>;

/// Validate what the codec cannot: `Host`, and the one case a target form makes impossible.
///
/// The codec already refused an illegal target and an unframeable body. What is left is *policy the
/// transport still owes the protocol*: RFC 9112 §3.2 makes `Host` mandatory for HTTP/1.1, and a
/// request without one (or with two that disagree) is how two hops route one request to different
/// origins.
fn validate(head: &IncomingRequest, config: &ServerConfig) -> Option<Response> {
    // `CONNECT` asks the recipient to open a tunnel and then relay bytes it does not interpret. This
    // transport never dials a peer (`INV-SERVER-01`), so it cannot open one — and a 2xx would tell the
    // client its tunnel bytes are being relayed when the next thing to read them would be the HTTP
    // parser. Refusing before dispatch is the only answer that is true.
    if head.method == http::Method::CONNECT {
        return Some(Response::not_implemented());
    }
    // An absolute-form target's authority *is* the Host for routing purposes, so a proxy request
    // without a `Host` header is legitimate. Everything else must carry exactly one.
    if config.require_host && head.version == http::Version::HTTP_11 {
        let hosts: Vec<&str> = head
            .headers
            .get_all(http::header::HOST)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        match hosts.len() {
            0 if head.form != TargetForm::Absolute => return Some(Response::bad_request()),
            0 => {}
            1 => {
                if let Err(error) = netune_http1::validate_host_field(hosts[0].as_bytes()) {
                    let _ = error;
                    return Some(Response::bad_request());
                }
                // An absolute-form target that names a different authority than `Host` is the shape
                // that makes a cache key differ from the origin a request is forwarded to.
                if head.form == TargetForm::Absolute
                    && !authority_matches_host(head.target_str().unwrap_or_default(), hosts[0])
                {
                    return Some(Response::bad_request());
                }
            }
            // Two `Host` headers is never a proxy artefact; it is a smuggling attempt.
            _ => return Some(Response::bad_request()),
        }
    }
    None
}

/// Whether an absolute-form target's authority equals `host` (case-insensitively, port included).
fn authority_matches_host(target: &str, host: &str) -> bool {
    let Some(rest) = target.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };
    let authority = rest.find(['/', '?']).map_or(rest, |end| &rest[..end]);
    authority.eq_ignore_ascii_case(host)
}

/// Whether the peer asked for permission to send its body.
fn expects_continue(head: &IncomingRequest) -> bool {
    head.headers
        .get_all(http::header::EXPECT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("100-continue"))
}

/// Drain a body the handler did not read. Returns `false` when the stream cannot be reused.
async fn drain_body(reader: &mut Reader, kind: BodyKind, config: &ServerConfig) -> bool {
    if kind == BodyKind::Empty {
        return true;
    }
    let mut source = Http1BodySource { reader, config };
    let mut body = RequestBody::new(
        &mut source,
        // The drain is not attributed to an exchange's handler span, and the
        // transport owns the real collector. A disabled collector keeps this
        // helper allocation-free and prevents a throwaway event ring.
        TraceCollector::disabled(),
    );
    match tokio::time::timeout(config.body_timeout, body.read_to_end()).await {
        Ok(Ok(_)) => true,
        Ok(Err(_)) | Err(_) => false,
    }
}

/// What the response must say about the connection's persistence.
#[derive(Debug, Clone, Copy)]
struct ConnectionDirective {
    /// Close after this response.
    close: bool,
    /// Announce `Connection: keep-alive`, which an HTTP/1.0 peer requires.
    announce_keep_alive: bool,
}

/// Write one response, with its framing enforced by the codec's writer.
///
/// Takes the response by value because a streaming body is consumed: pulling chunks out of it is the
/// only way to write them, and leaving a half-drained stream behind would be a body nobody can
/// finish.
async fn write_exchange(
    reader: &mut Reader,
    recorder: &TraceCollector,
    method: &http::Method,
    response: Response,
    directive: ConnectionDirective,
    write_timeout: Duration,
) -> bool {
    let Response { mut head, body } = response;
    if directive.close {
        head.headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
    } else if directive.announce_keep_alive {
        head.headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("keep-alive"),
        );
    }
    head.headers.insert(
        http::header::DATE,
        http::HeaderValue::from_str(&crate::date::http_date())
            .unwrap_or_else(|_| http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT")),
    );

    mark(recorder, EventKind::ResponseHeadSent, 0);

    let mut io = reader_io(reader);
    let mut deadline = crate::write_deadline::WriteDeadline::new(&mut io, write_timeout);
    // The writer borrows the transport rather than owning it, so the reader keeps its receive buffer
    // across the exchange. That is what makes the next pipelined request's bytes survive.
    let Ok(mut writer) = ResponseWriter::start(&mut deadline, method, &head).await else {
        return false;
    };

    let ok = write_body(&mut writer, body, recorder, write_timeout).await;
    if !ok {
        return false;
    }
    writer.finish().await.is_ok()
}

/// Write the body of a response, streaming it when it is a stream.
async fn write_body<W: AsyncWrite + Unpin>(
    writer: &mut ResponseWriter<W>,
    body: ResponseBody,
    recorder: &TraceCollector,
    write_timeout: Duration,
) -> bool {
    match body {
        ResponseBody::Empty => {
            mark(recorder, EventKind::ResponseEnd, 0);
            true
        }
        ResponseBody::Bytes(bytes) => {
            if writer.write(&bytes).await.is_err() {
                return false;
            }
            mark(
                recorder,
                EventKind::ResponseEnd,
                bytes.len().min(u32::MAX as usize) as u32,
            );
            true
        }
        ResponseBody::Stream(mut stream) => {
            let mut written = 0u64;
            loop {
                // `handler_timeout` bounds the handler's *future*, not the stream it returned: a
                // handler that returns immediately and then never produces a chunk would hold the
                // connection forever, and the write deadline cannot see it because nothing is being
                // written. So the interval between chunks is bounded by the same timeout, which is
                // the only reading of "the handler is allowed this long" that a streaming body can
                // honour.
                let chunk = match tokio::time::timeout(write_timeout, stream.next_chunk()).await {
                    Ok(Ok(Some(chunk))) => chunk,
                    Ok(Ok(None)) => break,
                    // A mid-body failure cannot be signalled to the peer: there is no status left to
                    // send, and a truncated message is the honest outcome.
                    Ok(Err(_)) => return false,
                    // A body that stopped producing: same outcome, different cause.
                    Err(_) => return false,
                };
                if chunk.is_empty() {
                    continue;
                }
                if writer.write(&chunk).await.is_err() {
                    return false;
                }
                written += chunk.len() as u64;
                mark(recorder, EventKind::ResponseChunkSent, chunk.len() as u32);
            }
            mark(
                recorder,
                EventKind::ResponseEnd,
                written.min(u32::MAX as u64) as u32,
            );
            true
        }
    }
}

/// Write a transport-authored rejection, ignoring any failure: the connection is about to close.
async fn write_failure(
    reader: &mut Reader,
    method: &http::Method,
    response: Response,
    write_timeout: Duration,
) -> bool {
    let Response { head, .. } = response;
    let mut io = reader_io(reader);
    let mut deadline = crate::write_deadline::WriteDeadline::new(&mut io, write_timeout);
    let Ok(writer) = ResponseWriter::start(&mut deadline, method, &head).await else {
        return false;
    };
    writer.finish().await.is_ok()
}

/// The request body, adapted to the orchestrator's [`BodySource`] boundary.
struct Http1BodySource<'a> {
    reader: &'a mut Reader,
    config: &'a ServerConfig,
}

impl BodySource for Http1BodySource<'_> {
    fn next_chunk(&mut self) -> crate::body::ChunkFuture<'_> {
        Box::pin(async move {
            match tokio::time::timeout(self.config.body_timeout, self.reader.read_body_chunk())
                .await
            {
                Ok(result) => result,
                // A body that stops arriving is a body timeout, which the codec has no vocabulary
                // for: it measures framing, not wall time.
                Err(_) => Err(HttpError::Incomplete("body read exceeded body_timeout")),
            }
        })
    }
}

/// Borrow the reader's transport for a write.
///
/// The codec's reader owns the stream, so writing a response on the same connection means going
/// through it. `&mut R` is an `AsyncWrite` whenever `R` is, which is what makes this a borrow rather
/// than a move — and what keeps the receive buffer (the next pipelined request) intact.
fn reader_io(reader: &mut Reader) -> ReaderWriter<'_> {
    ReaderWriter(reader)
}

/// An `AsyncWrite` view of a reader, so a response can be written on the socket the request arrived
/// on without taking the reader apart.
pub(crate) struct ReaderWriter<'a>(&'a mut Reader);

impl AsyncWrite for ReaderWriter<'_> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        std::pin::Pin::new(this.0.transport_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(this.0.transport_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(this.0.transport_mut()).poll_shutdown(cx)
    }
}

/// Whether the connection should close after this exchange.
///
/// HTTP/1.1 defaults to keep-alive; an explicit `Connection: close` (from either side), a configured
/// non-keep-alive server, or the connection's reuse quota turns it off.
pub(crate) fn wants_close(head: &IncomingRequest, config: &ServerConfig) -> bool {
    if !config.keep_alive {
        return true;
    }
    let has = |token: &str| {
        head.headers
            .get_all(http::header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case(token))
    };
    if has("close") {
        return true;
    }
    // A 1.0 peer must opt in to keep-alive; a 1.1 peer must opt out.
    match head.version {
        http::Version::HTTP_10 => !has("keep-alive"),
        _ => false,
    }
}

pub(crate) fn mark(recorder: &TraceCollector, kind: EventKind, a: u32) {
    recorder.mark(kind, a, 0);
}

/// The response a codec rejection deserves, when one can be justified.
///
/// `None` for a clean close (`Incomplete`): the peer is gone, so there is nobody to answer. Every
/// other class is answered, because a peer that sent bytes and is waiting deserves to learn that the
/// bytes were wrong rather than that the socket vanished.
fn rejection_for(error: &HttpError) -> Option<Response> {
    match error.class() {
        "incomplete" => None,
        "limit" => Some(Response::headers_too_large()),
        "protocol" => Some(Response::bad_request()),
        _ => None,
    }
}

/// Record a read failure unless it is the normal end of a keep-alive connection.
fn record_read_failure(recorder: &TraceCollector, error: &HttpError) {
    // A clean close between requests is how a keep-alive connection ends; recording it as an error
    // would make every well-behaved client look like a failure.
    if matches!(error, HttpError::Incomplete(_)) {
        return;
    }
    record_error(
        recorder,
        code_for(error),
        DiagnosticPhase::Http1,
        error.to_string(),
    );
}

pub(crate) fn code_for(error: &HttpError) -> DiagnosticCode {
    match error.class() {
        "protocol" => DiagnosticCode::SERVER_PROTOCOL,
        "limit" => DiagnosticCode::SERVER_LIMIT,
        "incomplete" => DiagnosticCode::SERVER_INCOMPLETE,
        _ => DiagnosticCode::SERVER_IO,
    }
}

pub(crate) fn record_error(
    recorder: &TraceCollector,
    code: DiagnosticCode,
    phase: DiagnosticPhase,
    message: impl Into<String>,
) {
    recorder.record_error(
        DiagnosticRecord::new(code)
            .with_phase(phase)
            .with_message(message),
    );
}

#[cfg(any(feature = "http2", feature = "http3"))]
pub(crate) fn record_error_stream(
    recorder: &TraceCollector,
    stream: u32,
    code: DiagnosticCode,
    phase: DiagnosticPhase,
    message: impl Into<String>,
) {
    recorder.record_error_stream(
        stream,
        DiagnosticRecord::new(code)
            .with_phase(phase)
            .with_message(message),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn request(version: http::Version, connection: Option<&str>) -> IncomingRequest {
        let mut headers = http::HeaderMap::new();
        if let Some(value) = connection {
            headers.insert(
                http::header::CONNECTION,
                http::HeaderValue::from_str(value).expect("value"),
            );
        }
        IncomingRequest {
            method: http::Method::GET,
            target: Bytes::from_static(b"/"),
            form: TargetForm::Origin,
            version,
            headers,
            body: BodyKind::Empty,
        }
    }

    #[test]
    fn http_11_keeps_alive_by_default() {
        assert!(!wants_close(
            &request(http::Version::HTTP_11, None),
            &ServerConfig::for_tests()
        ));
    }

    #[test]
    fn an_explicit_close_closes() {
        assert!(wants_close(
            &request(http::Version::HTTP_11, Some("close")),
            &ServerConfig::for_tests()
        ));
    }

    #[test]
    fn http_10_closes_unless_it_opts_in_to_keep_alive() {
        let config = ServerConfig::for_tests();
        assert!(wants_close(&request(http::Version::HTTP_10, None), &config));
        assert!(!wants_close(
            &request(http::Version::HTTP_10, Some("keep-alive")),
            &config
        ));
    }

    #[test]
    fn a_server_configured_for_no_keep_alive_closes_always() {
        let config = ServerConfig {
            keep_alive: false,
            ..ServerConfig::for_tests()
        };
        assert!(wants_close(&request(http::Version::HTTP_11, None), &config));
    }

    #[test]
    fn a_request_without_host_is_refused_on_http11() {
        let config = ServerConfig::for_tests();
        assert!(validate(&request(http::Version::HTTP_11, None), &config).is_some());
        // HTTP/1.0 has no `Host` requirement.
        assert!(validate(&request(http::Version::HTTP_10, None), &config).is_none());
    }

    #[test]
    fn two_host_headers_are_refused() {
        let mut head = request(http::Version::HTTP_11, None);
        head.headers
            .append(http::header::HOST, http::HeaderValue::from_static("a.test"));
        head.headers
            .append(http::header::HOST, http::HeaderValue::from_static("b.test"));
        assert!(validate(&head, &ServerConfig::for_tests()).is_some());
    }

    #[test]
    fn one_valid_host_is_accepted() {
        let mut head = request(http::Version::HTTP_11, None);
        head.headers
            .insert(http::header::HOST, http::HeaderValue::from_static("a.test"));
        assert!(validate(&head, &ServerConfig::for_tests()).is_none());
    }

    #[test]
    fn an_absolute_target_must_agree_with_host() {
        let mut head = request(http::Version::HTTP_11, None);
        head.target = Bytes::from_static(b"http://a.test/x");
        head.form = TargetForm::Absolute;
        head.headers
            .insert(http::header::HOST, http::HeaderValue::from_static("a.test"));
        assert!(validate(&head, &ServerConfig::for_tests()).is_none());

        head.headers
            .insert(http::header::HOST, http::HeaderValue::from_static("b.test"));
        assert!(
            validate(&head, &ServerConfig::for_tests()).is_some(),
            "a target that names a different origin than Host is a routing confusion"
        );
    }

    #[test]
    fn an_absolute_target_carries_its_own_authority_when_host_is_absent() {
        let mut head = request(http::Version::HTTP_11, None);
        head.target = Bytes::from_static(b"http://a.test/x");
        head.form = TargetForm::Absolute;
        assert!(validate(&head, &ServerConfig::for_tests()).is_none());
    }
}
