//! HTTP/2 over the ingress orchestrator: one handler, two protocols.
//!
//! This is the adapter that lets an application write **one** [`Handler`] and have it serve both
//! wire protocols. It does four things, and each exists because the protocol boundary cannot do it:
//!
//! 1. **Protocol selection.** `/` and `http/1.1` are HTTP/1.1; a connection that begins with the
//!    client preface is prior-knowledge HTTP/2; a TLS connection takes whatever ALPN negotiated.
//!    Deciding once, from the first bytes, is what makes an in-place upgrade unnecessary — and an
//!    in-place upgrade is a request-smuggling surface.
//! 2. **Translation.** [`netune_http2::server::H2Request`] becomes the same [`IncomingRequest`] a
//!    [`Handler`] already accepts, so routing is written once.
//! 3. **Stream identity in the trace.** A multiplexed connection carries several exchanges whose
//!    events interleave; the adapter is the layer that knows the stream id, so it attaches it.
//! 4. **Response translation.** A [`Response`] whose body is a stream becomes an HTTP/2 channel of
//!    `DATA` frames, because `END_STREAM` is the only terminator HTTP/2 has.
//!
//! # Why the header translation is not cosmetic
//!
//! HTTP/2 has no `Host`; it has `:authority`. A handler that read only `host` would see nothing on an
//! HTTP/2 request, and one that read only `:authority` would see nothing on HTTP/1.1. The translation
//! synthesises the missing one on each side so exactly one field answers "which authority is this",
//! which is the field a router keys on.

use std::sync::Arc;

use bytes::Bytes;
use netune_http1::{BodyKind, IncomingRequest, TargetForm};
use netune_http2::server::{
    H2Handler, H2Request, H2Response, H2ResponseBody, ResponseFuture as H2ResponseFuture,
    ServerSession, ServerSessionConfig, SessionEnd, SessionObserver, StreamEvent,
};
use netune_trace::{EventKind, TraceCollector};
use tokio::sync::mpsc;

use crate::body::{BodySource, RequestBody};
use crate::config::ServerConfig;
use crate::handler::{BodyStream, Handler, Response, ResponseBody};
use crate::panic::CatchPanic;

/// Serve one HTTP/2 connection on behalf of `handler`.
pub(crate) async fn serve_http2<S>(
    stream: S,
    config: Arc<ServerConfig>,
    handler: Arc<dyn Handler>,
    recorder: TraceCollector,
    preface_already_read: bool,
    shutdown: impl std::future::Future<Output = ()>,
) -> SessionEnd
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let session_config = ServerSessionConfig {
        settings: config.http2.parameters(),
        local: config.http2.local_settings(),
        connection_window: config.http2.connection_window_size,
        body_channel_capacity: 4,
        // The listener's slow-read bound, so the two protocols defend against a stalled reader the
        // same way. A constant here would have quietly made `write_timeout` mean "HTTP/1.1 only".
        write_timeout: config.write_timeout,
        // HTTP/1.1 bounds the wait for every request head with `head_timeout`, including
        // the idle keep-alive gap. HTTP/2 has no request line, so the same number bounds
        // the connection preface and a connection with no open streams.
        handshake_timeout: config.head_timeout,
        idle_timeout: config.head_timeout,
    };
    let observer = Arc::new(TraceObserver {
        recorder: recorder.clone(),
    });
    let adapter = Arc::new(HandlerAdapter {
        handler,
        config,
        recorder,
    });
    let session = ServerSession::new(adapter, session_config, observer);
    session.run(stream, preface_already_read, shutdown).await
}

/// The bridge from this crate's [`Handler`] to the codec's [`H2Handler`].
struct HandlerAdapter {
    handler: Arc<dyn Handler>,
    config: Arc<ServerConfig>,
    recorder: TraceCollector,
}

impl H2Handler for HandlerAdapter {
    fn handle(&self, request: H2Request) -> H2ResponseFuture<'_> {
        let handler = Arc::clone(&self.handler);
        let config = Arc::clone(&self.config);
        let recorder = self.recorder.clone();
        Box::pin(async move { self.answer(handler, config, recorder, request).await })
    }
}

impl HandlerAdapter {
    async fn answer(
        &self,
        handler: Arc<dyn Handler>,
        config: Arc<ServerConfig>,
        recorder: TraceCollector,
        request: H2Request,
    ) -> H2Response {
        let stream_id = request.stream_id;
        let incoming = incoming_request(&request);

        // The same host rule the HTTP/1.1 path enforces, applied to the field HTTP/2 spells
        // differently. `decode_request` already refused a request with no `:authority`; what is left is
        // the *policy* switch the operator set, and refusing it here keeps the two protocols from
        // disagreeing about which requests are routable (`INV-SERVER-09`'s sibling rule: one
        // configuration, both protocols).
        // A `CONNECT` asks for a tunnel this transport cannot open (`INV-SERVER-01`). Refusing before
        // the handler keeps the two protocols from disagreeing about what they will do.
        if incoming.method == http::Method::CONNECT {
            return H2Response {
                status: http::StatusCode::NOT_IMPLEMENTED,
                headers: http::HeaderMap::new(),
                body: H2ResponseBody::Empty,
            };
        }
        if config.require_host && !incoming.headers.contains_key(http::header::HOST) {
            return H2Response {
                status: http::StatusCode::BAD_REQUEST,
                headers: http::HeaderMap::new(),
                body: H2ResponseBody::Empty,
            };
        }

        // The body is handed over as an orchestrator `BodySource`, so a handler reads it through the
        // same `RequestBody` API it uses on HTTP/1.1.
        let mut source = H2BodySource { body: request.body };
        let body = RequestBody::new(&mut source, recorder.clone());

        crate::h1::mark(&recorder, EventKind::HandlerStart, 0);
        // `CatchPanic` wraps any future, so the owned future an HTTP/2 stream produces is contained
        // exactly as a borrowing HTTP/1.1 one is: a panicking handler answers `500` and the
        // connection keeps its other streams.
        let outcome = tokio::time::timeout(
            config.handler_timeout,
            handler.handle(incoming, body).catch_panic(),
        )
        .await;

        let response = match outcome {
            Ok(Ok(response)) => response,
            Ok(Err(payload)) => {
                // Recorded on *this* stream: `split_multiplexed` copies connection-level events into
                // every sub-log, so a stream-0 `Error` would make one stream's panic appear in every
                // other stream's derivation on the same connection.
                let _described = crate::panic::describe(payload.as_ref());
                recorder.mark_stream(
                    stream_id,
                    EventKind::Error,
                    crate::h1::ERROR_HANDLER_PANIC,
                    0,
                );
                Response::internal_error()
            }
            Err(_) => {
                recorder.mark_stream(
                    stream_id,
                    EventKind::Error,
                    crate::h1::ERROR_HANDLER_TIMEOUT,
                    0,
                );
                Response::internal_error()
            }
        };

        recorder.mark_stream(
            stream_id,
            EventKind::HandlerEnd,
            response.head.status.as_u16() as u32,
            0,
        );
        translate_response(response)
    }
}

/// Translate an HTTP/2 request into the head a [`Handler`] expects.
fn incoming_request(request: &H2Request) -> IncomingRequest {
    let form = if request.path.first() == Some(&b'/') {
        TargetForm::Origin
    } else if request.method == http::Method::CONNECT {
        TargetForm::Authority
    } else {
        TargetForm::Absolute
    };
    // The handler sees the absolute target when the peer sent a scheme and authority, because that is
    // what an HTTP/1.1 client behind a proxy would have produced. A handler that wants the path alone
    // has `:path` in the headers it was given.
    let target = request.absolute_target();
    let mut headers = request.headers.clone();
    // HTTP/2 forbids `Connection` (§8.2.2). A handler that reasons about keep-alive must not see a
    // header HTTP/1.1 would have set and HTTP/2 cannot express.
    headers.remove(http::header::CONNECTION);

    IncomingRequest {
        method: request.method.clone(),
        target,
        form,
        version: http::Version::HTTP_2,
        headers,
        body: body_kind(),
    }
}

/// What framing a request body has, as the HTTP/1.1 codec's vocabulary describes it.
///
/// HTTP/2 has no transfer coding at all: a body is `DATA` frames terminated by `END_STREAM`. Reporting
/// it as `Chunked` would have told a handler that chunked decoding happened — `transfer-encoding:
/// chunked` in no header map, a chunk-size parser that never ran — and a handler that branched on it
/// would have taken a path this protocol cannot produce.
///
/// `UntilClose` is the honest description: HTTP/2's equivalent of "no declared length" is "delimited by
/// the stream ending", which is exactly what `END_STREAM` is. A handler that asks `BodyKind::Empty`
/// must consult the request's own framing instead, and the two protocols therefore disagree here —
/// which is a truth about the protocols, not a gap in the transport.
fn body_kind() -> BodyKind {
    BodyKind::UntilClose
}

/// The [`BodySource`] adapter over an HTTP/2 stream body.
struct H2BodySource {
    body: netune_http2::server::H2Body,
}

impl BodySource for H2BodySource {
    fn next_chunk(&mut self) -> crate::body::ChunkFuture<'_> {
        Box::pin(async move { Ok(self.body.next_chunk().await) })
    }
}

/// Turn an orchestrator [`Response`] into one the HTTP/2 session writes.
fn translate_response(response: Response) -> H2Response {
    let Response { head, body } = response;
    let mut headers = head.headers;
    // HTTP/2 has no meaning for these and must not receive them (§8.2.2). Dropping them here rather
    // than in the codec keeps the codec's rule ("never forward one") and the orchestrator's
    // convenience ("a handler may set one for HTTP/1.1") from fighting.
    headers.remove(http::header::CONNECTION);
    headers.remove(http::header::TRANSFER_ENCODING);
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::DATE);
    headers.insert(
        http::header::DATE,
        http::HeaderValue::from_str(&crate::date::http_date())
            .unwrap_or_else(|_| http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT")),
    );

    let body = match body {
        ResponseBody::Empty => H2ResponseBody::Empty,
        ResponseBody::Bytes(bytes) if bytes.is_empty() => H2ResponseBody::Empty,
        ResponseBody::Bytes(bytes) => H2ResponseBody::Bytes(bytes),
        ResponseBody::Stream(stream) => {
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(pump(stream, tx));
            H2ResponseBody::Stream(rx)
        }
    };
    H2Response {
        status: head.status,
        headers,
        body,
    }
}

/// Pull a handler's stream into the channel the session reads.
async fn pump(mut stream: Box<dyn BodyStream>, tx: mpsc::Sender<Bytes>) {
    loop {
        match stream.next_chunk().await {
            Ok(Some(chunk)) => {
                if chunk.is_empty() {
                    continue;
                }
                if tx.send(chunk).await.is_err() {
                    return;
                }
            }
            Ok(None) => return,
            // A failing producer closes the body: the head is already on the wire, so the only
            // signal left is a truncated message, and that is what closing the channel means.
            Err(_) => return,
        }
    }
}

/// The adapter that turns the codec's stream events into trace events.
#[derive(Debug)]
struct TraceObserver {
    recorder: TraceCollector,
}

impl SessionObserver for TraceObserver {
    fn observed(&self, stream_id: u32, event: StreamEvent) {
        let (kind, a) = match event {
            StreamEvent::RequestHeadComplete { payload } => {
                (EventKind::RequestHeadComplete, payload)
            }
            // This is a decoded request-body chunk, not a socket read: the
            // socket read belongs to the transport tap, not to the H2 codec.
            StreamEvent::RequestBodyChunk { payload } => (EventKind::ChunkBoundary, payload),
            StreamEvent::RequestBodyEnd => (EventKind::RequestBodyEnd, 0),
            StreamEvent::HandlerEnd { status } => (EventKind::HandlerEnd, u32::from(status)),
            StreamEvent::ResponseHeadSent => (EventKind::ResponseHeadSent, 0),
            StreamEvent::ResponseBodyChunk { payload } => (EventKind::ResponseChunkSent, payload),
            StreamEvent::ResponseEnd => (EventKind::ResponseEnd, 0),
            StreamEvent::Failed { code } => (EventKind::Error, code),
        };
        self.recorder.mark_stream(stream_id, kind, a, 0);
    }
}
