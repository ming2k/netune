//! The handler boundary: the one place application code is called.
//!
//! Deliberately a trait with one method and a boxed future, not an extractor pipeline. A
//! transport that knows how to call a function and stream a body is useful to every
//! application; a transport that knows how an application routes, deserializes and
//! authorizes is useful to exactly one.
//!
//! ```text
//!   Server ──► Handler::handle(IncomingRequest, RequestBody) ──► Response
//!                    ▲                                            │
//!                    └─ the only application code the transport runs
//!                                                                 ├── buffered body
//!                                                                 └── streamed body
//! ```
//!
//! # A response is a head plus a body that may still be arriving
//!
//! [`ResponseBody`] has three shapes, and the third is the one that makes this a
//! production transport: a [`BodyStream`] is pulled chunk by chunk *by the transport*, so a
//! server-sent-events feed, an LLM token stream or a generated file is written as it is
//! produced rather than buffered to completion first. The transport keeps ownership of the
//! socket, which is what lets it apply the write timeout and the framing rules to every
//! chunk a handler produces.
//!
//! # A panicking handler is a failed request, not a failed connection
//!
//! The transport wraps every call in [`catch_unwind`], so a handler that panics gets a
//! `500` (when a response can still be written) and the connection is closed cleanly. The
//! alternative — letting the panic unwind through the connection task — turns an
//! application bug into a dropped socket with no status line, which a client cannot
//! distinguish from a network failure and cannot retry on.
//!
//! [`catch_unwind`]: crate::panic::CatchPanic

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use netune_http1::{BodyKind, IncomingRequest, ResponseHead};

/// One chunk pulled from a streaming response body.
///
/// `Ok(None)` ends the body. An error ends it *and* the connection: mid-body there is no
/// way to signal a failure to the peer other than to stop, so a stream that errors after
/// its head was sent leaves the peer with a truncated message and that is the honest
/// outcome.
pub type ChunkResult = Result<Option<Bytes>, std::io::Error>;

/// The future a [`BodyStream`] returns from `next_chunk`.
pub type ChunkFuture<'a> = Pin<Box<dyn Future<Output = ChunkResult> + Send + 'a>>;

/// A response body produced incrementally.
///
/// Object-safe by construction: one method, one boxed future, no generics. A handler that
/// has a concrete async stream (an `mpsc` receiver of tokens, a file reader, a decompressor)
/// wraps it in an implementation of this trait; the transport pulls from it and never knows
/// what is behind it.
pub trait BodyStream: Send {
    /// The next chunk, or `None` at the end of the body.
    fn next_chunk(&mut self) -> ChunkFuture<'_>;
}

impl BodyStream for tokio::sync::mpsc::Receiver<Bytes> {
    fn next_chunk(&mut self) -> ChunkFuture<'_> {
        Box::pin(async move { Ok(self.recv().await) })
    }
}

/// The body of a response the transport writes.
pub enum ResponseBody {
    /// No body at all.
    Empty,
    /// A body already in memory, framed by `Content-Length`.
    Bytes(Bytes),
    /// A body the transport pulls from as it is produced, framed by `Transfer-Encoding:
    /// chunked` on HTTP/1.1 and by `END_STREAM` on HTTP/2.
    Stream(Box<dyn BodyStream>),
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("ResponseBody::Empty"),
            Self::Bytes(bytes) => f.debug_tuple("ResponseBody::Bytes").field(bytes).finish(),
            Self::Stream(_) => f.write_str("ResponseBody::Stream(..)"),
        }
    }
}

impl ResponseBody {
    /// `true` when there is nothing to write.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Bytes(bytes) => bytes.is_empty(),
            Self::Stream(_) => false,
        }
    }
}

/// What a handler produces: a head plus the body that goes with it.
#[derive(Debug)]
pub struct Response {
    pub head: ResponseHead,
    pub body: ResponseBody,
}

impl Response {
    /// A `200 OK` with the given bytes.
    pub fn ok(body: impl Into<Bytes>) -> Self {
        let body = body.into();
        let head = ResponseHead::new(http::StatusCode::OK).with_body(&body);
        Self {
            head,
            body: ResponseBody::Bytes(body),
        }
    }

    /// A response with an explicit status and body.
    ///
    /// A status that forbids a body (`1xx`, `204`, `304`) loses the body and its
    /// `Content-Length`: emitting a body under such a status would make the peer read the
    /// next response's head out of this one's payload.
    pub fn with_status(status: http::StatusCode, body: impl Into<Bytes>) -> Self {
        let body = body.into();
        if ResponseHead::status_forbids_body(status) {
            let mut head = ResponseHead::new(status);
            head.body = BodyKind::Empty;
            head.headers.remove(http::header::CONTENT_LENGTH);
            return Self {
                head,
                body: ResponseBody::Empty,
            };
        }
        let head = ResponseHead::new(status).with_body(&body);
        Self {
            head,
            body: ResponseBody::Bytes(body),
        }
    }

    /// A streaming response: the head is written first, then every chunk as it is produced.
    ///
    /// The head's framing is forced to chunked so the peer can tell where the body ends
    /// without the connection being closed. A status that forbids a body keeps it forbidden:
    /// the stream is dropped and the message is head-only, because the alternative is
    /// writing bytes a peer will read as the next response.
    pub fn stream(status: http::StatusCode, stream: impl BodyStream + 'static) -> Self {
        Self::stream_boxed(status, Box::new(stream))
    }

    /// [`Response::stream`] for a body a handler already holds as a trait object.
    pub fn stream_boxed(status: http::StatusCode, stream: Box<dyn BodyStream>) -> Self {
        if ResponseHead::status_forbids_body(status) {
            let mut head = ResponseHead::new(status);
            head.body = BodyKind::Empty;
            head.headers.remove(http::header::CONTENT_LENGTH);
            return Self {
                head,
                body: ResponseBody::Empty,
            };
        }
        let head = ResponseHead::new(status).with_chunked_body();
        Self {
            head,
            body: ResponseBody::Stream(stream),
        }
    }

    /// A `500 Internal Server Error` with an empty body.
    ///
    /// Empty on purpose: a transport-authored error must not leak handler internals to a
    /// peer. A handler that wants to explain itself calls [`Response::with_status`].
    pub fn internal_error() -> Self {
        Self::with_status(http::StatusCode::INTERNAL_SERVER_ERROR, Bytes::new())
    }

    /// A `408 Request Timeout`.
    pub fn timeout() -> Self {
        Self::with_status(http::StatusCode::REQUEST_TIMEOUT, Bytes::new())
    }

    /// A `501 Not Implemented`.
    ///
    /// The transport's answer to a request it understood and will not serve — a `CONNECT` tunnel it
    /// cannot open, because it never dials a peer. Distinct from `500`: nothing went wrong, the
    /// capability is simply absent, and a client should not retry it.
    pub fn not_implemented() -> Self {
        Self::with_status(http::StatusCode::NOT_IMPLEMENTED, Bytes::new())
    }

    /// A `400 Bad Request`.
    pub fn bad_request() -> Self {
        Self::with_status(http::StatusCode::BAD_REQUEST, Bytes::new())
    }

    /// A `431 Request Header Fields Too Large`.
    pub fn headers_too_large() -> Self {
        Self::with_status(
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Bytes::new(),
        )
    }

    /// A `413 Content Too Large`.
    pub fn content_too_large() -> Self {
        Self::with_status(http::StatusCode::PAYLOAD_TOO_LARGE, Bytes::new())
    }

    /// Add a header to the response.
    #[must_use]
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.head = self.head.with_header(name, value);
        self
    }
}

/// A boxed future a handler returns.
///
/// Boxed rather than an associated type because the trait must stay object-safe: a server
/// holds one `Arc<dyn Handler>`, and a generic `Handler` would force the listener to be
/// generic over the application, which makes an application-assembled server impossible to
/// name in a type.
pub type HandlerFuture<'a> = Pin<Box<dyn Future<Output = Response> + Send + 'a>>;

/// The application boundary.
///
/// Implemented by application code; called by the transport exactly once per request, after
/// the head has been parsed and within the configured bounds.
///
/// # Contract
///
/// - The request head is complete and within `ServerConfig::limits` when `handle` is called.
/// - The body is correctly framed and bounded, but is **not** guaranteed to have been read.
///   A handler may ignore it; the transport drains it before reusing the connection.
/// - A [`ResponseBody::Stream`] may be returned while the request body is still unread; the
///   transport drains it first, so the stream starts at a known position. A handler that
///   wants full duplex must buffer or spawn, because HTTP/1.1 framing has one direction at a
///   time in this transport by construction.
/// - The transport bounds the total time `handle` may take. A handler that exceeds
///   `ServerConfig::handler_timeout` is abandoned, answered with `500` where possible, and
///   its connection closed.
/// - A handler that panics is contained: the transport answers `500` where it still can and
///   closes the connection. A panic is never allowed to reach the accept loop.
pub trait Handler: Send + Sync + 'static {
    /// Answer one request.
    fn handle<'a>(
        &'a self,
        request: IncomingRequest,
        body: crate::body::RequestBody<'a>,
    ) -> HandlerFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bodyless_status_loses_the_body_it_was_given() {
        let response = Response::with_status(http::StatusCode::NO_CONTENT, &b"ignored"[..]);
        assert_eq!(response.head.body, BodyKind::Empty);
        assert!(
            !response
                .head
                .headers
                .contains_key(http::header::CONTENT_LENGTH),
            "a 204 must not declare a length"
        );
        assert!(response.body.is_empty());
    }

    #[test]
    fn a_normal_status_keeps_its_body_and_length() {
        let response = Response::with_status(http::StatusCode::CREATED, &b"hi"[..]);
        assert_eq!(response.head.body, BodyKind::Length(2));
        assert_eq!(
            response
                .head
                .headers
                .get(http::header::CONTENT_LENGTH)
                .expect("length"),
            "2"
        );
    }

    #[test]
    fn a_streaming_response_declares_chunked_framing() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(tx);
        let response = Response::stream(http::StatusCode::OK, rx);
        assert_eq!(response.head.body, BodyKind::Chunked);
        assert!(
            !response
                .head
                .headers
                .contains_key(http::header::CONTENT_LENGTH),
            "chunked and length are exclusive"
        );
    }

    #[test]
    fn a_streaming_response_for_a_bodyless_status_loses_the_stream() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(tx);
        let response = Response::stream(http::StatusCode::NO_CONTENT, rx);
        assert_eq!(response.head.body, BodyKind::Empty);
        assert!(response.body.is_empty());
    }

    #[test]
    fn ok_declares_the_exact_length() {
        let response = Response::ok(&b"hello"[..]);
        assert_eq!(response.head.status, http::StatusCode::OK);
        assert_eq!(response.head.body, BodyKind::Length(5));
    }
}
