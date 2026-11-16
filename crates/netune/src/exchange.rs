//! The request-level seam: one request in, one response head and body out.
//!
//! Everything above this trait is protocol-neutral. [`crate::Client`] plans
//! the attempt, follows redirects, decodes the body and owns the trace; it
//! never names HTTP/1.1, HTTP/2 or a socket. Everything below it is one way of
//! producing an [`Exchange`]: [`crate::Wire`] dials and pools real
//! connections, [`crate::mock::Mock`] answers from a script. A new protocol,
//! or a new way of faking one, is a new implementation of [`RoundTrip`] or of
//! [`BodySource`], never a new branch in the client ([`INV-EXCHANGE-01`]).
//!
//! The seam is deliberately at the *request* level rather than the byte
//! level. A byte-level fake has to speak a wire protocol to say "answer 503";
//! a request-level one says it directly, and still produces a real trace,
//! because the events are recorded by the layers on either side of the seam.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use http::Method;
use netune_http1::{IncomingResponse, RequestHead};
use netune_trace::{ConnectionInfo, TapArtifact, TraceCollector};

use crate::client::ClientConfig;
use crate::connect::Established;
use crate::error::NetError;
use crate::profile::ConnectionPlan;

/// A boxed, sendable future: the object-safe form of an `async fn`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An incremental producer of request-body bytes for streaming uploads.
pub trait RequestBodySource: Send {
    /// Produce the next request-body chunk, or `None` when the upload ends.
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>>;
}

impl RequestBodySource for tokio::sync::mpsc::Receiver<Result<Bytes, NetError>> {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>> {
        Box::pin(async move {
            match self.recv().await {
                Some(Ok(chunk)) => Ok(Some(chunk)),
                Some(Err(error)) => Err(error),
                None => Ok(None),
            }
        })
    }
}

impl RequestBodySource for tokio::sync::mpsc::Receiver<Bytes> {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>> {
        Box::pin(async move { Ok(self.recv().await) })
    }
}

struct StreamBodyState {
    source: Option<Box<dyn RequestBodySource>>,
    consumed: bool,
}

/// Handle to a single-use streaming request body.
#[derive(Clone)]
pub struct RequestStream {
    inner: Arc<Mutex<StreamBodyState>>,
}

impl std::fmt::Debug for RequestStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("RequestStream")
            .field("consumed", &state.consumed)
            .finish()
    }
}

impl RequestStream {
    fn new(source: Box<dyn RequestBodySource>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StreamBodyState {
                source: Some(source),
                consumed: false,
            })),
        }
    }

    fn is_consumed(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .consumed
    }

    fn take(&self) -> Result<Box<dyn RequestBodySource>, NetError> {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.consumed = true;
        state.source.take().ok_or_else(|| {
            NetError::Protocol(
                "cannot replay a streaming request body that was already consumed".into(),
            )
        })
    }
}

/// A request body: buffered (replayable) or streaming (single-use once started).
#[derive(Debug, Clone, Default)]
pub enum RequestBody {
    /// No body.
    #[default]
    Empty,
    /// A body held in memory.
    Full(Bytes),
    /// A streaming request body pulled incrementally during upload.
    Stream(RequestStream),
}

impl RequestBody {
    /// Construct a streaming request body from any [`RequestBodySource`].
    pub fn stream(source: impl RequestBodySource + 'static) -> Self {
        Self::Stream(RequestStream::new(Box::new(source)))
    }

    /// Construct a streaming request body from a boxed [`RequestBodySource`].
    pub fn stream_boxed(source: Box<dyn RequestBodySource>) -> Self {
        Self::Stream(RequestStream::new(source))
    }

    /// The buffered body bytes, when this body is held in memory.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Empty | Self::Stream(_) => None,
            Self::Full(bytes) => Some(bytes),
        }
    }

    /// Known byte length for buffered bodies, or `None` for a stream.
    pub fn known_len(&self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::Full(bytes) => Some(bytes.len()),
            Self::Stream(_) => None,
        }
    }

    /// Whether there is definitely no body (false for streaming bodies).
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty) || matches!(self, Self::Full(bytes) if bytes.is_empty())
    }

    /// Whether this body can still be sent (again) on a redirect or replay.
    pub fn can_replay(&self) -> bool {
        match self {
            Self::Empty | Self::Full(_) => true,
            Self::Stream(stream) => !stream.is_consumed(),
        }
    }

    /// Take the streaming source for transmission, marking this body consumed.
    pub fn take_stream(&self) -> Result<Option<Box<dyn RequestBodySource>>, NetError> {
        match self {
            Self::Empty | Self::Full(_) => Ok(None),
            Self::Stream(stream) => stream.take().map(Some),
        }
    }

    /// Collect a buffered or streaming body into contiguous bytes (for mocks or tests).
    pub async fn collect_bytes(&self) -> Result<Bytes, NetError> {
        match self {
            Self::Empty => Ok(Bytes::new()),
            Self::Full(bytes) => Ok(bytes.clone()),
            Self::Stream(stream) => {
                let mut source = stream.take()?;
                let mut out = BytesMut::new();
                while let Some(chunk) = source.next_chunk().await? {
                    out.extend_from_slice(&chunk);
                }
                Ok(out.freeze())
            }
        }
    }
}

impl From<Option<Bytes>> for RequestBody {
    fn from(body: Option<Bytes>) -> Self {
        body.map_or(Self::Empty, Self::Full)
    }
}

impl From<Bytes> for RequestBody {
    fn from(body: Bytes) -> Self {
        Self::Full(body)
    }
}

impl From<Vec<u8>> for RequestBody {
    fn from(body: Vec<u8>) -> Self {
        Self::Full(Bytes::from(body))
    }
}

impl From<String> for RequestBody {
    fn from(body: String) -> Self {
        Self::Full(Bytes::from(body))
    }
}

impl From<&'static str> for RequestBody {
    fn from(body: &'static str) -> Self {
        Self::Full(Bytes::from_static(body.as_bytes()))
    }
}

impl From<&'static [u8]> for RequestBody {
    fn from(body: &'static [u8]) -> Self {
        Self::Full(Bytes::from_static(body))
    }
}

/// One request as a transport sees it: head and body, nothing about how it
/// travels.
#[derive(Debug, Clone)]
pub struct Request {
    pub head: RequestHead,
    pub body: RequestBody,
}

impl Request {
    pub fn new(head: RequestHead, body: impl Into<RequestBody>) -> Self {
        Self {
            head,
            body: body.into(),
        }
    }

    /// Whether sending this request a second time is safe when the first copy
    /// may have reached the origin.
    ///
    /// True for the methods RFC 9110 §9.2.2 defines as idempotent, and for a
    /// request that carries an `Idempotency-Key`: the caller has told the
    /// origin how to de-duplicate it. Everything else — a bare `POST` above
    /// all — is replayed only when the peer itself says it did not process the
    /// request ([`INV-TRANSPORT-06`]).
    pub fn is_replay_safe(&self) -> bool {
        if !self.body.can_replay() {
            return false;
        }
        let idempotent = [
            Method::GET,
            Method::HEAD,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
            Method::TRACE,
        ]
        .contains(&self.head.method);
        idempotent || self.has_header("idempotency-key") || self.has_header("x-idempotency-key")
    }

    fn has_header(&self, name: &str) -> bool {
        self.head.headers.contains_key(name)
            || self.head.raw_headers.as_ref().is_some_and(|raw| {
                raw.iter()
                    .any(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            })
    }
}

/// How finely the attempt asked to be observed. The transport installs the
/// matching socket tap; the artifact it hands back decides the fidelity the
/// trace may claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationLevel {
    Off,
    Counters,
    Traced,
}

/// Everything a transport needs to carry out one hop of one attempt.
#[derive(Debug, Clone, Copy)]
pub struct Attempt<'a> {
    /// The resolved plan: target, connection identity and wire profiles.
    pub plan: &'a ConnectionPlan,
    /// The attempt's control recorder. Disabled unless the attempt is traced.
    pub recorder: &'a TraceCollector,
    pub observation: ObservationLevel,
    /// The client's policy: limits and bounds.
    pub config: &'a ClientConfig,
    /// Absolute deadline for the whole attempt, including the response body.
    ///
    /// `None` only when the caller deliberately removed every bound. A
    /// transport that performs a long-poll or a long upload must not use this
    /// as a per-operation timeout; it is the outer ceiling.
    pub deadline: Option<tokio::time::Instant>,
}

/// What a transport hands back when a body gives up its connection.
#[derive(Debug)]
pub struct Released {
    /// What the socket tap recorded for this exchange. A transport without a
    /// socket (a mock, a multiplexed stream) returns [`TapArtifact::None`].
    pub artifact: TapArtifact,
}

impl Released {
    /// Nothing was tapped.
    pub const fn untapped() -> Self {
        Self {
            artifact: TapArtifact::None,
        }
    }
}

/// One protocol's incremental reader over a response body.
///
/// The chunks are the body as framed on the wire, still `Content-Encoding`
/// encoded; decoding, limits and trace marks belong to [`crate::Body`], which
/// is the same for every implementation.
pub trait BodySource: Send {
    /// The next chunk, or `None` at the end of the body.
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>>;

    /// Give up the transport.
    ///
    /// `complete` is true only when the body was read to its end; a transport
    /// may then keep its connection for another request. An incomplete body
    /// leaves the connection in an unknown position and it must not be reused.
    fn release(self: Box<Self>, complete: bool) -> Released;
}

/// The result of one round trip: a response head and a body still to be read.
pub struct Exchange {
    pub head: IncomingResponse,
    pub body: Box<dyn BodySource>,
    /// Provenance of the connection that served the exchange.
    pub connection: ConnectionInfo,
}

/// Something that can turn a request into a response.
///
/// Implementations record the phases they perform into
/// [`Attempt::recorder`]; a failure is returned *after* its diagnostic has
/// been recorded, so the caller's snapshot explains it.
pub trait RoundTrip: Send + Sync + 'static {
    /// Send `request` and return the response head with its unread body.
    fn round_trip<'a>(
        &'a self,
        attempt: Attempt<'a>,
        request: &'a Request,
    ) -> BoxFuture<'a, Result<Exchange, NetError>>;

    /// Open a dedicated byte stream to the attempt's target, for a protocol
    /// that takes the connection over (a WebSocket upgrade). The stream is
    /// never pooled.
    fn open_stream<'a>(
        &'a self,
        attempt: Attempt<'a>,
    ) -> BoxFuture<'a, Result<Established, NetError>>;

    /// Establish a connection for the attempt's target ahead of need.
    /// Returns whether anything was opened.
    fn prewarm<'a>(&'a self, attempt: Attempt<'a>) -> BoxFuture<'a, Result<bool, NetError>> {
        let _ = attempt;
        Box::pin(async { Ok(false) })
    }

    /// A stable description of the socket shape this transport applies, folded
    /// into the connection identity.
    fn socket_shape(&self) -> Option<String> {
        None
    }

    /// A stable description of a non-direct route, folded into the connection
    /// identity.
    fn route_shape(&self) -> Option<String> {
        None
    }
}

impl<T: RoundTrip + ?Sized> RoundTrip for std::sync::Arc<T> {
    fn round_trip<'a>(
        &'a self,
        attempt: Attempt<'a>,
        request: &'a Request,
    ) -> BoxFuture<'a, Result<Exchange, NetError>> {
        (**self).round_trip(attempt, request)
    }

    fn open_stream<'a>(
        &'a self,
        attempt: Attempt<'a>,
    ) -> BoxFuture<'a, Result<Established, NetError>> {
        (**self).open_stream(attempt)
    }

    fn prewarm<'a>(&'a self, attempt: Attempt<'a>) -> BoxFuture<'a, Result<bool, NetError>> {
        (**self).prewarm(attempt)
    }

    fn socket_shape(&self) -> Option<String> {
        (**self).socket_shape()
    }

    fn route_shape(&self) -> Option<String> {
        (**self).route_shape()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_transport_06_only_idempotent_or_keyed_requests_are_replay_safe() {
        let get = Request::new(RequestHead::new(Method::GET, "/"), RequestBody::Empty);
        assert!(get.is_replay_safe());

        let post = Request::new(RequestHead::new(Method::POST, "/"), "payload");
        assert!(!post.is_replay_safe());

        let keyed = Request::new(
            RequestHead::new(Method::POST, "/").with_header("idempotency-key", "k-1"),
            "payload",
        );
        assert!(keyed.is_replay_safe());

        let raw_keyed = Request::new(
            RequestHead::new(Method::POST, "/").with_raw_header("Idempotency-Key", "k-2"),
            "payload",
        );
        assert!(raw_keyed.is_replay_safe());

        let (_tx, rx) = tokio::sync::mpsc::channel::<Bytes>(2);
        let streamed_put = Request::new(
            RequestHead::new(Method::PUT, "/upload"),
            RequestBody::stream(rx),
        );
        assert!(streamed_put.is_replay_safe());
        let _ = streamed_put.body.take_stream().expect("take once");
        assert!(
            !streamed_put.is_replay_safe(),
            "a consumed stream must not be replayed"
        );
    }

    #[test]
    fn request_bodies_convert_from_the_shapes_callers_hold() {
        assert!(RequestBody::from(None::<Bytes>).is_empty());
        assert_eq!(
            RequestBody::from(Some(Bytes::from_static(b"ab"))).known_len(),
            Some(2)
        );
        assert_eq!(RequestBody::from("abc").as_bytes(), Some(&b"abc"[..]));
        assert_eq!(RequestBody::from(vec![1u8, 2]).known_len(), Some(2));
    }
}
