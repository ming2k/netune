//! The request body, as a handler sees it.
//!
//! A handler must be able to read a body in exactly the shapes HTTP/1.1 and HTTP/2 deliver:
//! all at once, chunk by chunk, or not at all. It must also not be able to read past the
//! body, because on a keep-alive connection the bytes after it belong to the next request —
//! a handler that could read them would be a smuggling vector dressed as a convenience.
//!
//! [`RequestBody`] enforces that by construction: it *borrows* the connection's decoder, so
//! the only bytes reachable through it are the body's, and the connection regains sole
//! ownership the moment the handler returns.
//!
//! # Why the body borrows instead of owning
//!
//! If the body owned the reader, a handler that dropped it without draining would leave the
//! connection unable to recover the stream — the transport would have to close
//! unconditionally. Borrowing keeps the connection in charge of the socket, so the transport
//! can drain what the handler ignored and keep the connection alive when it is safe to.
//!
//! # Why the transport is erased
//!
//! A handler is called through `Arc<dyn Handler>`, so its body type cannot be generic over
//! the connection. The stream is boxed once per connection rather than templated per
//! request: one dynamic dispatch per connection is unmeasurable against a body read, while a
//! generic handler would make an application-assembled server impossible to name in a type.
//!
//! # Version independence
//!
//! The body is a [`BodySource`], not an `Http1ServerReader`. That is what lets one handler
//! serve both protocols: HTTP/1.1 decodes chunks, HTTP/2 decodes `DATA` frames and emits
//! `WINDOW_UPDATE`, and the handler sees the same `next_chunk` either way.

use bytes::{Bytes, BytesMut};
use netune_http1::HttpError;
use netune_trace::{EventKind, TraceCollector};

/// The transport a handler's body reader is generic over.
///
/// A blanket trait so [`crate::Handler`] can stay object-safe: the concrete stream is erased at the
/// trait boundary (a handler is called through `Arc<dyn Handler>`, so its body type cannot name the
/// connection), and an implementation never names it.
pub trait AsyncIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncIo for T {}

/// What a body pulls its bytes from.
///
/// Implemented by the HTTP/1.1 connection decoder and by the HTTP/2 stream, so the handler
/// boundary does not name a protocol.
pub(crate) trait BodySource: Send {
    /// The next chunk, or `None` at the end of the body.
    ///
    /// Returns a boxed future because the trait is used behind `&mut dyn BodySource`: the connection
    /// type is erased at the handler boundary, so the returned future cannot name `Self`.
    fn next_chunk(&mut self) -> crate::body::ChunkFuture<'_>;
}

/// The future a [`BodySource`] returns from `next_chunk`.
pub(crate) type ChunkFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Option<Bytes>, HttpError>> + Send + 'a>,
>;

/// The body of one request.
///
/// Reads are bounded by the codec's `max_body_bytes`, so a handler that streams a body never
/// has to enforce the limit itself — an over-long body is an error from
/// [`RequestBody::next_chunk`] rather than something a handler can forget to check.
///
/// Every read is also recorded in the connection's trace: `RequestBodyStart` on the first
/// chunk and `RequestBodyEnd` with the byte total when the body ends, so a served request's
/// body cost is a derivation rather than an estimate.
pub struct RequestBody<'a> {
    source: &'a mut dyn BodySource,
    recorder: TraceCollector,
    /// Bytes read so far, for the trace and for the handler's own accounting.
    read: u64,
    /// Trace stream id. HTTP/1.1 and HTTP/2 use 0; HTTP/3 gives each request
    /// its own exchange id because stream 0 is a valid request stream.
    stream: u32,
    /// Whether the body was fully consumed.
    finished: bool,
    /// Whether `RequestBodyStart` has been recorded (the first byte is the anchor).
    started: bool,
}

impl std::fmt::Debug for RequestBody<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestBody")
            .field("read", &self.read)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<'a> RequestBody<'a> {
    pub(crate) fn new(source: &'a mut dyn BodySource, recorder: TraceCollector) -> Self {
        Self {
            source,
            recorder,
            read: 0,
            stream: 0,
            finished: false,
            started: false,
        }
    }

    /// Construct a body whose trace events belong to `stream`.
    #[cfg(feature = "http3")]
    pub(crate) fn new_at_stream(
        source: &'a mut dyn BodySource,
        recorder: TraceCollector,
        stream: u32,
    ) -> Self {
        Self {
            source,
            recorder,
            read: 0,
            stream,
            finished: false,
            started: false,
        }
    }

    /// Read the next chunk, or `None` at the end of the body.
    ///
    /// # Errors
    ///
    /// Any [`HttpError`] from the codec: a truncated body, a malformed chunk, or a configured
    /// limit exceeded. A caller should treat all of them as terminal for the connection — the
    /// stream's position is unknown after a framing error.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        if self.finished {
            return Ok(None);
        }
        let chunk = self.source.next_chunk().await?;
        match &chunk {
            Some(bytes) => {
                if !self.started {
                    self.started = true;
                    self.record(EventKind::RequestBodyStart, 0);
                }
                self.read += bytes.len() as u64;
                // A handler's body chunk is a decoded protocol boundary, not a
                // socket read; socket reads belong to the transport tap.
                self.record(EventKind::ChunkBoundary, bytes.len());
            }
            None => {
                self.finished = true;
                self.record(EventKind::RequestBodyEnd, self.read as usize);
            }
        }
        Ok(chunk)
    }

    /// Drain the body into one buffer.
    ///
    /// Bounded by `max_body_bytes` at the codec level, so this cannot be used to allocate
    /// without limit by sending a large declared body. A handler that needs a bounded
    /// read of a potentially large upload should use [`RequestBody::read_to_end_within`].
    pub async fn read_to_end(&mut self) -> Result<Bytes, HttpError> {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.next_chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Drain the body, refusing to hold more than `max` bytes in memory.
    ///
    /// An application-level ceiling that is stricter than the transport's: a handler that
    /// parses JSON wants a much smaller bound than the upload limit the operator granted,
    /// and it should be able to say so without the transport guessing on its behalf.
    ///
    /// # Errors
    ///
    /// [`HttpError::LimitExceeded`] when the body exceeds `max`. The bytes already read stay
    /// consumed; the caller should answer `413` and close.
    pub async fn read_to_end_within(&mut self, max: usize) -> Result<Bytes, HttpError> {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.next_chunk().await? {
            if out.len() + chunk.len() > max {
                return Err(HttpError::LimitExceeded("handler body ceiling"));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Whether the body was read to its end.
    ///
    /// A handler that returns with this `false` has not consumed everything; the transport
    /// drains the rest before reusing the connection and closes when draining is unsafe.
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// How many body bytes have been handed to the handler.
    pub const fn bytes_read(&self) -> u64 {
        self.read
    }

    fn record(&self, kind: EventKind, bytes: usize) {
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.recorder.mark_stream(self.stream, kind, bytes, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body source over a fixed list of chunks, so the reader's accounting is testable
    /// without a socket or a codec.
    struct Chunks {
        chunks: std::collections::VecDeque<Bytes>,
    }

    impl BodySource for Chunks {
        fn next_chunk(&mut self) -> ChunkFuture<'_> {
            Box::pin(async move { Ok(self.chunks.pop_front()) })
        }
    }

    fn recorder() -> TraceCollector {
        TraceCollector::start_ingress(64)
    }

    #[tokio::test]
    async fn every_chunk_is_handed_over_and_the_end_is_recorded() {
        let mut source = Chunks {
            chunks: [Bytes::from_static(b"hello"), Bytes::from_static(b" world")]
                .into_iter()
                .collect(),
        };
        let recorder = recorder();
        let mut body = RequestBody::new(&mut source, recorder.clone());
        assert_eq!(
            body.read_to_end().await.expect("body").as_ref(),
            b"hello world"
        );
        assert!(body.is_finished());
        assert_eq!(body.bytes_read(), 11);

        let log = recorder.log();
        assert!(log.first_of(EventKind::RequestBodyStart).is_some());
        assert_eq!(
            log.first_of(EventKind::RequestBodyEnd).map(|event| event.a),
            Some(11)
        );
    }

    #[tokio::test]
    async fn a_handler_ceiling_is_enforced_before_the_buffer_grows_past_it() {
        let mut source = Chunks {
            chunks: [Bytes::from_static(b"0123456789")].into_iter().collect(),
        };
        let mut body = RequestBody::new(&mut source, recorder());
        let error = body
            .read_to_end_within(4)
            .await
            .expect_err("over the handler's own ceiling");
        assert_eq!(error.class(), "limit");
    }

    #[tokio::test]
    async fn reading_a_finished_body_is_not_an_error() {
        let mut source = Chunks {
            chunks: std::collections::VecDeque::new(),
        };
        let mut body = RequestBody::new(&mut source, recorder());
        assert!(body.next_chunk().await.expect("end").is_none());
        assert!(body.next_chunk().await.expect("end again").is_none());
    }
}
