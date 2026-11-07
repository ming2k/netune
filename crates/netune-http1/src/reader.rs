//! Response head and body decoding (client role).
//!
//! Everything here is the response *role*: how to read a status line, and how to
//! decide which framing a response uses. The bytes are decoded by
//! [`crate::stream::Stream`], which the request-direction reader shares, so this
//! module contains no chunked decoding of its own.
//!
//! The reader owns its input and a small receive buffer. Everything it returns
//! is a slice of that buffer, so no copy is made between the socket and the
//! caller. Leftover bytes after the body ends are handed back by
//! [`Http1Reader::into_inner`] — on a pooled connection they belong to the next
//! response, and dropping them would corrupt the stream.

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode, Version};
use tokio::io::AsyncRead;

use crate::error::HttpError;
use crate::head::{BodyKind, IncomingResponse};
use crate::stream::{Stream, framing_headers};

/// Bounds on what a peer may make us allocate or scan.
pub use crate::stream::Limits;

/// Decodes one HTTP/1.x response from `io`.
#[derive(Debug)]
pub struct Http1Reader<R> {
    io: Stream<R>,
}

impl<R: AsyncRead + Unpin> Http1Reader<R> {
    pub fn new(io: R) -> Self {
        Self::with_limits(io, Limits::default())
    }

    pub fn with_limits(io: R, limits: Limits) -> Self {
        Self::with_limits_and_buffer(io, limits, BytesMut::new())
    }

    /// Resume a reader on a pooled connection, seeding the buffer with bytes the
    /// previous response left behind (pipelined or simply already delivered).
    pub fn with_limits_and_buffer(io: R, limits: Limits, buffered: BytesMut) -> Self {
        Self {
            io: Stream::new(io, limits, &buffered),
        }
    }

    /// Recover the transport and any bytes already buffered beyond the body.
    pub fn into_inner(self) -> (R, BytesMut) {
        self.io.split()
    }

    /// Borrow the transport, to write on the same connection this role read from.
    ///
    /// The reader keeps ownership of the receive buffer, so the bytes after the body
    /// survive: on a keep-alive connection they are the next message.
    pub fn transport_mut(&mut self) -> &mut R {
        self.io.transport_mut()
    }

    /// Parse the response head. `request_method` is needed because a `HEAD`
    /// response carries no body regardless of its framing headers.
    pub async fn read_response_head(
        &mut self,
        request_method: &Method,
    ) -> Result<IncomingResponse, HttpError> {
        let status_line = self.io.read_line(self.io.limits.max_head_bytes).await?;
        let status_line = std::str::from_utf8(&status_line)
            .map_err(|_| HttpError::Protocol("status line is not UTF-8"))?;
        let mut parts = status_line.splitn(3, ' ');
        let version = match parts.next() {
            Some("HTTP/1.1") => Version::HTTP_11,
            Some("HTTP/1.0") => Version::HTTP_10,
            _ => return Err(HttpError::Protocol("unsupported HTTP version")),
        };
        let code = parts
            .next()
            .ok_or(HttpError::Protocol("status line has no status code"))?;
        let status = code
            .parse::<u16>()
            .ok()
            .filter(|code| (100..1000).contains(code))
            .and_then(|code| StatusCode::from_u16(code).ok())
            .ok_or(HttpError::Protocol("invalid status code"))?;

        let headers = self.io.read_header_block(status_line.len()).await?;
        let body = Self::body_kind(&headers, &status, request_method)?;
        self.io.set_body(body);
        Ok(IncomingResponse {
            version,
            status,
            headers,
            body,
        })
    }

    fn body_kind(
        headers: &HeaderMap,
        status: &StatusCode,
        request_method: &Method,
    ) -> Result<BodyKind, HttpError> {
        if request_method == Method::HEAD || crate::head::ResponseHead::status_forbids_body(*status)
        {
            return Ok(BodyKind::Empty);
        }
        let (chunked, lengths) = framing_headers(headers);
        if chunked {
            if !lengths.is_empty() {
                // RFC 9112 §6.1 lets transfer-encoding win, but a message with
                // both is the classic smuggling shape: refuse it.
                return Err(HttpError::Protocol(
                    "both transfer-encoding and content-length",
                ));
            }
            return Ok(BodyKind::Chunked);
        }
        if !lengths.is_empty() {
            if lengths.iter().any(|len| *len != lengths[0]) {
                return Err(HttpError::Protocol("conflicting content-length headers"));
            }
            return Ok(BodyKind::Length(lengths[0]));
        }
        Ok(BodyKind::UntilClose)
    }

    /// Read the next body bytes, or `None` at the end of the body.
    ///
    /// The returned slice may be smaller than the remaining body; call again.
    pub async fn read_body_chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        self.io.read_body_chunk().await
    }

    /// Drain the body into one buffer, bounded by [`Limits::max_body_bytes`].
    pub async fn read_body_to_end(&mut self) -> Result<Bytes, HttpError> {
        self.io.read_body_to_end().await
    }
}
