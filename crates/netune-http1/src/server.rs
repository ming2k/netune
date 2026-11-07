//! Request head and body decoding (server role).
//!
//! The mirror of [`crate::reader`]: a request line instead of a status line, and
//! the framing rules a *request* obeys instead of the ones a response obeys.
//! Byte decoding is [`crate::stream::Stream`], shared with the client role, so
//! the chunked decoder exists once (`[INV-SERVER-04]`).
//!
//! # Why the request role is stricter, not just different
//!
//! A server reads a start line from someone it did not choose. Four rules differ
//! from the response direction, and every one of them is a hardening rule rather
//! than a formatting preference:
//!
//! 1. **No close-delimited request bodies.** RFC 9112 §6.3 permits
//!    `UntilClose` only for responses. A request that declares neither
//!    `Content-Length` nor `Transfer-Encoding` has no body, full stop — treating
//!    the remainder of the socket as a body would let a client write one request
//!    and have the server consume the next one's bytes as payload.
//! 2. **`Content-Length` and `Transfer-Encoding` together is refused.** The
//!    same smuggling shape the response direction refuses, and here the
//!    consequence is worse: two intermediaries disagreeing about the framing of a
//!    *request* is the canonical CL.TE / TE.CL desync.
//! 3. **`Transfer-Encoding` must end in `chunked`.** RFC 9112 §6.1 requires it;
//!    a request whose final coding is not `chunked` cannot be framed, and
//!    guessing has no safe answer.
//! 4. **The target is kept as bytes.** An origin-form target is not a
//!    `http::Uri` until something routes on it; rejecting a request because its
//!    path is not URI-shaped would be the codec making a policy decision that
//!    belongs to the handler.
//!
//! # What this does not do
//!
//! No routing, no `Host` validation, no method allow-list, no timeouts. Every one
//! of those is policy and belongs to `netune-server`, which is the crate that
//! knows it is listening.

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, Version};
use tokio::io::AsyncRead;

use crate::error::HttpError;
use crate::head::{BodyKind, IncomingRequest};
use crate::stream::{Stream, framing_headers};

pub use crate::stream::Limits;

/// Decodes HTTP/1.x requests from `io`.
#[derive(Debug)]
pub struct Http1ServerReader<R> {
    io: Stream<R>,
}

impl<R: AsyncRead + Unpin> Http1ServerReader<R> {
    /// A reader with [`Limits::for_ingress`] bounds.
    ///
    /// The tight defaults are not a courtesy: this constructor is the one a
    /// listener should use, and `Limits::default` was sized for a client's small
    /// set of known origins.
    pub fn new(io: R) -> Self {
        Self::with_limits(io, Limits::for_ingress())
    }

    pub fn with_limits(io: R, limits: Limits) -> Self {
        Self::with_limits_and_buffer(io, limits, BytesMut::new())
    }

    /// Resume a reader on a keep-alive connection, seeding the buffer with bytes
    /// the previous request left behind (pipelined or already delivered).
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

    /// Parse the next request head.
    ///
    /// Returns [`HttpError::Incomplete`] when the peer closed cleanly before a
    /// request line arrived, which is a normal end of a keep-alive connection
    /// rather than a protocol violation — the orchestrator distinguishes them by
    /// [`HttpError::class`].
    pub async fn read_request_head(&mut self) -> Result<IncomingRequest, HttpError> {
        let request_line = self.io.read_line(self.io.limits.max_head_bytes).await?;
        if request_line.is_empty() {
            // RFC 9112 §2.2 allows a server to ignore at least one empty line
            // before the request line (a legacy client's habit), but an empty
            // line where a request should begin is otherwise the end of the
            // connection.
            return Err(HttpError::Incomplete("empty request line"));
        }
        let request_line = std::str::from_utf8(&request_line)
            .map_err(|_| HttpError::Protocol("request line is not UTF-8"))?;

        // `METHOD SP request-target SP HTTP-version` — the target may not contain
        // a space, so splitting from the right is unambiguous and tolerates no
        // stray whitespace in the middle.
        let mut parts = request_line.split(' ');
        let method = parts
            .next()
            .filter(|method| !method.is_empty())
            .ok_or(HttpError::Protocol("request line has no method"))?;
        let target = parts
            .next()
            .filter(|target| !target.is_empty())
            .ok_or(HttpError::Protocol("request line has no target"))?;
        let version = parts
            .next()
            .ok_or(HttpError::Protocol("request line has no version"))?;
        if parts.next().is_some() {
            return Err(HttpError::Protocol("request line has too many parts"));
        }
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| HttpError::Protocol("invalid request method"))?;
        let version = match version {
            "HTTP/1.1" => Version::HTTP_11,
            "HTTP/1.0" => Version::HTTP_10,
            _ => return Err(HttpError::Protocol("unsupported HTTP version")),
        };

        // The target grammar is checked before the header block is read, so a peer that
        // sends an unservable start line costs one line rather than a whole head
        // (RFC 9112 §3.2, and the smuggling surface it exists to close).
        let form = crate::target::classify(&method, target.as_bytes())
            .map_err(|error| HttpError::Protocol(error.reason()))?;

        let headers = self.io.read_header_block(request_line.len()).await?;
        let body = Self::body_kind(&method, &headers)?;
        self.io.check_declared_length(body)?;
        self.io.set_body(body);

        Ok(IncomingRequest {
            method,
            target: Bytes::copy_from_slice(target.as_bytes()),
            form,
            version,
            headers,
            body,
        })
    }

    /// Which framing a *request* uses. See the module docs for why each refusal
    /// exists.
    fn body_kind(method: &Method, headers: &HeaderMap) -> Result<BodyKind, HttpError> {
        let (chunked, lengths) = framing_headers(headers);
        let has_transfer_encoding = headers.contains_key(http::header::TRANSFER_ENCODING);
        // RFC 9110 §9.3.6: a `CONNECT` request has no body. Accepting one would frame
        // bytes that belong to the tunnel this request is trying to open.
        if method == Method::CONNECT && (chunked || !lengths.is_empty()) {
            return Err(HttpError::Protocol(
                "a CONNECT request may not carry a body",
            ));
        }
        if chunked {
            if !lengths.is_empty() {
                return Err(HttpError::Protocol(
                    "both transfer-encoding and content-length",
                ));
            }
            // RFC 9112 §6.1: chunked must be the final coding, or the message
            // cannot be framed at all.
            let final_coding = headers
                .get_all(http::header::TRANSFER_ENCODING)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .rfind(|coding| !coding.is_empty());
            if final_coding.is_none_or(|coding| !coding.eq_ignore_ascii_case("chunked")) {
                return Err(HttpError::Protocol(
                    "transfer-encoding does not end in chunked",
                ));
            }
            return Ok(BodyKind::Chunked);
        }
        if has_transfer_encoding {
            // RFC 9112 §6.1: a request whose `Transfer-Encoding` does not include
            // `chunked` cannot be framed, and a server must not guess — the
            // alternatives are "consume the socket as a body" (which eats the next
            // request) and "ignore the body" (which leaves it in the stream).
            return Err(HttpError::Protocol("unsupported request transfer-encoding"));
        }
        if !lengths.is_empty() {
            if lengths.iter().any(|len| *len != lengths[0]) {
                return Err(HttpError::Protocol("conflicting content-length headers"));
            }
            return Ok(BodyKind::Length(lengths[0]));
        }
        // No framing headers: a request has no body. Never `UntilClose`.
        Ok(BodyKind::Empty)
    }

    /// Read the next body bytes, or `None` at the end of the body.
    pub async fn read_body_chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        self.io.read_body_chunk().await
    }

    /// Drain the body into one buffer, bounded by [`Limits::max_body_bytes`].
    pub async fn read_body_to_end(&mut self) -> Result<Bytes, HttpError> {
        self.io.read_body_to_end().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_of(headers: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).expect("name"),
                http::header::HeaderValue::from_str(value).expect("value"),
            );
        }
        map
    }

    #[test]
    fn a_request_without_framing_headers_has_no_body() {
        let headers = head_of(&[("host", "example.com")]);
        assert_eq!(
            Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &headers)
                .expect("framed"),
            BodyKind::Empty,
            "a request is never close-delimited"
        );
    }

    #[test]
    fn a_content_length_request_declares_its_body() {
        let headers = head_of(&[("content-length", "5")]);
        assert_eq!(
            Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &headers)
                .expect("framed"),
            BodyKind::Length(5)
        );
    }

    #[test]
    fn a_chunked_request_is_chunked() {
        let headers = head_of(&[("transfer-encoding", "chunked")]);
        assert_eq!(
            Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &headers)
                .expect("framed"),
            BodyKind::Chunked
        );
    }

    #[test]
    fn a_transfer_encoding_not_ending_in_chunked_is_refused() {
        let headers = head_of(&[("transfer-encoding", "gzip")]);
        let error = Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &headers)
            .expect_err("refused");
        assert_eq!(error.class(), "protocol");
    }

    #[test]
    fn a_chunked_among_other_codings_is_accepted_only_when_final() {
        let final_chunked = head_of(&[("transfer-encoding", "gzip, chunked")]);
        assert_eq!(
            Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &final_chunked)
                .expect("framed"),
            BodyKind::Chunked
        );
        let not_final = head_of(&[("transfer-encoding", "chunked, gzip")]);
        assert!(
            Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &not_final).is_err()
        );
    }

    #[test]
    fn both_framing_headers_is_the_smuggling_shape_and_is_refused() {
        let headers = head_of(&[("content-length", "5"), ("transfer-encoding", "chunked")]);
        let error = Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &headers)
            .expect_err("refused");
        assert_eq!(error.class(), "protocol");
    }

    #[test]
    fn conflicting_content_lengths_are_refused() {
        let headers = head_of(&[("content-length", "5"), ("content-length", "6")]);
        assert!(Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &headers).is_err());
    }

    #[test]
    fn agreeing_duplicate_content_lengths_are_tolerated() {
        // RFC 9112 §6.3 permits a repeated identical value.
        let headers = head_of(&[("content-length", "5"), ("content-length", "5")]);
        assert_eq!(
            Http1ServerReader::<tokio::io::Empty>::body_kind(&Method::GET, &headers)
                .expect("framed"),
            BodyKind::Length(5)
        );
    }
}
