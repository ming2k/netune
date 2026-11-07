//! The framing core: one body state machine, two message roles.
//!
//! HTTP/1.1's body framing is direction-agnostic. `Content-Length`, chunked
//! transfer coding, the trailer drain, the bounded line reader and the
//! `Transfer-Encoding`/`Content-Length` conflict rule are the same bytes
//! whether you are reading a response or a request. Only two things differ
//! between the roles:
//!
//! 1. the **start line** (status line vs request line), and
//! 2. the **decision** about which framing applies, because a request has no
//!    close-delimited framing and may not be answered by `204`.
//!
//! This module owns (1) as nothing at all and (2) as a parameter, so the chunked
//! decoder exists exactly once. That is `[INV-SERVER-04]`: the request-smuggling
//! surface is a single implementation, so a fix cannot land in one role and stay
//! armed in the other.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::HttpError;
use crate::head::BodyKind;

/// Hard bounds on what a peer may make us allocate or scan.
///
/// One `Limits` type serves both roles. A server and a client disagree about the
/// *values* they should use, never about which quantities must be bounded — an
/// unbounded head is a memory exhaustion vector in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum bytes of start line plus headers.
    pub max_head_bytes: usize,
    /// Maximum number of header fields.
    pub max_headers: usize,
    /// Maximum size of a single chunk.
    pub max_chunk_bytes: u64,
    /// Maximum body bytes any single message may deliver, counted across every call to
    /// [`crate::Http1Reader::read_body_chunk`] and
    /// [`crate::Http1ServerReader::read_body_chunk`].
    ///
    /// Counted cumulatively rather than per chunk, and enforced on the streaming path as
    /// well as the buffered one: a caller that never accumulates the body must not be able
    /// to read past the bound either, and a declared `Content-Length` beyond it is refused
    /// before the first body byte is read.
    pub max_body_bytes: u64,
    /// Whether a line terminator must be CRLF.
    ///
    /// `true` for the server role: a bare LF is a request-smuggling primitive, because a
    /// second hop that only recognises CRLF reads the difference as part of the next
    /// header. `false` for the client role, where tolerating a sloppy origin costs the
    /// client nothing and refusing it would fail a request the origin did answer.
    pub require_crlf: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head_bytes: 64 * 1024,
            max_headers: 128,
            max_chunk_bytes: 16 * 1024 * 1024,
            max_body_bytes: 256 * 1024 * 1024,
            require_crlf: false,
        }
    }
}

impl Limits {
    /// The values a public-facing server should start from.
    ///
    /// Tighter than [`Limits::default`] on every axis, because the default was
    /// chosen for a client that talks to a small set of known origins, while a
    /// listener is addressed by anyone who can reach the port. A request head
    /// larger than 16 KiB is already unusual; a 16 MiB single chunk is not a
    /// legitimate upload, it is a way to make one allocation enormous.
    pub const fn for_ingress() -> Self {
        Self {
            max_head_bytes: 16 * 1024,
            max_headers: 64,
            max_chunk_bytes: 1024 * 1024,
            max_body_bytes: 64 * 1024 * 1024,
            require_crlf: true,
        }
    }
}

/// Where a message's body currently stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyState {
    /// The head has not been read yet.
    Head,
    Empty,
    Length {
        remaining: u64,
    },
    Chunked {
        remaining: u64,
        need_crlf: bool,
    },
    UntilClose,
    Done,
}

impl BodyState {
    pub(crate) fn from_kind(kind: BodyKind) -> Self {
        match kind {
            BodyKind::Empty => Self::Empty,
            BodyKind::Length(len) => Self::Length { remaining: len },
            BodyKind::Chunked => Self::Chunked {
                remaining: 0,
                need_crlf: false,
            },
            BodyKind::UntilClose => Self::UntilClose,
        }
    }
}

/// The buffered-reader plumbing both roles share: a receive buffer, a bounded
/// line reader, and the body state machine.
///
/// Holding the transport by value is deliberate — a codec owns no socket, but it
/// does own the *buffer* in front of one, and handing back the leftovers on
/// [`Stream::into_inner`] is what makes a pooled or pipelined connection safe.
#[derive(Debug)]
pub(crate) struct Stream<R> {
    pub(crate) io: R,
    pub(crate) buf: BytesMut,
    pub(crate) limits: Limits,
    pub(crate) body: BodyState,
    /// Body bytes handed to the caller since the current message's body began.
    ///
    /// Counted here, not in the caller, because the limit has to hold for a *streaming*
    /// reader too: a handler that calls `next_chunk` in a loop never builds one large
    /// buffer, so a limit enforced only in `read_body_to_end` would be no limit at all.
    body_read: u64,
}

impl<R: AsyncRead + Unpin> Stream<R> {
    pub(crate) fn new(io: R, limits: Limits, buffered: &[u8]) -> Self {
        let mut buf = BytesMut::with_capacity(8 * 1024 + buffered.len());
        buf.extend_from_slice(buffered);
        Self {
            io,
            buf,
            limits,
            body: BodyState::Head,
            body_read: 0,
        }
    }

    /// Recover the transport and any bytes already buffered beyond the body.
    pub(crate) fn split(self) -> (R, BytesMut) {
        (self.io, self.buf)
    }

    /// Borrow the transport, for a role that must write on the same connection it
    /// read from.
    ///
    /// A server answers on the socket its request arrived on, so the response writer
    /// needs the transport while the reader still owns the receive buffer. Borrowing
    /// rather than unwrapping keeps the buffer intact: the leftover bytes after this
    /// request belong to the next one.
    pub(crate) fn transport_mut(&mut self) -> &mut R {
        &mut self.io
    }

    /// Read one CRLF-terminated line, without the terminator.
    ///
    /// `max` bounds how many bytes may accumulate before a terminator arrives, so
    /// a peer that never sends `\n` cannot grow the buffer without limit. This is
    /// the slow-loris defence at the codec level: a header line that does not
    /// terminate is a [`HttpError::LimitExceeded`], not an unbounded wait.
    pub(crate) async fn read_line(&mut self, max: usize) -> Result<Bytes, HttpError> {
        let strict = self.limits.require_crlf;
        loop {
            if let Some(position) = self.buf.iter().position(|&byte| byte == b'\n') {
                let mut line = self.buf.split_to(position + 1);
                line.truncate(position);
                let terminated = line.last() == Some(&b'\r');
                if terminated {
                    line.truncate(position - 1);
                } else if strict {
                    // A bare LF is where a request-smuggling desync begins: one hop
                    // terminates the line, the next reads the difference as payload. The
                    // server role refuses it; the client role tolerates it because a
                    // sloppy origin is the client's problem, not a security boundary.
                    return Err(HttpError::Protocol("a line was terminated by a bare LF"));
                }
                return Ok(line.freeze());
            }
            if self.buf.len() >= max {
                return Err(HttpError::LimitExceeded("max_head_bytes"));
            }
            if self.fill().await? == 0 {
                return Err(HttpError::Incomplete("connection closed inside head"));
            }
        }
    }

    /// Read exactly `n` bytes.
    async fn read_exact(&mut self, n: usize) -> Result<Bytes, HttpError> {
        while self.buf.len() < n {
            if self.fill().await? == 0 {
                return Err(HttpError::Protocol("body truncated"));
            }
        }
        Ok(self.buf.split_to(n).freeze())
    }

    /// Pull more bytes from the transport. Returns 0 at end of stream.
    pub(crate) async fn fill(&mut self) -> Result<usize, HttpError> {
        Ok(self.io.read_buf(&mut self.buf).await?)
    }

    /// Read the header block that follows a start line of `head_bytes` bytes.
    ///
    /// Shared by both roles because the *grammar* is shared: case-insensitive
    /// names, duplicate fields preserved, obsolete line folding rejected (RFC
    /// 9112 §5.2 — accepting it is a smuggling vector), and the same byte and
    /// count budgets as the start line.
    pub(crate) async fn read_header_block(
        &mut self,
        head_bytes: usize,
    ) -> Result<http::HeaderMap, HttpError> {
        let mut headers = http::HeaderMap::new();
        let mut count = 0usize;
        let mut head_bytes = head_bytes;
        loop {
            let line = self
                .read_line(self.limits.max_head_bytes.saturating_sub(head_bytes))
                .await?;
            head_bytes = head_bytes.saturating_add(line.len() + 2);
            if head_bytes > self.limits.max_head_bytes {
                return Err(HttpError::LimitExceeded("max_head_bytes"));
            }
            if line.is_empty() {
                return Ok(headers);
            }
            count += 1;
            if count > self.limits.max_headers {
                return Err(HttpError::LimitExceeded("max_headers"));
            }
            if matches!(line.first(), Some(b' ') | Some(b'\t')) {
                return Err(HttpError::Protocol("obsolete header line folding"));
            }
            let colon = line
                .iter()
                .position(|&b| b == b':')
                .ok_or(HttpError::Protocol("header line has no colon"))?;
            let (name, rest) = line.split_at(colon);
            let value = &rest[1..];
            let name = http::header::HeaderName::from_bytes(name)
                .map_err(|_| HttpError::Protocol("invalid header name"))?;
            let value = http::header::HeaderValue::from_bytes(trim_ows(value))
                .map_err(|_| HttpError::Protocol("invalid header value"))?;
            headers.append(name, value);
        }
    }

    /// Install a framing decision taken by a role.
    pub(crate) fn set_body(&mut self, kind: BodyKind) {
        self.body = BodyState::from_kind(kind);
        self.body_read = 0;
    }

    /// Refuse a framing that could not possibly be within `max_body_bytes`.
    ///
    /// A declared `Content-Length` larger than the bound is refused *before* the first
    /// body byte is read, so a peer cannot make the server allocate or read toward a size
    /// the operator never granted. A chunked body has no declared total, so it is bounded
    /// cumulatively in [`Self::read_body_chunk`] instead.
    pub(crate) fn check_declared_length(&self, kind: BodyKind) -> Result<(), HttpError> {
        if let BodyKind::Length(len) = kind
            && len > self.limits.max_body_bytes
        {
            return Err(HttpError::LimitExceeded("max_body_bytes"));
        }
        Ok(())
    }

    /// Credit one chunk of body against the cumulative bound.
    fn account_body(&mut self, bytes: usize) -> Result<(), HttpError> {
        self.body_read = self.body_read.saturating_add(bytes as u64);
        if self.body_read > self.limits.max_body_bytes {
            return Err(HttpError::LimitExceeded("max_body_bytes"));
        }
        Ok(())
    }

    /// Read the next body bytes, or `None` at the end of the body.
    ///
    /// The returned slice may be smaller than the remaining body; call again.
    pub(crate) async fn read_body_chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        loop {
            match self.body {
                BodyState::Head => return Err(HttpError::Protocol("head not read")),
                BodyState::Empty | BodyState::Done => return Ok(None),
                BodyState::Length { remaining } => {
                    if remaining == 0 {
                        self.body = BodyState::Done;
                        return Ok(None);
                    }
                    if self.buf.is_empty() {
                        if self.fill().await? == 0 {
                            return Err(HttpError::Incomplete("body truncated"));
                        }
                        continue;
                    }
                    let take = self
                        .buf
                        .len()
                        .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                    self.account_body(take)?;
                    let chunk = self.buf.split_to(take).freeze();
                    self.body = BodyState::Length {
                        remaining: remaining - take as u64,
                    };
                    return Ok(Some(chunk));
                }
                BodyState::Chunked {
                    remaining,
                    need_crlf,
                } => {
                    if need_crlf {
                        let crlf = self.read_exact(2).await?;
                        if &crlf[..] != b"\r\n" {
                            return Err(HttpError::Protocol("chunk data not CRLF-terminated"));
                        }
                        self.body = BodyState::Chunked {
                            remaining,
                            need_crlf: false,
                        };
                        continue;
                    }
                    if remaining == 0 {
                        let size = self.read_chunk_size().await?;
                        if size == 0 {
                            self.read_trailers().await?;
                            self.body = BodyState::Done;
                            return Ok(None);
                        }
                        if size > self.limits.max_chunk_bytes {
                            return Err(HttpError::LimitExceeded("max_chunk_bytes"));
                        }
                        self.body = BodyState::Chunked {
                            remaining: size,
                            need_crlf: false,
                        };
                        continue;
                    }
                    if self.buf.is_empty() {
                        if self.fill().await? == 0 {
                            return Err(HttpError::Incomplete("chunk truncated"));
                        }
                        continue;
                    }
                    let take = self
                        .buf
                        .len()
                        .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                    self.account_body(take)?;
                    let chunk = self.buf.split_to(take).freeze();
                    let remaining = remaining - take as u64;
                    self.body = BodyState::Chunked {
                        remaining,
                        need_crlf: remaining == 0,
                    };
                    return Ok(Some(chunk));
                }
                BodyState::UntilClose => {
                    if !self.buf.is_empty() {
                        let take = self.buf.len();
                        self.account_body(take)?;
                        let chunk = self.buf.split().freeze();
                        return Ok(Some(chunk));
                    }
                    if self.fill().await? == 0 {
                        self.body = BodyState::Done;
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Drain the body into one buffer.
    ///
    /// The bound is applied by [`Self::read_body_chunk`], per chunk, so this cannot
    /// accumulate past [`Limits::max_body_bytes`] — and neither can a caller that streams.
    pub(crate) async fn read_body_to_end(&mut self) -> Result<Bytes, HttpError> {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.read_body_chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    async fn read_chunk_size(&mut self) -> Result<u64, HttpError> {
        // A chunk-size line is tiny; bound it independently of the head budget.
        let line = self.read_line(8 * 1024).await?;
        let digits = line
            .iter()
            .position(|&b| b == b';')
            .map_or(&line[..], |semicolon| &line[..semicolon]);
        let text = std::str::from_utf8(digits)
            .map_err(|_| HttpError::Protocol("chunk size is not ASCII"))?
            .trim();
        if text.is_empty() || text.len() > 16 {
            return Err(HttpError::Protocol("invalid chunk size"));
        }
        u64::from_str_radix(text, 16).map_err(|_| HttpError::Protocol("invalid chunk size"))
    }

    async fn read_trailers(&mut self) -> Result<(), HttpError> {
        let mut count = 0usize;
        let mut bytes = 0usize;
        loop {
            let line = self
                .read_line(self.limits.max_head_bytes.saturating_sub(bytes))
                .await?;
            bytes = bytes.saturating_add(line.len() + 2);
            if bytes > self.limits.max_head_bytes {
                return Err(HttpError::LimitExceeded("max_head_bytes"));
            }
            if line.is_empty() {
                return Ok(());
            }
            count += 1;
            if count > self.limits.max_headers {
                return Err(HttpError::LimitExceeded("max_headers"));
            }
        }
    }
}

/// Trim optional whitespace (SP / HTAB) from both ends, as RFC 9112 requires for
/// header values.
pub(crate) fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ') | Some(b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ') | Some(b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

/// The framing headers, decomposed once for both roles.
///
/// Returns `(is_chunked, lengths)`. The *policy* — what to do with a message that
/// declares both, or with a body-less status — belongs to the role, because a
/// request and a response disagree about all of it. The parsing does not.
pub(crate) fn framing_headers(headers: &http::HeaderMap) -> (bool, Vec<u64>) {
    let chunked = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
    let lengths: Vec<u64> = headers
        .get_all(http::header::CONTENT_LENGTH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| value.trim().parse::<u64>().ok())
        .collect();
    (chunked, lengths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_limits_are_tighter_than_client_defaults() {
        let ingress = Limits::for_ingress();
        let default = Limits::default();
        assert!(ingress.max_head_bytes < default.max_head_bytes);
        assert!(ingress.max_headers < default.max_headers);
        assert!(ingress.max_chunk_bytes < default.max_chunk_bytes);
        assert!(ingress.max_body_bytes < default.max_body_bytes);
    }

    #[test]
    fn trim_ows_removes_only_optional_whitespace() {
        assert_eq!(trim_ows(b"  value \t"), b"value");
        assert_eq!(trim_ows(b"\t\tx"), b"x");
        assert_eq!(trim_ows(b""), b"");
        assert_eq!(trim_ows(b"a b"), b"a b");
    }

    #[test]
    fn framing_headers_reports_chunked_and_lengths() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("gzip, chunked"),
        );
        headers.append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("5"),
        );
        let (chunked, lengths) = framing_headers(&headers);
        assert!(chunked, "the chunked coding is found among several");
        assert_eq!(lengths, vec![5]);
    }

    #[test]
    fn framing_headers_sees_duplicate_lengths() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("5"),
        );
        headers.append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("6"),
        );
        let (chunked, lengths) = framing_headers(&headers);
        assert!(!chunked);
        assert_eq!(lengths, vec![5, 6]);
    }
}
