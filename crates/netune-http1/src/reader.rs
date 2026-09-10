//! Response head and body decoding.
//!
//! The reader owns its input and a small receive buffer. Everything it returns
//! is a slice of that buffer, so no copy is made between the socket and the
//! caller. Leftover bytes after the body ends are handed back by
//! [`Http1Reader::into_inner`] — on a pooled connection they belong to the next
//! response, and dropping them would corrupt the stream.

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::HttpError;
use crate::head::{BodyKind, ResponseHead};

/// Hard bounds on what a peer may make us allocate or scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum bytes of status line plus headers.
    pub max_head_bytes: usize,
    /// Maximum number of header fields.
    pub max_headers: usize,
    /// Maximum size of a single chunk.
    pub max_chunk_bytes: u64,
    /// Maximum body accumulated by [`Http1Reader::read_body_to_end`].
    pub max_body_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head_bytes: 64 * 1024,
            max_headers: 128,
            max_chunk_bytes: 16 * 1024 * 1024,
            max_body_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyState {
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

/// Decodes one HTTP/1.x response from `io`.
#[derive(Debug)]
pub struct Http1Reader<R> {
    io: R,
    buf: BytesMut,
    limits: Limits,
    body: BodyState,
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
        let mut buf = BytesMut::with_capacity(8 * 1024 + buffered.len());
        buf.extend_from_slice(&buffered);
        Self {
            io,
            buf,
            limits,
            body: BodyState::Head,
        }
    }

    /// Recover the transport and any bytes already buffered beyond the body.
    pub fn into_inner(self) -> (R, BytesMut) {
        (self.io, self.buf)
    }

    /// Parse the response head. `request_method` is needed because a `HEAD`
    /// response carries no body regardless of its framing headers.
    pub async fn read_response_head(
        &mut self,
        request_method: &Method,
    ) -> Result<ResponseHead, HttpError> {
        if self.body != BodyState::Head {
            return Err(HttpError::Protocol("head already read"));
        }

        let status_line = self.read_line(self.limits.max_head_bytes).await?;
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

        let mut headers = HeaderMap::new();
        let mut count = 0usize;
        let mut head_bytes = status_line.len();
        loop {
            let line = self
                .read_line(self.limits.max_head_bytes.saturating_sub(head_bytes))
                .await?;
            head_bytes = head_bytes.saturating_add(line.len() + 2);
            if head_bytes > self.limits.max_head_bytes {
                return Err(HttpError::LimitExceeded("max_head_bytes"));
            }
            if line.is_empty() {
                break;
            }
            count += 1;
            if count > self.limits.max_headers {
                return Err(HttpError::LimitExceeded("max_headers"));
            }
            if matches!(line.first(), Some(b' ') | Some(b'\t')) {
                // RFC 9112 forbids obsolete line folding; accepting it is a
                // request-smuggling vector.
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

        let body = Self::body_kind(&headers, &status, request_method)?;
        self.body = match body {
            BodyKind::Empty => BodyState::Empty,
            BodyKind::Length(len) => BodyState::Length { remaining: len },
            BodyKind::Chunked => BodyState::Chunked {
                remaining: 0,
                need_crlf: false,
            },
            BodyKind::UntilClose => BodyState::UntilClose,
        };
        Ok(ResponseHead {
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
        if request_method == Method::HEAD || ResponseHead::status_forbids_body(*status) {
            return Ok(BodyKind::Empty);
        }
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
                            return Err(HttpError::Protocol("body truncated"));
                        }
                        continue;
                    }
                    let take = self
                        .buf
                        .len()
                        .min(usize::try_from(remaining).unwrap_or(usize::MAX));
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
                            return Err(HttpError::Protocol("chunk truncated"));
                        }
                        continue;
                    }
                    let take = self
                        .buf
                        .len()
                        .min(usize::try_from(remaining).unwrap_or(usize::MAX));
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

    /// Drain the body into one buffer, bounded by [`Limits::max_body_bytes`].
    pub async fn read_body_to_end(&mut self) -> Result<Bytes, HttpError> {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.read_body_chunk().await? {
            if out.len() as u64 + chunk.len() as u64 > self.limits.max_body_bytes {
                return Err(HttpError::LimitExceeded("max_body_bytes"));
            }
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

    /// Read one CRLF-terminated line, without the terminator. `max` bounds how
    /// many bytes may accumulate before a terminator arrives, so a peer that
    /// never sends `\n` cannot grow the buffer without limit.
    async fn read_line(&mut self, max: usize) -> Result<Bytes, HttpError> {
        loop {
            if let Some(position) = self.buf.iter().position(|&byte| byte == b'\n') {
                let mut line = self.buf.split_to(position + 1);
                line.truncate(position);
                if line.last() == Some(&b'\r') {
                    line.truncate(position - 1);
                }
                return Ok(line.freeze());
            }
            if self.buf.len() >= max {
                return Err(HttpError::LimitExceeded("max_head_bytes"));
            }
            if self.fill().await? == 0 {
                return Err(HttpError::Protocol("connection closed inside head"));
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
    async fn fill(&mut self) -> Result<usize, HttpError> {
        let read = self.io.read_buf(&mut self.buf).await?;
        Ok(read)
    }
}

/// Trim optional whitespace (SP / HTAB) from both ends, as RFC 9112 requires for
/// header values.
fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ') | Some(b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ') | Some(b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}
