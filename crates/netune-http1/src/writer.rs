//! Request serialization (client role).
//!
//! One function, one direction. A client writes a request and a server writes a response;
//! they are not the same operation and they are not in the same crate module any more —
//! [`crate::response::ResponseWriter`] exists because a *response* has framing obligations
//! (streaming, `HEAD`, `204`, chunk termination) that a request simply does not.
//!
//! # Why a request is usually self-delimiting
//!
//! A request that carries a body must say where it ends: only a request that declares its
//! length can traverse a proxy that does not buffer, be replayed by a
//! redirect-follower, or be answered by a server that reuses the connection. So
//! [`write_request`] writes a `Content-Length` (0 when there is no body), and if the caller
//! already supplied one it is not duplicated.
//!
//! [`write_request_head`] is the deliberately non-synthetic variant. A protocol whose
//! request *is* the whole message — a WebSocket upgrade is the case here — must be able to
//! control the exact header set and order, including sending no `Content-Length` and no
//! `User-Agent`. The codec still owns the request-line/header grammar; the caller owns the
//! fingerprint.
//!
//! # Header fidelity
//!
//! When the caller sets `raw_headers`, those exact names and bytes are written, in that
//! order, with their original casing. Order and casing are what a passive observer
//! fingerprints (`JA4H`), so the codec spells what it is handed rather than normalising
//! through `HeaderMap`.

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::HttpError;
use crate::head::RequestHead;

/// How a streamed request body is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestFraming {
    /// Declared `Content-Length`: exact byte total is checked before `finish`.
    Length(u64),
    /// `Transfer-Encoding: chunked`: chunks framed as `<hex>\r\n...\r\n`, terminated by `0\r\n\r\n`.
    Chunked,
}

/// Writes a request head followed by a streamed request body, enforcing the
/// framing declared by the head (`Content-Length` or `Transfer-Encoding: chunked`).
#[derive(Debug)]
pub struct RequestWriter<W> {
    io: W,
    framing: RequestFraming,
    written: u64,
    finished: bool,
}

impl<W: AsyncWrite + Unpin> RequestWriter<W> {
    /// Write `head` and take a mutable borrow of `io` for streaming body chunks.
    ///
    /// If `head` declares a `Content-Length`, that exact length is enforced;
    /// otherwise `Transfer-Encoding: chunked` must already be declared on `head`
    /// (and conflicting `Content-Length` + `Transfer-Encoding` is refused).
    ///
    /// # Errors
    ///
    /// [`HttpError::Protocol`] when the request target is invalid, when both
    /// `Content-Length` and `Transfer-Encoding` appear, when `Content-Length`
    /// is malformed, or when `Transfer-Encoding` is not `chunked` without a
    /// `Content-Length`.
    pub async fn start(mut io: W, head: &RequestHead) -> Result<Self, HttpError> {
        let framing = classify_request_framing(head)?;
        let out = encode_head(head, None, false)?;
        io.write_all(&out).await?;
        io.flush().await?;
        Ok(Self {
            io,
            framing,
            written: 0,
            finished: false,
        })
    }

    /// Write the next body chunk. An empty slice is a no-op.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        if self.finished {
            return Err(HttpError::Protocol("write after the request ended"));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        match self.framing {
            RequestFraming::Length(declared) => {
                let after = self.written + bytes.len() as u64;
                if after > declared {
                    return Err(HttpError::Protocol(
                        "the request body exceeds the content-length the head declared",
                    ));
                }
                self.io.write_all(bytes).await?;
                self.io.flush().await?;
                self.written = after;
                Ok(())
            }
            RequestFraming::Chunked => {
                let mut framed = BytesMut::with_capacity(bytes.len() + 16);
                framed.put_slice(format!("{:x}\r\n", bytes.len()).as_bytes());
                framed.put_slice(bytes);
                framed.put_slice(b"\r\n");
                self.io.write_all(&framed).await?;
                self.io.flush().await?;
                self.written += bytes.len() as u64;
                Ok(())
            }
        }
    }

    /// Terminate the request body, checking declared `Content-Length` or
    /// writing the chunked terminator `0\r\n\r\n`.
    pub async fn finish(mut self) -> Result<W, HttpError> {
        if self.finished {
            return Ok(self.io);
        }
        self.finished = true;
        match self.framing {
            RequestFraming::Length(declared) if self.written != declared => {
                return Err(HttpError::Protocol(
                    "the request ended before the declared content-length was written",
                ));
            }
            RequestFraming::Length(_) => {}
            RequestFraming::Chunked => self.io.write_all(b"0\r\n\r\n").await?,
        }
        self.io.flush().await?;
        Ok(self.io)
    }

    /// Total body bytes written so far.
    pub const fn written(&self) -> u64 {
        self.written
    }
}

fn classify_request_framing(head: &RequestHead) -> Result<RequestFraming, HttpError> {
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    let check_pair = |name: &str,
                      value: &str,
                      cl: &mut Option<u64>,
                      chunked: &mut bool|
     -> Result<(), HttpError> {
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<u64>()
                .map_err(|_| HttpError::Protocol("invalid request content-length header"))?;
            if let Some(prev) = cl
                && *prev != parsed
            {
                return Err(HttpError::Protocol(
                    "conflicting content-length headers on request",
                ));
            }
            *cl = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if value.trim().eq_ignore_ascii_case("chunked") {
                *chunked = true;
            } else {
                return Err(HttpError::Protocol(
                    "streaming request transfer-encoding must be chunked",
                ));
            }
        }
        Ok(())
    };

    if let Some(raw) = &head.raw_headers {
        for (name, value) in raw {
            check_pair(name, value, &mut content_length, &mut chunked)?;
        }
    } else {
        for (name, value) in &head.headers {
            let value = value
                .to_str()
                .map_err(|_| HttpError::Protocol("non-ASCII request framing header"))?;
            check_pair(name.as_str(), value, &mut content_length, &mut chunked)?;
        }
    }
    match (content_length, chunked) {
        (Some(_), true) => Err(HttpError::Protocol(
            "request declares both content-length and transfer-encoding",
        )),
        (Some(len), false) => Ok(RequestFraming::Length(len)),
        (None, true) => Ok(RequestFraming::Chunked),
        (None, false) => Err(HttpError::Protocol(
            "streaming request head must declare content-length or transfer-encoding: chunked",
        )),
    }
}

/// Serialize `head` plus an optional length-delimited body onto `writer`.
///
/// # Errors
///
/// An I/O failure from the transport. A target that is not a valid request-target is
/// refused before a byte is written, because a client that sends one is building the very
/// request a server is required to reject.
pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    head: &RequestHead,
    body: Option<&[u8]>,
) -> Result<(), HttpError> {
    let out = encode_head(head, body, true)?;
    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

/// Serialize exactly `head`, with no synthetic body-framing headers.
///
/// This is the WebSocket-upgrade seam: the caller supplies the complete header set and
/// order (including `Host`, `Upgrade`, `Connection`, `Sec-WebSocket-*` and any product
/// headers), and the codec writes it byte-for-byte. No `Content-Length`, `User-Agent` or
/// other default is inserted; adding one would change the fingerprint the peer sees.
///
/// # Errors
///
/// An I/O failure from the transport, or a target that is not a valid request-target.
pub async fn write_request_head<W: AsyncWrite + Unpin>(
    writer: &mut W,
    head: &RequestHead,
) -> Result<(), HttpError> {
    let out = encode_head(head, None, false)?;
    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

fn encode_head(
    head: &RequestHead,
    body: Option<&[u8]>,
    synthesize_length: bool,
) -> Result<BytesMut, HttpError> {
    crate::target::classify(&head.method, head.target.as_bytes())
        .map_err(|error| HttpError::Protocol(error.reason()))?;

    let mut out = BytesMut::with_capacity(512 + body.map_or(0, <[u8]>::len));

    out.put_slice(head.method.as_str().as_bytes());
    out.put_slice(b" ");
    out.put_slice(head.target.as_bytes());
    out.put_slice(b" HTTP/1.1\r\n");

    let mut wrote_length = false;
    if let Some(raw_headers) = &head.raw_headers {
        for (name, value) in raw_headers {
            if name.eq_ignore_ascii_case("content-length") {
                wrote_length = true;
            }
            out.put_slice(name.as_bytes());
            out.put_slice(b": ");
            out.put_slice(value.as_bytes());
            out.put_slice(b"\r\n");
        }
    } else {
        for (name, value) in head.headers.iter() {
            if name == http::header::CONTENT_LENGTH {
                wrote_length = true;
            }
            out.put_slice(name.as_str().as_bytes());
            out.put_slice(b": ");
            out.put_slice(value.as_bytes());
            out.put_slice(b"\r\n");
        }
    }
    if synthesize_length && !wrote_length {
        let length = body.map_or(0, <[u8]>::len);
        let cl_name = if head.raw_headers.is_some() {
            b"Content-Length: ".as_slice()
        } else {
            b"content-length: ".as_slice()
        };
        out.put_slice(cl_name);
        out.put_slice(length.to_string().as_bytes());
        out.put_slice(b"\r\n");
    }
    out.put_slice(b"\r\n");
    if let Some(body) = body {
        out.put_slice(body);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    async fn encode(head: &RequestHead, body: Option<&[u8]>) -> String {
        let mut out = Vec::new();
        write_request(&mut out, head, body).await.expect("write");
        String::from_utf8(out).expect("utf-8")
    }

    #[tokio::test]
    async fn a_request_is_self_delimiting() {
        let head = RequestHead::new(Method::POST, "/v1/chat/completions")
            .with_header("content-type", "application/json")
            .with_header("authorization", "Bearer secret");
        let text = encode(&head, Some(b"{\"stream\":true}")).await;
        assert!(text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
        assert!(text.contains("content-type: application/json\r\n"));
        assert!(text.contains("authorization: Bearer secret\r\n"));
        assert!(text.contains("content-length: 15\r\n"));
        assert!(text.ends_with("\r\n\r\n{\"stream\":true}"));
    }

    #[tokio::test]
    async fn an_absent_body_still_declares_zero_length() {
        let head = RequestHead::new(Method::GET, "/models");
        let text = encode(&head, None).await;
        assert!(text.contains("content-length: 0\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn a_caller_supplied_length_is_not_duplicated() {
        let head = RequestHead::new(Method::POST, "/x").with_header("content-length", "3");
        let text = encode(&head, Some(b"abc")).await;
        assert_eq!(text.matches("content-length").count(), 1);
    }

    #[tokio::test]
    async fn raw_headers_are_spelled_verbatim_in_the_callers_order() {
        let head = RequestHead::new(Method::GET, "/v1")
            .with_raw_header("User-Agent", "netune/0")
            .with_raw_header("X-Trace", "1");
        let text = encode(&head, None).await;
        let user_agent = text.find("User-Agent: netune/0").expect("casing kept");
        let trace = text.find("X-Trace: 1").expect("order kept");
        assert!(user_agent < trace, "caller order is preserved: {text}");
    }

    #[tokio::test]
    async fn a_target_a_server_would_reject_is_never_written() {
        let head = RequestHead::new(Method::GET, "/a b");
        let error = write_request(&mut Vec::new(), &head, None)
            .await
            .expect_err("must refuse");
        assert_eq!(error.class(), "protocol");
    }

    #[tokio::test]
    async fn a_head_only_request_has_no_synthetic_framing_headers() {
        let head = RequestHead::new(Method::GET, "/ray")
            .with_raw_header("Host", "lab.example.com")
            .with_raw_header("Upgrade", "websocket")
            .with_raw_header("Connection", "Upgrade");
        let mut out = Vec::new();
        write_request_head(&mut out, &head)
            .await
            .expect("write head");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.starts_with("GET /ray HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Host: lab.example.com\r\n"), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("content-length"),
            "{text}"
        );
        assert!(!text.to_ascii_lowercase().contains("user-agent"), "{text}");
        assert!(text.ends_with("\r\n\r\n"), "{text}");
    }

    #[tokio::test]
    async fn streaming_request_writer_chunks_and_terminates() {
        let head = RequestHead::new(Method::POST, "/upload")
            .with_header("host", "example.com")
            .with_header("transfer-encoding", "chunked");
        let mut out = Vec::new();
        let mut writer = RequestWriter::start(&mut out, &head).await.expect("start");
        writer.write(b"hello ").await.expect("chunk 1");
        writer.write(b"").await.expect("empty chunk is a no-op");
        writer.write(b"world").await.expect("chunk 2");
        writer.finish().await.expect("finish");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("transfer-encoding: chunked\r\n"));
        assert!(text.ends_with("\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n"));
    }

    #[tokio::test]
    async fn streaming_request_writer_enforces_declared_content_length() {
        let head = RequestHead::new(Method::POST, "/upload")
            .with_header("host", "example.com")
            .with_header("content-length", "5");
        let mut out = Vec::new();
        let mut writer = RequestWriter::start(&mut out, &head).await.expect("start");
        writer.write(b"ab").await.expect("write");
        let over = writer.write(b"cdef").await.expect_err("must reject excess");
        assert_eq!(over.class(), "protocol");
        let short = writer.finish().await.expect_err("must reject short body");
        assert_eq!(short.class(), "protocol");
    }

    #[tokio::test]
    async fn streaming_request_writer_rejects_conflicting_framing_headers() {
        let head = RequestHead::new(Method::POST, "/upload")
            .with_header("content-length", "5")
            .with_header("transfer-encoding", "chunked");
        let error = RequestWriter::start(Vec::new(), &head)
            .await
            .expect_err("conflicting framing must fail");
        assert_eq!(error.class(), "protocol");
    }
}
