//! Response serialization as a state machine (server role).
//!
//! A response is the only message a server writes, and every way a server can
//! desynchronise a peer lives in it. Writing one is therefore not a function call with a
//! byte slice; it is a small machine that knows three things at once:
//!
//! 1. **what the head declared** (`Content-Length: 5`, chunked, or nothing);
//! 2. **what the request forbids** (`HEAD` carries no body, `CONNECT` 2xx opens a tunnel,
//!    `1xx` / `204` / `304` never carry one);
//! 3. **what has actually been handed to the kernel so far.**
//!
//! Those three can disagree, and each disagreement is a distinct bug: a declared length
//! that was never reached leaves the peer waiting forever, a byte written under `204`
//! becomes the next response's status line, and a body written for `HEAD` shifts every
//! subsequent response on a keep-alive connection by its length.
//!
//! # Why this is a type and not a pair of functions
//!
//! Streaming (SSE, an LLM token stream, a generated file) writes the head, then an
//! unbounded number of body writes, then a terminator. A function-per-write API cannot
//! enforce "the declared length is what you actually wrote", because it has no state;
//! [`ResponseWriter`] does, and its [`ResponseWriter::finish`] is the only place that can
//! check it. It also makes `write_response` removable: a buffered response is just
//! `start → write → finish`.
//!
//! # Header order
//!
//! `HeaderMap` iteration order is not the insertion order, and this writer does not
//! pretend otherwise: a response is not fingerprinted by its byte order the way a request
//! is, and the alternative — a second, order-preserving header container — would have to
//! be built for every response to fix a problem no origin server has.

use bytes::{BufMut, BytesMut};
use http::{Method, StatusCode};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::HttpError;
use crate::head::{BodyKind, ResponseHead};

/// How the body of a response being written is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// No body: the head is the whole message.
    None,
    /// Exactly this many bytes will be written.
    Length(u64),
    /// Chunked transfer coding, terminated by `finish`.
    Chunked,
}

/// Writes one response head plus its body, enforcing the framing it declared.
///
/// Construct with [`ResponseWriter::start`], which writes and flushes the head; feed the
/// body with [`ResponseWriter::write`]; close with [`ResponseWriter::finish`].
///
/// Dropping the writer without calling `finish` is not an error the type can detect, but
/// the caller that does it leaves a chunked body unterminated, so the transport treats a
/// drop as a failed exchange and closes the connection.
#[derive(Debug)]
pub struct ResponseWriter<W> {
    io: W,
    framing: Framing,
    /// Whether body bytes may reach the wire at all.
    ///
    /// False for `HEAD`, for `1xx`/`204`/`304`, and for a `CONNECT` 2xx — in those cases
    /// the head is the entire message, even when it *declares* a body's length.
    write_body: bool,
    /// Body bytes handed to the transport so far.
    written: u64,
    finished: bool,
}

impl<W: AsyncWrite + Unpin> ResponseWriter<W> {
    /// Write `head` for `method` and take ownership of the transport for the body.
    ///
    /// # Errors
    ///
    /// Refuses, before a byte reaches the wire:
    ///
    /// - a body under `1xx`, `204`, `304`, or in reply to `HEAD`/`CONNECT`-success when
    ///   the head *also* declares a `Content-Length` that contradicts the status
    ///   (`204` with any length, `1xx` with any length);
    /// - a `Content-Length` on a status that forbids one (RFC 9110 §8.6);
    /// - `BodyKind::UntilClose`, which no server may declare: only the orchestrator knows
    ///   whether it is closing, and a keep-alive peer would misread the response.
    pub async fn start(io: W, method: &Method, head: &ResponseHead) -> Result<Self, HttpError> {
        let status = head.status;
        let informational = status.is_informational();
        let no_content = status == StatusCode::NO_CONTENT;
        let not_modified = status == StatusCode::NOT_MODIFIED;

        if informational || no_content {
            if head.body != BodyKind::Empty {
                return Err(HttpError::Protocol(
                    "a 1xx/204 response may not declare a body",
                ));
            }
            if head.headers.contains_key(http::header::CONTENT_LENGTH) {
                return Err(HttpError::Protocol(
                    "a 1xx/204 response may not carry content-length",
                ));
            }
        }

        let framing = match head.body {
            BodyKind::Empty => Framing::None,
            BodyKind::Length(len) => Framing::Length(len),
            BodyKind::Chunked => Framing::Chunked,
            BodyKind::UntilClose => {
                return Err(HttpError::Protocol(
                    "a server may not delimit a response body by closing the connection",
                ));
            }
        };

        // `HEAD` promises the length the body *would* have had, and `304` may repeat the
        // length of the representation it did not send; both declare a framing and send
        // no bytes. Every other body-less case is a contradiction already refused above.
        let write_body = !(method.eq(&Method::HEAD)
            || informational
            || no_content
            || not_modified
            || (method.eq(&Method::CONNECT) && status.is_success()));

        let mut out = BytesMut::with_capacity(512);
        encode_head(&mut out, head)?;
        let mut io = io;
        io.write_all(&out).await?;
        io.flush().await?;

        Ok(Self {
            io,
            framing,
            write_body,
            written: 0,
            finished: false,
        })
    }

    /// Whether body bytes will reach the wire for this response.
    ///
    /// A streaming handler asks this before generating a body it would otherwise waste
    /// work producing — the answer is `false` for `HEAD` and for every status that
    /// forbids a body.
    pub const fn writes_body(&self) -> bool {
        self.write_body
    }

    /// Whether this response is frame-delimited, so each write reaches the peer as soon
    /// as it is flushed.
    pub const fn is_chunked(&self) -> bool {
        matches!(self.framing, Framing::Chunked)
    }

    /// Bytes of body handed to the transport so far.
    pub const fn written(&self) -> u64 {
        self.written
    }

    /// Write the next slice of body.
    ///
    /// An empty slice is a no-op: a handler that has nothing to add yet must be able to
    /// loop without turning that into a zero-length chunk (which *is* the terminator).
    ///
    /// # Errors
    ///
    /// - any body byte for a response that carries none ([`Self::writes_body`] is false);
    /// - more bytes than the head declared, which would push every later response on the
    ///   connection out of alignment;
    /// - an I/O failure on the transport.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        if self.finished {
            return Err(HttpError::Protocol("write after the response ended"));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        if !self.write_body {
            return Err(HttpError::Protocol(
                "a body was written for a response that carries none",
            ));
        }
        match self.framing {
            Framing::None => Err(HttpError::Protocol(
                "a body was written for a head that declares no framing",
            )),
            Framing::Length(declared) => {
                let after = self.written + bytes.len() as u64;
                if after > declared {
                    return Err(HttpError::Protocol(
                        "the body exceeds the content-length the head declared",
                    ));
                }
                self.io.write_all(bytes).await?;
                self.io.flush().await?;
                self.written = after;
                Ok(())
            }
            Framing::Chunked => {
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

    /// Terminate the body and return the transport.
    ///
    /// # Errors
    ///
    /// Refuses to report success when the declared length was not reached — the peer is
    /// waiting for bytes that will never come, and a caller that ignores this leaves a
    /// hung request rather than a failed one.
    pub async fn finish(mut self) -> Result<W, HttpError> {
        if self.finished {
            return Ok(self.io);
        }
        self.finished = true;
        if self.write_body {
            match self.framing {
                Framing::None => {}
                Framing::Length(declared) if self.written != declared => {
                    return Err(HttpError::Protocol(
                        "the response ended before the declared content-length was written",
                    ));
                }
                Framing::Length(_) => {}
                Framing::Chunked => self.io.write_all(b"0\r\n\r\n").await?,
            }
        }
        self.io.flush().await?;
        Ok(self.io)
    }
}

/// Write one interim (`1xx`) response head and flush it.
///
/// `103 Early Hints`, `100 Continue` and `102 Processing` are heads without bodies that
/// precede the final response on the same connection. They are a separate entry point
/// rather than a `ResponseWriter` mode because an interim response never terminates
/// anything: a final response must still follow, and a type that could be mistaken for
/// the final one would eventually be used as it.
///
/// # Errors
///
/// [`HttpError::Protocol`] when `status` is not informational, and any transport failure.
pub async fn write_interim<W: AsyncWrite + Unpin>(
    io: &mut W,
    status: StatusCode,
    headers: &http::HeaderMap,
) -> Result<(), HttpError> {
    if !status.is_informational() {
        return Err(HttpError::Protocol(
            "an interim response must carry a 1xx status",
        ));
    }
    if headers.contains_key(http::header::CONTENT_LENGTH)
        || headers.contains_key(http::header::TRANSFER_ENCODING)
    {
        return Err(HttpError::Protocol(
            "an interim response may not declare a body",
        ));
    }
    let head = ResponseHead {
        status,
        headers: headers.clone(),
        reason: crate::head::ReasonPhrase::default(),
        body: BodyKind::Empty,
    };
    let mut out = BytesMut::with_capacity(128);
    encode_head(&mut out, &head)?;
    io.write_all(&out).await?;
    io.flush().await?;
    Ok(())
}

/// Serialize a head into `out`.
///
/// The status line is `HTTP/1.1` always: this writer serves peers that spoke HTTP/1.1, and
/// answering `HTTP/1.0` to a 1.0 request is permitted but *not* permitted to change the
/// framing rules — the response is self-delimiting either way, so the version field only
/// costs a parser a branch.
fn encode_head(out: &mut BytesMut, head: &ResponseHead) -> Result<(), HttpError> {
    let status = head.status;
    out.put_slice(b"HTTP/1.1 ");
    out.put_slice(status.as_str().as_bytes());
    out.put_slice(b" ");
    out.put_slice(head.reason.bytes_for(status));
    out.put_slice(b"\r\n");
    for (name, value) in head.headers.iter() {
        out.put_slice(name.as_str().as_bytes());
        out.put_slice(b": ");
        out.put_slice(value.as_bytes());
        out.put_slice(b"\r\n");
    }
    out.put_slice(b"\r\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(status: StatusCode) -> ResponseHead {
        ResponseHead::new(status)
    }

    async fn collect<F, Fut>(method: Method, head: ResponseHead, build: F) -> Vec<u8>
    where
        F: FnOnce(ResponseWriter<Vec<u8>>) -> Fut,
        Fut: std::future::Future<Output = ResponseWriter<Vec<u8>>>,
    {
        let writer = ResponseWriter::start(Vec::new(), &method, &head)
            .await
            .expect("head");
        build(writer).await.finish().await.expect("body").to_vec()
    }

    #[tokio::test]
    async fn a_length_delimited_body_is_written_verbatim() {
        let bytes = collect(
            Method::GET,
            head(StatusCode::OK).with_body(b"hello"),
            async |mut w: ResponseWriter<Vec<u8>>| {
                w.write(b"hello").await.expect("write");
                w
            },
        )
        .await;
        let text = String::from_utf8(bytes).expect("utf8");
        assert_eq!(text, "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello");
    }

    #[tokio::test]
    async fn a_body_under_an_unframed_head_is_refused() {
        let head = head(StatusCode::OK);
        let mut writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
            .await
            .expect("head");
        let error = writer.write(b"hello").await.expect_err("must refuse");
        assert!(
            format!("{error}").contains("declares no framing"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_body_under_two_hundred_four_is_refused_before_it_reaches_the_wire() {
        let head = head(StatusCode::NO_CONTENT).with_body(b"oops");
        let error = ResponseWriter::start(Vec::new(), &Method::GET, &head)
            .await
            .expect_err("must refuse");
        assert!(format!("{error}").contains("1xx/204"), "{error}");
    }

    #[tokio::test]
    async fn a_head_response_declares_a_length_and_writes_no_body() {
        let head = head(StatusCode::OK).with_body(b"hello");
        let mut writer = ResponseWriter::start(Vec::new(), &Method::HEAD, &head)
            .await
            .expect("head");
        assert!(!writer.writes_body());
        let error = writer.write(b"hello").await.expect_err("must refuse");
        assert!(format!("{error}").contains("carries none"), "{error}");
        let bytes = writer.finish().await.expect("finish");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("content-length: 5"), "{text}");
        assert!(
            text.ends_with("\r\n\r\n"),
            "no body after the head: {text:?}"
        );
    }

    #[tokio::test]
    async fn a_truncated_length_is_refused_at_finish() {
        let head = head(StatusCode::OK).with_body(&b"hello"[..]);
        let mut writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
            .await
            .expect("head");
        writer.write(b"hel").await.expect("write");
        let error = writer.finish().await.expect_err("must refuse");
        assert!(format!("{error}").contains("content-length"), "{error}");
    }

    #[tokio::test]
    async fn exceeding_the_declared_length_is_refused_mid_write() {
        let head = head(StatusCode::OK).with_body(&b"hello"[..]);
        let mut writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
            .await
            .expect("head");
        let error = writer.write(b"hello!").await.expect_err("must refuse");
        assert!(format!("{error}").contains("exceeds"), "{error}");
    }

    #[tokio::test]
    async fn a_chunked_body_is_framed_and_terminated() {
        let head = head(StatusCode::OK).with_chunked_body();
        let mut writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
            .await
            .expect("head");
        assert!(writer.is_chunked());
        writer.write(b"hello").await.expect("chunk");
        writer.write(b"").await.expect("an empty write is a no-op");
        writer.write(b" world").await.expect("chunk");
        let bytes = writer.finish().await.expect("finish");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(
            text.ends_with("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
            "{text:?}"
        );
    }

    #[tokio::test]
    async fn a_head_of_a_chunked_response_is_never_terminated() {
        let head = head(StatusCode::OK).with_chunked_body();
        let writer = ResponseWriter::start(Vec::new(), &Method::HEAD, &head)
            .await
            .expect("head");
        let text = String::from_utf8(writer.finish().await.expect("finish")).expect("utf8");
        assert!(
            !text.ends_with("0\r\n\r\n"),
            "a HEAD response has no body to terminate: {text:?}"
        );
    }

    #[tokio::test]
    async fn a_connect_tunnel_response_carries_no_body() {
        let head = head(StatusCode::OK);
        let mut writer = ResponseWriter::start(Vec::new(), &Method::CONNECT, &head)
            .await
            .expect("head");
        assert!(!writer.writes_body());
        assert!(writer.write(b"x").await.is_err());
    }

    #[tokio::test]
    async fn a_not_modified_response_may_repeat_the_length_without_a_body() {
        let head = head(StatusCode::NOT_MODIFIED).with_body(&b"hello"[..]);
        let writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
            .await
            .expect("head");
        assert!(!writer.writes_body());
        writer.finish().await.expect("no bytes were promised");
    }

    #[tokio::test]
    async fn an_interim_response_must_be_informational() {
        let mut out = Vec::new();
        let error = write_interim(&mut out, StatusCode::OK, &http::HeaderMap::new())
            .await
            .expect_err("must refuse");
        assert!(format!("{error}").contains("1xx"), "{error}");
        write_interim(&mut out, StatusCode::CONTINUE, &http::HeaderMap::new())
            .await
            .expect("continue");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(text, "HTTP/1.1 100 Continue\r\n\r\n");
    }
}
