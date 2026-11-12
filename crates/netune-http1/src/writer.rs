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
}
