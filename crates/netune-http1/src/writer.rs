//! Request serialization (client role).
//!
//! One function, one direction. A client writes a request and a server writes a response;
//! they are not the same operation and they are not in the same crate module any more —
//! [`crate::response::ResponseWriter`] exists because a *response* has framing obligations
//! (streaming, `HEAD`, `204`, chunk termination) that a request simply does not.
//!
//! # Why a request is always self-delimiting
//!
//! A request must say where its body ends even when the body is empty: only a request that
//! declares its length can traverse a proxy that does not buffer, be replayed by a
//! redirect-follower, or be answered by a server that reuses the connection. So a
//! `Content-Length` is always written (0 when there is no body), and if the caller already
//! supplied one it is not duplicated.
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
    if !wrote_length {
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

    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
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
}
