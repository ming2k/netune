//! Request serialization.

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::HttpError;
use crate::head::RequestHead;

/// Serialize `head` plus an optional length-delimited body onto `writer`.
///
/// A `Content-Length` is always written (0 for an absent body) unless the caller
/// already supplied one, so every request is self-delimiting: a proxy or server
/// never has to guess where the body ends.
pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    head: &RequestHead,
    body: Option<&[u8]>,
) -> Result<(), HttpError> {
    let mut out = BytesMut::with_capacity(512 + body.map_or(0, <[u8]>::len));

    out.put_slice(head.method.as_str().as_bytes());
    out.put_slice(b" ");
    out.put_slice(head.target.as_bytes());
    out.put_slice(b" HTTP/1.1\r\n");

    let mut wrote_length = false;
    for (name, value) in head.headers.iter() {
        if name == http::header::CONTENT_LENGTH {
            wrote_length = true;
        }
        out.put_slice(name.as_str().as_bytes());
        out.put_slice(b": ");
        out.put_slice(value.as_bytes());
        out.put_slice(b"\r\n");
    }
    if !wrote_length {
        let length = body.map_or(0, <[u8]>::len);
        out.put_slice(b"content-length: ");
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

    // -- the HTTP-layer fingerprint surface -------------------------------
    //
    // Header order and casing are what a passive observer fingerprints at
    // the HTTP layer (JA4H). `http::HeaderMap` preserves insertion order,
    // and the writer spells each name exactly as it was inserted, so the
    // caller — not the codec — owns both. These tests pin that: any change
    // to the writer that reorders, recases, or normalizes headers shows up
    // here as a fingerprint-relevant regression, not a silent drift.

    #[tokio::test]
    async fn header_order_is_what_the_caller_inserted() {
        let head = RequestHead::new(Method::GET, "/models")
            .with_header("user-agent", "netune/0.1")
            .with_header("accept", "application/json")
            .with_header("authorization", "Bearer t");
        let text = encode(&head, None).await;
        let body_start = text.find("\r\n\r\n").expect("head terminator");
        let head_text = &text[..body_start];
        let ua = head_text.find("user-agent").expect("user-agent");
        let accept = head_text.find("accept").expect("accept");
        let auth = head_text.find("authorization").expect("authorization");
        assert!(
            ua < accept && accept < auth,
            "insertion order is wire order:\n{head_text}"
        );
    }

    #[tokio::test]
    async fn header_casing_is_lowercased_by_the_header_map() {
        // A real, recorded limitation: `http::HeaderName::try_from`
        // lowercases every name, so the wire casing is always lowercase —
        // unlike some browsers that send title-cased names. Order is still
        // ours (see `header_order_is_what_the_caller_inserted`), so the
        // JA4H order signal is available while the casing signal is fixed
        // lowercase. If a future profile needs arbitrary casing, the seam
        // is here: the writer spells whatever name it is handed, so the
        // change belongs in header construction, not serialization.
        let head = RequestHead::new(Method::GET, "/x").with_header("X-API-Key", "k");
        let text = encode(&head, None).await;
        assert!(
            text.contains("x-api-key: k\r\n"),
            "HeaderMap lowercases; the writer does not re-case:\n{text}"
        );
    }

    #[tokio::test]
    async fn duplicate_headers_replace_their_predecessor_on_insert() {
        // Another recorded limitation: `with_header` inserts, and a
        // `HeaderMap` insert replaces a same-named value. A multi-value
        // header (cookie, accept) therefore needs `append` semantics, which
        // `RequestHead` does not yet expose. The writer, given such a map,
        // would emit both values in order — the constraint is in the
        // head builder, not the codec.
        let head = RequestHead::new(Method::GET, "/x")
            .with_header("accept", "text/html")
            .with_header("accept", "application/json");
        let text = encode(&head, None).await;
        assert!(text.contains("accept: application/json\r\n"));
        assert!(
            !text.contains("accept: text/html"),
            "insert replaced the earlier value:\n{text}"
        );
    }

    #[tokio::test]
    async fn the_content_length_fills_in_after_the_callers_headers() {
        // The synthesized `content-length` must not jump ahead of the
        // caller's headers: a passive observer counting "which header closes
        // the block" would see a different fingerprint depending on where it
        // landed.
        let head = RequestHead::new(Method::POST, "/x")
            .with_header("user-agent", "netune/0.1")
            .with_header("accept", "application/json");
        let text = encode(&head, Some(b"{}")).await;
        let head_text = &text[..text.find("\r\n\r\n").expect("terminator")];
        let user_agent = head_text.find("user-agent").expect("user-agent");
        let accept = head_text.find("accept").expect("accept");
        let length = head_text.find("content-length").expect("content-length");
        assert!(
            user_agent < accept && accept < length,
            "the synthesized length closes the header block, after the caller's:\n{head_text}"
        );
    }
}
