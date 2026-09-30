//! Framing corpus: every case here is a shape a real provider or proxy sends.

#![allow(clippy::expect_used, clippy::unwrap_used)]
mod support;

use http::{HeaderMap, Method, StatusCode};
use netune_http1::{BodyKind, Http1Reader, HttpError, Limits};
use support::{CHUNKED_RESPONSE, CONTENT_LENGTH_RESPONSE, ScriptedIo, UNTIL_CLOSE_RESPONSE};

async fn read_all(
    data: &[u8],
    chunk: usize,
    method: Method,
) -> Result<(StatusCode, HeaderMap, Vec<u8>), HttpError> {
    let mut reader = Http1Reader::new(ScriptedIo::chunked(data, chunk));
    let head = reader.read_response_head(&method).await?;
    let body = reader.read_body_to_end().await?;
    Ok((head.status, head.headers, body.to_vec()))
}

#[tokio::test]
async fn content_length_body_survives_any_chunk_boundary() {
    for chunk in [1, 3, 7, 64, 4096] {
        let (status, headers, body) = read_all(CONTENT_LENGTH_RESPONSE, chunk, Method::GET)
            .await
            .expect("parse");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(body, b"hello world");
    }
}

#[tokio::test]
async fn chunked_body_decodes_extensions_and_trailers() {
    let (status, headers, body) = read_all(CHUNKED_RESPONSE, 1, Method::GET)
        .await
        .expect("parse");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["transfer-encoding"], "chunked");
    assert_eq!(&body[..], b"data: a\ndata: b");
}

#[tokio::test]
async fn a_close_delimited_body_reads_until_eof() {
    let (_, _, body) = read_all(UNTIL_CLOSE_RESPONSE, 5, Method::GET)
        .await
        .expect("parse");
    assert_eq!(body, b"until the socket closes");
}

#[tokio::test]
async fn a_head_response_has_no_body_despite_a_length_header() {
    let data = b"HTTP/1.1 200 OK\r\ncontent-length: 99\r\n\r\n";
    let mut reader = Http1Reader::new(ScriptedIo::chunked(data, 4));
    let head = reader
        .read_response_head(&Method::HEAD)
        .await
        .expect("head");
    assert_eq!(head.body, BodyKind::Empty);
    assert_eq!(&reader.read_body_to_end().await.expect("body")[..], b"");
}

#[tokio::test]
async fn no_content_and_not_modified_have_no_body() {
    for line in [
        "HTTP/1.1 204 No Content\r\n",
        "HTTP/1.1 304 Not Modified\r\n",
    ] {
        let data = format!("{line}content-length: 99\r\n\r\n");
        let mut reader = Http1Reader::new(ScriptedIo::chunked(data.as_bytes(), 8));
        let head = reader.read_response_head(&Method::GET).await.expect("head");
        assert_eq!(head.body, BodyKind::Empty);
    }
}

#[tokio::test]
async fn duplicate_headers_are_preserved_in_order() {
    let data =
        b"HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nset-cookie: b=2\r\ncontent-length: 0\r\n\r\n";
    let (_, headers, _) = read_all(data, 8, Method::GET).await.expect("parse");
    let cookies: Vec<_> = headers
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect();
    assert_eq!(cookies, vec!["a=1".to_string(), "b=2".to_string()]);
}

#[tokio::test]
async fn header_values_are_whitespace_trimmed() {
    let data = b"HTTP/1.1 200 OK\r\nx-a:   spaced   \r\ncontent-length: 0\r\n\r\n";
    let (_, headers, _) = read_all(data, 8, Method::GET).await.expect("parse");
    assert_eq!(headers["x-a"], "spaced");
}

#[tokio::test]
async fn obsolete_line_folding_is_rejected() {
    let data = b"HTTP/1.1 200 OK\r\nx-a: one\r\n  two\r\ncontent-length: 0\r\n\r\n";
    let error = read_all(data, 8, Method::GET)
        .await
        .expect_err("must reject");
    assert_eq!(error.class(), "protocol");
}

#[tokio::test]
async fn transfer_encoding_with_content_length_is_rejected_as_smuggling() {
    let data =
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-length: 5\r\n\r\n0\r\n\r\n";
    let error = read_all(data, 8, Method::GET)
        .await
        .expect_err("must reject");
    assert_eq!(error.class(), "protocol");
}

#[tokio::test]
async fn conflicting_content_lengths_are_rejected() {
    let data = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-length: 6\r\n\r\nhello";
    let error = read_all(data, 8, Method::GET)
        .await
        .expect_err("must reject");
    assert_eq!(error.class(), "protocol");
}

#[tokio::test]
async fn a_truncated_body_is_an_incomplete_stream_not_a_protocol_error() {
    // The peer stopped speaking rather than speaking wrongly. The distinction
    // decides the retry verdict: a truncated body on a fresh connection is
    // transient, so it must not be classified as a syntax judgement.
    let data = b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nhello";
    let error = read_all(data, 8, Method::GET)
        .await
        .expect_err("must reject");
    assert_eq!(error.class(), "incomplete");
    assert!(error.is_retryable());
}

#[tokio::test]
async fn a_chunk_not_terminated_by_crlf_is_a_protocol_error() {
    let data = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n";
    let error = read_all(data, 8, Method::GET)
        .await
        .expect_err("must reject");
    assert_eq!(error.class(), "protocol");
}

#[tokio::test]
async fn an_oversized_head_is_refused_without_unbounded_growth() {
    let mut data = b"HTTP/1.1 200 OK\r\n".to_vec();
    for i in 0..2000 {
        data.extend_from_slice(format!("x-pad-{i}: v\r\n").as_bytes());
    }
    data.extend_from_slice(b"\r\n");
    let mut reader = Http1Reader::with_limits(
        ScriptedIo::chunked(&data, 64),
        Limits {
            max_head_bytes: 4096,
            ..Limits::default()
        },
    );
    let error = reader
        .read_response_head(&Method::GET)
        .await
        .expect_err("must reject");
    assert_eq!(error.class(), "limit");
}

#[tokio::test]
async fn an_oversized_chunk_is_refused() {
    let data = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nfffffff\r\n";
    let mut reader = Http1Reader::with_limits(
        ScriptedIo::chunked(data, 8),
        Limits {
            max_chunk_bytes: 1024,
            ..Limits::default()
        },
    );
    reader.read_response_head(&Method::GET).await.expect("head");
    let error = reader.read_body_chunk().await.expect_err("must reject");
    assert_eq!(error.class(), "limit");
}

#[tokio::test]
async fn bytes_after_the_body_are_handed_back_for_the_next_response() {
    // Pipelined: the next response's head follows in the same buffer. Delivered
    // in one read so the whole remainder is already buffered.
    let mut data = CONTENT_LENGTH_RESPONSE.to_vec();
    data.extend_from_slice(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    let mut reader = Http1Reader::new(ScriptedIo::chunked(&data, data.len()));
    reader.read_response_head(&Method::GET).await.expect("head");
    assert_eq!(
        &reader.read_body_to_end().await.expect("body")[..],
        b"hello world"
    );
    let (_, leftover) = reader.into_inner();
    assert_eq!(
        &leftover[..],
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        "leftover bytes must be handed back, not dropped"
    );
}

#[tokio::test]
async fn a_malformed_status_line_is_rejected() {
    for line in [
        &b"NOTHTTP 200 OK\r\ncontent-length: 0\r\n\r\n"[..],
        b"HTTP/1.1 abc OK\r\ncontent-length: 0\r\n\r\n",
        b"HTTP/1.1 99\r\ncontent-length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nbroken-header\r\n\r\n",
    ] {
        let error = read_all(line, 4, Method::GET)
            .await
            .expect_err("must reject");
        assert_eq!(error.class(), "protocol");
    }
}
