//! Differential oracle: hyper parses the same byte streams we do.
//!
//! ADR-0200 keeps hyper as a `[dev-dependencies]` oracle rather than a shipping
//! codec. This is that contract: for every corpus response, hyper and
//! `netune-http1` must agree on status, framing-relevant headers and body bytes.
//! A divergence here is a release blocker, not a flake.

#![allow(clippy::expect_used, clippy::unwrap_used)]
mod support;

use http::{HeaderMap, Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes as HyperBytes;
use hyper_util::rt::TokioIo;
use netune_http1::Http1Reader;
use support::{CHUNKED_RESPONSE, CONTENT_LENGTH_RESPONSE, ScriptedIo, UNTIL_CLOSE_RESPONSE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Parse `corpus` with hyper's client over a duplex stream.
async fn hyper_parse(corpus: &[u8], method: Method) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
    let corpus = corpus.to_vec();
    let server = tokio::spawn(async move {
        // Drain the request hyper writes, then answer with the corpus. Dropping
        // the write half afterwards produces the EOF a close-delimited body
        // needs.
        let mut scratch = [0u8; 2048];
        let _ = server_io.read(&mut scratch).await;
        let _ = server_io.write_all(&corpus).await;
        let _ = server_io.flush().await;
    });

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .expect("handshake");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder()
        .method(method)
        .uri("/")
        .body(Empty::<HyperBytes>::new())
        .expect("request");
    let response = sender.send_request(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();

    let _ = server.await;
    let _ = driver.await;
    (status, headers, body)
}

/// Parse `corpus` with our codec.
async fn ours_parse(corpus: &[u8], method: Method) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut reader = Http1Reader::new(ScriptedIo::chunked(corpus, 13));
    let head = reader.read_response_head(&method).await.expect("head");
    let body = reader.read_body_to_end().await.expect("body");
    (head.status, head.headers, body.to_vec())
}

async fn assert_agrees(name: &str, corpus: &[u8], method: Method) {
    let (our_status, our_headers, our_body) = ours_parse(corpus, method.clone()).await;
    let (hyper_status, hyper_headers, hyper_body) = hyper_parse(corpus, method).await;
    assert_eq!(our_status, hyper_status, "{name}: status");
    assert_eq!(our_body, hyper_body, "{name}: body");
    for header in [
        http::header::CONTENT_TYPE,
        http::header::CONTENT_LENGTH,
        http::header::TRANSFER_ENCODING,
    ] {
        assert_eq!(
            our_headers.get(&header),
            hyper_headers.get(&header),
            "{name}: header {header}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn content_length_response_agrees_with_hyper() {
    assert_agrees("content-length", CONTENT_LENGTH_RESPONSE, Method::GET).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn chunked_response_agrees_with_hyper() {
    assert_agrees("chunked", CHUNKED_RESPONSE, Method::GET).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn close_delimited_response_agrees_with_hyper() {
    assert_agrees("until-close", UNTIL_CLOSE_RESPONSE, Method::GET).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_content_response_agrees_with_hyper() {
    assert_agrees(
        "204",
        b"HTTP/1.1 204 No Content\r\ncontent-length: 99\r\n\r\n",
        Method::GET,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn head_response_agrees_with_hyper() {
    assert_agrees(
        "head",
        b"HTTP/1.1 200 OK\r\ncontent-length: 99\r\n\r\n",
        Method::HEAD,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_chunked_body_agrees_with_hyper() {
    assert_agrees(
        "empty-chunked",
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
        Method::GET,
    )
    .await;
}
