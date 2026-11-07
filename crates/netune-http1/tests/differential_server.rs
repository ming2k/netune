//! Differential oracle for the server role: hyper is the client, we are the
//! server.
//!
//! The client-role suite (`differential.rs`) proves we parse what hyper writes.
//! This one proves the opposite direction, which the workspace could not test
//! before ADR-0011: that a request hyper sends is framed by us the way hyper
//! intended, and that a response we write is accepted by hyper unchanged.
//!
//! Both halves matter and they fail differently. A request-framing divergence is a
//! smuggling surface. A response-framing divergence is a hang or a truncated
//! body — the peer waits for bytes that are already on the wire.

#![allow(clippy::expect_used, clippy::unwrap_used)]
mod support;

use std::time::Duration;

use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes as HyperBytes;
use hyper_util::rt::TokioIo;
use netune_http1::{
    BodyKind, Http1ServerReader, Limits, ReasonPhrase, ResponseHead, ResponseWriter, TargetForm,
};
use support::ScriptedIo;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Read one request from a real hyper client and report how we framed it.
///
/// The client is hyper over a real loopback socket rather than a duplex pair so
/// that the bytes are the ones hyper actually puts on a wire, including its
/// `Host`, `Accept` and `Content-Length` defaults.
async fn hyper_client_request(
    method: Method,
    path: &str,
    body: Option<&'static [u8]>,
) -> (netune_http1::IncomingRequest, Option<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut reader = Http1ServerReader::new(socket);
        let head = reader.read_request_head().await.expect("request head");
        let body = if head.body == BodyKind::Empty {
            None
        } else {
            Some(reader.read_body_to_end().await.expect("body").to_vec())
        };
        let (mut socket, _) = reader.into_inner();
        let response = ResponseHead::new(StatusCode::OK).with_header("content-length", "0");
        ResponseWriter::start(&mut socket, &Method::GET, &response)
            .await
            .expect("head")
            .finish()
            .await
            .expect("response");
        (head, body)
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // An origin-form URI carries no authority, so hyper would omit `Host`
    // entirely; supply it the way a real client does.
    let request = if let Some(body) = body {
        http::Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, "probe.test")
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(http_body_util::Full::new(HyperBytes::from_static(body)))
            .expect("request")
    } else {
        http::Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, "probe.test")
            .body(http_body_util::Full::new(HyperBytes::new()))
            .expect("request")
    };
    let response = sender.send_request(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    server.await.expect("server")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hyper_get_is_framed_as_a_bodyless_request() {
    let (head, body) = hyper_client_request(Method::GET, "/api/models", None).await;
    assert_eq!(head.method, Method::GET);
    assert_eq!(head.target_str(), Some("/api/models"));
    assert_eq!(head.form, TargetForm::Origin);
    assert_eq!(
        head.body,
        BodyKind::Empty,
        "a GET with no body must not be close-delimited"
    );
    assert_eq!(body, None);
    // The `Host` a client sent is what makes routing possible; it must survive.
    assert_eq!(head.host(), Some("probe.test"), "host is preserved as sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hyper_post_body_arrives_intact_and_with_the_declared_length() {
    let payload: &'static [u8] = b"{\"stream\":true}";
    let (head, body) = hyper_client_request(Method::POST, "/v1/chat", Some(payload)).await;
    assert_eq!(head.body, BodyKind::Length(payload.len() as u64));
    assert_eq!(
        body.as_deref(),
        Some(payload),
        "the body must arrive byte-identical"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_query_string_survives_in_the_target() {
    let (head, _) = hyper_client_request(Method::GET, "/search?q=hello%20world&n=1", None).await;
    assert_eq!(head.target_str(), Some("/search?q=hello%20world&n=1"));
}

/// A response we write must be readable by hyper, unmodified.
async fn assert_hyper_reads_our_response<F, Fut>(method: Method, build: F, name: &str)
where
    F: FnOnce(Vec<u8>, Method) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Vec<u8>> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server_method = method.clone();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // Read the request *first*. Writing a response before hyper's client has
        // finished writing the request is a legitimate client-side error
        // (`UnexpectedMessage`), and would be testing hyper's state machine
        // rather than our framing.
        let mut reader = Http1ServerReader::new(&mut socket);
        reader.read_request_head().await.expect("request head");
        let bytes = build(Vec::new(), server_method).await;
        socket.write_all(&bytes).await.expect("write");
        socket.flush().await.expect("flush");
        // Close so a keep-alive wait ends.
        let _ = socket.shutdown().await;
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("handshake");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(method)
        .uri("/")
        .header(http::header::HOST, "probe.test")
        .body(Empty::<HyperBytes>::new())
        .expect("request");
    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .unwrap_or_else(|_| panic!("{name}: hyper hung on our response"))
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK, "{name}: status");
    let body = tokio::time::timeout(Duration::from_secs(5), response.into_body().collect())
        .await
        .unwrap_or_else(|_| panic!("{name}: hyper hung reading our body"))
        .expect("body")
        .to_bytes();
    driver.abort();
    assert_eq!(&body[..], b"hello world", "{name}: body");
}

#[tokio::test(flavor = "multi_thread")]
async fn hyper_accepts_a_content_length_response_we_write() {
    assert_hyper_reads_our_response(
        Method::GET,
        async |out: Vec<u8>, method: Method| {
            let head = ResponseHead::new(StatusCode::OK).with_body(b"hello world");
            let mut writer = ResponseWriter::start(out, &method, &head)
                .await
                .expect("head");
            writer.write(b"hello world").await.expect("body");
            writer.finish().await.expect("finish")
        },
        "content-length",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hyper_accepts_a_chunked_response_we_write() {
    assert_hyper_reads_our_response(
        Method::GET,
        async |out: Vec<u8>, method: Method| {
            let head = ResponseHead::new(StatusCode::OK).with_chunked_body();
            let mut writer = ResponseWriter::start(out, &method, &head)
                .await
                .expect("head");
            writer.write(b"hello ").await.expect("chunk");
            writer.write(b"world").await.expect("chunk");
            writer.finish().await.expect("finish")
        },
        "chunked",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hyper_accepts_an_empty_reason_phrase_we_write() {
    // RFC 9112 §4 permits the reason phrase to be empty; hyper must not care.
    assert_hyper_reads_our_response(
        Method::GET,
        async |out: Vec<u8>, method: Method| {
            let mut head = ResponseHead::new(StatusCode::OK).with_body(b"hello world");
            head.reason = ReasonPhrase::Empty;
            let mut writer = ResponseWriter::start(out, &method, &head)
                .await
                .expect("head");
            writer.write(b"hello world").await.expect("body");
            writer.finish().await.expect("finish")
        },
        "empty-reason",
    )
    .await;
}

/// A `HEAD` response declares the length its body *would* have had, and hyper must
/// read exactly the head — no bytes consumed beyond it, so the connection stays usable.
#[tokio::test(flavor = "multi_thread")]
async fn hyper_accepts_a_head_response_with_a_declared_length_and_no_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut reader = Http1ServerReader::new(&mut socket);
        let head = reader.read_request_head().await.expect("head");
        assert_eq!(head.method, Method::HEAD);
        let response = ResponseHead::new(StatusCode::OK).with_body(b"hello world");
        let writer = ResponseWriter::start(&mut socket, &Method::HEAD, &response)
            .await
            .expect("head");
        writer.finish().await.expect("finish");
        // A second response on the same connection proves nothing was written under the
        // first one's declared length.
        let response = ResponseHead::new(StatusCode::OK).with_body(b"second");
        let mut writer = ResponseWriter::start(&mut socket, &Method::GET, &response)
            .await
            .expect("head");
        writer.write(b"second").await.expect("body");
        writer.finish().await.expect("finish");
        let _ = socket.shutdown().await;
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("handshake");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(Method::HEAD)
        .uri("/")
        .header(http::header::HOST, "probe.test")
        .body(Empty::<HyperBytes>::new())
        .expect("request");
    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .expect("hyper read the HEAD head")
        .expect("response");
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .map(|value| value.to_str().expect("ascii")),
        Some("11"),
        "the declared length is what the body would have been"
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert!(body.is_empty(), "a HEAD response carries no body");
    driver.abort();
}

/// The framing core is shared, so the same smuggling corpus must be refused in
/// both roles. This is `[INV-SERVER-04]`'s falsifier.
#[tokio::test(flavor = "multi_thread")]
async fn both_roles_refuse_the_same_smuggling_shapes() {
    let cases: [&[u8]; 3] = [
        // CL.TE
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        // conflicting lengths
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
        // obsolete line folding
        b"POST / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n\tfolded\r\n\r\n",
    ];
    for case in cases {
        let mut server =
            Http1ServerReader::with_limits(ScriptedIo::chunked(case, 7), Limits::for_ingress());
        let request_error = server
            .read_request_head()
            .await
            .expect_err("request role must refuse");
        assert_eq!(request_error.class(), "protocol");

        // The response direction refuses the same bytes for the CL.TE and folding
        // shapes; it cannot reuse the request's start line, so the corpus is
        // re-headed as a response.
        let response_bytes = match case {
            c if c.starts_with(b"POST") => {
                let mut rebuilt = b"HTTP/1.1 200 OK\r\n".to_vec();
                rebuilt.extend_from_slice(
                    c.windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map_or(&[][..], |_| {
                            &c[c.iter().position(|b| *b == b'\n').unwrap_or(0) + 1..]
                        }),
                );
                rebuilt
            }
            other => other.to_vec(),
        };
        let mut client = netune_http1::Http1Reader::with_limits(
            ScriptedIo::chunked(&response_bytes, 7),
            Limits::default(),
        );
        let response_error = client
            .read_response_head(&Method::GET)
            .await
            .expect_err("response role must refuse the same shape");
        assert_eq!(response_error.class(), "protocol");
    }
}

/// A bare LF is refused by the server role and tolerated by the client role: the server
/// is a security boundary, the client is not, and RFC 9112 §2.2 makes the strictness the
/// *recipient's* choice.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_lf_terminator_is_refused_by_the_server_role_only() {
    let bytes = b"GET / HTTP/1.1\nHost: x\n\n";
    let mut server =
        Http1ServerReader::with_limits(ScriptedIo::chunked(bytes, 3), Limits::for_ingress());
    let error = server
        .read_request_head()
        .await
        .expect_err("a bare LF is a smuggling primitive");
    assert_eq!(error.class(), "protocol");

    let response = b"HTTP/1.1 200 OK\ncontent-length: 0\n\n";
    let mut client = Http1Reader_::new(ScriptedIo::chunked(response, 3));
    client
        .read_response_head(&Method::GET)
        .await
        .expect("a lenient origin is tolerated");
}

use netune_http1::Http1Reader as Http1Reader_;

/// A request target that no conforming hop could agree on never reaches application code.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_with_a_space_is_refused_before_the_header_block_is_read() {
    // Only the start line is present: a parser that read the head first would need the
    // header block to fail, and this test would hang rather than fail.
    let bytes = b"GET /a b HTTP/1.1\r\n";
    let mut server =
        Http1ServerReader::with_limits(ScriptedIo::chunked(bytes, 64), Limits::for_ingress());
    let error = server
        .read_request_head()
        .await
        .expect_err("an unservable target is refused");
    assert_eq!(error.class(), "protocol");
}

/// A declared body larger than the operator's bound is refused before the first body byte.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_declared_length_is_refused_before_the_body_is_read() {
    let bytes = b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n";
    let mut server = Http1ServerReader::with_limits(
        ScriptedIo::chunked(bytes, 64),
        Limits {
            max_body_bytes: 1024,
            ..Limits::for_ingress()
        },
    );
    let error = server
        .read_request_head()
        .await
        .expect_err("a declared length beyond the bound is refused at the head");
    assert_eq!(error.class(), "limit");
}
