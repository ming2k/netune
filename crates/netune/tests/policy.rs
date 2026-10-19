//! Policy layer: redirects and content-encoding, end to end.
//!
//! Every case here is a shape a real gateway produces: a `302` to a canonical
//! host, a `303` after a `POST`, a gzipped JSON body, a redirect that tries to
//! carry credentials to another origin. The assertions are about *behaviour* and
//! about what the trace recorded, because both are the contract.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, StatusCode};
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_trace::{EventKind, Recorder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One scripted HTTP response.
#[derive(Clone)]
struct Reply {
    raw: Vec<u8>,
}

impl Reply {
    fn raw(raw: impl Into<Vec<u8>>) -> Self {
        Self { raw: raw.into() }
    }

    /// A body-less status with headers.
    fn status(status: u16, headers: &[(&str, &str)]) -> Self {
        let mut text = format!("HTTP/1.1 {status} X\r\n");
        for (name, value) in headers {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        text.push_str("content-length: 0\r\n\r\n");
        Self::raw(text.into_bytes())
    }

    /// A 200 with a body and optional extra headers.
    fn body(body: &[u8], headers: &[(&str, &str)]) -> Self {
        let mut text = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n", body.len());
        for (name, value) in headers {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        text.push_str("\r\n");
        let mut raw = text.into_bytes();
        raw.extend_from_slice(body);
        Self::raw(raw)
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip");
    encoder.finish().expect("finish")
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
    writer.write_all(data).expect("brotli");
    writer.flush().expect("flush");
    writer.into_inner()
}

/// Serve one request per accepted connection, recording what was received.
async fn serve(listener: TcpListener, replies: Vec<Reply>, seen: Arc<Mutex<Vec<String>>>) {
    for reply in replies {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        // Read the head.
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).await.expect("read head");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        // Then the declared body, so the client's write never blocks.
        let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        if let Some(length) = text
            .split("content-length:")
            .nth(1)
            .and_then(|rest| rest.split("\r\n").next())
            .and_then(|value| value.trim().parse::<usize>().ok())
        {
            let head_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .unwrap_or(request.len());
            while request.len() - head_end < length {
                let read = socket.read(&mut buffer).await.expect("read body");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
        }
        seen.lock()
            .expect("seen")
            .push(String::from_utf8_lossy(&request).to_string());
        socket.write_all(&reply.raw).await.expect("reply");
        socket.flush().await.expect("flush");
    }
}

async fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    (listener, address)
}

fn recorder() -> Arc<Mutex<Recorder>> {
    Arc::new(Mutex::new(Recorder::start(1024)))
}

async fn send(
    client: &Client<TcpConnector>,
    address: &str,
    path: &str,
    method: Method,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> (netune::Response, Arc<Mutex<Recorder>>) {
    let recorder = recorder();
    let mut head = RequestHead::new(method, path);
    for (name, value) in headers {
        head = head.with_header(name, *value);
    }
    let response = client
        .send(
            &Target::plain(address),
            Arc::clone(&recorder),
            head,
            body.map(Bytes::copy_from_slice),
        )
        .await
        .expect("send");
    (response, recorder)
}

fn client() -> Client<TcpConnector> {
    Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    )
}

fn events(recorder: &Arc<Mutex<Recorder>>) -> Vec<EventKind> {
    recorder
        .lock()
        .expect("recorder")
        .log()
        .iter()
        .map(|event| event.kind)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gzipped_body_is_decoded_and_the_header_is_consumed() {
    let payload = br#"{"models":["a","b"]}"#;
    let (listener, address) = listener().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(serve(
        listener,
        vec![Reply::body(&gzip(payload), &[("content-encoding", "gzip")])],
        Arc::clone(&seen),
    ));

    let (mut response, _) = send(&client(), &address, "/models", Method::GET, &[], None).await;
    assert_eq!(response.head.status, StatusCode::OK);
    assert!(
        response.head.headers.get("content-encoding").is_none(),
        "a decoded body must not claim to be encoded"
    );
    assert_eq!(
        &response.body.read_to_end().await.expect("body")[..],
        payload
    );
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_brotli_body_is_decoded() {
    let payload = b"streamed bytes".repeat(200);
    let (listener, address) = listener().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(serve(
        listener,
        vec![Reply::body(
            &brotli(&payload),
            &[("content-encoding", "br")],
        )],
        Arc::clone(&seen),
    ));

    let (mut response, _) = send(&client(), &address, "/models", Method::GET, &[], None).await;
    assert_eq!(
        &response.body.read_to_end().await.expect("body")[..],
        payload
    );
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_encoding_is_refused() {
    let (listener, address) = listener().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(serve(
        listener,
        vec![Reply::body(
            b"\x28\xb5\x2f\xfd",
            &[("content-encoding", "zstd")],
        )],
        Arc::clone(&seen),
    ));

    // The failure surfaces before the caller ever sees a response: an
    // undecodable body is not something to hand downstream.
    let error = client()
        .send(
            &Target::plain(&address),
            recorder(),
            RequestHead::new(Method::GET, "/models"),
            None,
        )
        .await
        .err()
        .expect("unsupported encoding");
    assert_eq!(error.class(), "encoding");
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_is_followed_and_only_the_final_head_completes() {
    let (listener, address) = listener().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(serve(
        listener,
        vec![
            Reply::status(302, &[("location", "/final")]),
            Reply::body(b"landed", &[]),
        ],
        Arc::clone(&seen),
    ));

    let (mut response, recorder) =
        send(&client(), &address, "/start", Method::GET, &[], None).await;
    assert_eq!(response.head.status, StatusCode::OK);
    assert_eq!(
        &response.body.read_to_end().await.expect("body")[..],
        b"landed"
    );

    let kinds = events(&recorder);
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == EventKind::HeadComplete)
            .count(),
        1,
        "TTFT must be measured against the final head, not a 302"
    );
    assert!(kinds.contains(&EventKind::Redirect));
    let seen = seen.lock().expect("seen").clone();
    assert!(seen[0].starts_with("GET /start "), "{:?}", seen[0]);
    assert!(seen[1].starts_with("GET /final "), "{:?}", seen[1]);
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_303_turns_a_post_into_a_bodyless_get() {
    let (listener, address) = listener().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(serve(
        listener,
        vec![
            Reply::status(303, &[("location", "/done")]),
            Reply::body(b"ok", &[]),
        ],
        Arc::clone(&seen),
    ));

    let (mut response, _) = send(
        &client(),
        &address,
        "/submit",
        Method::POST,
        &[("content-type", "application/json")],
        Some(b"{\"a\":1}"),
    )
    .await;
    assert_eq!(&response.body.read_to_end().await.expect("body")[..], b"ok");

    let seen = seen.lock().expect("seen").clone();
    assert!(seen[1].starts_with("GET /done "), "{:?}", seen[1]);
    assert!(
        !seen[1].to_ascii_lowercase().contains("content-type"),
        "a GET after 303 carries no body and no content type"
    );
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_307_preserves_the_method_and_body() {
    let (listener, address) = listener().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(serve(
        listener,
        vec![
            Reply::status(307, &[("location", "/retry")]),
            Reply::body(b"ok", &[]),
        ],
        Arc::clone(&seen),
    ));

    let (mut response, _) = send(
        &client(),
        &address,
        "/submit",
        Method::POST,
        &[("content-type", "application/json")],
        Some(b"{\"a\":1}"),
    )
    .await;
    assert_eq!(&response.body.read_to_end().await.expect("body")[..], b"ok");

    let seen = seen.lock().expect("seen").clone();
    assert!(seen[1].starts_with("POST /retry "), "{:?}", seen[1]);
    assert!(seen[1].ends_with("{\"a\":1}"), "the body is replayed");
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_do_not_follow_a_cross_origin_redirect() {
    let (listener_a, address_a) = listener().await;
    let (listener_b, address_b) = listener().await;
    let seen_a = Arc::new(Mutex::new(Vec::new()));
    let seen_b = Arc::new(Mutex::new(Vec::new()));
    let location = format!("http://{address_b}/other");
    let server_a = tokio::spawn(serve(
        listener_a,
        vec![Reply::status(302, &[("location", &location)])],
        Arc::clone(&seen_a),
    ));
    let server_b = tokio::spawn(serve(
        listener_b,
        vec![Reply::body(b"other", &[])],
        Arc::clone(&seen_b),
    ));

    let (mut response, _) = send(
        &client(),
        &address_a,
        "/start",
        Method::GET,
        &[("authorization", "Bearer secret"), ("cookie", "a=1")],
        None,
    )
    .await;
    assert_eq!(
        &response.body.read_to_end().await.expect("body")[..],
        b"other"
    );

    let seen_a = seen_a.lock().expect("seen_a").clone();
    let seen_b = seen_b.lock().expect("seen_b").clone();
    assert!(
        seen_a[0].to_ascii_lowercase().contains("authorization"),
        "the original request carried the credential"
    );
    let forwarded = seen_b[0].to_ascii_lowercase();
    assert!(!forwarded.contains("authorization"), "{:?}", seen_b[0]);
    assert!(!forwarded.contains("cookie"), "{:?}", seen_b[0]);
    let _ = (server_a.await, server_b.await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_loop_is_refused() {
    let (listener, address) = listener().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    // Each hop points back at the same path: the client must give up.
    let replies: Vec<Reply> = (0..6)
        .map(|_| Reply::status(302, &[("location", "/loop")]))
        .collect();
    let server = tokio::spawn(serve(listener, replies, Arc::clone(&seen)));

    let recorder = recorder();
    let error = client()
        .send(
            &Target::plain(&address),
            recorder,
            RequestHead::new(Method::GET, "/loop"),
            None,
        )
        .await
        .err()
        .expect("must give up");
    assert_eq!(error.class(), "redirect");
    assert!(!error.is_retryable());
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_to_an_absolute_url_switches_authority() {
    let (listener_a, address_a) = listener().await;
    let (listener_b, address_b) = listener().await;
    let seen_a = Arc::new(Mutex::new(Vec::new()));
    let seen_b = Arc::new(Mutex::new(Vec::new()));
    let location = format!("http://{address_b}/canonical?x=1");
    let server_a = tokio::spawn(serve(
        listener_a,
        vec![Reply::status(301, &[("location", &location)])],
        Arc::clone(&seen_a),
    ));
    let server_b = tokio::spawn(serve(
        listener_b,
        vec![Reply::body(b"canonical", &[])],
        Arc::clone(&seen_b),
    ));

    let (mut response, _) = send(&client(), &address_a, "/old", Method::GET, &[], None).await;
    assert_eq!(
        &response.body.read_to_end().await.expect("body")[..],
        b"canonical"
    );
    let seen_b = seen_b.lock().expect("seen_b").clone();
    assert!(
        seen_b[0].starts_with("GET /canonical?x=1 "),
        "{:?}",
        seen_b[0]
    );
    assert!(
        seen_b[0]
            .to_ascii_lowercase()
            .contains(&format!("host: {address_b}")),
        "{:?}",
        seen_b[0]
    );
    let _ = (server_a.await, server_b.await);
}
