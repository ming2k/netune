//! A scripted origin for the server's own suite and, later, for `netune`'s.
//!
//! Every test in this crate needs the same three things: a handler that answers
//! deterministically, a bound server, and a way to speak HTTP/1.1 to it without a
//! client library. This module is those three, so a test states what it is testing
//! instead of re-deriving how to open a socket.

#![allow(dead_code)]

use std::sync::Arc;

use bytes::Bytes;
use netune_http1::IncomingRequest;

use netune_server::{Handler, HandlerFuture, RequestBody, Response, Server, ServerConfig};

/// A handler that echoes the request body and reports the method and target it saw.
pub struct Echo;

impl Handler for Echo {
    fn handle<'a>(
        &'a self,
        request: IncomingRequest,
        mut body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            let bytes = body.read_to_end().await.unwrap_or_default();
            Response::ok(bytes)
                .with_header("x-method", request.method.as_str())
                .with_header("x-target", request.target_str().unwrap_or(""))
        })
    }
}

/// A handler that always answers with a fixed status and body.
pub struct Fixed {
    pub status: http::StatusCode,
    pub body: Bytes,
}

impl Handler for Fixed {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        _body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        let status = self.status;
        let body = self.body.clone();
        Box::pin(async move { Response::with_status(status, body) })
    }
}

/// A handler that ignores the body entirely, to prove the transport drains it.
pub struct IgnoresBody;

impl Handler for IgnoresBody {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        _body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move { Response::ok(&b"ignored"[..]) })
    }
}

/// A handler that counts its invocations, so a test can assert the transport did or
/// did not reach application code.
pub struct Counting {
    count: Arc<std::sync::atomic::AtomicUsize>,
    /// How long to wait before answering, for timeout and drain tests.
    delay: std::time::Duration,
}

impl Counting {
    pub fn new(delay: std::time::Duration) -> (Self, Arc<std::sync::atomic::AtomicUsize>) {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Self {
                count: Arc::clone(&count),
                delay,
            },
            count,
        )
    }
}

impl Handler for Counting {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        _body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let delay = self.delay;
        Box::pin(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            Response::ok(&b"counted"[..])
        })
    }
}

/// Bind an echo server on an ephemeral port with the test configuration.
pub async fn echo_server() -> Server {
    Server::bind("127.0.0.1:0", ServerConfig::for_tests(), Arc::new(Echo))
        .await
        .expect("bind")
}

/// Bind a server with an explicit config and handler.
pub async fn server_with(config: ServerConfig, handler: Arc<dyn Handler>) -> Server {
    Server::bind("127.0.0.1:0", config, handler)
        .await
        .expect("bind")
}

/// A raw HTTP/1.1 exchange: send `bytes`, read until the peer closes or `done` says
/// stop.
///
/// Deliberately not a client library: the point of these tests is to send bytes a
/// well-behaved client would not, and a library would refuse to.
pub async fn exchange(
    address: std::net::SocketAddr,
    request: &[u8],
    done: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    use tokio::io::AsyncWriteExt;
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    stream.write_all(request).await.expect("write");
    stream.flush().await.expect("flush");
    read_until(&mut stream, done).await
}

/// Read from `stream` until `done` is satisfied or the peer closes.
pub async fn read_until(
    stream: &mut tokio::net::TcpStream,
    done: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut collected = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        if done(&collected) {
            return collected;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buffer))
            .await
        {
            Ok(Ok(0)) => return collected,
            Ok(Ok(read)) => collected.extend_from_slice(&buffer[..read]),
            Ok(Err(error)) => panic!("read failed: {error}"),
            Err(_) => return collected,
        }
    }
}

/// A reader that yields pre-scripted byte slices, so a decoder can be exercised on exact
/// wire bytes without a socket.
#[derive(Debug, Default)]
pub struct ScriptedIo {
    chunks: std::collections::VecDeque<Vec<u8>>,
}

impl ScriptedIo {
    /// Deliver each provided slice as one read.
    pub fn from_slices(slices: &[&[u8]]) -> Self {
        Self {
            chunks: slices.iter().map(|slice| slice.to_vec()).collect(),
        }
    }
}

impl tokio::io::AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(chunk) = self.chunks.pop_front() {
            let take = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..take]);
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for ScriptedIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Wait until the response for a `Content-Length` body has fully arrived.
pub fn response_complete(bytes: &[u8]) -> bool {
    let Some(head_end) = find(bytes, b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&bytes[..head_end]);
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    bytes.len() >= head_end + 4 + length
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
