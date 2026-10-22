//! A pooled connection must not outlive the runtime that registered it.
//!
//! `Pool` is process-scoped: one `Client` is shared by every task in the
//! process, so a keep-alive socket can be handed from one runtime to another. A
//! socket is a *tokio I/O resource*: it is registered with the reactor that
//! created it. When that reactor is dropped (an `#[tokio::test]` returning, a
//! worker thread's runtime shutting down, a scoped runtime in a library), tokio
//! marks the registration shut down and the next read on that socket fails with
//! `RUNTIME_SHUTTING_DOWN_ERROR` — "A Tokio 1.x context was found, but it is
//! being shutdown."
//!
//! The pool therefore has to refuse a connection whose origin runtime is gone,
//! before the request is written, so the caller pays a handshake instead of
//! receiving a transport error it cannot act on.
//!
//! The sequence below is the real one: runtime A dials, completes a request and
//! releases the connection into a pool both runtimes share; runtime A is
//! dropped; runtime B takes that pooled connection and must transparently dial
//! a fresh one.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_trace::Recorder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve one request per accepted connection, then hold the socket open so the
/// client believes it is reusable.
async fn serve(listener: TcpListener) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match socket.read(&mut buffer).await {
                    Ok(0) => return,
                    Ok(read) => request.extend_from_slice(&buffer[..read]),
                    Err(_) => return,
                }
            }
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .await;
            let _ = socket.flush().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
    }
}

async fn one_request(client: &Client<TcpConnector>, target: &Target) -> u16 {
    let recorder = Arc::new(Mutex::new(Recorder::start(64)));
    let head = RequestHead::new(http::Method::GET, "/");
    let mut response = client
        .send(target, recorder, head, None)
        .await
        .expect("request must succeed");
    let mut body = Vec::new();
    while let Some(chunk) = response.body.next_chunk().await.expect("body chunk") {
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, b"ok");
    response.head.status.as_u16()
}

#[test]
fn a_pooled_connection_from_a_dead_runtime_is_discarded() {
    // The peer lives on its own runtime for the whole test: only the *client's*
    // socket is meant to die with runtime A, so the server must not be a
    // variable in the experiment.
    let (address, server) = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let handle = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("server runtime");
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).expect("adopt listener");
                serve(listener).await;
            });
        });
        (address, handle)
    };

    // One pool, shared by two client runtimes — exactly how a process-global
    // `shared_client()` pool is used.
    let pool = Pool::default();
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime A");
        runtime.block_on(async {
            let target = Target::plain(address.to_string());
            let client = Client::new(TcpConnector::new(), pool.clone(), ClientConfig::default());
            let status = one_request(&client, &target).await;
            assert_eq!(status, 200, "the fresh connection must work");
        });
        // Runtime A is dropped here with a keep-alive socket of its own still
        // sitting in `pool` — the same shape as a test binary whose
        // `#[tokio::test]` returned, or a worker thread whose runtime shut down,
        // while the process-global client still holds the connection.
    }

    // Runtime B takes the connection runtime A registered.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime B");
    let status = runtime.block_on(async {
        let target = Target::plain(address.to_string());
        let client = Client::new(TcpConnector::new(), pool, ClientConfig::default());
        one_request(&client, &target).await
    });
    assert_eq!(
        status, 200,
        "a stale pooled socket must not become an error"
    );
    drop(server);
}
