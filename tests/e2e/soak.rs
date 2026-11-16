// SPDX-License-Identifier: MIT

//! Long-running churn, resource-leak, and fault soak suite.
//!
//! All tests are `#[ignore]` so regular PR runs stay fast and are executed by
//! `cargo nextest run --workspace --all-features --run-ignored ignored-only --profile soak`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use netune::{
    Client, ClientConfig, HttpProtocol, Observation, Pool, PoolConfig, RequestBody, RequestHead,
    Target, TcpConnector,
};
use netune_server::{Protocols, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};

use crate::common::server::Echo;

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.count())
        .unwrap_or(0)
}

fn rss_pages() -> usize {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<usize>().ok())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running soak: run explicitly with --profile soak --run-ignored ignored-only"]
async fn soak_pool_concurrency_reaper_and_fd_bounds() {
    let cfg = ServerConfig::default()
        .with_protocols(Protocols::HTTP1)
        .with_max_requests_per_connection(100);
    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(Echo))
        .await
        .unwrap();
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let sw = Arc::clone(&shutdown);
    let srv = tokio::spawn(async move {
        server.serve(async move { sw.notified().await }).await;
    });

    let pool = Pool::new(
        PoolConfig::default()
            .with_max_idle_per_authority(16)
            .with_max_idle_total(32)
            .with_max_in_flight_per_authority(Some(32))
            .with_idle_timeout(Duration::from_millis(250)),
    );
    let client = Client::new(
        TcpConnector::new(),
        pool.clone(),
        ClientConfig::default().with_observation(Observation::Off),
    );
    let target = Target::plain(addr.to_string()).with_protocol(HttpProtocol::Http1);

    let baseline_fds = open_fd_count();
    let baseline_rss = rss_pages();

    // High concurrency waves interleaved with idle expiry.
    for wave in 0..8 {
        let mut tasks = Vec::new();
        for i in 0..32 {
            let c = client.clone();
            let t = target.clone();
            tasks.push(tokio::spawn(async move {
                let payload = Bytes::from(format!("wave-{wave}-item-{i}"));
                let mut r = c
                    .request(
                        &t,
                        RequestHead::new(Method::POST, "/soak"),
                        RequestBody::Full(payload.clone()),
                    )
                    .await
                    .unwrap();
                assert_eq!(r.head.status, StatusCode::OK);
                let body = r.body.read_to_end().await.unwrap();
                assert_eq!(body, payload);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _reaped = pool.reap();
        assert!(
            pool.total_idle_count() <= 32,
            "idle count exceeded configured cap"
        );
    }

    drop(client);
    pool.reap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let final_fds = open_fd_count();
    let final_rss = rss_pages();
    assert!(
        final_fds <= baseline_fds + 16,
        "possible fd leak across 256 concurrent pool waves: baseline={baseline_fds}, final={final_fds}"
    );
    // Allow generous growth for allocator fragmentation, assert no runaway leak.
    if baseline_rss > 0 {
        assert!(
            final_rss <= baseline_rss.saturating_mul(4).max(baseline_rss + 8192),
            "unexpected RSS growth: baseline={baseline_rss} pages, final={final_rss} pages"
        );
    }

    shutdown.notify_one();
    let _ = srv.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "long-running soak: run explicitly with --profile soak --run-ignored ignored-only"]
async fn soak_h1_early_response_half_write_never_pools() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                    if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 4\r\n\r\nstop")
                    .await;
            });
        }
    });

    let pool = Pool::default();
    let client = Client::new(TcpConnector::new(), pool.clone(), ClientConfig::default());
    let target = Target::plain(addr.to_string()).with_protocol(HttpProtocol::Http1);

    let baseline_fds = open_fd_count();
    for _ in 0..100 {
        let (tx, rx) = mpsc::channel::<Bytes>(2);
        let sender = tokio::spawn(async move {
            let _ = tx.send(Bytes::from_static(b"partial-chunk")).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = tx.send(Bytes::from_static(b"never-sent")).await;
        });

        let mut resp = client
            .request(
                &target,
                RequestHead::new(Method::POST, "/early"),
                RequestBody::stream(rx),
            )
            .await
            .unwrap();
        assert_eq!(resp.head.status, StatusCode::PAYLOAD_TOO_LARGE);
        let body = resp.body.read_to_end().await.unwrap();
        assert_eq!(body, Bytes::from_static(b"stop"));
        sender.abort();
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        pool.total_idle_count(),
        0,
        "half-written early-response H1 sockets must never be returned to pool"
    );
    let final_fds = open_fd_count();
    assert!(
        final_fds <= baseline_fds + 16,
        "fd leak after 100 early-response H1 aborts: baseline={baseline_fds}, final={final_fds}"
    );

    srv.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "long-running soak: run explicitly with --profile soak --run-ignored ignored-only"]
async fn soak_server_slow_half_open_clients_and_graceful_drain() {
    let cfg = ServerConfig::default()
        .with_protocols(Protocols::HTTP1)
        .with_drain_timeout(Duration::from_millis(500));
    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(Echo))
        .await
        .unwrap();
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let sw = Arc::clone(&shutdown);
    let srv = tokio::spawn(async move {
        server.serve(async move { sw.notified().await }).await;
    });

    // Open 64 half-written/half-open raw TCP sockets and drop or stall them.
    let mut stalled = Vec::new();
    for i in 0..64 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"POST /stall HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1024\r\n\r\npart")
            .await
            .unwrap();
        if i % 2 == 0 {
            let _ = s.shutdown().await;
            drop(s);
        } else {
            stalled.push(s);
        }
    }

    // Also verify healthy traffic still gets served cleanly.
    let mut healthy = TcpStream::connect(addr).await.unwrap();
    healthy
        .write_all(b"GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut reply = Vec::new();
    healthy.read_to_end(&mut reply).await.unwrap();
    assert!(
        String::from_utf8_lossy(&reply).contains("200 OK"),
        "healthy request failed amidst slow clients"
    );

    // Trigger graceful shutdown; drain grace must cap wait even with stalled clients open.
    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(3), srv)
        .await
        .expect("server drain exceeded grace period")
        .unwrap();
    drop(stalled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running soak: run explicitly with --profile soak --run-ignored ignored-only"]
async fn soak_h2_stream_churn_and_fd_bounds() {
    let cfg = ServerConfig::default().with_protocols(Protocols::HTTP2);
    let server = Server::bind("127.0.0.1:0", cfg, Arc::new(Echo))
        .await
        .unwrap();
    let addr = server.local_addr();
    let shutdown = Arc::new(Notify::new());
    let sw = Arc::clone(&shutdown);
    let srv = tokio::spawn(async move {
        server.serve(async move { sw.notified().await }).await;
    });

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default().with_observation(Observation::Off),
    );
    let target = Target::plain(addr.to_string()).with_protocol(HttpProtocol::Http2);

    let baseline_fds = open_fd_count();
    for round in 0..20 {
        let mut tasks = Vec::with_capacity(25);
        for s in 0..25 {
            let c = client.clone();
            let t = target.clone();
            tasks.push(tokio::spawn(async move {
                let payload = Bytes::from(format!("h2-round-{round}-stream-{s}"));
                let mut r = c
                    .request(
                        &t,
                        RequestHead::new(Method::POST, "/h2soak"),
                        RequestBody::Full(payload.clone()),
                    )
                    .await
                    .unwrap();
                assert_eq!(r.head.status, StatusCode::OK);
                assert_eq!(r.body.read_to_end().await.unwrap(), payload);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    }

    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let final_fds = open_fd_count();
    assert!(
        final_fds <= baseline_fds + 16,
        "fd leak after 500 HTTP/2 streams: baseline={baseline_fds}, final={final_fds}"
    );

    shutdown.notify_one();
    let _ = srv.await;
}
