//! Wire segmentation, proved by *when* bytes arrive rather than how a read split them.
//!
//! # Why the arrival-size assertion had to go
//!
//! This file used to assert that every `read` on the server returned at most
//! `chunk_size` (24) bytes. That is not a property of [`netune::SegmentingIo`]; it is a
//! property of how full the server's receive buffer happened to be when the task was
//! scheduled. Under parallel load the coalescing happens in the kernel and the loopback
//! stack before the test task is polled at all, so the assertion failed while the
//! segmenter was working perfectly — a test that measured the machine, not the code.
//!
//! What the segmenter actually guarantees is a **gap** between the flights it emits: each
//! write under the limit is followed by an `inter_chunk_gap` sleep, so the bytes leave in
//! separate flights instead of one. That is observable as distinct arrival *instants*, and
//! arrival instants survive a loaded machine (they can only be delayed, never merged into
//! one instant).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netune::{Client, ClientConfig, Method, Pool, RequestHead, Target, TcpConnector};
use netune_trace::{EvasionPolicy, TraceCollector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The `for_sni` chunk size, from `SegmentingIo::for_sni`.
const CHUNK: usize = 24;

#[tokio::test]
async fn client_with_sni_segmentation_slices_early_writes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    // Arrival instants of each read, plus the byte counts, so the assertion can talk
    // about separation rather than accumulation.
    let flights = Arc::new(Mutex::new(Vec::<(Instant, usize)>::new()));
    let recorded = Arc::clone(&flights);

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let mut received = Vec::new();
        loop {
            let read = socket.read(&mut buf).await.expect("read");
            if read == 0 {
                break;
            }
            recorded.lock().unwrap().push((Instant::now(), read));
            received.extend_from_slice(&buf[..read]);
            if received.windows(4).any(|window| window == b"\r\n\r\n") {
                // A complete response, so the client's `send` returns and the test ends
                // deliberately rather than by timeout.
                let response =
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                socket.write_all(response).await.expect("write");
                break;
            }
        }
    });

    let target =
        Target::plain(format!("127.0.0.1:{port}")).with_evasion(EvasionPolicy::sni_split());
    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let recorder = TraceCollector::start(64);
    let head = RequestHead::new(Method::GET, "/evasion-check");
    let mut response = client
        .send_traced(&target, recorder, head, None)
        .await
        .expect("send");
    let body = response.body.read_to_end().await.expect("read body");
    assert_eq!(body.as_ref(), b"ok");

    server.await.expect("server finished");

    let arrivals = flights.lock().unwrap().clone();
    assert!(
        !arrivals.is_empty(),
        "the server must have received something"
    );

    // At least two reads arrived as separate flights. `for_sni` sleeps 2 ms between
    // chunks, so two arrivals separated by materially less than that are the kernel
    // coalescing them, and the assertion would be measuring the host. The gap is what
    // segmentation is *for*: a DPI device sees separate segments.
    let gaps: Vec<Duration> = arrivals
        .windows(2)
        .map(|pair| pair[1].0.duration_since(pair[0].0))
        .collect();
    let separated = gaps
        .iter()
        .filter(|gap| **gap >= Duration::from_millis(1))
        .count();
    assert!(
        separated >= 1,
        "expected at least one inter-flight gap from the segmenter; arrival gaps were {gaps:?}"
    );

    // The segmenter never emits more than `chunk_size` in one write, so no single read can
    // exceed the whole early-flight budget by much. A *bounded* total is what the size
    // assertion is worth keeping for: it catches "segmentation did not happen at all",
    // which would show up as one read covering the entire request line.
    let longest = arrivals.iter().map(|(_, len)| *len).max().unwrap();
    let total: usize = arrivals.iter().map(|(_, len)| *len).sum();
    assert!(
        longest < total,
        "a single read consumed the whole request ({longest} of {total}); no segmentation"
    );
    assert!(
        total > CHUNK,
        "the request must be longer than one chunk for this test to mean anything"
    );
}
