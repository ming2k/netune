//! Integration test: SegmentingIo actively segments wire writes during early flight (ADR-0006).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_trace::Recorder;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

#[tokio::test]
async fn client_with_sni_segmentation_slices_early_writes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let chunks = Arc::new(Mutex::new(Vec::new()));
    let chunks_clone = Arc::clone(&chunks);

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let mut received = Vec::new();

        // Read flights and record individual chunk sizes received
        loop {
            let n = socket.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            chunks_clone.lock().unwrap().push(n);
            received.extend_from_slice(&buf[..n]);

            if received.windows(4).any(|w| w == b"\r\n\r\n") {
                // Reply 200 OK
                let resp = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                tokio::io::AsyncWriteExt::write_all(&mut socket, resp)
                    .await
                    .expect("write");
                break;
            }
        }
    });

    let target = Target::plain(format!("127.0.0.1:{port}")).with_sni_segmentation(true);
    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let recorder = Arc::new(Mutex::new(Recorder::start(64)));
    let head = RequestHead::new(Method::GET, "/evasion-check");

    let mut response = client
        .send(&target, recorder, head, None)
        .await
        .expect("send");
    let body = response.body.read_to_end().await.expect("read body");
    assert_eq!(body.as_ref(), b"ok");

    server.await.expect("server finished");

    let recorded_chunks = chunks.lock().unwrap().clone();
    assert!(!recorded_chunks.is_empty(), "must have received chunks");
    // Verify that writes were broken into chunks (for_sni caps chunk at 24 bytes)
    for &chunk in &recorded_chunks {
        assert!(chunk <= 24, "expected chunk <= 24 bytes, got {chunk}");
    }
}
