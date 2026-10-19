//! Tap fidelity harness: record a streamed response and print the tap's read
//! timeline, for comparison against a packet capture.
//!
//! Run by `scripts/check-tap-fidelity.sh`, which starts `tcpdump` first. The
//! example is deliberately self-contained: one listener, one request, N frames
//! delivered on a fixed cadence, and a line per read event on stdout.
//!
//! ```text
//! cargo run -p netune --example tap_fidelity -- --port 8080 --frames 8 --gap-ms 25
//! ```

// An example is a test harness: it should panic on a broken invariant rather
// than plumb an error type nobody reads.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_trace::{EventKind, Recorder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Options {
    port: u16,
    frames: usize,
    gap: Duration,
}

fn parse_options() -> Options {
    let mut port = 0u16;
    let mut frames = 8usize;
    let mut gap = Duration::from_millis(25);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                port = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0)
            }
            "--frames" => {
                frames = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(8)
            }
            "--gap-ms" => {
                gap = Duration::from_millis(
                    args.next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(25),
                )
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    Options { port, frames, gap }
}

async fn serve(listener: TcpListener, frames: usize, gap: Duration) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = socket.read(&mut buffer).await.expect("read");
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    socket
        .write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
        )
        .await
        .expect("head");
    socket.flush().await.expect("flush head");
    tokio::time::sleep(gap).await;
    for index in 0..frames {
        let frame = format!("data: {index}\n\n");
        socket
            .write_all(format!("{:x}\r\n{frame}\r\n", frame.len()).as_bytes())
            .await
            .expect("chunk");
        socket.flush().await.expect("flush");
        tokio::time::sleep(gap).await;
    }
    socket.write_all(b"0\r\n\r\n").await.expect("end");
    socket.flush().await.expect("flush end");
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let options = parse_options();
    let listener = TcpListener::bind(("127.0.0.1", options.port))
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    // The script needs the port before tcpdump starts.
    println!("port {port}");
    use std::io::Write as _;
    std::io::stdout().flush().expect("flush port");

    let server = tokio::spawn(serve(listener, options.frames, options.gap));

    let recorder = Arc::new(Mutex::new(Recorder::start(4096)));
    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let mut response = client
        .send(
            &Target::plain(format!("127.0.0.1:{port}")),
            Arc::clone(&recorder),
            RequestHead::new(http::Method::GET, "/stream"),
            None,
        )
        .await
        .expect("send");
    while response.body.next_chunk().await.expect("chunk").is_some() {}

    let lines: Vec<String> = {
        let recorder = recorder.lock().expect("recorder");
        recorder
            .log()
            .iter()
            .filter(|event| event.kind == EventKind::Read)
            .map(|event| format!("read {} {}", event.at_ns, event.a))
            .collect()
    };
    for line in lines {
        println!("{line}");
    }
    println!("done");
    let _ = server.await;
}
