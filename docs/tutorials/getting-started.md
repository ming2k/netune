# Getting Started with netune

This tutorial guides you through making your first HTTP/1.1 request with `netune`, recording transport syscall events, and deriving microsecond-precision network metrics.

---

## What You Will Build

You will create a minimal Rust application that:
1. Connects to an HTTP server using `netune`'s owned transport.
2. Streams and reads the response body.
3. Inspects the zero-allocation `RequestTrace` event log.
4. Derives TTFB (Time-To-First-Byte) and transport timings without clock estimation.

---

## Prerequisites

- Rust 1.95 or later (`cargo`).
- A local terminal.

---

## Step 1: Add Dependencies

Add `netune`, `netune-trace`, `tokio`, and `http` to your `Cargo.toml`:

```toml
[dependencies]
netune = "0.1"
netune-trace = "0.1"
http = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

---

## Step 2: Write the Client Request

Create `src/main.rs` with the following code:

```rust
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_trace::{Recorder, derive};
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize the client with standard TCP connector and an in-memory pool
    let connector = TcpConnector::new();
    let pool = Pool::default();
    let config = ClientConfig::default();
    let client = Client::new(connector, pool, config);

    // 2. Set the target and request head
    let target = Target::plain("127.0.0.1:8080");
    let head = RequestHead::new(Method::GET, "/health");

    // 3. Create an attempt recorder with a 1024-event ring buffer
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));

    // 4. Send the request and consume the response body
    println!("Sending request to {}...", target.authority);
    let mut response = client.send(&target, recorder.clone(), head, None).await?;
    let body = response.body.read_to_end().await?;
    println!("Response status: {}", response.head.status);
    println!("Response bytes: {}", body.len());

    // 5. Derive pure mathematical timings from the recorded trace
    let trace = response.body.trace().expect("completed attempt trace");
    let timings = derive(&trace);

    println!("\nDerived Timings:");
    println!("- TCP Connect: {:?} µs", timings.tcp_us.value());
    println!("- TTFB (Time to first byte): {:?} µs", timings.ttfb_us.value());
    println!("- Total End-to-End: {:?} µs", timings.e2e_us.value());

    Ok(())
}
```

---

## Step 3: Run the Code

Start a local HTTP server on port 8080 or point the target to an active test endpoint, then run:

```bash
cargo run
```

You will observe the derived microsecond timings printed directly from the recorded event ring buffer.

---

## Next Steps

- Explore TLS identity and presets in [Configure TLS Profiles and Fingerprints](../how-to/configure-tls-profiles.md).
- Learn about fault injection in [Simulate Network Chaos with FaultIo](../how-to/fault-injection.md).
- Read about our structural privilege isolation in [Structural Privilege Boundaries](../explanation/privilege-boundaries.md).
