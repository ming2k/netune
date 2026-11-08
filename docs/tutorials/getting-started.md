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

Add `netune`, `netune-trace`, `tokio`, and `http` to your `Cargo.toml`. The
crates are distributed by git tag, not from a registry:

```toml
[dependencies]
netune = { git = "https://github.com/ming2k/netune", tag = "v0.0.9" }
netune-trace = { git = "https://github.com/ming2k/netune", tag = "v0.0.9" }
http = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

---

## Step 2: Write the Client Request

Create `src/main.rs` with the following code:

```rust,no_run
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_trace::{Recorder, derive};
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. A connector, a connection pool, and client configuration.
    let connector = TcpConnector::new();
    let pool = Pool::default();
    let config = ClientConfig::default();
    let client = Client::new(connector, pool, config);

    // 2. The target names an authority; the head carries the origin-form path.
    let target = Target::plain("127.0.0.1:8080");
    let head = RequestHead::new(Method::GET, "/health");

    // 3. An attempt recorder with a bounded event ring.
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));

    // 4. Send the request and consume the response body.
    println!("Sending request to {}...", target.authority);
    let mut response = client.send(&target, Arc::clone(&recorder), head, None).await?;
    let body = response.body.read_to_end().await?;
    println!("Response status: {}", response.head.status);
    println!("Response bytes: {}", body.len());

    // 5. Timings are derived from the recorded events, never from a clock read.
    //    A `Reading` carries its verdict, so an unmeasured scope is `None`.
    if let Some(trace) = response.body.trace() {
        let timings = derive(&trace);
        if let Some(tcp) = timings.tcp_us.value() {
            println!("- TCP connect: {tcp} µs");
        }
        if let Some(ttfb) = timings.ttfb_us.value() {
            println!("- TTFB: {ttfb} µs");
        }
        if let Some(e2e) = timings.e2e_us.value() {
            println!("- End to end: {e2e} µs");
        }
    }

    Ok(())
}
```

The `no_run` annotation is deliberate: the example is compiled by the test
suite but not executed, because it dials a host that only exists on your
machine. Everything else about it is checked — the imports, the signatures, and
the types — so the guide cannot drift from the real API.

---

## Step 3: Run the Code

Start a local HTTP server on port 8080 (or point the target at a test
endpoint), then run:

```bash
cargo run
```

You will see the derived microsecond timings printed from the recorded event
ring. Each number is a pure function of events the transport emitted, so it is
reproducible from the trace alone.

---

## Next Steps

- Explore TLS identity and presets in [Configure TLS Profiles and Fingerprints](../how-to/configure-tls-profiles.md).
- Learn about fault injection in [Simulate Network Chaos with FaultIo](../how-to/fault-injection.md).
- Read about our structural privilege isolation in [Structural Privilege Boundaries](../explanation/privilege-boundaries.md).
