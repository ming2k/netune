# netune

An owned, observable, and *intervention-capable* network stack in Rust.

netune owns every layer from DNS to the HTTP/1.1 message — no third-party HTTP
implementation in the production dependency graph — and makes the transport
itself an object you can inspect, fingerprint, and change:

| Crate | What it is |
|---|---|
| [`netune-trace`] | The trace model and pure derivations. Every timing a surface shows is a pure function of a recorded trace. Also: TLS ClientHello parsing and JA3/JA4 fingerprints. |
| [`netune-http1`] | The HTTP/1.1 codec. Differential-tested against hyper (dev-dependency only) over recorded byte streams. |
| [`netune-http2`] | HTTP/2 wire protocol placeholder and design reservation (ADR-0003). Reserved at 0.0.1; no I/O implementation. |
| [`netune-ws`] | Pure RFC 6455 WebSocket codec: role-enforced masking, fragmented-message reassembly, SHA-1 handshake keys. No I/O runtime. |
| [`netune`] | The transport: DNS, TCP, TLS (rustls), the syscall tap (`TimedIo`), connection pool (`Pool`), TLS fingerprint presets and routing (`TlsProfile`, `Preset`), proxies (HTTP CONNECT & SOCKS5), redirects, decompression, client WebSocket upgrade (`connect_ws`), stale-socket absorption — and `FaultIo`, the chaos twin that injects delays, splits, truncations, and resets. |
| [`netune-probe`] | The L2 probe: pure Ethernet/IPv4/TCP parse **and build** (forge) plus an opt-in `inject` feature for frame transmission. |

## Capability surface

**Observe** — a three-level tap with graceful degradation:

- **L0** protocol events, portable, always on
- **L1** syscall boundaries (`TimedIo`) + `TCP_INFO` sampling (RTT, retransmits, cwnd)
- **L2** per-segment capture (Linux, `CAP_NET_RAW`, opt-in)

**Fingerprint** — inspect and configure TLS identity:

- Pure wire parser: `netune-trace::ja4` parses ClientHello bytes and computes the JA4 fingerprint, cross-tool anchored against FoxIO's published test vectors.
- Profile presets: named presets (`netune-default`, `codex-reqwest`, `codex-network-proxy`) configure ALPN, protocol versions, ciphers, and key-exchange groups.
- Per-request selection: `Target::with_tls_profile` picks the identity at request time; unknown profile names fail loudly.
- Pool isolation: connection pool keys on `authority#profile`, preventing connection reuse across disparate TLS identities.

**Intervene** — change behaviour at two privilege levels:

- **In-process, zero privileges** (`netune::FaultIo`): script delays, split reads, truncations, and connection resets against any stream to test retry policies and streaming pipelines hermetically.
- **On the wire, feature-gated** (`netune-probe` with `--features inject`): build arbitrary TCP frames (forged seq/ack, RSTs, window games) with pure, fully tested functions; transmit them only when the feature is compiled in *and* `CAP_NET_RAW` is held. The default build has no transmit path at all.

**Resilience** — culled keep-alive absorption:

- Shortened idle pool bound (20 s) prevents handing out connections about to be culled by intermediate gateways.
- Transparent single retry on stale pooled sockets before receiving a response head (`INV-TRANSPORT-01`), eliminating spurious keep-alive failures without request replay hazard.
- Precise error classification (`HttpError::Incomplete`) distinguishing peer socket closure from protocol smuggling or violations.

## The privilege boundary is structural

```
                 default build      --features inject + CAP_NET_RAW
parse/build      ✅ present         ✅ present        (pure, tested)
transmit         ❌ not compiled    ✅ present        (socket)
```

Injection changes the network rather than measuring it; it is never a default
capability of anything long-running.

## Quick Start

### Use as a dependency

The crates are consumed from this repository by tag:

```toml
[dependencies]
netune = { git = "https://github.com/ming2k/netune", tag = "v0.0.1" }
netune-trace = { git = "https://github.com/ming2k/netune", tag = "v0.0.1" }
```

Pin a `tag` (or a `rev` for the strictest reproducibility) and upgrade
deliberately with `cargo update -p netune`.

### Build and Test

```bash
# Run unit and integration tests across all workspace crates
cargo test

# Run tests with nextest
cargo nextest run
```

### Basic Request & Trace Inspection

```rust
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};
use netune_trace::{Recorder, derive};
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(TcpConnector, Pool::default(), ClientConfig::default());
    let target = Target::http("127.0.0.1", 8080);
    let head = RequestHead::new(Method::GET, "/health");
    let recorder = Arc::new(Mutex::new(Recorder::new(1024)));

    let mut response = client.send(target, head, recorder.clone()).await?;
    let body = response.body().read_to_end(64 * 1024).await?;
    println!("Status: {}, Body len: {}", response.status(), body.len());

    // Inspect derived microsecond timings from the recorded trace
    let trace = recorder.lock().unwrap().take();
    let timings = derive(&trace);
    println!("TTFB: {:?} µs", timings.ttfb_us);
    Ok(())
}
```

## Documentation Map

- **Tutorials**: [Getting Started](docs/tutorials/index.md)
- **How-To Guides**: [all guides](docs/how-to/index.md)
  - [Configure TLS Profiles and Fingerprints](docs/how-to/configure-tls-profiles.md)
  - [Simulate Network Chaos with FaultIo](docs/how-to/fault-injection.md)
  - [Configure Proxies](docs/how-to/configure-proxies.md)
  - [Establish a WebSocket Client Connection](docs/how-to/websocket-client.md)
- **Reference**:
  - [Crates Reference](docs/reference/crates.md)
  - [System Architecture](docs/reference/architecture.md)
- **Explanation**: [all articles](docs/explanation/index.md)
  - [Structural Privilege Boundaries](docs/explanation/privilege-boundaries.md)
- **Architecture Decisions**: [ADR Registry](docs/adr/index.md)
- **Contributing**: [Contributor Guide](CONTRIBUTING.md) · [Engineering Standards](docs/dev/standards/README.md)
- **Contributing**: [Contributor Guide](CONTRIBUTING.md)

## Status

Pre-1.0. Every workspace crate is lockstep-versioned at `0.0.1`.

MSRV: 1.95. License: MIT.

[`netune-trace`]: crates/netune-trace
[`netune-http1`]: crates/netune-http1
[`netune-http2`]: crates/netune-http2
[`netune-ws`]: crates/netune-ws
[`netune`]: crates/netune
[`netune-probe`]: crates/netune-probe
