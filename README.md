# netune

An owned, observable, and *intervention-capable* network stack in Rust.

netune owns every layer from DNS to the HTTP message — in both directions, HTTP/1.1,
HTTP/2 and HTTP/3, plus a draft-pinned WebTransport layer — with no third-party HTTP
implementation in the production dependency graph, and makes the transport itself an
object you can inspect, fingerprint, and change:

| Crate | What it is |
|---|---|
| [`netune-trace`] | The trace model and pure derivations. Every timing a surface shows is a pure function of a recorded trace. Also: TLS ClientHello parsing and JA3/JA4 fingerprints. |
| [`netune-http1`] | The HTTP/1.1 codec. Differential-tested against hyper (dev-dependency only) over recorded byte streams. |
| [`netune-http2`] | RFC 9113, both roles over one connection machine: frame codec, HPACK with a full dynamic table (RFC 7541), Huffman coding, per-stream and connection flow control, `PADDED`/`PRIORITY` stripping, `CONTINUATION` reassembly, `PUSH_PROMISE` refusal, a server session with `REFUSED_STREAM` shedding, and declarative Akamai fingerprint impersonation (ADR-0006, ADR-0012). |
| [`netune-ws`] | Pure RFC 6455 WebSocket codec: role-enforced masking, fragmented-message reassembly, SHA-1 handshake keys. No I/O runtime. |
| [`netune-quic`] | First-class QUIC (RFC 9000/9221) with named handshake profiles, pre-connect confinement, datagrams, streams and `aws-lc-rs` crypto. Consumer seams: per-connection socket and congestion factories, keep-alive/idle policy and verified peer-certificate access (ADR-0034). |
| [`netune-http3`] | HTTP/3 client and server adapter (RFC 9114): streaming uploads and trailers, typed SETTINGS, controlled dynamic QPACK (encoder/decoder/ACKs/blocked streams), and request-header order. |
| [`netune-io`] | The byte path both directions share: `TimedIo` records every syscall boundary, `FaultIo` injects chaos. No socket, no policy. |
| [`netune-egress`] | Pure egress-address policy: `is_public_ip` and `EgressConfinement`, the one predicate every outbound transport (TCP, UDP, QUIC) checks before opening a socket. No I/O. |
| [`netune`] | **Egress**: DNS, TCP, TLS (rustls), connection pool (`Pool`), TLS fingerprint presets and routing (`TlsProfile`, `Preset`), proxies (HTTP CONNECT & SOCKS5), egress confinement, redirects, decompression, client WebSocket upgrade (`connect_ws`), stale-socket absorption. |
| [`netune-server`] | **Ingress**: an observable listener serving **HTTP/1.1, HTTP/2 and optional HTTP/3** behind one handler — accept loop, admission control that sheds instead of queueing, separate phase bounds, streaming responses, request validation before dispatch, per-connection ingress traces, graceful drain. HTTP/3 is a peer QUIC listener, not a mode of the TCP server. A transport, not a framework. |
| [`netune-webtransport`] | Owned WebTransport over HTTP/3 draft-17: sessions, bidi/uni streams, datagrams, flow-control/close capsules and multi-session routing. Reliable `RESET_STREAM_AT` and browser interop remain outstanding (ADR-0033). |
| [`netune-probe`] | The L2 probe: `AF_PACKET` capture of one TCP flow, pure Ethernet/IPv4/TCP parse **and build** (forge), plus an opt-in `inject` feature for frame transmission. |

## Capability surface

**Observe** — typed observation with an explicit cost:

- **L0** byte/call counters by default (`Observation::Counters`); no clock, no allocation, no lock on the byte path. `Observation::Off` is the fully untraced mode.
- **L1** syscall-boundary event ring (`Observation::Traced`) + `TCP_INFO` sampling (RTT, retransmits, cwnd); the ring is opt-in and bounded.
- **L2** per-segment capture (Linux, `CAP_NET_RAW`, opt-in) — a **separate binary**,
  `netune-probe`. It captures one 4-tuple for a bounded window and prints one JSON object
  per segment; the daemon never links it. `TimeSource::PacketCapture` in `netune-trace` is
  reserved for a segment timestamp and is **not yet emitted**: nothing today feeds an L2
  arrival time into a `TraceCollector`. What exists is the capture and the timeline; joining the
  two is unstarted.

**Fingerprint** — inspect and configure TLS identity:

- Pure wire parser: `netune-trace::ja4` parses ClientHello bytes and computes the JA4 fingerprint, cross-tool anchored against FoxIO's published test vectors.
- Profile presets: named presets (`netune-default`, `codex-reqwest`, `codex-network-proxy`) configure ALPN, protocol versions, ciphers, and key-exchange groups.
- Per-request selection: `Target::with_tls_profile` picks the identity at request time; unknown profile names fail loudly.
- Pool isolation: connection pool keys on `authority#profile`, preventing connection reuse across disparate TLS identities.

**Intervene** — change behaviour at two privilege levels:

- **In-process, zero privileges** (`netune::FaultIo`): script delays, split reads, truncations, and connection resets against any stream to test retry policies and streaming pipelines hermetically.
- **On the wire, feature-gated** (`netune-probe` with `--features inject`): build arbitrary TCP frames (forged seq/ack, RSTs, window games) with pure, fully tested functions; transmit them only when the feature is compiled in *and* `CAP_NET_RAW` is held. The default build has no transmit path at all.

**Serve** — the other direction of travel (ADR-0011):

- `netune-server` owns the only listening socket in the workspace. `netune` never
  listens; `netune-server` never dials. Neither depends on the other, so a client-only
  build cannot accept a connection and an ingress build cannot leak an egress stack.
- Every ingress timing is a pure derivation of a recorded trace, exactly as on the
  egress side: `request_read_us` (accept → head), `queue_us` (head → handler),
  `handler_us`, `write_us` (handler → last byte). A slow client and a slow handler look
  different because they are measured differently.
- A request is bounded before it is served: head size, header count, body size, and the
  time allowed to produce each. A peer that will not finish its head never reaches
  application code.

**Resilience** — culled keep-alive absorption:

- Shortened idle pool bound (20 s) prevents handing out connections about to be culled by intermediate gateways.
- Transparent single retry on stale pooled sockets before receiving a response head (`INV-TRANSPORT-01`), eliminating spurious keep-alive failures without request replay hazard.
- Precise error classification (`HttpError::Incomplete`) distinguishing peer socket closure from protocol smuggling or violations.

## The privilege boundary is structural

```text
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
netune = { git = "https://github.com/ming2k/netune", tag = "v0.0.14" }
netune-trace = { git = "https://github.com/ming2k/netune", tag = "v0.0.14" }
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

Every traced attempt is recorded, and every displayed number is derived from
that record. This program sends one traced request and reads the trace back:

```rust,no_run
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TraceConfig};
use netune_trace::derive;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(TcpConnector::new(), Pool::default(), ClientConfig::default());
    let target = Target::plain("127.0.0.1:8080");
    let head = RequestHead::new(Method::GET, "/health");

    let mut response = client
        .request_traced(&target, head, None, TraceConfig::default())
        .await?;
    let body = response.body.read_to_end().await?;
    println!("status {}, {} bytes", response.head.status, body.len());

    // Timings are a pure function of the recorded events. A `Reading` carries
    // its own verdict, so a scope that was not measured yields `None` rather
    // than a fabricated zero.
    if let Some(trace) = response.body.trace() {
        let timings = derive(&trace);
        if let Some(ttfb) = timings.ttfb_us.value() {
            println!("ttfb {ttfb} us");
        }
    }
    Ok(())
}
```

`request_traced` begins the attempt's trace at "now" and records a dispatch
event at offset zero; `Response::body.trace()` returns the attempt's trace only
once the body is fully consumed, because a partial trace would report missing
stages as if they had not happened.

## Documentation Map

- **Tutorials**: [Getting Started](docs/tutorials/index.md)
- **How-To Guides**: [all guides](docs/how-to/index.md)
  - [Configure TLS Profiles and Fingerprints](docs/how-to/configure-tls-profiles.md)
  - [Simulate Network Chaos with FaultIo](docs/how-to/fault-injection.md)
  - [Configure Proxies](docs/how-to/configure-proxies.md)
  - [Establish a WebSocket Client Connection](docs/how-to/websocket-client.md)
  - [Use HTTP/3](docs/how-to/use-http3.md)
- **Reference**:
  - [Crates Reference](docs/reference/crates.md)
  - [System Architecture](docs/reference/architecture.md)
- **Explanation**: [all articles](docs/explanation/index.md)
  - [Structural Privilege Boundaries](docs/explanation/privilege-boundaries.md)
- **Architecture Decisions**: [ADR Registry](docs/adr/index.md)
- **Documentation Portal**: [Documentation Index](docs/index.md)
- **Contributing**: [Contributor Guide](CONTRIBUTING.md) · [Engineering Standards](docs/dev/standards/README.md)

## Status

Pre-1.0. Every workspace crate is lockstep-versioned at `0.0.14`.

MSRV: 1.95. License: MIT.

[`netune-trace`]: crates/netune-trace
[`netune-http1`]: crates/netune-http1
[`netune-http2`]: crates/netune-http2
[`netune-ws`]: crates/netune-ws
[`netune-quic`]: crates/netune-quic
[`netune-http3`]: crates/netune-http3
[`netune-io`]: crates/netune-io
[`netune-egress`]: crates/netune-egress
[`netune-webtransport`]: crates/netune-webtransport
[`netune`]: crates/netune
[`netune-server`]: crates/netune-server
[`netune-probe`]: crates/netune-probe
