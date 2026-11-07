---
id: RFC-0001
title: "First-Class QUIC and HTTP/3 Client Transport in netune"
status: accepted
date: 2026-11-07
author: "Ming Li"
target_adr: ADR-0016
withdrawn_reason: null
scope: [transport/quic, protocol/http3, crypto/provider, trace/quic, crate-topology]
---

# RFC-0001: First-Class QUIC and HTTP/3 Client Transport in netune

- **Status**: Accepted
- **Author**: Ming Li
- **Date**: 2026-11-07
- **Supersedes / Re-evaluates**: [netune ADR-0010](../adr/0010-quic-ownership-and-trace-sink.md)
- **Target ADR**: [ADR-0016](../adr/0016-quic-and-http3-transport.md)
- **Scope**: `crates/netune-quic`, `crates/netune-http3`, `crates/netune`, `crates/netune-trace`

---

## 1. Motivation & Problem Statement

### 1.1 The Context of ADR-0010
In `netune ADR-0010` (2026-11-01), QUIC support was intentionally deferred with the following rationale:
> *"netune does not add a transport whose handshake it cannot shape. 'We can call a library that does it' is not ownership. netune gains QUIC only when a consumer needs it as a client in netune's own identity model — that is, when there is a `QuicProfile` that shapes a QUIC handshake the way `TlsProfile` shapes a TCP one, and a trace vocabulary for QUIC frames."*

To avoid prematurely adopting an unshaped wrapper, the consumer (`daer`) absorbed `quinn`, `quinn-proto`, `h3`, `h3-quinn`, and a secondary `rustls` stack into `daer-proxy-protocols`.

### 1.2 The Growing Architectural Costs of Deferral
With production deployment and multi-protocol proxying (specifically Hysteria 2, and upcoming HTTP/3 DoH / egress tunneling), keeping QUIC and HTTP/3 out of `netune` has produced severe system-level friction:

1. **Crypto Provider Duality and Binary Bloat**:
   `netune` standardizes on `aws-lc-rs` as its cryptographic provider for `rustls 0.23`. In contrast, consumer crates pulled `quinn` with default `ring` backing, forcing two full cryptographic engines and two separate compilations of `rustls` into the final executable. This adds ~18 MB of text section and inflates debug/test link times significantly.
2. **Erosion of Generic Network Ownership**:
   RFC 9000 (QUIC Transport), RFC 9221 (QUIC Datagrams), and RFC 9114 (HTTP/3) are IETF core network standards, not proxy-specific product protocols. Forcing consumer applications to write and maintain raw QUIC endpoint lifecycle, MTU discovery, stream multiplexing, and HTTP/3 framing violates the fundamental architectural split: *network capabilities belong to netune; application and data path logic belong to the consumer*.
3. **Observability Blind Spot (`INV-TRACE-01`)**:
   Because QUIC bypasses `netune`, all QUIC/H3 handshakes, frame timings, loss events, and stream latencies are invisible to `netune-trace`. Consumers cannot derive consistent, non-synthetic request latencies or correlate network degradation across TCP and QUIC transports.
4. **Pre-Connect Socket Semantics (`INV-SOCKET-01`)**:
   QUIC operates over UDP, which requires the exact same socket safeguards (`SO_MARK` loop evasion, `IP_TOS`, interface binding `SO_BINDTODEVICE`, and local address binding) that `netune::SocketConfig` manages for TCP and UDP Datagrams. Currently, consumers must hand-roll raw socket configuration before handing the socket to an external QUIC engine.

Therefore, this RFC proposes bringing **QUIC transport and HTTP/3 client capabilities into `netune` as first-class, identity-shaped, fully observable primitives**.

---

## 2. Detailed Architectural Design

### 2.1 Workspace & Crate Topology
To uphold `[INV-HTTP2-01]` and ADR-0003's strict principle of localized attack surfaces and zero unneeded code compilation, QUIC and HTTP/3 are factored into dedicated leaf crates behind opt-in Cargo features:

```text
                     ┌───────────────────────┐
                     │     netune (facade)   │
                     │  features: quic, http3│
                     └───────────┬───────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│  netune-http1 │        │  netune-http2 │        │  netune-http3 │ (RFC 9114, QPACK)
└───────────────┘        └───────────────┘        └───────┬───────┘
                                                          │
                                                          ▼
                                                  ┌───────────────┐
                                                  │  netune-quic  │ (RFC 9000, 9221)
                                                  └───────┬───────┘
                                                          │
                                                          ▼
                                                  ┌───────────────┐
                                                  │  netune-trace │ (Event vocabulary)
                                                  └───────────────┘
```

* **`crates/netune-quic`**:
  * Owns the QUIC endpoint lifecycle, connection state machine, stream multiplexing, and unreliable datagram transport (RFC 9221).
  * Backed by `quinn` / `quinn-proto` configured strictly with `rustls/aws-lc-rs`.
* **`crates/netune-http3`**:
  * Implements RFC 9114 (HTTP/3 framing, request/response lifecycle, control stream) and RFC 9204 (QPACK instruction decoding/encoding).
  * Built atop `h3` or an owned minimal H3 framing engine over `netune-quic` streams.
* **`crates/netune` feature flags**:
  ```toml
  [features]
  default = ["http2", "ws"]
  quic = ["dep:netune-quic"]
  http3 = ["quic", "dep:netune-http3"]
  ```

---

### 2.2 Unification on `aws-lc-rs`
All QUIC dependencies must use `aws-lc-rs` through `rustls/aws-lc-rs` and `quinn/rustls-aws-lc-rs`. `ring` is strictly prohibited in the dependency graph, resolving the crypto split and eliminating binary duplication.

---

### 2.3 Handshake Shaping: `QuicProfile`
To fulfill the requirement that *netune does not add a transport whose handshake it cannot shape*, this RFC introduces `QuicProfile` alongside `TlsProfile`:

```rust
pub struct QuicProfile {
    pub name: &'static str,
    /// Client transport parameters shaping
    pub transport_parameters: QuicTransportParameters,
    /// TLS 1.3 ClientHello shaping for QUIC
    pub tls_profile: TlsProfile,
    /// Initial packet sizing and padding behavior
    pub initial_packet_size: u16,
    /// Supported QUIC versions and wire preference order
    pub supported_versions: Vec<u32>,
}

pub struct QuicTransportParameters {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout: Option<Duration>,
    pub max_udp_payload_size: u16,
    pub active_connection_id_limit: u64,
    pub enable_datagrams: bool,
}
```

Predefined presets mirror realistic browser/client behaviors:
* `"quic-default"`: Balanced standard RFC values.
* `"chrome-quic"`: Matches Chrome stable QUIC transport parameter order, greased frame extensions, and ALPN priorities.
* `"cloud-optimized"`: High initial flow-control windows for low-latency backend and tunneling operations.

---

### 2.4 Pre-Connect Socket Stack & Custom Layer Injection
Netune must guarantee that `SocketConfig` applies to QUIC UDP sockets before `connect` or sending any datagrams (`[INV-SOCKET-01]`), and that egress confinement runs before any socket exists (`[INV-EGRESS-01]`, `[INV-QUIC-02]`). Both are enforced by `QuicConnector`: it checks the shared `netune-egress` policy on the resolved address first, then applies `SocketConfig` to the UDP socket before the first datagram.

Furthermore, to accommodate advanced consumer requirements (such as packet obfuscation, port-hopping, or custom pacing), `netune-quic` exposes an abstract socket extension seam:

```rust
/// Abstract asynchronous UDP socket provider for QUIC endpoints.
pub trait QuicUdpSocket: Send + Sync + 'static {
    fn poll_send(&self, cx: &mut Context<'_>, transmits: &[Transmit]) -> Poll<io::Result<usize>>;
    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [io::IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn rebind(&self, new_addr: SocketAddr) -> io::Result<()>;
}
```

Standard endpoints use `DefaultQuicSocket`, which constructs a non-blocking `tokio::net::UdpSocket` and enforces `SocketConfig::apply_to_socket2` (`SO_MARK`, `SO_BINDTODEVICE`, `IP_TOS`, `bind_address`).

---

### 2.5 Connector & Stream Abstraction
`netune-quic` integrates directly with netune's connector hierarchy:

```rust
pub struct QuicConnector {
    profile: Arc<QuicProfile>,
    socket_config: SocketConfig,
    congestion_factory: Arc<dyn CongestionControllerFactory>,
}

impl QuicConnector {
    pub async fn connect(
        &self,
        target: &Target,
        recorder: Option<Arc<Mutex<Recorder>>>,
    ) -> Result<QuicConnection, NetuneError>;
}

pub struct QuicConnection {
    inner: quinn::Connection,
    recorder: Option<Arc<Mutex<Recorder>>>,
}

impl QuicConnection {
    /// Opens a bidirectional stream conforming to netune's `Transport` trait.
    pub async fn open_stream(&self) -> Result<Box<dyn Transport>, NetuneError>;

    /// Obtains an RFC 9221 Datagram session for unreliable payload relay.
    pub fn datagram_session(&self) -> QuicDatagramSession;
}
```

Notice that `QuicStream` implements `AsyncRead + AsyncWrite + Send + Unpin`, automatically satisfying `netune::Transport`. A bidirectional QUIC stream thus seamlessly connects to any higher-level pipeline (proxies, relays, or TLS-in-TLS encapsulation).

---

### 2.6 Full Integration with `netune-trace`
`netune-trace` gains an explicit QUIC and HTTP/3 event vocabulary:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEvent {
    // ... existing DNS, TCP, TLS, Ingress events ...

    // QUIC Transport Events
    QuicEndpointBound { local_addr: SocketAddr },
    QuicHandshakeStarted { remote_addr: SocketAddr, alpn: Vec<Vec<u8>> },
    QuicHandshakeCompleted { negotiated_version: u32, negotiated_alpn: Option<Vec<u8>> },
    QuicHandshakeFailed { reason: String },
    QuicCongestionUpdate { cwnd: u64, rtt: Duration, bytes_in_flight: u64 },
    QuicLossEvent { lost_packets: u32, lost_bytes: u64 },
    QuicStreamOpened { stream_id: u64, bidirectional: bool },
    QuicStreamClosed { stream_id: u64, error_code: Option<u64> },
    QuicDatagramDropped { reason: &'static str },

    // HTTP/3 Events
    H3StreamStarted { stream_id: u64, method: String, path: String },
    H3HeadersSent { stream_id: u64 },
    H3HeadersReceived { stream_id: u64, status: u16 },
    H3Finished { stream_id: u64, bytes_received: u64 },
}
```

This guarantees `[INV-TRACE-01]`: TTFB, handshake duration, packet-loss penalty, and transport delays for QUIC and HTTP/3 requests are deterministically calculated from immutable recorded traces without external timing bias.

---

### 2.7 HTTP/3 Client Integration in `netune::Client`
When `features = ["http3"]` is enabled, `netune::Client` can transparently dispatch requests over HTTP/3:

```rust
let client = Client::builder()
    .with_quic_profile("chrome-quic")
    .enable_http3(true)
    .build();

// Automatically initiates QUIC handshake with ALPN "h3"
let response = client.get("https://cloudflare.com/").await?;
assert_eq!(response.version(), http::Version::HTTP_3);
```

The connection pool (`netune::Pool`) manages persistent `QuicConnection` sessions, multiplexing new HTTP/3 requests across active streams on the same connection while respecting RFC 9114 concurrency limits.

---

## 3. Security, Adversarial & Failure Modes

1. **Amplification & Anti-Amplification Limits**:
   Initial flights and handshakes strictly adhere to RFC 9000 §8: unvalidated client addresses cannot trigger responses larger than 3× received bytes. Handshake packet padding to 1200 bytes is enforced.
2. **Slowloris & Unbounded Stream Exhaustion**:
   `QuicTransportParameters` strictly bounds `initial_max_streams_bidi` and `initial_max_streams_uni`. Incoming stream creation exceeding peer credit immediately aborts with `STREAM_LIMIT_ERROR`.
3. **Egress Confinement ([INV-EGRESS-01])**:
   Prior to binding or sending the initial UDP packet, the destination IP is validated against `EgressConfinement`. Dials to metadata endpoints (169.254.169.254), private ranges (unless explicitly permitted), or invalid multicast are rejected before the socket is opened.
4. **Datagram MTU Violations ([INV-QUIC-04])**:
   Datagram payloads exceeding current path MTU return `NetuneError::DatagramTooLarge` synchronously, preventing silent kernel packet drops.

---

## 4. Invariants & Verification Plan

This RFC proposes four new system invariants:

| Invariant | Statement | Verification Mechanism |
| :--- | :--- | :--- |
| **`[INV-QUIC-01]`** | **Crypto Unification**: `netune-quic` must link against workspace `aws-lc-rs`; no secondary crypto provider (e.g. `ring`) may appear in `cargo metadata`. | Automated `cargo metadata` dependency-tree test in CI. |
| **`[INV-QUIC-02]`** | **Socket Confinement & Pre-Connect Invariants**: Every `SocketConfig` parameter (`so-mark`, `tos`, interface) must be applied to the underlying UDP socket before the first datagram leaves the host. | Loopback test verifying `SO_MARK` and TOS on intercepted initial packets. |
| **`[INV-QUIC-03]`** | **Pure Trace Derivation**: QUIC and HTTP/3 request latencies and TTFB must be exact pure functions of `TraceEvent` records in `netune-trace`. | Test validating `RequestTrace` calculations against golden recorded traces. |
| **`[INV-QUIC-04]`** | **Zero Silent Datagram Loss**: Datagrams exceeding negotiated PMTU must return an immediate error rather than silently failing in the socket buffer. | Negative control unit test with MTU boundary checks. |

---

## 5. Migration & Consumer Impact (`daer`)

Once ratified and implemented:
1. `crates/daer-proxy-protocols` deletes:
   * Direct dependencies: `quinn`, `quinn-proto`, `h3`, `h3-quinn`, `rustls` (ring), `tokio-rustls`.
   * Ad-hoc QUIC connection pooling and endpoint constructors.
2. `daer` retains exclusively its domain-specific logic:
   * Hysteria 2 authentication header encoding (`auth.rs`).
   * Salamander & Gecko obfuscation layers (implemented as a `QuicUdpSocket` plugin).
   * Brutal congestion control (implemented as a `CongestionControllerFactory` for `netune-quic`).
   * SOCKS5/Transparent datagram framing.
3. Binary artifacts across `daer` shrink by ~18 MB, test build times decrease by over 30%, and full trace observability is restored to UDP-based tunnels.

---

## 6. Unresolved Questions

1. **Owned QPACK vs. Existing Codec**:
   Should `netune-http3` implement a lightweight, zero-allocation QPACK decoder from scratch (consistent with `netune-http2`'s owned HPACK implementation), or wrap an established crate like `h3` during Phase 1?
   * *Recommendation*: Start with `h3` over `netune-quic` for the alpha release, then distill an owned RFC 9204 QPACK implementation for full zero-copy trace fidelity.
2. **Multipath QUIC**:
   Should `QuicConnector` anticipate Multipath QUIC (draft-ietf-quic-multipath) interfaces now?
   * *Recommendation*: Keep interfaces scoped to single-path RFC 9000 in RFC-0001; reserve multi-connection aggregation for a subsequent RFC.
