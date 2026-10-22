# Crates Reference

This document provides a factual overview of all crates comprising the `netune` workspace.

---

## Workspace Crates Overview

| Crate | Directory | Current Version | Primary Responsibility |
| :--- | :--- | :--- | :--- |
| `netune-trace` | `crates/netune-trace` | `0.0.2` | Zero-allocation trace ring buffer, pure timing derivations, JA3/JA4 TLS ClientHello parser |
| `netune-http1` | `crates/netune-http1` | `0.0.2` | HTTP/1.1 line protocol parser and serializer, differential-tested against `hyper` |
| `netune-http2` | `crates/netune-http2` | `0.0.2` | HTTP/2 wire protocol (RFC 9113), HPACK header compression (RFC 7541), and Akamai fingerprint impersonation |
| `netune-ws` | `crates/netune-ws` | `0.0.2` | Pure RFC 6455 WebSocket codec: frame encoder/decoder, role-enforced masking, fragmented-message reassembly, SHA-1 handshake keys |
| `netune` | `crates/netune` | `0.0.2` | Core transport: DNS, TCP, TLS, pool, proxy, fault injection, and client request orchestration |
| `netune-probe` | `crates/netune-probe` | `0.0.2` | Pure L2 Ethernet/IPv4/TCP frame builder and opt-in wire injector |

---

## Crate Details

### `netune-trace`
- **Dependencies**: `serde`, `serde_json` (dev). No runtime networking or clock dependencies.
- **Key Types**:
  - `RequestTrace`: Envelope storing attempt identifiers, connection provenance, and event logs.
  - `EventLog`: Ring buffer supporting delta-encoded microsecond timestamps with loss tracking.
  - `DerivedTimings`: Pure derived metrics (`connect_us`, `tcp_us`, `tls_us`, `ttfb_us`, `stream_us`, `e2e_us`).
  - `ja4::ja4`: Computes JA4 TLS fingerprint from raw ClientHello bytes.

### `netune-http1`
- **Dependencies**: `bytes`, `http`, `tokio` (io-util). `hyper` is strictly a `dev-dependency` for differential testing.
- **Key Types**:
  - `RequestHead`: Request method, URI target, headers, and raw wire header vectors.
  - `ResponseHead`: Parsed status code, version, headers, and body kind (`Content-Length`, `Chunked`, `Empty`, `UntilClose`).
  - `Http1Reader`: Streaming chunk parser with hard buffer limits against request smuggling.

### `netune-http2`
- **Dependencies**: `bytes`, `http`, `tokio` (io-util, sync, time). No third-party HTTP/2 or HPACK implementation.
- **Key Types**:
  - `H2Connection`: Client lifecycle — connection preface, SETTINGS acknowledgement, and stream multiplexing under hard frame-size limits.
  - `HpackEncoder` / `HpackDecoder`: RFC 7541 static and dynamic tables plus the 257-symbol Huffman coder.
  - `H2Fingerprint` / `PseudoHeaderOrder`: Declarative Akamai HTTP/2 fingerprint models (ordered SETTINGS, window increments, pseudo-header order) ([ADR-0006](../adr/0006-transport-customizability-wire-evasion.md)).
- **Distribution**: consumed from this repository by git tag; the version is inherited from the workspace.

### `netune-ws`
- **Dependencies**: `bytes`, `base64`, `http`. No I/O runtime; purely synchronous wire math.
- **Key Types**:
  - `Frame` / `Opcode` / `CloseCode`: RFC 6455 §5.2 wire vocabulary.
  - `FrameDecoder` / `FrameEncoder`: Stateless codec pair; the decoder enforces role-correct masking ([ADR-0007](../adr/0007-owned-client-websocket-codec.md)).
  - `MessageAssembler`: Fragmented-message reassembly with interleaved control frames and bounded message size.
  - `compute_accept_key` / `verify_handshake`: Self-contained SHA-1 handshake digest (RFC 6455 §1.3).
- **Role Boundary**: The codec understands both endpoint roles for testability, but server transport code exists nowhere in the workspace ([INV-WS-01]).

### `netune`
- **Key Types**:
  - `Client`: Drives the request lifecycle, redirect handling, and response body streaming.
  - `Client::connect_ws` / `WsStream`: RFC 6455 client upgrade over the owned transport, with automatic pong and close-handshake completion ([ADR-0007](../adr/0007-owned-client-websocket-codec.md)).
  - `WsSession` / `WsSessionConfig`: Client-driven heartbeat liveness (ping interval + pong deadline) for long-lived WebSocket sessions; automatic reconnection is deliberately excluded as harness policy.
  - `Pool`: Connection reuse pool keyed on `authority#profile` with 20 s idle timeout.
  - `TlsProfile` & `TlsRouterConnector`: Configures and lazily compiles TLS identities.
  - `FaultIo`: In-process fault injection engine.
  - `DnsResolver` & `StaticResolver`: Asynchronous, mockable DNS resolution.
  - `SocketConfig`: L3/L4 transport tuning (TTL, buffer sizing, MSS).
  - `SegmentingIo`: Early flight wire segmentation for SNI middlebox evasion.

### `netune-probe`
- **Privilege Separation**:
  - Default build: Pure frame parsing (`parse_ethernet_ipv4_tcp`) and construction (`build_ethernet_ipv4_tcp`).
  - `--features inject`: Compiles socket transmit path (`Capture::send_frame`), requiring Linux `CAP_NET_RAW`.
