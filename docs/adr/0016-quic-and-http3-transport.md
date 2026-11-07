---
id: ADR-0016
title: "First-Class QUIC and HTTP/3 Client Transport in netune"
status: accepted
date: 2026-11-07
scope: [transport/quic, protocol/http3, crypto/provider, trace/quic, crate-topology]
superseded_by: null
---

# 0016. First-Class QUIC and HTTP/3 Client Transport in netune

- Status: Accepted
- Date: 2026-11-07
- Deciders: Ming Li
- Supersedes: Decision 1 of [ADR-0010](0010-quic-ownership-and-trace-sink.md) (QUIC deferral)
- Distilled From: [RFC-0001](../rfc/0001-quic-and-http3-transport.md)
- Related: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md),
  [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md),
  [ADR-0008](0008-datagram-transport-and-socks5-udp-association.md)

---

## Context and Problem Statement

In [ADR-0010](0010-quic-ownership-and-trace-sink.md), QUIC transport was deferred from `netune`:
> *"netune does not add a transport whose handshake it cannot shape. 'We can call a library that does it' is not ownership. netune gains QUIC only when a consumer needs it as a client in netune's own identity model — that is, when there is a `QuicProfile` that shapes a QUIC handshake the way `TlsProfile` shapes a TCP one, and a trace vocabulary for QUIC frames."*

Because this capability was withheld, downstream consumers (`daer`) were forced to embed `quinn`, `quinn-proto`, `h3`, `h3-quinn`, and a secondary `rustls` engine compiled with `ring` inside `daer-proxy-protocols`.

This compromise resulted in severe architectural friction:
1. **Cryptographic Divergence and Binary Bloat**: `netune` standardizes on `aws-lc-rs`. Consumers linking `quinn` with default `ring` pulled two complete crypto suites and two `rustls` builds into the binary (~18 MB wasted text section and doubled link times).
2. **Boundary Inversion**: RFC 9000 (QUIC), RFC 9221 (QUIC Datagrams), and RFC 9114 (HTTP/3) are foundational IETF transports. Trapping them inside proxy-specific crates broke the primary system invariant: *generic network capabilities belong to netune; the proxy datapath belongs to daer*.
3. **Observability Loss**: Neither QUIC connection lifecycles nor HTTP/3 stream exchanges appeared in `netune-trace`, violating `[INV-TRACE-01]`.

The conditions set by ADR-0010 for admitting QUIC have now been met: an explicit identity model (`QuicProfile`), full event vocabulary in `netune-trace`, and an abstract socket stack that honours `SocketConfig` before packet dispatch.

---

## Decision

### 1. Workspace Decomposition into Dedicated Leaf Crates
Consistent with `[INV-HTTP2-01]` and ADR-0003, QUIC and HTTP/3 do not bloat existing clients; they live in dedicated leaf crates behind opt-in features:
* **`crates/netune-quic`**: Owns QUIC endpoint lifecycle, connection state machines, bidirectional/unidirectional stream management (`Transport`), and RFC 9221 unreliable datagram sessions.
* **`crates/netune-http3`**: Owns RFC 9114 client framing and request/response dispatch, built atop `netune-quic`.
* **`crates/netune`**: Re-exports `netune::quic` and `netune::http3` when `quic` or `http3` features are enabled. Defaults remain untouched (`default = ["http2", "ws"]`).

### 2. Single Unified Crypto Provider (`aws-lc-rs`)
`netune-quic` is backed by `quinn` configured with `default-features = false, features = ["runtime-tokio", "rustls-aws-lc-rs"]`.
`ring` is strictly forbidden across the workspace. A build that compiles a second crypto engine fails CI.

### 3. Handshake Shaping: `QuicProfile`
QUIC handshakes are explicit data via `QuicProfile` and `QuicTransportParameters`:
* Initial packet sizing (minimum 1200 bytes, padding policy).
* Client transport parameters (flow control limits, stream concurrency, idle timeout, connection ID limits).
* ALPN list ordering and TLS 1.3 ClientHello shaping via `TlsProfile`.

### 4. Socket Invariants & Abstract Extension Seam
* **`[INV-SOCKET-01]` & `[INV-EGRESS-01]` Enforcement**: `QuicConnector` configures the UDP socket with `SocketConfig` (`so_mark`, `bind_device`, `bind_address`, `tos`) before the initial QUIC datagram is sent.
* **`QuicUdpSocket` Seam**: Advanced consumers (such as proxy obfuscation and port-hopping) can supply an implementation of `QuicUdpSocket` to wrap UDP I/O without modifying QUIC state machines.

### 5. Deterministic Trace Observability
`netune-trace` carries the ordered boundaries of a QUIC/HTTP-3 exchange: `QuicStart` /
`QuicEnd` (the handshake; `a` = 1 on success), `QuicStreamOpen`, `H3StreamStart`,
`H3HeadComplete` (`a` = status) and `H3Finished` (`a` = body bytes received). `derive_quic`
and `derive_h3` compute the handshake, TTFB, body and end-to-end spans as pure functions of
the log (`[INV-TRACE-01]`, `[INV-QUIC-03]`).

Congestion-window and packet-loss counters are transport **state**, not ordered boundaries:
they are sampled on demand from `QuicConnection::stats()` and deliberately not recorded as
events. Recording them would require inventing a sampling clock and would put
non-reproducible numbers inside a trace whose value is that it is reproducible.

---

## Invariants & Behavioral Boundaries

- **`[INV-QUIC-01]` Unified Crypto Backend**: `netune-quic` and all consumers compile exclusively against `aws-lc-rs`; no secondary crypto provider (`ring`) may appear in the dependency tree.
- **`[INV-QUIC-02]` Socket Confinement Precedence**: Every `SocketConfig` option is applied to the UDP socket before any QUIC packet is sent. Egress confinement checks strictly precede socket creation.
- **`[INV-QUIC-03]` Trace Equivalence**: QUIC and HTTP/3 request latencies and TTFB are derived as pure functions from `netune-trace` events without external clock calls.
- **`[INV-QUIC-04]` Predictable Datagram Sizing**: An RFC 9221 datagram exceeding path MTU must fail predictably with an explicit error rather than silently vanishing in the socket buffer.

---

## Consequences

- Decision 1 of ADR-0010 is formally superseded.
- `daer` removes `quinn`, `quinn-proto`, `h3`, `h3-quinn`, and `ring` from its dependencies, migrating entirely to `netune-quic` and `netune-http3`.
- Workspace binaries lose ~18 MB of duplicated text sections and eliminate multiple redundant TLS compilations.
