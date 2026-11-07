# System Architecture Reference

This reference document defines system boundaries, layering models, and behavioral contracts across the `netune` network stack.

---

## Architectural Layering

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ High-Level Consumer Application / Agent Harness                         │
└──────────────────┬──────────────────────────────────┬───────────────────┘
                   │ Client::send / Target            │ Server::bind
                   ▼                                  ▼
┌───────────────────────────────────┐ ┌───────────────────────────────────┐
│ netune: Egress Orchestrator       │ │ netune-server: Ingress Orchestrator│
│  - Redirect & Credential Stripping│ │  - Accept Loop & Admission Control│
│  - Pool (authority#profile slice) │ │  - Phase Timeouts & Ingress Traces│
│  - Keep-Alive Stale Replay Safety │ │  - Unified Handler (H1/H2)        │
│  - WebSocket Client Upgrade       │ │  - ResponseWriter State Machine   │
│  - QUIC / H3 Client Facade        │ │  - Self-Terminated Ingress TLS    │
└─────────┬─────────┬───────────────┘ └───────┬───────────┬───────────────┘
          │         │                         │           │
          ▼         ▼                         ▼           ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌─────────────────────┐
│ netune-io: Shared I/O │ │ netune-http1 / http2  │ │ netune-trace: Model │
│  - TimedIo Syscall Tap│ │  - Bidirectional Codec│ │  - Functional Timing│
│  - FaultIo Chaos Twin │ │  - Smuggling Limits   │ │  - Ring & Stream Log│
└───────────────────────┘ └───────────────────────┘ └─────────────────────┘
          │                         │                         │
          ▼                         ▼                         ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌─────────────────────┐
│ netune-quic / http3   │ │ netune-ws: RFC 6455   │ │ netune-probe: L2    │
│  - RFC 9000 / 9221    │ │  - Role Masking Enforc│ │  - Pure Frame Math  │
│  - aws-lc-rs Unified  │ │  - Bounded Reassembly │ │  - Opt-in Inject    │
└───────────────────────┘ └───────────────────────┘ └─────────────────────┘
```

---

## Architectural Decision Records Mapping

The architectural evolution is governed by the following decisions:

| ID | Title | Summary & Primary Invariant |
| :--- | :--- | :--- |
| [ADR-0001](../adr/0001-owned-transport-trace-model.md) | Owned Transport Substrate & Trace Model | Zero third-party HTTP runtime; timings are pure functions of event traces. |
| [ADR-0002](../adr/0002-egress-confinement-policy.md) | Egress Confinement Policy | `StrictPublic` rejects loopback, RFC 1918, link-local, and cloud metadata (`INV-EGRESS-01..03`). |
| [ADR-0003](../adr/0003-workspace-decomposition-privilege-boundaries.md) | Workspace Decomposition | Privilege boundary: socket transmission compiled only behind `--features inject` (`INV-HTTP2-01`, `INV-PROBE-01..02`). |
| [ADR-0004](../adr/0004-tls-fingerprint-profiles-pool-isolation.md) | TLS Fingerprint Profiles & Pool Isolation | Pure data `TlsProfile`, request-time routing, `authority#profile` pool slicing (`INV-TLS-01..03`). |
| [ADR-0005](../adr/0005-keepalive-socket-culling-absorption.md) | Keep-Alive Socket Culling Recovery | 20 s idle pool bound, pre-head replay-safe retry (`INV-TRANSPORT-01..04`). |
| [ADR-0006](../adr/0006-transport-customizability-wire-evasion.md) | Customizability & Wire Evasion | Pluggable `DnsResolver`, L3/L4 `SocketConfig`, `SegmentingIo`, raw headers (`INV-CUSTOM-01..03`). |
| [ADR-0007](../adr/0007-owned-client-websocket-codec.md) | Owned Client WebSocket Codec & Egress Stream | Pure RFC 6455 codec (`netune-ws`), role-enforced masking, no WS pooling (`INV-WS-01..08`). |
| [ADR-0008](../adr/0008-datagram-transport-and-socks5-udp-association.md) | Datagram Transport & SOCKS5 UDP Association | Confinement precedes datagram socket; connected per-peer sessions; source verification (`INV-UDP-01..05`). |
| [ADR-0009](../adr/0009-reality-client-authentication-not-a-netune-capability.md) | REALITY Client Authentication | Rejected: requires custom session IDs and CA verifier bypass incompatible with `rustls` 0.23 identity invariants. |
| [ADR-0010](../adr/0010-quic-ownership-and-trace-sink.md) | QUIC Ownership & Streaming Trace Sink | Trace model streaming `TraceSink` (`INV-TRACE-03`); pre-connect socket invariants (`INV-SOCKET-01`). |
| [ADR-0011](../adr/0011-server-side-ingress-transport.md) | Server-Side Ingress Transport | Ingress is a peer orchestrator (`netune-server`) over shared framing core; ingress timings are pure derivations (`INV-SERVER-01..07`). |
| [ADR-0012](../adr/0012-http2-ingress.md) | HTTP/2 Ingress | One `H2Connection` behind both roles; per-event stream identity in trace; one `Handler` serves both protocols (`INV-SERVER-08..11`, `17`). |
| [ADR-0013](../adr/0013-response-writer-state-machine.md) | Response State Machine | `ResponseWriter` refuses contradictions between declared framing and payload bytes; streaming body support (`INV-SERVER-12..13`). |
| [ADR-0014](../adr/0014-request-validation-before-dispatch.md) | Request Validation | Target and `Host` grammar, CRLF strictness, cumulative body limits enforced before dispatch (`INV-SERVER-14..16`). |
| [ADR-0015](../adr/0015-self-terminated-tls.md) | Self-Terminated TLS | Ingress TLS termination; SNI configuration routing; ALPN negotiation; trace recorded handshakes (`INV-SERVER-18..21`). |
| [ADR-0016](../adr/0016-quic-and-http3-transport.md) | QUIC & HTTP/3 Transport | First-class QUIC (`netune-quic`) and HTTP/3 (`netune-http3`) unified on `aws-lc-rs`; `QuicProfile` shaping (`INV-QUIC-01..04`). |

---

## System Invariants

### 1. Replay Safety (`[INV-TRANSPORT-01]`)
A pooled connection that drops before any byte of a response head is parsed is transparently replaced with a fresh connection. If the connection fails after any response head byte has been parsed, it must not be re-attempted.

### 2. Documentation Firewall
Public documentation surfaces (`docs/{tutorials,how-to,reference,explanation}/`) must never author relative links into internal contributor files (`docs/dev/**`). Contributor-facing rules live under `docs/dev/standards/`, reached through `CONTRIBUTING.md`.

### 3. Structural Privilege Isolation (`[INV-PROBE-01]`)
Workspace default builds must never compile socket frame transmission paths. All packet generation routines are pure mathematical functions.

### 4. Directional Exclusivity (`[INV-SERVER-01]`)
Each orchestrator exposes one direction of travel: `netune` opens sockets outward and never listens, `netune-server` accepts inward and never dials. A codec may understand both wire roles — a one-directional codec cannot be differential-tested in the direction it lacks — but symmetry in a codec never becomes symmetry in a transport ([ADR-0007](../adr/0007-owned-client-websocket-codec.md), [ADR-0011](../adr/0011-server-side-ingress-transport.md), [ADR-0012](../adr/0012-http2-ingress.md)). A connection is one protocol, decided once from its first bytes or its ALPN result, and never upgraded in place.

### 5. Ingress Timings Are Pure Derivations (`[INV-SERVER-02]`)
Every ingress timing is a function of the recorded ingress trace, anchored on `IngressDispatch`. A server that reads a clock to report a duration has not measured the server ([ADR-0011](../adr/0011-server-side-ingress-transport.md)).
