# System Architecture Reference

This reference document defines system boundaries, layering models, and behavioral contracts across the `netune` network stack.

---

## Architectural Layering

```text
┌─────────────────────────────────────────────────────────────┐
│ High-Level Consumer Application / Agent Harness            │
└──────────────────────────────┬──────────────────────────────┘
                               │ Client::send / Target
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ netune: Transport & Policy Orchestration                    │
│  - Redirect Following & Cross-Origin Credential Stripping    │
│  - Pool Management (authority#profile slice isolation)     │
│  - Transparent Keep-Alive Stale Socket Recovery             │
│  - WebSocket Client Upgrade & WsStream (INV-WS-01..05)      │
│  - TimedIo (read/write boundary tap) & TCP_INFO Sampler     │
│  - SegmentingIo (SNI slicing) & SocketConfig (TTL/MSS)       │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│ netune-http1: Codec          │ │ netune-trace: Data Model   │
│  - Zero-Copy Line Protocol   │ │  - Pure Functional Timings │
│  - Limits & Smuggling Checks │ │  - Delta-Encoded Ring Log  │
│  - Raw Header Casing Mode    │ │  - JA3 / JA4 Fingerprints  │
└──────────────────────────────┘ └────────────────────────────┘
               │                              
               ▼                              
┌──────────────────────────────┐
│ netune-ws: Pure RFC 6455     │
│  - Role-Enforced Masking     │
│  - Fragmented Reassembly     │
│  - SHA-1 Handshake Keys      │
└──────────────────────────────┘
```

---

## Architectural Decision Records Mapping

The architectural evolution is governed by the following decisions:

| ID | Title | Summary & Primary Invariant |
| :--- | :--- | :--- |
| [ADR-0001](../adr/0001-owned-transport-trace-model.md) | Owned Transport Substrate & Trace Model | Zero third-party HTTP runtime; timings are pure functions of event traces. |
| [ADR-0002](../adr/0002-egress-confinement-policy.md) | Egress Confinement Policy | `StrictPublic` rejects loopback, RFC 1918, link-local, and cloud metadata. |
| [ADR-0003](../adr/0003-workspace-decomposition-privilege-boundaries.md) | Workspace Decomposition | Privilege boundary: socket transmission compiled only behind `--features inject`. |
| [ADR-0004](../adr/0004-tls-fingerprint-profiles-pool-isolation.md) | TLS Fingerprint Profiles & Pool Isolation | Pure data `TlsProfile`, request-time routing, `authority#profile` pool slicing. |
| [ADR-0005](../adr/0005-keepalive-socket-culling-absorption.md) | Keep-Alive Socket Culling Recovery | 20 s idle pool bound, pre-head replay-safe retry (`INV-TRANSPORT-01`..`04`). |
| [ADR-0006](../adr/0006-transport-customizability-wire-evasion.md) | Customizability & Wire Evasion | Pluggable `DnsResolver`, L3/L4 `SocketConfig`, `SegmentingIo`, raw headers. |
| [ADR-0007](../adr/0007-owned-client-websocket-codec.md) | Owned Client WebSocket Codec & Egress Stream | Pure RFC 6455 codec (`netune-ws`), client-only egress transport, role-enforced masking, no WS pooling (`INV-WS-01..05`). |

---

## System Invariants

### 1. Replay Safety (`[INV-TRANSPORT-01]`)
A pooled connection that drops before any byte of a response head is parsed is transparently replaced with a fresh connection. If the connection fails after any response head byte has been parsed, it must not be re-attempted.

### 2. Documentation Firewall
Public documentation surfaces (`docs/{tutorials,how-to,reference,explanation}/`) must never author relative links into internal contributor files (`docs/dev/**`). Contributor-facing rules live under `docs/dev/standards/`, reached through `CONTRIBUTING.md`.

### 3. Structural Privilege Isolation (`[INV-PROBE-01]`)
Workspace default builds must never compile socket frame transmission paths. All packet generation routines are pure mathematical functions.

### 4. Client-Role WebSocket Exclusivity (`[INV-WS-01]`)
The WebSocket transport surface is client-egress only. Server-side accept/listen code exists nowhere in the workspace; the pure codec understands both endpoint roles for testability, while production APIs expose only client egress ([ADR-0007](../adr/0007-owned-client-websocket-codec.md)).
