---
id: ADR-0003
title: "Workspace Decomposition and Structural Privilege Separation"
status: accepted
date: 2026-09-10
scope: [workspace/topology, security/privilege, probe/inject]
superseded_by: null
---

# 0003. Workspace Decomposition and Structural Privilege Separation

- Status: Accepted
- Date: 2026-09-10
- Deciders: Ming Li

---

## Context and Problem Statement

Mixing low-level frame construction and network transmission capabilities with high-level HTTP client code within a single crate violates the principle of least privilege: an HTTP consumer crate should never compile or expose raw socket capabilities capable of transmitting forged packets.

Furthermore, line-protocol parsing (`HTTP/1.1`) and planned binary multiplexed streaming (`HTTP/2`) have fundamentally divergent data structures and compression lifecycles, and must not be forced into a single monolithic crate.

## Decision Drivers

- Structural privilege separation: long-running applications must not compile raw transmission sockets by default.
- Loose coupling: pure trace modeling, HTTP codecs, transport orchestration, and L2 frame forging must compile as independent, focused crates.
- Explicit future path for HTTP/2 without polluting HTTP/1.1 codec boundaries.

## Considered Options

- Option 1: Monolithic single-crate workspace with Cargo feature flags controlling capabilities.
- Option 2: Multi-crate workspace with discrete crates for trace, HTTP/1.1, transport, probe, and a reserved HTTP/2 placeholder, enforcing compilation boundaries for privileged paths.

## Decision Outcome

Chosen option: "Option 2: Multi-crate workspace with discrete crates", splitting the project into:
1. `netune-trace`: zero-allocation trace ring buffer and pure timing derivations.
2. `netune-http1`: HTTP/1.1 codec, differential-tested against `hyper`.
3. `netune-http2`: reserved 0.0.1 crate preserving namespace and architecture plan.
4. `netune`: owned transport substrate, TLS router, pool, proxies, and in-process fault injection.
5. `netune-probe`: pure Ethernet/IPv4/TCP frame builder; socket transmission gated strictly behind `--features inject` and requiring Linux `CAP_NET_RAW`.

### Invariants & Behavioral Boundaries

- **`[INV-PROBE-01]` Zero Default Transmission**: The default build of `netune-probe` (and all workspace crates) must contain zero socket transmission code. Packet transmission is compiled in only when `--features inject` is explicitly activated.
- **`[INV-PROBE-02]` Privilege Requirement**: Frame transmission requires `CAP_NET_RAW` privileges; unprivileged builds fail safely at runtime without panics or UB.
- **`[INV-HTTP2-01]` Separate Wire Implementations**: HTTP/2 framing and HPACK dynamic tables must be authored in `netune-http2` rather than added as feature flags in `netune-http1`.

### Consequences

- **Positive**:
  - The default build of every crate is completely safe and unprivileged.
  - Consumers can depend on `netune-trace` or `netune-http1` in isolation without pulling in networking or raw socket dependencies.
  - Architectural contracts for HTTP/2 are pinned before implementation commences.
- **Negative & Trade-offs**:
  - Requires maintaining workspace-wide version synchronization and release automation across multiple crates.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Monolithic Single-Crate with Feature Flags

- **Why considered**: Easier versioning and single-package publishing on crates.io.
- **Why rejected**: Cargo features are additive across dependency graphs. If any transitive dependency enabled an `inject` or `raw-socket` flag, every dependent in the workspace would silently inherit transmission capabilities, destroying the structural privilege boundary.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0002](0002-egress-confinement-policy.md)
