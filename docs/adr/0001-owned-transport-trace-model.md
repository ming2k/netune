---
id: ADR-0001
title: "Owned Transport Substrate and Protocol-Neutral Trace Model"
status: accepted
date: 2026-09-08
scope: [transport/owned-stack, trace/model]
superseded_by: null
---

# 0001. Owned Transport Substrate and Protocol-Neutral Trace Model

- Status: Accepted
- Date: 2026-09-08
- Deciders: Ming Li

---

## Context and Problem Statement

Diagnosing network latency, TLS negotiation anomalies, and transport failure modes requires exact, microsecond-level timing and protocol boundary visibility. Mainstream Rust HTTP clients (`reqwest`, `hyper`) treat the connection layer as an opaque implementation detail: connection pools, DNS resolution, TLS handshakes, and partial chunk streams are obscured behind high-level futures. Furthermore, standard logging engines rely on asynchronous flushes and side-effects, making deterministic replay and mathematical derivation of attempt metrics impossible.

We need a network stack that owns every layer from DNS resolution to the HTTP message wire format without third-party HTTP runtime dependencies, while recording every protocol and syscall boundary into a deterministic, zero-allocation trace model.

## Decision Drivers

- Microsecond-precision observability over DNS, TCP, TLS handshakes, first-token delivery, and body streams.
- Zero third-party HTTP client libraries in production dependency graph.
- Pure functional trace analysis: metrics and timings must be pure functions of recorded events, allowing offline verification and snapshot diffing.
- Graceful observability degradation across portable protocol events (L0), syscall boundaries (L1), and raw segment captures (L2).

## Considered Options

- Option 1: Wrap `reqwest` or `hyper` with callback hooks and tracing subscribers.
- Option 2: Build an owned transport stack and HTTP/1.1 codec over a protocol-neutral trace model (`netune`).

## Decision Outcome

Chosen option: "Option 2: Build an owned transport stack and HTTP/1.1 codec over a protocol-neutral trace model", because owning the substrate provides deterministic control over socket boundaries, pool lifetimes, and TLS ClientHello offerings.

### Invariants & Behavioral Boundaries

- **`[INV-TRACE-01]` Pure Derivations**: Every surface timing (`connect_us`, `tcp_us`, `tls_us`, `ttfb_us`, `stream_us`, `e2e_us`) must be a pure derivation over the recorded `Trace`. No timing values may be computed from ambient clocks after execution.
- **`[INV-TRANSPORT-00]` Zero 3rd-Party HTTP**: Production runtime crates must not depend on external HTTP implementations (`hyper`, `reqwest`). External HTTP engines are restricted to dev-dependencies as differential test oracles.
- **`[INV-TRACE-02]` Protocol Neutrality**: The trace model (`netune-trace`) must remain neutral across HTTP/1.1, HTTP/2, and raw TCP streams by modeling generic frame classes and stream tokens.

### Consequences

- **Positive**:
  - Full microsecond fidelity for transport latency breakdowns without ambient clock drift.
  - Complete control over TLS ClientHello fingerprints and connection pool reuse behavior.
  - Deterministic testing and headless golden trace assertions.
- **Negative & Trade-offs**:
  - Requires maintaining our own HTTP/1.1 line protocol parser and writer (`netune-http1`). Mitigated by continuous differential testing against `hyper`.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Wrap `reqwest` or `hyper` with Event Hooks

- **Why considered**: Significantly faster initial prototyping with broad protocol coverage out of the box.
- **Why rejected**: Internal connection pooling, socket-level keep-alive handling, and partial chunk boundaries cannot be intercepted at microsecond precision without forking the runtime. Furthermore, `reqwest`'s dependency tree introduces non-negotiable transitive crates that prevent custom TLS fingerprint synthesis.

## Links

- Related ADRs: [ADR-0002](0002-egress-confinement-policy.md), [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md)
