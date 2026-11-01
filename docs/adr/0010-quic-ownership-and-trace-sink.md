---
id: ADR-0010
title: "QUIC stays out of netune until a consumer needs it as a client, and the trace model gains a streaming sink"
status: accepted
date: 2026-02-14
scope: [transport/quic, trace/sink, transport/datagram]
supersedes: []
---

# 0010. QUIC stays out of netune until a consumer needs it as a client, and the trace model gains a streaming sink

- Status: Accepted
- Date: 2026-02-14
- Deciders: Ming Li
- Related: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0008](0008-datagram-transport-and-socks5-udp-association.md),
  [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md)

---

## Context and Problem Statement

Two questions arrived together, from the same consumer (`daer`) and the same shape of
problem: a capability netune does not have, where the honest answer is not obviously
"add it".

**QUIC.** `daer`'s Hysteria2 outbound needs a QUIC client, and `daer` currently pulls
`quinn`, `h3`, `h3-quinn`, and a **second `rustls`** built with `ring` (netune uses
`aws-lc-rs`). That is two TLS implementations and two crypto providers in one binary, which
is exactly the duplication ADR-0001's ownership argument exists to prevent. The obvious move
is "put QUIC in netune". That is wrong for a specific reason: netune's TLS identity is a
`rustls::ClientConfig` built by `platform_client_config` and shaped by `TlsProfile`. QUIC's
handshake is not TLS-over-TCP — it has its own record framing, its own loss recovery, its own
congestion control — and `quinn` owns that whole stack, not a socket. Handing `quinn` a
`rustls::ClientConfig` does not let netune shape the handshake the way `TlsProfile` shapes a
TCP one, and a QUIC fingerprint profile is a different problem from a JA3/JA4 one.

**Observability.** `netune-trace` is a per-attempt ring buffer (`EventLog`, default capacity
1024, `Arc<Mutex<Recorder>>`). It is designed for a request/response client: one attempt, one
`RequestTrace`, timings derived as pure functions of the events (ADR-0001's `INV-TRACE-01`).
A transparent proxy relay is not that shape. A tunnelled connection lives for minutes or
hours and moves gigabytes; a fixed ring buffer keeps only the last N events, and the
per-read/per-write lock is paid on the hot path. `daer` today works around this by creating a
`Recorder::start(64)` per dial and **discarding it** — so netune's observability reaches
`daer` as nothing at all.

## Decision

1. **QUIC is not a netune capability yet, and the duplication is recorded rather than
   hidden.** netune gains QUIC only when a consumer needs it *as a client in netune's own
   identity model* — that is, when there is a `QuicProfile` that shapes a QUIC handshake the
   way `TlsProfile` shapes a TCP one, and a trace vocabulary for QUIC frames. Until then,
   `daer` owns its QUIC stack, and the cost is stated where it can be seen: a second
   `rustls` and a second crypto provider in the binary. This is the same reasoning as
   ADR-0009 (REALITY): a capability whose identity model netune cannot express belongs to the
   consumer, and pretending otherwise produces a worse abstraction than a documented gap.

   The rule this leaves behind: **netune does not add a transport whose handshake it cannot
   shape.** "We can call a library that does it" is not ownership.

2. **The trace model gains a streaming sink, and a long-lived relay is its first use.**
   `Recorder` keeps its ring buffer (it is the right structure for an attempt, and `INV-TRACE-01`
   depends on it), and gains an optional `TraceSink`: a `Send + Sync` trait that receives each
   event as it is recorded. The default is no sink, so a request/response client pays nothing.
   A relay installs one sink per connection and gets a stream rather than a window.

   The sink is **not** a `tracing` dependency: netune's leaves must not depend on a logging
   facade (ADR-0003's decomposition), and a consumer that wants `tracing` output writes a
   three-line sink. What netune owes the consumer is the event vocabulary and the guarantee
   that an event is emitted before the operation returns, not a logging policy.

3. **A trace is not a metric, and netune does not grow a metrics API.** The gap that mattered
   for `daer` was "no per-flow trace beyond the debug logs", not "no Prometheus endpoint". A
   sink covers the first; counters already exist on the types that own them
   (`Pool::stats`, the datagram counters). A metrics façade is a consumer concern.

## Consequences

- `daer` keeps `quinn`/`h3`, and this ADR is the record of why that is not a boundary
  violation. `daer`'s own ADR-0002 (amended) must name it, or the two documents disagree.
- A `QuicProfile` is a prerequisite, not a follow-up: adding QUIC without it would give
  netune a transport that cannot present the identity its callers select, which is the
  failure mode ADR-0004 exists to prevent for TCP.
- `TraceSink` makes `Recorder::push` a branch plus a virtual call when a sink is present. The
  cost is bounded and measurable (`tests/overhead.rs` is the harness); the alternative — a
  consumer reimplementing the event vocabulary — costs correctness instead.
- The ring buffer stays. A sink that misses events because the consumer is slow must not
  lose the window that `RequestTrace` reports, so the two are independent: the sink is
  fire-and-forget, the ring is the record of truth for the attempt.

## Evidence

- `crates/netune/src/socket.rs`'s `SocketConfig` now carries `bind_device`, `bind_address`,
  `keepalive`, `tos`, and `tcp_fast_open`, and `needs_manual_socket` is the single predicate
  that decides between the fast path and the manual socket. Its falsifier is
  `every_pre_connect_option_forces_the_manual_socket_path` plus
  `a_bound_source_address_is_what_the_peer_sees`: with the old `mark.is_none()` test, the
  bound source was silently ignored and the peer saw the route's choice.
- The QUIC duplication is visible in `daer`'s `Cargo.lock`: `ring` and `aws-lc-rs` both
  present, and two `rustls` builds.
