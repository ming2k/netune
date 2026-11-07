---
id: ADR-0010
title: "QUIC stays out of netune until a consumer needs it as a client, and the trace model gains a streaming sink"
status: accepted
date: 2026-11-01
scope: [transport/quic, trace/sink, transport/datagram]
superseded_by: null
---

# 0010. QUIC stays out of netune until a consumer needs it as a client, and the trace model gains a streaming sink

- Status: Partially Superseded by [ADR-0016](0016-quic-and-http3-transport.md) (Decision 1 on QUIC deferral superseded; Decision 2 on `TraceSink` and Decision 3 on metrics remain active)
- Date: 2026-11-01
- Deciders: Ming Li
- Related: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0008](0008-datagram-transport-and-socks5-udp-association.md),
  [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md),
  [ADR-0016](0016-quic-and-http3-transport.md)

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

### Invariants & Behavioral Boundaries

- **`[INV-TRACE-03]` Sink Completeness, Ring Independence**: an event reaches a configured
  `TraceSink` before the operation that recorded it returns, and installing a sink cannot
  truncate the attempt's window — the ring buffer stays an independent bounded record, so a
  sink that drops events (a slow consumer) does not make the trace lose its history silently.
  *Enforced by*: `Recorder::with_sink` consumes and returns `self`, so a sink cannot be
  installed halfway through a trace (`a_sink_streams_every_event_from_offset_zero`), and
  `push` writes the ring before the sink (`a_recorder_without_a_sink_pays_nothing`).

- **`[INV-SOCKET-01]` Pre-Connect Options Are Applied or Reported**: every `SocketConfig`
  option is either applied to the socket before `connect(2)`, or the attempt fails loudly.
  No pre-connect option may be silently skipped by the fast path. *Enforced by*:
  `SocketConfig::needs_manual_socket` is the single predicate deciding fast path versus
  manual construction (`every_pre_connect_option_forces_the_manual_socket_path`), and the
  bound source address is verified from the peer's side rather than assumed
  (`a_bound_source_address_is_what_the_peer_sees`).

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

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Wrap `quinn` and re-export it as `netune::quic`

- **Why considered**: the shortest path to a QUIC client. `netune` would gain `connect_quic`
  in an afternoon, and `daer` would drop its own `quinn` dependency.
- **Why rejected**: `quinn` owns the whole transport — record framing, loss recovery,
  congestion control — and takes a `rustls::ClientConfig`. Handing it one does not let netune
  shape the handshake the way `TlsProfile` shapes a TCP one, because the ClientHello is
  assembled by `quinn`'s state machine, not by ours. The result would be a transport whose
  wire identity the caller cannot select, which is precisely the failure ADR-0004 exists to
  prevent. It also imports a second `rustls` and a second crypto provider into every build
  that touches it, which is the duplication ADR-0001's ownership argument forbids. A wrapper
  that cannot answer "what identity does this send" is not ownership; it is a dependency with
  extra steps.

### Option 2 (Rejected): Add the sink as a `tracing` subscriber

- **Why considered**: `tracing` already solves fan-out, filtering, and formatting, and every
  Rust service already depends on it.
- **Why rejected**: a logging facade in a leaf crate is a dependency the consuming binary did
  not choose, and ADR-0003's decomposition exists so leaves stay dependency-light. It would
  also make netune's event vocabulary a function of `tracing`'s data model, so a consumer that
  wants structured events without a subscriber pays for both. Three lines of `TraceSink` give
  a consumer exactly the bridge they want, and nothing to a consumer who wants none.

### Option 3 (Rejected): Make the sink the record of truth and drop the ring

- **Why considered**: two paths for one event is a smell, and a sink is strictly more
  expressive than a bounded ring.
- **Why rejected**: a sink is fire-and-forget. If the consumer's channel is full, the event is
  gone, and a `RequestTrace` built from that stream would silently report a shorter attempt
  than happened. `INV-TRACE-01`'s timings are pure functions of the recorded events, so losing
  events does not just lose detail — it fabricates a faster request. The ring stays the record
  of truth precisely because it cannot silently lose its window; the drop count is reported.
