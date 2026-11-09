---
id: ADR-0018
title: "One Trace Collector per Attempt; Recorder Leaves the Public API"
status: accepted
date: 2026-11-08
scope: [trace/model, trace/cost, transport/egress, protocol/http2, protocol/http3]
superseded_by: null
---

# 0018. One Trace Collector per Attempt; Recorder Leaves the Public API

- Status: Accepted
- Date: 2026-11-08
- Deciders: Ming Li
- Amends: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0010](0010-quic-ownership-and-trace-sink.md), [ADR-0017](0017-tiered-observation-and-connection-identity.md)

---

## Context and Problem Statement

ADR-0017 introduced the typed byte-path `Tap`, but left the public handle unchanged: callers and
protocol clients still exchange `Arc<Mutex<Recorder>>`. That makes the architecture true only
where the code remembers to use a tap. A caller can still bypass the tap, mutate the ring
directly, or hand a recorder to a protocol that never observes bytes at all.

The remaining bypasses are concrete:

- `Client::send_traced` accepts `Arc<Mutex<Recorder>>`.
- `H2Client::send` accepts `Arc<Mutex<Recorder>>` and records only phase/frame events.
- `netune-http3::H3Client` and `netune-quic` accept `Option<Arc<Mutex<Recorder>>>`.
- `netune-server` threads the same handle through every ingress task.
- `Recorder::read`/`wrote` are public, so any holder can manufacture byte events.

At the same time, multiplexed transports need a fidelity decision rather than an implicit
exception. An HTTP/2 or HTTP/3 connection carries many exchanges; a per-exchange byte tap would
slice one connection's bytes arbitrarily. The honest unit for those transports is the connection's
protocol/frame timeline, which is L0, not a per-exchange syscall timeline.

The goal is a single entry point: **control events go through `TraceCollector`; byte events go
through `Tap`; no other path exists.** A protocol that does not attach a byte tap must say so in
its fidelity, not inherit an L1 label.

---

## Decision

### 1. `TraceCollector` is the only public trace handle

`netune-trace` exposes `TraceCollector`, a cloneable, internally synchronized handle for the cold
path. `Recorder` becomes an implementation detail of the crate and is no longer re-exported.

`TraceCollector` exposes only:
- construction (`start`, `start_ingress`, `disabled`)
- sink installation
- phase/protocol marks (`mark`, `mark_stream`, `frame`, `tcp_info`, `reused_connection`, and the
  ingress helper marks)
- merge of an owned byte-tap log
- snapshot access (`origin`, `capacity`, `is_enabled`, `sink`, `log`, `dropped`)

It does **not** expose `read`/`wrote`. Byte events can only be produced by `Tap` implementations
through `TimedIo`/`RingIo`. Even the merge boundary is typed: `TraceCollector::merge` accepts
`TapLog`, whose constructor is crate-private, so a caller cannot build a raw `EventLog` with
`Read`/`Write` events and inject it. A caller that needs byte evidence selects
`Observation::Traced`; a caller that needs only phase evidence uses `Counters`/`Off` or a sink.

### 2. Every protocol client accepts the same collector

`Connector`, `TlsConnector`, `TlsRouterConnector`, `ProxyConnector`, `H2Client`, `H3Client`,
`netune-quic` and the ingress server all take `TraceCollector` / `Option<TraceCollector>`, never
`Arc<Mutex<Recorder>>`. The collector can be cloned cheaply when a sampler or a second task needs
to emit a control event; the byte path never clones it.

### 3. Multiplexed transports report L0 explicitly

HTTP/2 and HTTP/3 traces are **connection-level control/frame traces**. Their envelope fidelity is
`Fidelity::l0()`. They do not claim `syscall: true`, and they do not return a per-exchange byte
timeline.

This is not a silent downgrade: it is the correct unit for a multiplexed connection. A future
connection-level byte tap is a new capability and would require its own ADR; it is not faked by
reusing a per-request `Observation::Traced`.

Stream transports (HTTP/1.1 and WebSocket) attach `Tap` and may report L1.

### 4. `RequestTrace` is assembled from the collector, not mutated by callers

The collector owns the event log; the orchestrator supplies the envelope identity and endpoint.
A caller may read `Response::body::trace()` / `Response::body::counters()`, but it does not hold a
recorder it can write to. The only supported injection point for an extra producer event is the
collector's mark API, which cannot produce `Read`/`Write`.

### 5. The old API is deleted, not deprecated

There is no `Recorder` re-export, no compatibility `send(..., recorder, ...)`, and no
`Arc<Mutex<Recorder>>` in a public signature. Existing callers migrate to:

```rust
let client = Client::new(connector, pool, ClientConfig::default());
let response = client.request(&target, head, body).await?;
let trace = response.body.trace();       // Some only for Traced
let counters = response.body.counters(); // Some only for Counters
```

A caller that needs an explicit collector for tests or a harness uses
`TraceCollector::start(capacity)` and `Client::send_traced(..., collector)`.

---

## Invariants & Behavioral Boundaries

- **`[INV-TRACE-07]` One Public Entry**: `TraceCollector` and `Tap` are the only observation
  entry points. `Recorder` is not nameable outside `netune-trace`; no public method accepts or
  returns an `Arc<Mutex<Recorder>>`. *Enforced by*: compilation of the workspace and a grep gate
  that rejects `Arc<Mutex<Recorder>>` in public signatures.

- **`[INV-TRACE-08]` Multiplexed Fidelity Is Honest**: HTTP/2 and HTTP/3 traces report
  `Fidelity::l0()` unless a connection-level byte tap is explicitly attached. No per-exchange
  syscall timeline is synthesized. *Enforced by*: `BodyStream::trace()` derives fidelity from the
  body observation, and H2/H3 tests assert `l0`.

- **`[INV-TRACE-09]` Byte Events Only from Taps**: `Read` and `Write` events are produced by
  `Ring`/`RingIo` and merged through `TraceCollector::merge(TapLog)`; the collector has no
  public `read`/`wrote` method and `TapLog` has no public constructor. *Enforced by*: the
  `TraceCollector` API surface and the absence of a public `Recorder`.

- **`[INV-CUSTOM-07]` One Collector, Every Protocol**: every protocol client and connector uses
  the same `TraceCollector` type; no protocol owns a parallel recorder abstraction. *Enforced by*:
  crate-level signatures and the architecture gate.

---

## Consequences

- **Positive**:
  - There is no supported way to write a byte event except through a tap.
  - HTTP/2/HTTP/3 stop pretending to be L1; their traces are comparable and honest.
  - The egress and ingress orchestrators share one cold-path handle instead of two recorder
    idioms.
  - The public API no longer exposes a mutex or a ring.

- **Negative & Trade-offs**:
  - Breaking change: `send_traced` and every protocol constructor change their trace parameter.
  - H2/H3 do not gain a byte timeline from this ADR; that remains a deliberate capability gap.
  - `TraceCollector` still uses an internal mutex for cold-path fan-out (sampler, ingress tasks);
    ADR-0017's hot-path invariant remains the reason it is not on `poll_read`/`poll_write`.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep `Recorder` public and document "prefer tap"

A convention is not a mechanism. As long as `Recorder::read` is public, every new protocol can
bypass the tap and claim fidelity it did not produce. The bypass was already present in H2/H3.

### Option 2 (Rejected): make every protocol generic over `Tap`

A per-exchange tap over a multiplexed connection slices one connection's byte stream arbitrarily;
it does not produce a per-exchange timeline. For H2/H3 the connection is the observation unit, and
the frame/control trace is the correct artifact. A future connection-scoped tap can be added
without pretending it is per-exchange.

### Option 3 (Rejected): keep `Arc<Mutex<Recorder>>` as the internal implementation

The internal storage stays, but it is not the public contract. The collector owns it so a future
lock-free/ordered implementation can replace it without touching every protocol client.

---

## Evidence

- Current bypasses: `crates/netune/src/client.rs`, `crates/netune/src/h2_client.rs`,
  `crates/netune-http3/src/client.rs`, `crates/netune-quic/src/connector.rs`,
  `crates/netune-server/src/*.rs`.
- Typed tap: `crates/netune-trace/src/tap.rs`, `crates/netune-io/src/timed.rs`.
- H2 fidelity: `BodyStream::trace()` must derive `Fidelity::l0()` for the H2 body variant.

---

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0010](0010-quic-ownership-and-trace-sink.md),
  [ADR-0011](0011-server-side-ingress-transport.md),
  [ADR-0017](0017-tiered-observation-and-connection-identity.md)
