---
id: ADR-0042
title: "One Trace Identity and One Sink Contract Across Both Directions"
status: accepted
date: 2026-11-11
scope: [trace/identity, trace/sink, transport/egress, transport/ingress, observability]
superseded_by: null
---

# 0042. One Trace Identity and One Sink Contract Across Both Directions

- Status: Accepted
- Date: 2026-11-11
- Deciders: Ming Li
- Amends: [ADR-0010](0010-quic-ownership-and-trace-sink.md), [ADR-0011](0011-server-side-ingress-transport.md), [ADR-0018](0018-one-trace-collector-per-attempt.md)

---

## Context and Problem Statement

`TraceId` is documented as a correlation id carried on the request, but nothing generates it,
injects it, extracts it, or echoes it. Egress traces use the literal string `"egress"`, H3 traces use
`"h3"`, and `AttemptRef` is zeroed.

`TraceSink` receives a bare `Event` with no trace identity, direction, peer, protocol, or attempt.
`SinkObserver` replays an ingress connection's events into that sink but drops the envelope, and
`log_from_events` rebuilds a log with `push_at`, which hardcodes stream `0` and destroys HTTP/2
stream identity.

The server also has three observability paths: per-connection `TraceObserver`, the H3
`subscribe_handshake_errors` broadcast, and a silent accept/shed loop. A shared sink cannot tell
which attempt, connection, or direction an event belongs to.

## Decision Drivers

- One attempt must have one identity across egress and ingress.
- One sink must serve both directions without flattening the envelope.
- Multiplexed stream identity must survive every serialization and rebuild path.
- Adding a correlation header changes the wire; it cannot be a silent default.
- Operational failures outside a connection trace (accept, shed, drain, handshake) need a scope too.

## Decision

### 1. `TraceMeta` is the envelope identity

Every trace carries a `TraceMeta`:

```text
id: TraceId                  // real, generated, not a placeholder
direction: Egress | Ingress
started_unix_ns: u64         // correlation only; never a timing input
build_version, process_id    // provenance
listener / endpoint fields   // what the trace was attached to
```

`TraceId::generate()` produces a UUIDv7-shaped identifier from time, process entropy, and a
monotonic counter. It is a correlation id, not a secret. `AttemptRef` is populated from the real
attempt; `EventKind::Retry` is emitted when a retry happens.

`RequestTrace` and `IngressTrace` both carry `TraceMeta`. The old bare `id` field and `"egress"` /
`"h3"` placeholders are deleted.

### 2. `TraceSink` v2 receives the envelope

`TraceSink` gains lifecycle methods and passes the `TraceMeta` with every event:

```rust
trait TraceSink {
    fn trace_started(&self, meta: &TraceMeta) {}
    fn event(&self, meta: &TraceMeta, event: Event) -> Flow;
    fn trace_finished(&self, meta: &TraceMeta, summary: &TraceSummary) {}
}
```

- `SinkObserver` forwards the ingress envelope instead of flattening it.
- `log_from_events` uses `push_at_stream`; stream identity is preserved.
- `Flow::Drop` increments a sink-drop counter reported in `TraceSummary`.
- A sink implementation can be shared by egress and ingress without guessing.

### 3. One listener/control scope

Operational facts outside a connection trace are recorded through a dedicated listener observer with the same delivery rules (non-blocking, bounded, never the record of truth). The scope is separate because a connection that was shed never had a trace to attach the fact to:

```text
ListenerBound, AcceptFailed, Shed, ProtocolSelected,
DrainStarted, DrainExpired, H3HandshakeFailed, SinkLagged
```

The H3 `handshake_errors` broadcast remains as a convenience but is no longer the only record.
Connection-task `JoinError`s and drain aborts are recorded rather than ignored.

### 4. Correlation propagation is a named policy

Adding `x-netune-request-id` changes HTTP/1 header order and the HTTP/2 header set, which are wire
identity. It is therefore an explicit policy:

```text
TracePropagation::Off
TracePropagation::Header(name)
```

When enabled, egress adds the header and records it; ingress extracts it or generates a new id,
echoes it, and both envelopes carry the same `TraceId`. The policy is part of the request/connection
plan, not a hidden side effect.

### 5. Schema v2 is a clean break

`TRACE_SCHEMA_VERSION` becomes `2`. The old `RequestTrace { id, ... }` shape is deleted, not
deprecated. Consumers that need v1 must convert it themselves; the workspace does not carry a
compatibility shim.

## Invariants & Behavioral Boundaries

- **`[INV-DIAG-03]` One Identity Across Directions**: when propagation is enabled, the egress and
  ingress envelopes for one exchange share a `TraceId`; when it is disabled, each side still has a
  real locally generated id. *Enforced by*: an egress-to-server integration test and a trace-id
  format test.

- **`[INV-DIAG-04]` Sink Context Is Not Flattened**: every event delivered to a `TraceSink` carries
  the `TraceMeta` of its attempt; rebuilding a log from streamed events preserves `Event::stream`.
  *Enforced by*: sink contract tests, including a multiplexed HTTP/2 log.

- **`[INV-DIAG-07]` Operational Failures Are Observable**: accept failure, admission shed, drain
  expiry, H3 handshake failure, and sink lag are recorded on the listener scope. *Enforced by*:
  listener tests and a sink-drop test.

## Consequences

- **Positive**:
  - A client trace and a server trace can be joined without guessing.
  - A shared sink can attribute events to an attempt, direction, and stream.
  - Server operational failures stop disappearing at `continue`.
  - `log_from_events` becomes safe for multiplexed logs.
- **Negative & Trade-offs**:
  - The sink trait breaks; every implementor updates in the same change.
  - Propagation changes the wire and is therefore opt-in.
  - `TraceMeta` adds cold-path fields; the event size is unchanged.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Put the trace id in `Event`

The event is fixed-size and hot. The envelope already travels with the attempt; adding identity to
every event would either bloat it or duplicate the same pointer.

### Option 2 (Rejected): Keep `TraceSink::event(Event)` and add a global registry

A global registry is ambient state, cannot be scoped to a test, and reintroduces the second-record
problem. The envelope must travel with the event.

### Option 3 (Rejected): Always inject the correlation header

It would silently change HTTP/1 header order and HTTP/2 header sets, which are fingerprint-relevant.
A wire-identity change must be a named policy.

## Links

- Related ADRs: [ADR-0010](0010-quic-ownership-and-trace-sink.md),
  [ADR-0011](0011-server-side-ingress-transport.md),
  [ADR-0018](0018-one-trace-collector-per-attempt.md),
  [ADR-0041](0041-diagnostic-spine-side-table.md)
