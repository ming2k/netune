---
id: ADR-0051
title: "Attempt Evidence Is Consumer-Neutral, Socket-Level and Always Reachable"
status: accepted
date: 2026-11-16
scope: [trace/model, trace/fidelity, transport/egress, observability/evidence]
superseded_by: null
---

# 0051. Attempt Evidence Is Consumer-Neutral, Socket-Level and Always Reachable

- Status: Accepted
- Date: 2026-11-16
- Deciders: Ming Li
- Amends: [ADR-0017](0017-tiered-observation-and-connection-identity.md),
  [ADR-0018](0018-one-trace-collector-per-attempt.md)

---

## Context and Problem Statement

Three properties of the trace contradicted "trace, then trust":

1. **The trace leaf carried one consumer's domain.** `RequestTrace` had
   `EndpointRef { provider, model }` and `AttemptRef { round, turn, attempt }`;
   events included `OutputToken`; `FrameClass` had `Reasoning`, `Tool` and
   `Usage`. The client filled these with empty strings and zeros, and the
   WebSocket path recorded binary frames as `Usage` and close frames as
   `Open` because no honest class existed.
2. **`TimeSource::Syscall` was not a syscall.** `TimedIo` wrapped the stream a
   connector returned, which for HTTPS is the TLS stream. Its `Read` events
   were decrypted-record deliveries, labelled as socket reads.
3. **The trace was unreachable when it mattered.** `body.trace()` returned
   `None` unless the body finished, and a body read returned a bare
   `NetError`. A truncated stream had no trace unless a sink was configured,
   and the socket log of a failed TLS handshake was dropped with the stream.

## Decision Drivers

- A leaf crate must not carry a consumer's vocabulary.
- An event's label must describe what was measured.
- Every terminal state of an attempt must leave its evidence.
- No `Arc`, lock or boxed tap on `poll_read`/`poll_write` (ADR-0017).

## Considered Options

- Option 1: Keep the tap above TLS and relabel its events.
- Option 2: A shared, lock-guarded tap handle the client can retarget.
- Option 3: An owned, switchable tap at the socket, reached through the
  stream stack; neutral vocabulary; traces at every terminal state.

## Decision Outcome

Chosen option: "Option 3".

**Neutral vocabulary.** `AttemptRef` and `EndpointRef` are removed;
`RequestTrace` carries `authority` and nothing else about who was called.
`EventKind::OutputToken` becomes `Payload` (caller-counted units).
`FrameClass` is `Unknown`, `Open`, `Metadata`, `Text`, `Binary`, `Close`,
`KeepAlive`. Derived fields are renamed to match: `first_payload_us`,
`first_payload_after_sent_us`, `frame_to_payload_us`, `payload_span_us`. The
rate constants a consumer's ledger used are removed. `TRACE_SCHEMA_VERSION`
is 3. A consumer keeps its own labels beside the trace, keyed by the trace id.

**Socket-level tap.** `SocketTap` is an enum (`Off`, `Counters`, `Ring`)
owned by value by `TappedSocket`, the stream `TcpConnector` returns.
`Transport::socket_tap` is forwarded by every layer (TLS, wire shaping, fault
injection, boxes) down to it. An attempt installs its tap when it takes a
connection and takes it back when it releases one. A traced dial installs the
ring at the socket's first byte, so handshake bytes are in the timeline. A
stream with no socket answers `None`, and the attempt is reported at protocol
fidelity. A multiplexed connection retires its dial tap after the handshake:
no single exchange owns that socket.

**Reachable evidence.** `Body` reads return `AttemptError`, which carries the
snapshot. `Body::trace` answers once the body is terminal: finished, failed
or abandoned. `Body::abandon` makes an early stop an explicit terminal state.
A `TappedSocket` dropped before anything collected its dial tap merges the
log into the attempt's recorder itself. Fidelity on a failure is decided by
the evidence: L1 only if socket events were recorded.

### Invariants & Behavioral Boundaries

- `[INV-TRACE-10]` A byte event is a socket event: the tap is owned by the
  socket wrapper beneath every layer. *Enforced by*: `Transport::socket_tap`
  forwarding; `inv_trace_10_a_traced_tls_attempt_records_socket_events_under_the_handshake`
  (socket writes and reads inside the TLS phase, read total above the
  plaintext size).
- `[INV-TRACE-11]` Every terminal body state leaves a trace, and an open body
  has none. *Enforced by*: `inv_trace_11_a_body_that_fails_part_way_returns_its_trace`,
  `inv_trace_11_an_abandoned_body_has_a_trace`.
- `[INV-TRACE-12]` The trace crate names no consumer domain. *Enforced by*:
  the type surface (`RequestTrace` has no endpoint or attempt fields) and
  `frame_class_and_time_source_codes_round_trip`.

### Consequences

- **Positive**: HTTPS attempts have a real socket timeline including the
  handshake; counters count socket bytes; a failure always explains itself;
  the trace schema is usable by any consumer.
- **Negative & Trade-offs**: one predictable branch per syscall where a
  monomorphized tap had none. `Counters` on a TLS connection now count
  ciphertext, which is what crossed the socket. Persisted v2 traces with
  frame classes 4 and 5 read as `Binary` and `Close`. A custom `Connector`
  must return a `Transport`; arbitrary streams are wrapped in `Untapped`.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected)

- **Why considered**: no structural change; only a new `TimeSource` value.
- **Why rejected**: it makes the label true and leaves the measurement
  useless for the owned TLS engine, whose record buffering sits exactly
  between the socket and that tap. The handshake would stay invisible.

### Option 2 (Rejected)

- **Why considered**: a handle is the simplest way to retarget a tap on a
  pooled connection.
- **Why rejected**: it puts an `Arc` and a lock acquisition on every read and
  write, which ADR-0017 forbids for a measured reason.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0017](0017-tiered-observation-and-connection-identity.md),
  [ADR-0018](0018-one-trace-collector-per-attempt.md),
  [ADR-0050](0050-request-level-exchange-seam-and-mock-transport.md)
