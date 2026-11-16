---
id: ADR-0050
title: "A Request-Level Exchange Seam, With Mocking as a Transport"
status: accepted
date: 2026-11-16
scope: [transport/egress, transport/exchange, testing/mocking, protocol/abstraction]
superseded_by: null
---

# 0050. A Request-Level Exchange Seam, With Mocking as a Transport

- Status: Accepted
- Date: 2026-11-16
- Deciders: Ming Li
- Amends: [ADR-0019](0019-connection-plan-and-wire-profile-registry.md)

---

## Context and Problem Statement

`Client<C: Connector>` owned the pool, the connector and both wire protocols.
HTTP/1.1 and HTTP/2 were `cfg` branches inside one 2,100-line module, and the
response body was a struct holding an optional reader for each protocol.
Three consequences followed:

- **No protocol abstraction.** Adding a protocol meant editing every branch of
  the client. HTTP/3 was never added there at all: it grew a parallel
  `H3Client` with its own target, error and response types.
- **No way to mock a request.** `Response` and its body had private fields, so
  the only way to fake a response was to implement `Connector` and script raw
  wire bytes. Saying "answer 503" required speaking HTTP/1.1.
- **Policy was duplicated or absent per protocol.** Decoding, the decoded-size
  limit and the trace marks were written against each protocol's reader.

The library's stated goals are deep observability and flexible request
mocking. The second had no mechanism.

## Decision Drivers

- A mocked request must run the same client code a real one does: redirects,
  decoding, bounds and the trace.
- Adding a protocol, or a way of faking one, must not touch the client.
- Code under test must not need to be generic over the transport: production
  and test code hold the same `Client` type.
- Connection identity must still be resolved before anything is opened
  (ADR-0019).

## Considered Options

- Option 1: Keep `Client<C>`; mock by implementing `Connector` over an
  in-memory stream.
- Option 2: A public trait object for the response body only, keeping protocol
  dispatch inside the client.
- Option 3: A request-level seam (`RoundTrip`) below a protocol-neutral
  client, with the real network and the mock as two implementations.

## Decision Outcome

Chosen option: "Option 3", because it is the only one that makes mocking and
protocol extension the same mechanism.

- `RoundTrip` turns a `Request` into an `Exchange` (response head plus a
  `BodySource`). It also opens a dedicated byte stream for upgrades and
  optionally pre-warms a connection.
- `Client` is no longer generic. It holds an `Arc<dyn RoundTrip>` and owns
  what is true of every request: the plan, the trace-id header, the redirect
  chain, `Content-Encoding` decoding, the decoded-size limit, the body idle
  bound and the attempt's evidence.
- `Wire<C: Connector>` is the `RoundTrip` over real connections. It owns the
  pool, protocol selection and the replay decision, and delegates each
  protocol to its own module.
- `mock::Mock` is a `RoundTrip` that answers from routes: matchers, one-shot
  and standing replies, computed replies, scripted delays and failures, a call
  log, queued streams for upgrades, and an optional fallback transport.
- `Body` is one type for every transport. It pulls raw chunks from a
  `BodySource` and applies decoding, limits, bounds and trace marks.
- `ConnectionPlan` carries the HTTP/2 mode (`Http2Mode`), so a transport reads
  the protocol decision from the plan instead of re-deriving it.
- `FaultConnector` puts the existing `FaultIo` into the connector stack. It is
  the byte-level complement of the mock, on a real connection.

### Invariants & Behavioral Boundaries

- `[INV-EXCHANGE-01]` One client, any transport: `Client` names no protocol,
  socket or pool. *Enforced by*: `Client` holding only `Arc<dyn RoundTrip>`;
  `tests/integration/mock.rs` driving redirects, decoding, bounds and traces
  through a `Mock` with no socket, and `unmatched_requests_can_fall_through_to_the_real_wire`
  putting both transports behind one client.
- `[INV-EXCHANGE-02]` A response body is transport-neutral: decoding, limits
  and trace marks are written once in `Body`. *Enforced by*: `BodySource`
  exposing only raw chunks and `release`;
  `a_mocked_encoded_body_is_decoded_by_the_client`.

### Consequences

- **Positive**: request mocking exists and exercises real client behaviour;
  a protocol is added by implementing `BodySource` and one module under
  `wire`; decoding and bounds cannot drift between protocols.
- **Negative & Trade-offs**: one boxed future per round trip and per body
  chunk at the seam. The byte path is unaffected: the socket tap stays owned
  by value beneath the seam (ADR-0051). `Client::pool()` is gone; a caller
  that inspects the pool keeps its own `Pool` handle. `Client<C>` type
  annotations become `Client`. `BodyStream` is renamed `Body`, and its reads
  return `AttemptError`.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected)

- **Why considered**: no API change; `Connector` already exists.
- **Why rejected**: a byte-level fake must emit a correct wire encoding for
  every response it scripts, per protocol, and cannot fake HTTP/3 at all
  because that path takes a concrete `QuicConnector`. The mock becomes a
  second protocol implementation that has to be kept correct.

### Option 2 (Rejected)

- **Why considered**: it removes the per-protocol body struct with a smaller
  change.
- **Why rejected**: the request side stays hard-wired, so nothing can answer a
  request without a connection. It fixes the symptom in the body type and
  leaves both stated problems in place.

## Links

- Related ADRs: [ADR-0019](0019-connection-plan-and-wire-profile-registry.md),
  [ADR-0051](0051-attempt-evidence-is-neutral-socket-level-and-always-reachable.md),
  [ADR-0052](0052-replay-and-exchange-bounds.md)
