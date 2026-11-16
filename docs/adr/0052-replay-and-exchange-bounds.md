---
id: ADR-0052
title: "Replay Is Decided by the Request; the Exchange Itself Is Bounded"
status: accepted
date: 2026-11-16
scope: [transport/pool, transport/replay, transport/timeouts, security/replay]
superseded_by: null
---

# 0052. Replay Is Decided by the Request; the Exchange Itself Is Bounded

- Status: Accepted
- Date: 2026-11-16
- Deciders: Ming Li
- Amends: [ADR-0005](0005-keepalive-socket-culling-absorption.md),
  [ADR-0040](0040-egress-handshakes-share-a-bound.md)

---

## Context and Problem Statement

ADR-0005 absorbs a pooled socket the peer closed while idle by re-sending the
request on a fresh connection, for any method, whenever a reused connection
failed before a response head. Its justification was that the request
"provably had not reached the origin". That does not hold: a peer can read a
complete request, act on it, and die before answering. Replaying a `POST` in
that window duplicates a side effect.

Separately, nothing bounded an exchange after connection establishment. A peer
that accepted a request and never answered held the attempt forever, and the
only remedy, an outer `tokio::time::timeout`, discards the trace by cancelling
the future.

## Decision Drivers

- A transparent replay must never duplicate a side effect.
- The common case (a socket culled while idle) must still be invisible to the
  caller, including for `POST`.
- A bound must return evidence, not destroy it.
- A long stream must never be cut for being long.

## Considered Options

- Option 1: Keep replaying every method.
- Option 2: Never replay; surface every stale socket to the caller.
- Option 3: Probe pooled sockets before use, and replay only requests for
  which a second copy is safe.

## Decision Outcome

Chosen option: "Option 3".

**Probe before use.** A pooled HTTP/1.1 connection is polled once at checkout
with a waker that goes nowhere. Anything but `Pending` (end of stream, an
error, unsolicited bytes) discards it before a request byte is written. The
discard is recorded as `ConnectStaleDiscarded` with an `EGRESS_POOL_STALE`
note. Nothing is replayed, so this path is safe for every method.

**Replay only what is safe.** If a reused connection dies between the probe
and the response head, the request is re-sent only when the peer said it did
not process it (`NetError::RetryableProtocol`: HTTP/2 `GOAWAY` or
`REFUSED_STREAM`), or `Request::is_replay_safe` holds: an RFC 9110 idempotent
method, or an `Idempotency-Key` header. Otherwise the failure is returned. It
still reports `is_stale_connection()` and a retryable verdict, so the caller,
who knows what a duplicate costs, can decide.

**Bound the exchange.** `ClientConfig::response_head_timeout` bounds the wait
from request written to head received; `ClientConfig::body_idle_timeout`
bounds the silence between body reads; `ClientConfig::request_timeout` bounds
the whole attempt, including redirects and the response body. They default to
30 s, 60 s and 300 s respectively. Expiry is `NetError::Timeout`, returned with
the attempt's trace. It is retryable and is never classified as a stale
connection. Setting any of them to `None` is an explicit caller opt-out, not a
production default.

### Invariants & Behavioral Boundaries

- `[INV-TRANSPORT-06]` A request that may have reached the origin is replayed
  only if it is replay-safe or the peer refused it. *Enforced by*:
  `wire::may_replay` and its unit test;
  `inv_transport_06_a_post_swallowed_by_a_reused_socket_is_not_replayed`,
  `inv_transport_06_a_get_swallowed_by_a_reused_socket_is_replayed`.
- `[INV-TRANSPORT-07]` A socket closed while idle is discarded before use and
  nothing is replayed. *Enforced by*:
  `a_pooled_socket_the_peer_dropped_is_replaced_transparently` (a `POST`
  succeeds with zero `ConnectReused` events) and
  `an_idle_stream_is_quiet_until_the_peer_closes_or_speaks`.
- `[INV-TRANSPORT-08]` An exchange bound returns the attempt's evidence and
  is not a stale-socket signature. *Enforced by*:
  `a_head_that_never_comes_trips_the_bound_and_returns_evidence`,
  `a_body_that_goes_quiet_trips_the_idle_bound_but_a_long_one_does_not`.

### Consequences

- **Positive**: no transparent duplicate of a non-idempotent request; the
  idle-cull case still costs the caller nothing; stalls are bounded with
  evidence.
- **Negative & Trade-offs**: a non-idempotent request that dies in the narrow
  window after the probe now surfaces as a retryable error where it was
  previously absorbed. A caller that wants it absorbed sends an
  `Idempotency-Key`.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected)

- **Why considered**: it is the existing behaviour and hides the most
  failures.
- **Why rejected**: it trades a visible, retryable error for an invisible
  duplicated side effect, and the premise that justified it is false.

### Option 2 (Rejected)

- **Why considered**: it is trivially safe.
- **Why rejected**: it reintroduces the failure ADR-0005 exists to remove.
  Peers cull idle sockets routinely, and the probe handles that case with no
  replay at all.

## Links

- Related ADRs: [ADR-0005](0005-keepalive-socket-culling-absorption.md),
  [ADR-0040](0040-egress-handshakes-share-a-bound.md),
  [ADR-0050](0050-request-level-exchange-seam-and-mock-transport.md)
