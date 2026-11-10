---
id: ADR-0035
title: "Incoming QUIC Handshake Failures Are Observable and Non-Fatal"
status: accepted
date: 2026-11-10
scope: [transport/quic, transport/ingress, api/quic, observability]
superseded_by: null
---

# 0035. Incoming QUIC Handshake Failures Are Observable and Non-Fatal

- Status: Accepted
- Date: 2026-11-10
- Deciders: Ming Li
- Amends: [ADR-0016](0016-quic-and-http3-transport.md)
- Related: [ADR-0025](0025-h3-ingress-peer-transport.md),
  [ADR-0034](0034-quic-consumer-seams.md)

---

## Context and Problem Statement

`Endpoint::accept` used to expose only an established connection. A peer that
failed QUIC or TLS negotiation disappeared: no connection was produced, no
error reached the listener, and `H3Server` treated the `Result` as fatal. A
single bad client could therefore either be invisible (if ignored) or stop the
listener (if treated as an endpoint failure). Neither is acceptable for a
production ingress.

## Decision Drivers

- A listener must distinguish "no connection yet" from "a peer failed to
  negotiate".
- A hostile or broken peer must not stop service for other peers.
- An operator must be able to account for handshake failures without a global
  logging dependency.
- The existing trace model is per-established-connection; a failed handshake
  has no application attempt to attach to.

## Considered Options

### Option 1: Keep `accept` returning only `Result<Connection, QuicError>`

- **Why considered**: no new public type.
- **Why rejected**: `QuicError::Closed` cannot distinguish endpoint shutdown
  from a peer's failed handshake, and callers cannot safely decide whether to
  continue or stop.

### Option 2: Log inside `netune-quic`

- **Why considered**: one place to observe.
- **Why rejected**: the workspace has no logging dependency, and a transport
  leaf must not choose an application's logging policy.

### Option 3: Typed accept events (chosen)

- **Why considered**: the listener already owns the accept queue.
- **Why chosen**: failures become values, callers decide policy, and
  `H3Server` can continue while publishing failures to its operator.

## Decision Outcome

Chosen option: **Option 3**.

`Endpoint::accept` returns `Result<Connection, AcceptError>` where
`AcceptError` is either `EndpointClosed` or `Handshake(QuicError)`. A failed
handshake is delivered to exactly one `accept` call; it is never returned as a
connection and never interpreted as endpoint shutdown. The endpoint driver
reports failures that occur before a connection object exists, and the
per-connection watcher reports failures after it exists.

`H3Server` continues accepting after `AcceptError::Handshake` and publishes the
error through `subscribe_handshake_errors()`, a bounded broadcast channel. A
listener with no subscriber still continues; observability is opt-in but the
availability behavior is not.

### Invariants & Behavioral Boundaries

- **`[INV-QUIC-23]` Handshake Failure Is a Value**: a failed incoming handshake
  is reported exactly once as `AcceptError::Handshake`, never as a connection
  and never as `EndpointClosed`. *Enforced by*:
  `a_failed_handshake_is_observed_and_accept_continues`.
- **`[INV-SERVER-25]` A Failed Peer Does Not Stop the Listener**: `H3Server`
  continues after a handshake failure and publishes the error to every current
  subscriber. *Enforced by*: the H3 ingress accept loop and the handshake-error
  broadcast; a failed handshake followed by a valid connection is covered by
  the quic endpoint test and the H3 ingress suite.

### Consequences

- **Positive**: a bad peer is visible, bounded, and non-fatal. A proxy operator
  can alert on handshake failures without a new logging framework.
- **Negative & Trade-offs**: `accept` gains a public error type (a pre-1.0
  break). A caller that treats every `Err` as shutdown must now match
  `AcceptError`; this is deliberate because the two conditions have opposite
  policies. The broadcast channel is lossy for a slow subscriber by design;
  availability does not depend on the observer.

## Rejected Alternatives & Negative Knowledge

### Returning `QuicError` and relying on its variant

- **Why considered**: no new enum.
- **Why rejected**: `QuicError` describes connection operations, not the accept
  state machine. Endpoint shutdown and peer failure are different decisions and
  must not share an ambiguous catch-all.

### Sending failed handshakes as `Connection` objects with an error state

- **Why considered**: one channel type.
- **Why rejected**: a failed handshake has no streams, peer certificate or
  usable transport; exposing it as a connection invites accidental use and
  breaks the "Connection means established" boundary.

### Unbounded per-failure queue

- **Why considered**: never lose an error.
- **Why rejected**: a handshake flood would turn observability into memory
  exhaustion. The broadcast channel is bounded and explicitly lossy for slow
  observers; the listener remains available.

## Links

- [ADR-0016](0016-quic-and-http3-transport.md) — QUIC/HTTP3 transport
- [ADR-0025](0025-h3-ingress-peer-transport.md) — H3 ingress peer transport
- [ADR-0034](0034-quic-consumer-seams.md) — consumer seams
