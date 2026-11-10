---
id: ADR-0036
title: "DPLPMTUD Is a Bounded Probe State Machine, Not a Fixed MTU"
status: accepted
date: 2026-11-10
scope: [transport/quic, protocol/rfc9000, recovery/path-mtu, observability]
superseded_by: null
---

# 0036. DPLPMTUD Is a Bounded Probe State Machine, Not a Fixed MTU

- Status: Accepted
- Date: 2026-11-10
- Deciders: Ming Li
- Related: [ADR-0028](0028-owned-quic.md),
  [ADR-0029](0029-quic-lifecycle-hardening.md),
  [ADR-0034](0034-quic-consumer-seams.md)

---

## Context and Problem Statement

The owned engine currently caps every datagram at 1200 bytes. That is safe and
correct on every path, but it leaves substantial throughput on 1280–1500 byte
paths. Raising the fixed value would be wrong: a path can be smaller than the
peer's `max_udp_payload_size`, and a datagram that is too large is either
fragmented (a middlebox hazard) or dropped.

DPLPMTUD (RFC 8899) is the only honest way to use a larger path MTU. It is not a
configuration flag: it is a probe state machine with ACK/loss feedback, a search
strategy and a black-hole response.

## Decision Drivers

- Never send an application packet larger than a validated path MTU.
- Never lose or duplicate application data while probing.
- Keep the public `QuicProfile` data-only; probe state is per connection.
- Bound probe frequency and memory; a hostile path must not create an unbounded
  retry loop.
- Make the state observable without adding a wall-clock measurement.

## Decision

Implement a bounded DPLPMTUD subset in `Core`:

1. Start at the 1200-byte QUIC minimum. The peer's `max_udp_payload_size` and a
   conservative local ceiling bound the search.
2. Probe with a PING plus PADDING at a candidate size, tracked by packet number.
   A probe is never an application frame.
3. On ACK of the probe, raise the validated MTU to that size. On loss or PTO,
   do not raise it; fall back to the last validated size.
4. Probe candidates grow monotonically to a ceiling (initially 1500), with one
   probe in flight and a fixed timer. A black-hole event stops probing until the
   next connection.
5. Initial and Handshake packets remain padded to 1200 regardless of the
   validated path MTU.
6. Expose the validated value as a reading, not a guessed number; a missing ACK
   is `None`, not zero.

The exact search constants belong in one named module and are tested before the
feature is enabled by default.

### Invariants & Behavioral Boundaries

- **`[INV-QUIC-24]` Probe-Only Path MTU Growth**: the validated path MTU is
  raised only when an ACK acknowledges a probe packet; a probe carries no
  application frame, never exceeds the local/peer ceiling, and a lost or
  black-holed probe leaves the validated MTU unchanged. *Enforced by*:
  `dplpmtud_validates_a_larger_loopback_path`,
  `dplpmtud_never_exceeds_the_advertised_ceiling` and
  `dplpmtud_does_not_validate_a_black_holed_size`.

## Acceptance Criteria

- A probe larger than the peer's advertised maximum is never sent.
- Application data is never placed in a probe packet.
- Loss/black-hole tests show no application-frame loss and no MTU increase.
- A 1500-byte loopback path validates 1500 bytes; a 1280-byte restricted path
  never sends 1500.
- The packet-size budget tests from ADR-0034 continue to pass.

## Rejected Alternatives

### Raise the fixed 1200-byte cap

- **Why considered**: one constant.
- **Why rejected**: it assumes a path property no protocol endpoint can assume;
  it invites fragmentation and silent drops.

### Trust the peer's `max_udp_payload_size`

- **Why considered**: no state machine.
- **Why rejected**: the peer advertises what it can receive, not what the path
  can carry. The two are independent.

## Links

- [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899)
- [ADR-0028](0028-owned-quic.md)
