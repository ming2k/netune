---
id: ADR-0026
title: "Controlled Dynamic QPACK and Typed H3 SETTINGS"
status: accepted
date: 2026-11-09
scope: [protocol/http3, transport/quic, trace/model, workspace/topology]
superseded_by: null
---

# 0026. Controlled Dynamic QPACK and Typed H3 SETTINGS

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0022](0022-http3-connection-identity.md),
  [ADR-0023](0023-h3-request-header-order.md)

---

## Context and Problem Statement

Before this change the controlled `h3` fork opened the QPACK encoder and decoder
streams, but every header block used `qpack::encode_stateless` /
`qpack::decode_stateless`. `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and
`SETTINGS_QPACK_BLOCKED_STREAMS` were parsed but ignored. That was safe, but it
made two claims impossible:

- a caller could not select a QPACK capacity, and
- dynamic-table behaviour could not be part of a connection identity.

The upstream `h3` crate contains a `qpack::Encoder` and `qpack::Decoder`, but
they were not wired to the critical streams, request streams or response streams.
The choice was therefore either to build a parallel QPACK implementation or to
finish the upstream state machine in the controlled fork.

## Decision Drivers

- The H3 request/response path must be able to use dynamic QPACK without
  rebuilding QUIC or the H3 connection machine.
- A peer that blocks on a missing insertion must wait on an event, not spin.
- A decoder must acknowledge header sections so the peer's encoder can untrack
  them and make progress.
- QPACK capacities and blocked-stream budgets are connection-level, so they
  belong in the SETTINGS profile and the trace identity.
- A capacity that the decoder cannot enforce must not be exposed.

## Decision

### 1. Finish the dynamic path in the fork, do not duplicate it

`vendor/h3` now wires its existing `qpack::Encoder` and `qpack::Decoder` into
the connection:

- request and response heads are encoded with `Encoder::encode_with_size`, which
  preserves `RequestHeaderOrder` and returns the header-section memory size;
- decoder instructions from the peer are drained on the QPACK decoder stream and
  applied to the encoder's blocked-stream bookkeeping;
- encoder instructions from the peer are applied to the shared decoder table;
  `InsertCountIncrement` is written back on our decoder stream;
- a decoded header section is acknowledged with `HeaderAck(stream_id)`;
- a stream that references a not-yet-inserted field waits on a `Notify` until
  the driver records the insertion, then retries against a fresh cursor.

The fork still does not own QUIC, the H3 frame loop or response semantics. The
patch remains a QPACK/SETTINGS integration inside the approved H3 state machine.

### 2. SETTINGS is a typed profile

`H3SettingsProfile` carries:

```text
max_field_section_size
enable_datagram
enable_extended_connect
send_grease
qpack_max_table_capacity
qpack_blocked_streams
```

`H3SettingsRegistry` resolves built-in and caller profiles by name. The client
and server builders consume the same fields, so the value an operator sets is
the value sent in SETTINGS. Out-of-range capacities are refused at bind/connect
time rather than failing later in the handshake.

`ConnectionIdentity.h3_settings_profile` records the profile name alongside the
resolved QUIC profile. The profile is connection-fixed; there is no
per-request SETTINGS change.

`H3SettingsProfile::default()` uses zero QPACK capacity: the stateless path
remains the default, and dynamic table use is opt-in. `H3SettingsProfile::dynamic()`
uses 4096 bytes and 16 blocked streams.

### 3. Header order is still applied before QPACK

The dynamic encoder consumes the already-ordered `Header` iterator. Header order
therefore remains a pre-QPACK request property and is not entangled with table
state.

### 4. Trailers use the same dynamic path

Request and response trailer blocks are encoded with the same dynamic encoder
and decoded through the asynchronous `recv_trailers_dynamic` path. A trailer
block therefore carries the same table state and acknowledgement rules as an
initial header block; there is no second QPACK implementation for trailers.

## Invariants & Behavioral Boundaries

- **`[INV-H3-03]` SETTINGS Is Enforceable and Typed**: a QPACK capacity or
  blocked-stream budget that reaches SETTINGS must be backed by the decoder and
  encoder in the same connection; out-of-range values fail before the listener
  or endpoint is usable. *Enforced by*: `H3SettingsProfile`, builder validation,
  `H3Server::bind`, and the `qpack` fork constructor.

- **`[INV-H3-04]` Dynamic Sections Are Acknowledged**: every successfully
  decoded request/response header or trailer block sends `HeaderAck(stream_id)`; a missing insertion waits
  for a recorded insertion notification rather than returning a false decode
  error or spinning. *Enforced by*: `SharedState::decode_headers`,
  `poll_qpack`, and the repeated-request loopback suite.

- **`[INV-H3-05]` Header Order Is Independent of Table State**: enabling dynamic
  QPACK must not change the ordered input to the encoder. *Enforced by*: the
  same `RequestHeaderOrder` path is used by `encode_with_size`.

## Consequences

- **Positive**:
  - QPACK capacity and blocked-stream count become real, typed connection
    settings instead of ignored wire bytes.
  - H3 can interoperate with peers that use dynamic QPACK for request and
    response heads.
  - The fork's QPACK state is driven by the connection, not by a separate
    mutex-heavy side task.
  - The default remains stateless, so a caller that does not opt in pays no
    dynamic-table complexity on the wire.
- **Negative & Trade-offs**:
  - The fork's behavioural diff is larger: QPACK critical-stream driving is now
    ours to audit on each `h3` upgrade.
  - A peer that advertises zero capacity still gets correct stateless blocks;
    an operator cannot claim browser-like dynamic behaviour by naming a profile
    without enabling the corresponding fields.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep stateless-only and document the gap

That leaves SETTINGS bytes parsed but ignored: a caller cannot distinguish a
profile that is enforced from one that is decorative. It also makes the dynamic
QPACK code in the dependency dead weight.

### Option 2 (Rejected): write a second QPACK implementation in `netune-http3`

Two implementations of a security-sensitive state machine with blocked streams
and table eviction is exactly the drift the owned-codec rule avoids. The
approved H3 runtime already has the tables; the missing piece was connection
wiring.

### Option 3 (Rejected): expose only `max_field_section_size`

It avoids the hard part, but then a QPACK-capacity profile name would be a
label. The typed SETTINGS profile exists to prevent that.

## Links

- Related ADRs: [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0022](0022-http3-connection-identity.md),
  [ADR-0023](0023-h3-request-header-order.md),
  [ADR-0024](0024-h3-streaming-request-bodies.md),
  [ADR-0025](0025-h3-ingress-peer-transport.md)
