---
id: ADR-0028
title: "Own the QUIC Transport Instead of Wrapping quinn"
status: accepted
date: 2026-11-09
scope: [transport/quic, protocol/rfc9000, crypto/provider, recovery/congestion, workspace/topology]
superseded_by: null
---

# 0028. Own the QUIC Transport Instead of Wrapping quinn

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0016](0016-quic-and-http3-transport.md)
- Related: [ADR-0027](0027-owned-h3-qpack.md)

---

## Context and Problem Statement

ADR-0016 admitted `quinn` and `quinn-proto` as the approved QUIC runtime.
ADR-0027 then removed the H3/QPACK fork and left QUIC as the last third-party
protocol engine in the production graph. `netune-quic` currently owns the policy
boundary — socket configuration, egress confinement, profiles, trace and
congestion selection — but the packet state machine, loss recovery, stream
state and TLS handshake integration still live in `quinn`.

That boundary is sufficient while `quinn` exposes the control points netune
needs, but it is not the owned stack ADR-0001 describes. The remaining
third-party engine also owns the packet parser, the ACK/loss machinery and the
flow-control state, which are exactly the places where a trace-derived stack
must be able to explain its decisions.

This decision does not treat TLS or cryptography as part of the rewrite.
`rustls` already exposes a QUIC handshake API and derives Initial, Handshake and
1-RTT packet keys; `aws-lc-rs` remains the only crypto provider. The owned work
is the QUIC protocol engine around those keys.

## Decision Drivers

- The production graph must not contain a third-party QUIC state machine
  (`[INV-QUIC-05]`).
- The transport must emit trace events at packet, ACK, loss, stream and
  flow-control boundaries, and timings must remain pure derivations
  (`[INV-TRACE-01]`).
- Packet validation must happen before any connection or stream state changes
  (`[INV-QUIC-07]`).
- The migration must not regress the existing H3 client/ingress paths, so
  `quinn` remains a differential oracle until parity is proven.
- TLS 1.3 and AEAD/header protection stay in `rustls`/`aws-lc-rs`; rewriting
  them would add security risk without improving wire control.

## Considered Options

- Option 1: Keep `quinn` as the QUIC runtime indefinitely.
- Option 2: Own the QUIC engine in `netune-quic`, with `rustls` for TLS and
  `aws-lc-rs` for cryptography; migrate behind an `owned-quic` feature and make
  it the only production path once the parity gates pass.
- Option 3: Vendor or fork `quinn` and patch the control points.

## Decision Outcome

Chosen option: "Option 2". `netune-quic` becomes the owner of the RFC 9000
state machine, RFC 9001 packet protection wiring, RFC 9002 recovery and
congestion logic, and RFC 9221 datagrams. `rustls` remains the TLS 1.3 engine and
`aws-lc-rs` the crypto provider; `ring` stays forbidden.

### 1. Sans-IO core, async endpoint at the edge

The owned core is a deterministic state machine over caller-provided bytes:

- `wire`: QUIC varints, packet headers, frames, transport parameters and error
  codes.
- `crypto`: Initial/Handshake/1-RTT keys from `rustls::quic`, AEAD and header
  protection application, packet-number encoding and decoding.
- `recovery`: packet-number spaces, ACK ranges, RTT estimation, loss detection,
  probe timeouts and congestion control.
- `connection`: connection IDs, handshake state, stream state, flow control,
  timers and close.
- `endpoint`: UDP I/O, datagram dispatch, connection routing and the async
  `QuicConnector` surface.

No codec opens a socket. The endpoint is the only layer that owns a UDP socket,
and it applies `SocketConfig` and `EgressConfinement` before the first packet
([`INV-SOCKET-01`], [`INV-EGRESS-01`], [`INV-QUIC-02`]).

### 2. Crypto is delegated, not reimplemented

Initial keys are derived through `rustls::quic::Keys::initial`; Handshake and
1-RTT keys arrive through `KeyChange` from `write_hs`. Header protection and
packet protection use the `rustls::quic::HeaderProtectionKey` and
`PacketKey` traits, which are backed by `aws-lc-rs`. The owned code never
implements a cipher, HKDF, or TLS transcript.

### 3. Staged migration with a hard parity gate

> Implementation status: the migration gate is complete. The owned client and
> server handshake, bidirectional streams, ACK generation and flow control run
> against `quinn` and against each other; H3 client and ingress run on the owned
> endpoint. `quinn`/`quinn-proto` are dev-only oracles and the `owned-quic`
> feature gate was removed.

The rewrite lands in reviewable layers:

1. Wire codec: varint, long/short headers, frames, transport parameters; RFC
   vectors and malformed-input tests.
2. Packet protection: Initial keys, header protection, AEAD, packet-number
   recovery; RFC 9001 Appendix A vectors.
3. Handshake and connection state: TLS CRYPTO streams, packet-number spaces,
   ACK generation, connection IDs, close.
4. Recovery and congestion: RTT, PTO, retransmission, fast loss detection and
   profile-selected NewReno/Cubic/BBR windows.
5. Streams and flow control: bidirectional/unidirectional streams, limits,
   RESET/STOP_SENDING, datagrams.
6. Endpoint and server path: UDP routing, stateless reset, Retry, server
   handshake, H3 ingress.
7. Remove `quinn`/`quinn-proto` from production; keep them as dev-only
   differential oracles. The architecture gate then rejects them in
   `[dependencies]`.

Steps 1-6 are now the production path. Step 7 removed `quinn`/`quinn-proto`
from `[dependencies]`; the architecture gate rejects them in any production
graph.

### 4. Differential tests are the acceptance criterion

`quinn`/`quinn-proto` are dev-only oracles during migration. Each owned layer is
tested against:

- RFC 9000/9001/9002 vectors, including Initial packet and key-update examples;
- malformed packets that must be dropped without state change;
- `quinn` packet/stream behaviour for the same input (dev-dependency only);
- our H3 client and `H3Server` over the owned endpoint before the production
  switch.

### Known gaps (not claimed as complete)

The owned production path covers the handshake, packet protection, streams,
ACK/RTT/PTO retransmission, fast loss detection, a bounded AIMD congestion
window, dynamic flow-control windows, RFC 9221 datagrams, Retry, stateless
reset, key update, QUIC v2 and Version Negotiation (ADR-0029). The following RFC 9000/9001 edges are not yet
implemented and must not be inferred from the production switch:

- 0-RTT and session resumption.


They are separate capabilities, not hidden behaviour.

## Invariants & Behavioral Boundaries

- **`[INV-QUIC-05]` Owned QUIC Production Path**: after the migration gate, the
  production dependency graph contains neither `quinn` nor `quinn-proto`; the
  state machine, recovery and stream logic live in `netune-quic`. *Enforced by*:
  `.github/scripts/check-architecture.py`, `Cargo.toml`, and `cargo tree
  --edges normal`.

- **`[INV-QUIC-06]` Delegated QUIC Crypto**: Initial, Handshake and 1-RTT keys,
  header protection and packet protection are derived or applied only through
  `rustls::quic` backed by `aws-lc-rs`; `ring` is absent. *Enforced by*:
  `netune-quic`'s crypto module, the workspace crypto gate, and key-vector tests.

- **`[INV-QUIC-07]` Validate Before Mutate**: a packet with an invalid version,
  connection ID, reserved bit, packet number, AEAD tag or frame encoding must be
  dropped before connection or stream state changes. *Enforced by*: the
  connection receive path and malformed-packet tests.

- **`[INV-QUIC-08]` Recovery Is Timestamp-Driven and Bounded**: RTT and PTO
  decisions are derived from monotonic send/ACK timestamps, retransmission is
  bounded by PTO backoff, and no synthetic measurement is exposed. *Enforced
  by*: `SentPacket`, `Core::handle_ack`, `Core::handle_timeout`, and
  `Connection::rtt`.

- **`[INV-QUIC-09]` Flow Control Before Buffering**: connection and stream
  receive limits are checked before bytes are retained, and credit is released
  when the consumer reads, not when a frame arrives. *Enforced by*:
  stream/connection receive APIs and flow-control tests.

## Consequences

- **Positive**:
  - The production graph can become fully owned from DNS/TCP/TLS through
    HTTP/3, with one trace model across every layer.
  - Packet validation, ACK/loss decisions and flow control become inspectable
    workspace code instead of opaque dependency behaviour.
  - `quinn` remains available as an oracle during migration, so a bug is a test
    failure rather than a silent interop regression.
- **Negative & Trade-offs**:
  - This is the largest and most security-sensitive capability in the
    repository: packet parsing, AEAD wiring, loss recovery and congestion
    control all become our maintenance burden.
  - The migration is multi-stage; keeping `quinn` during the transition is a
    deliberate, tracked dependency, not the final state.
  - TLS 1.3 and cryptography remain third-party (`rustls`, `aws-lc-rs`); "own
    QUIC" does not mean "own every primitive".
  - Conformance requires real interop peers, not only loopback tests.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep `quinn` indefinitely

- **Why considered**: it works, is maintained, and exposes the socket,
  congestion and transport-config seams netune uses.
- **Why rejected**: it keeps the packet parser, ACK/loss state and stream state
  outside the workspace, leaves a third-party protocol runtime in production,
  and makes trace claims about decisions the dependency owns.

### Option 3 (Rejected): vendor or fork `quinn`

- **Why considered**: a narrow fork would preserve quinn's implementation while
  exposing a missing control point.
- **Why rejected**: `quinn-proto` is roughly 31k lines and its packet/recovery
  surface is security-critical. A fork makes every upstream bug fix a replay and
  every diff audit a manual exercise; it is the same failure mode ADR-0027
  removed for H3, at a larger scale.

### Option 4 (Rejected): rewrite TLS and cryptography too

- **Why considered**: complete independence from third-party code.
- **Why rejected**: TLS 1.3 and AEAD are not the layer whose wire decisions
  netune needs to shape, and reimplementing them would add enormous security
  risk while `rustls`/`aws-lc-rs` already provide the required QUIC key API.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0002](0002-egress-confinement-policy.md),
  [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0021](0021-named-quic-profiles.md),
  [ADR-0027](0027-owned-h3-qpack.md)
- RFCs: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000),
  [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001),
  [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002),
  [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221)
- Tests: `crates/netune-quic/src/wire/`, `crates/netune-quic/src/crypto/`,
  `crates/netune-quic/tests/`
