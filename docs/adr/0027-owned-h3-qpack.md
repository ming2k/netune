---
id: ADR-0027
title: "Own HTTP/3 and QPACK Instead of Vendoring a Fork"
status: accepted
date: 2026-11-09
scope: [protocol/http3, protocol/qpack, workspace/topology, trace/model]
superseded_by: null
---

# 0027. Own HTTP/3 and QPACK Instead of Vendoring a Fork

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Supersedes: [ADR-0023](0023-h3-request-header-order.md), [ADR-0026](0026-controlled-dynamic-qpack.md)
- Amends: [ADR-0016](0016-quic-and-http3-transport.md)

---

## Context and Problem Statement

ADR-0023 admitted `h3` 0.0.8 as a controlled fork because the request-header
order control point lived inside a private API. ADR-0026 extended that fork to
drive dynamic QPACK and typed SETTINGS. Both decisions solved the immediate
problem, but they made the workspace depend on a pre-1.0 third-party H3 state
machine whose upgrade path is "copy upstream, replay the diff".

The fork now owns the exact surfaces netune exists to control: request-field
order before QPACK, dynamic table state, SETTINGS, critical streams, and error
codes. Keeping those behaviours outside the workspace means every future H3
change is negotiated with an upstream release and audited through a patch note.
The alternative is to own the HTTP/3 state machine and QPACK codec in
`netune-http3`.

QUIC remains a different decision. `netune-quic` already controls the policy
boundary (profile, socket, confinement, trace, congestion factory) through
`quinn`'s public extension points. H3 is the layer where the required control
point was actually blocked, so it is the layer to own first.

## Decision Drivers

- The H3 request-order and QPACK control points must be ordinary workspace code,
  not a fork whose diff has to be replayed on every upstream release.
- A production graph must not contain a third-party H3 or QPACK runtime
  (`[INV-H3-06]`).
- The public `netune-http3` surfaces (`H3Client`, `H3ServerConnection`,
  streaming request bodies, trailers, profiles, per-exchange trace) must keep
  their shape.
- QPACK dynamic state is security-sensitive: capacity, blocked streams,
  acknowledgements, eviction, and invalid references need one owned
  implementation with explicit bounds.
- H3 must still interoperate with an independent implementation; using `h3` as
  a **dev-dependency oracle** is allowed because it never ships.

## Considered Options

- Option 1: Keep the controlled fork and vendor layout.
- Option 2: Own HTTP/3 and QPACK in `netune-http3`, keep `quinn` as the QUIC
  runtime, and delete `vendor/h3` and `vendor/h3-quinn`.
- Option 3: Own HTTP/3, QPACK, and QUIC in the same change.

## Decision Outcome

Chosen option: "Option 2". `netune-http3` owns the RFC 9114 state machine and
the RFC 9204 QPACK codec. `netune-quic` continues to wrap `quinn` under
ADR-0016; rewriting QUIC is a separate capability with its own ADR, conformance
program, and interop budget.

### 1. One H3 state machine, two roles

`netune-http3` implements the connection machine once:

- one control stream per endpoint, with SETTINGS as its first frame;
- one QPACK encoder stream and one QPACK decoder stream, created at most once;
- client-initiated request streams carry `HEADERS`, optional `DATA`, and optional
  trailer `HEADERS`;
- server-initiated push and WebTransport are not advertised;
- GOAWAY, CANCEL_PUSH, and critical-stream closure are connection-scoped.

The client and server modules are thin role adapters over the same connection
and stream state. A codec may understand both roles; an orchestrator still
exposes only its own direction (ADR-0011).

### 2. QPACK is owned, bounded, and connection-scoped

`crates/netune-http3/src/qpack/` implements:

- the RFC 9204 static table and the RFC 7541 Huffman code;
- prefixed integers and string literals;
- the dynamic table, absolute/relative/post-Base indexing, eviction, and
  duplicate insertion;
- encoder and decoder instructions on the critical streams;
- Required Insert Count and Base handling;
- Section Acknowledgement, Stream Cancellation, and Insert Count Increment.

The encoder references an unacknowledged dynamic entry only when the peer's
`SETTINGS_QPACK_BLOCKED_STREAMS` budget permits it. The decoder waits for a
missing insertion on a `watch` generation rather than spinning or failing
immediately, and it enforces the advertised table capacity and blocked-stream
budget. A reference to an evicted entry, an out-of-range static index, or an
instruction that exceeds the capacity is a connection error.

One deliberate interoperability allowance is recorded here: `h3` 0.0.8 omits
the `Set Dynamic Table Capacity` instruction and treats the advertised maximum
as the initial capacity. The owned decoder accepts that shape by enabling the
advertised maximum on the first insertion. It still cannot exceed the capacity
it advertised, so the memory bound and `[INV-H3-08]` hold.

### 3. SETTINGS stays typed and enforceable

`H3SettingsProfile` keeps `max_field_section_size`, `send_grease`,
`qpack_max_table_capacity`, and `qpack_blocked_streams`. SETTINGS that describe
a capability with no public transport surface are not advertised: HTTP/3
datagrams and extended CONNECT remain out of scope until their send/receive
API exists. A profile is still validated before a listener or connection is
usable.

The resolved QUIC profile remains the connection identity and
`ConnectionIdentity.h3_settings_profile` records this SETTINGS profile
(ADR-0022).

### 4. h3 is an oracle, not a runtime

`h3` and `h3-quinn` remain available only as `dev-dependencies` for
differential and interop tests. They are not in any `[dependencies]` section,
they are not vendored, and a default build of `netune-http3` links neither.

## Invariants & Behavioral Boundaries

- **`[INV-CUSTOM-18]` H3 Request Order Is Enforced**: an `H3RequestProfile`
  must change the QPACK header-block field order before bytes are written. A
  profile that is not consumed by the encoder is forbidden. *Enforced by*:
  `RequestHeaderOrder` in `proto/headers.rs` and `H3Client::open_request`
  passing the ordered fields to the owned QPACK encoder.

- **`[INV-CUSTOM-19]` H3 Order Is Request-Scoped**: changing an H3 request
  profile must not change the QUIC connection identity or open a new socket.
  *Enforced by*: the H3 profile is stored on the session/request, while the
  QUIC profile remains the connection identity. `[INV-CUSTOM-20]` (fork
  narrowness) is retired and not reused.

- **`[INV-H3-03]` SETTINGS Is Enforceable and Typed**: a QPACK capacity or
  blocked-stream budget that reaches SETTINGS must be backed by the decoder and
  encoder in the same connection; out-of-range values fail before the listener
  or endpoint is usable. *Enforced by*: `H3SettingsProfile::validate`,
  `H3ServerConnection::new`, `H3Client::new_with_settings_and_config`, and
  `qpack::Decoder::set_capacity`.

- **`[INV-H3-04]` Dynamic Sections Are Acknowledged**: every successfully
  decoded request/response header or trailer block that references the dynamic
  table sends a Section Acknowledgement; a missing insertion waits for a
  recorded insertion notification rather than returning a false decode error
  or spinning. *Enforced by*: `QpackDecoder::decode_section`, the `watch`
  generation in `SharedConnection`, and the repeated-request loopback suite.

- **`[INV-H3-05]` Header Order Is Independent of Table State**: enabling
  dynamic QPACK must not change the ordered input to the encoder. *Enforced
  by*: the owned `RequestHeaderOrder` is applied before QPACK field lines are
  generated.

- **`[INV-H3-06]` No Third-Party H3 or QPACK Runtime Ships**: the production
  dependency graph of `netune-http3` contains neither `h3` nor `h3-quinn`, and
  no `vendor/` tree supplies them. *Enforced by*: `Cargo.toml`,
  `.github/scripts/check-architecture.py`, and `cargo tree --edges normal`.

- **`[INV-H3-07]` Critical Stream Integrity**: the control, QPACK encoder and
  QPACK decoder streams are created at most once, are never closed by the
  sender, and closure by either peer closes the connection with
  `H3_CLOSED_CRITICAL_STREAM`. *Enforced by*: `ConnectionDriver` stream
  dispatch and the critical-stream tests.

- **`[INV-H3-08]` QPACK References Are Bounded**: a decoder rejects an invalid
  static index, an evicted dynamic entry, a Required Insert Count larger than
  the received insert count, or more blocked streams than advertised. *Enforced
  by*: `QpackDecoder::decode_section` and its unit vectors.

## Consequences

- **Positive**:
  - The request-order, QPACK, SETTINGS, and trace surfaces are ordinary
    workspace code with no fork to replay.
  - `vendor/h3` and `vendor/h3-quinn` disappear; downstream consumers resolve
    one `netune-http3` package with no path patch.
  - Dynamic QPACK behaviour is testable at the table and connection level.
  - `h3` remains a dev-only oracle, so interop can still catch a wrong
    implementation.
- **Negative & Trade-offs**:
  - `netune-http3` now owns a security-sensitive protocol state machine and
    must track RFC 9114/9204 errata.
  - Push, WebTransport, HTTP/3 datagrams, and extended CONNECT are explicitly
    out of scope; their SETTINGS are not advertised.
  - A bug in the owned QPACK table can break every request on a connection;
    the decoder's bounds and the interop suite are load-bearing.
  - QUIC is still third-party; "no vendor" does not mean "no dependency".

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep the controlled fork

- **Why considered**: it already passes the tests and preserves upstream H3
  behaviour.
- **Why rejected**: it keeps the control points outside the workspace, requires
  a diff replay for every upstream release, and leaves a pre-1.0 third-party
  runtime in the production graph. ADR-0023's own exit plan says to delete the
  fork when native hooks are unnecessary; owning the code is the stronger form
  of that exit.

### Option 3 (Rejected for this change): rewrite QUIC at the same time

- **Why considered**: if the goal is full stack ownership, QUIC is the next
  layer down.
- **Why rejected**: `quinn` is roughly twice the size of the H3/QPACK surface,
  is the foundation under every HTTP/3 exchange, and already exposes the
  extension points `netune-quic` uses. Rewriting both layers in one change
  would delay the H3 control surface and replace a working QUIC engine before
  a concrete QUIC control point is blocked. It remains a separate future
  decision.

### Option 4 (Rejected): keep `h3` as a production dependency and wrap it more tightly

- **Why considered**: smaller diff and immediate interop.
- **Why rejected**: it cannot remove the fork or satisfy `[INV-H3-06]`, and a
  wrapper cannot control QPACK state that lives in the dependency.

## Links

- Related ADRs: [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0022](0022-http3-connection-identity.md),
  [ADR-0024](0024-h3-streaming-request-bodies.md),
  [ADR-0025](0025-h3-ingress-peer-transport.md)
- Superseded: [ADR-0023](0023-h3-request-header-order.md),
  [ADR-0026](0026-controlled-dynamic-qpack.md)
- Amended by: [ADR-0028](0028-owned-quic.md) — QUIC is now owned by
  `netune-quic`; the H3/QPACK decision is unchanged.
- Amended by: [ADR-0030](0030-h3-datagrams-and-extended-connect.md) — RFC 9297
  datagrams and RFC 9220 extended CONNECT are now owned extension surfaces.
- RFCs: [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114),
  [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204),
  [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)
- Tests: `crates/netune-http3/tests/`, `crates/netune-server/tests/http3_ingress.rs`
