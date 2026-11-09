---
id: ADR-0020
title: "Split Connection and Request Halves of Multiplexed Profiles"
status: accepted
date: 2026-11-09
scope: [protocol/http2, transport/pool, transport/customizability, trace/model]
superseded_by: null
---

# 0020. Split Connection and Request Halves of Multiplexed Profiles

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0006](0006-transport-customizability-wire-evasion.md), [ADR-0019](0019-connection-plan-and-wire-profile-registry.md)

---

## Context and Problem Statement

ADR-0019 separated connection identity from request wire profiles, but the HTTP/2 data model
still carried one `H2Fingerprint` that mixed two different lifetimes:

- **connection-fixed**: initial `SETTINGS` order/values, the connection-level
  `WINDOW_UPDATE`, the HPACK header-table size, and whether priority frames are sent. These are
  on the wire before the first request and cannot change for the life of the socket.
- **request-fixed**: pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`). This
  changes one `HEADERS` block, not the connection.

The mixed value was used as a pool key input, carried into the connection, and re-read for every
request. That made a request cosmetic look like connection identity, and it made an independent
request-profile override impossible without inventing a second type.

## Decision

### 1. Two named halves

`netune-http2` exposes:

```rust
pub struct H2ConnectionProfile {
    pub name: &'static str,
    pub settings: Vec<(u16, u32)>,
    pub initial_connection_window_update: Option<u32>,
    pub header_table_size: u32,
    pub send_priority_frames: bool,
}

pub struct H2RequestProfile {
    pub name: &'static str,
    pub pseudo_headers_order: PseudoHeaderOrder,
}
```

`H2Fingerprint` is a **pairing convenience** for presets, not the identity unit:

```rust
pub struct H2Fingerprint {
    pub connection: H2ConnectionProfile,
    pub request: H2RequestProfile,
}
```

`H2ClientConnection` stores the two halves separately. The handshake consumes the connection
half; `start_request` consumes the stored request half, and `start_request_with_profile` applies
an explicit request half for one exchange without reopening the socket.

### 2. The pool key uses only the connection half

`ConnectionIdentity.h2_profile` names the `H2ConnectionProfile` (the registry ID), never the
request profile. `H2Registry` is keyed by the connection profile ID. `H2Fingerprint` values in
`ConnectionPlan` are pairs because the common case is a paired preset; the plan does not imply
that both halves share a pool lifetime.

### 3. Registry and trace stay honest

`H2Registry::resolve` returns the pair; `Client::with_h2_profile` registers a pair under one ID.
A separate `H2RequestRegistry` resolves request profiles. `Target::with_h2_request_profile` and
`Client::with_h2_request_profile` select the request half independently; the pool key still
contains only the connection half. The trace envelope records the connection profile ID.

---

## Invariants & Behavioral Boundaries

- **`[INV-CUSTOM-12]` Multiplexed Half Separation**: an HTTP/2 connection profile contains only
  properties written before the first request; a request profile contains only properties of a
  `HEADERS` block. The pool key contains only the connection half. *Enforced by*: the two types
  in `netune-http2`, `H2ClientConnection` storing them separately, and the connection-profile
  key in `H2Registry`.

- **`[INV-CUSTOM-13]` Request Half Is Reapplicable**: changing the request profile must be
  possible without reopening the socket. *Enforced by*: `start_request` reads
  `H2RequestProfile`, not the connection profile, and `H2ClientConnection` keeps the request
  half as a separate field.

---

## Consequences

- **Positive**:
  - A request cosmetic can no longer fragment the pool.
  - A connection can apply a different pseudo-header order per exchange without a reconnect.
  - The `H2Fingerprint` preset remains ergonomic while its two halves have truthful types.
- **Negative & Trade-offs**:
  - Breaking change: `H2Fingerprint` is no longer a flat struct. Callers that read
    `fingerprint.settings` migrate to `fingerprint.connection.settings`; pseudo-header readers
    migrate to `fingerprint.request`.
  - `H2ClientConnection::fingerprint()` is replaced by `connection_profile()` and
    `request_profile()`; a caller that needs a pair reconstructs it explicitly.
  - The paired preset remains the default; an explicit request override is an additional
    selection, not a second connection identity.

## Rejected Alternatives & Negative Truths

### Option 1 (Rejected): keep one flat `H2Fingerprint`

The flat type is exactly the bug: it makes request order look like connection identity and
forces every pool consumer to carry a value whose request half is irrelevant to reuse.

### Option 2 (Rejected): put both halves in the pool key

Pseudo-header order does not change the socket. Keying on it would multiply pooled connections
for a per-message choice and defeat the point of connection-level SETTINGS.

### Option 3 (Rejected): duplicate the request order in `H2ClientConnection`

The connection must not copy the request field into the connection profile or read it from a
flat fingerprint. The separate field is what makes a future override possible without another
migration.

---

## Evidence

- `crates/netune-http2/src/fingerprint.rs`: `H2ConnectionProfile`, `H2RequestProfile`,
  `H2Fingerprint`.
- `crates/netune-http2/src/client.rs`: handshake consumes the connection half; `start_request`
  reads the request half; `connection_profile()` / `request_profile()` accessors.
- `crates/netune/src/profile.rs`: `H2Registry` keyed by the connection profile name;
  `H2RequestRegistry` keyed by the request profile name.
- `crates/netune/src/client.rs`: `Client::with_h2_request_profile`,
  `Target::with_h2_request_profile`, and `H2ClientConnection::start_request_with_profile`.
- Tests: H2 fingerprint/ordering tests, HTTP/2 integration tests, the connection-level L0
  trace test, and request-profile pool-key invariance.

---

## Links

- Related ADRs: [ADR-0006](0006-transport-customizability-wire-evasion.md),
  [ADR-0019](0019-connection-plan-and-wire-profile-registry.md),
  [ADR-0017](0017-tiered-observation-and-connection-identity.md)
