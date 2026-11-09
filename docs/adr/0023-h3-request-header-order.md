---
id: ADR-0023
title: "Own H3 Request Header Order Through a Controlled h3 Fork"
status: accepted
date: 2026-11-09
scope: [protocol/http3, transport/customizability, trace/model]
superseded_by: null
---

# 0023. Own H3 Request Header Order Through a Controlled h3 Fork

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0016](0016-quic-and-http3-transport.md), [ADR-0022](0022-http3-connection-identity.md)
- Amended by: [ADR-0026](0026-controlled-dynamic-qpack.md) — the fork now also drives dynamic QPACK and typed SETTINGS; the request-order decision stands.

---

## Context and Problem Statement

ADR-0022 correctly refused to add an `H3RequestProfile` while the `h3` runtime owned
pseudo-header order and exposed no ordering hook. But "not currently controllable" is not a
stable architecture: H3 request header/pseudo-header order is observable identity, and leaving it
uncontrollable makes H3 the only protocol in the stack that cannot present a selected order.

The control point is precise: `h3` builds a `Header` from `http::Request`, and its `HeaderIter`
emits pseudo-headers in a hard-coded order (`:method`, `:scheme`, `:authority`, `:path`), then
whatever order `HeaderMap` happens to yield. To control the wire order we must own that
pre-QPACK ordering step.

Rewriting H3/QPACK from scratch is a separate, much larger project. A controlled fork of the
approved `h3` runtime is the minimum change that makes the order real: we own the header-order
surface, not a parallel H3 state machine.

## Decision

### 1. Vendor `h3` 0.0.8 as a controlled fork

`vendor/h3` is the approved H3 state machine, pinned to the version already in the dependency
graph. The only behavioural diff is an explicit request-header order API. The fork is linked
through `[patch.crates-io]`, so `h3-quinn`, `netune-http3` and any other consumer resolve the
same `h3` implementation.

The fork carries its upstream license and a patch note. It is not a second H3 implementation
and it does not duplicate QUIC or QPACK state.

### 2. `RequestHeaderOrder` is explicit data

The fork exposes:

```rust
pub struct RequestHeaderOrder {
    pub pseudo: Vec<&'static str>,   // ":method", ":authority", ...
    pub regular: Vec<&'static str>,  // lower-case names
}
```

`Header::into_iter` emits the listed pseudo-headers in the requested order, then regular headers
in the requested order, with unlisted headers stable-appended. Duplicate regular fields keep
their relative order. The default order is the historical h3 order, so a caller that does not
select a profile gets the existing bytes.

`SendRequest::send_request_with_order(request, &order)` is the explicit entry point;
`send_request` delegates with the default order.

### 3. H3 profiles are request-level, not connection identity

`netune-http3` adds `H3RequestProfile` and `H3RequestRegistry`:

```rust
pub struct H3RequestProfile {
    pub name: ProfileId,
    pub order: RequestHeaderOrder,
}
```

`H3Client::with_request_profile(profile)` selects the order for subsequent exchanges on the
same QUIC connection. The resolved QUIC profile remains the connection identity
(`ConnectionIdentity.h3_profile`); the H3 request profile is per request and must not key the
pool.

### 4. The fork stays narrow

The patch changes only:

- `proto/headers.rs`: request-header order data and `HeaderIter` emission.
- `client/connection.rs`: `send_request_with_order`.
- `lib.rs`: re-export the order type.

No change to QUIC ownership, QPACK coding, SETTINGS, control streams, response decoding or errors.

## Invariants & Behavioral Boundaries

- **`[INV-CUSTOM-18]` H3 Request Order Is Enforced**: an `H3RequestProfile` must change the
  QPACK header-block field order before bytes are written. A profile that is not consumed by the
  encoder is forbidden. *Enforced by*: `RequestHeaderOrder` in the fork and
  `H3Client::send` passing it to `send_request_with_order`.

- **`[INV-CUSTOM-19]` H3 Order Is Request-Scoped**: changing an H3 request profile must not
  change the QUIC connection identity or open a new socket. *Enforced by*: H3 profile stored on
  the session/request, QUIC profile stored separately.

- **`[INV-CUSTOM-20]` Fork Narrowness**: the vendored h3 fork differs from upstream only in the
  documented header-order surface. *Enforced by*: a diff audit in `vendor/h3/PATCHES.md` and the
  workspace CI check.

---

## Consequences

- **Positive**:
  - H3 can present a selected pseudo-header and regular-header order.
  - The order is real at the QPACK input boundary, not a label.
  - H2 and H3 now have equivalent request-order control while keeping connection identity
    separate.
- **Negative & Trade-offs**:
  - The workspace owns a small fork of `h3` 0.0.8; upgrades require replaying the narrow patch.
  - Regular-header order is still limited to fields supplied to the request; unknown fields are
    stable-appended.
  - The fork is not a full owned H3 implementation; dynamic-table encoding is wired inside the controlled h3 fork by ADR-0026.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep `H3RequestProfile` as metadata on `H3Client`

That is the exact unenforceable label ADR-0022 rejected. It would let a caller claim an order
that never reaches the wire.

### Option 2 (Rejected): rewrite H3/QPACK from scratch now

That is a separate multi-week protocol project. It would duplicate a working state machine
before the request-order control point is even exercised.

### Option 3 (Rejected): patch upstream by feature flag only

`h3` does not expose a header-order hook through its public API, and its QPACK/request framing
types are private. A local controlled fork is the minimum enforceable change.

---

## Evidence

- `vendor/h3/PATCHES.md`: the narrow diff and upgrade procedure.
- `vendor/h3/src/proto/headers.rs`: `RequestHeaderOrder` and ordered emission.
- `vendor/h3/src/client/connection.rs`: `send_request_with_order`.
- `crates/netune-http3/src/profile.rs`: `H3RequestProfile`, `H3RequestRegistry`.
- `crates/netune-http3/src/client.rs`: profile selection and `send_request_with_order`.
- Tests: ordered header-block unit tests in the fork and H3 client profile tests.

---

## Links

- Related ADRs: [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0022](0022-http3-connection-identity.md),
  [ADR-0019](0019-connection-plan-and-wire-profile-registry.md)
