---
id: ADR-0021
title: "Named QUIC Profiles Resolve Through a Registry"
status: accepted
date: 2026-11-09
scope: [transport/quic, transport/customizability, trace/model]
superseded_by: null
---

# 0021. Named QUIC Profiles Resolve Through a Registry

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0016](0016-quic-and-http3-transport.md), [ADR-0019](0019-connection-plan-and-wire-profile-registry.md)

---

## Context and Problem Statement

QUIC already had `QuicProfile` as a pure-data identity, but name selection was a hard-coded
`QuicProfile::by_name` match. That left the same failure mode ADR-0019 removed from H1/H2:

- a caller could not add a profile without editing `netune-quic`;
- an unknown name returned `None` at one call site and had no single registry record;
- there was no resolved profile name to put in a trace envelope or connection identity.

HTTP/3 is a consumer of an established QUIC connection, not a second handshake owner. Its
identity is therefore the QUIC profile plus the H3 request metadata; it must not grow a parallel
profile lookup.

## Decision

### 1. One registry for built-ins and caller profiles

`netune-quic` exposes `QuicProfileRegistry`:

```rust
let registry = QuicProfileRegistry::default()
    .with_profile(my_profile);
let connector = QuicConnector::from_registry(&registry, "my-quic")?;
```

Built-ins (`quic-default`, `chrome-quic`, `cloud-optimized`) and caller profiles travel through
the same `resolve(&str)` path. An unknown name is `QuicError::Config`, never a silent default.

### 2. The connector carries the resolved profile name

`QuicConnector::profile_name()` returns the name of the profile it will actually apply. A caller
that builds a `ConnectionIdentity` records that name in `h3_profile`; a trace envelope can then
name the QUIC identity without reaching into the connector.

### 3. H3 consumes a QUIC identity; it does not select one

`H3Client` continues to wrap an established `netune_quic::Connection`. There is no
`H3ProfileRegistry` because HTTP/3 has no independent handshake identity: its transport identity
is the QUIC profile. H3 request-header profiles are a future request-level capability, analogous
to `H2RequestProfile`, and must not be added to the connection key.

## Invariants & Behavioral Boundaries

- **`[INV-CUSTOM-14]` One QUIC Registry Path**: built-in and caller-supplied QUIC profiles resolve
  through `QuicProfileRegistry`; no hard-coded name match remains. *Enforced by*:
  `QuicProfileRegistry::resolve`, `QuicConnector::from_registry`, and the unknown-name test.

- **`[INV-CUSTOM-15]` Resolved QUIC Name Is Visible**: a connector exposes the resolved profile
  name for identity/trace construction. *Enforced by*: `QuicConnector::profile_name`.

---

## Consequences

- **Positive**:
  - A caller can add a QUIC profile without patching the crate.
  - Unknown names fail before endpoint/socket creation.
  - H3 does not grow a second handshake-identity registry.
- **Negative & Trade-offs**:
  - Breaking change: `QuicProfile::by_name` now delegates to the registry; callers that need a
    custom profile use `QuicProfileRegistry`.
  - H3 request-header profiles are still not modeled; that remains a request-level extension,
    not a connection identity.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep the hard-coded `by_name` match

It makes custom profiles second-class and produces `None` instead of a diagnostic listing the
registered names.

### Option 2 (Rejected): an `H3ProfileRegistry` that selects QUIC parameters

HTTP/3 does not perform a second handshake. Duplicating QUIC transport parameters under an H3
name would create two sources of truth for one identity.

---

## Evidence

- `crates/netune-quic/src/profile.rs`: `QuicProfileRegistry`, built-ins, unknown-name test.
- `crates/netune-quic/src/connector.rs`: `QuicConnector::from_registry`, `profile_name`.
- `crates/netune-quic/tests/quic_e2e.rs`: establish/inspect a connection through the registry.

---

## Links

- Related ADRs: [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0019](0019-connection-plan-and-wire-profile-registry.md),
  [ADR-0006](0006-transport-customizability-wire-evasion.md)
