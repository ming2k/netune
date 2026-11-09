---
id: ADR-0019
title: "Connection Plan and Wire-Profile Registry"
status: accepted
date: 2026-11-09
scope: [transport/pool, transport/customizability, protocol/http1, protocol/http2, trace/model]
superseded_by: null
---

# 0019. Connection Plan and Wire-Profile Registry

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md), [ADR-0006](0006-transport-customizability-wire-evasion.md), [ADR-0017](0017-tiered-observation-and-connection-identity.md), [ADR-0018](0018-one-trace-collector-per-attempt.md)

---

## Context and Problem Statement

ADR-0017 made connection identity a typed value in the pool key. That fixed the worst
omissions, but profile selection was still partly implicit:

- `Target` was a mutable bag of fields (`tls_profile`, `evasion`, `force_h2`) rather than a
  resolved plan.
- The HTTP/2 profile was selected by a hard-coded `match` on the TLS profile name inside
  `Client`; there was no registry and no way to add a profile without editing the crate.
- HTTP/1 header order and casing had no profile at all, even though `RequestHead::raw_headers`
  exists precisely to control them.
- Connection-fixed axes and request-only axes were not separated in the type system. H1 header
  order is per request; H2 SETTINGS is per connection; H2 pseudo-header order is per request.
  Putting them all in a pool key would fragment the pool for no reason; leaving them all out
  silently drops customization.

The result was a familiar failure mode: a caller could name a profile that did not exist and
only discover it after a socket was opened, or could set a wire decision that no pool key and
no trace envelope mentioned.

## Decision Drivers

- Every profile name must resolve before a socket is opened; an unknown name is a loud failure.
- The pool key must contain exactly the connection-fixed identity, no more and no less.
- Request-only wire decisions must still be nameable, hashable and visible in the trace envelope.
- Built-in and caller-supplied profiles must go through the same resolution path.
- No hard-coded `match` on a TLS profile name may decide an HTTP/2 identity.

## Decision

### 1. `ConnectionPlan` is the only path from `Target` to a request

`Client::plan(&Target)` resolves:

- the full `ConnectionIdentity` (socket shape, route, TLS profile/name, evasion, H2 profile);
- the `H1WireProfile` for HTTP/1 requests;
- the `H2Fingerprint` when HTTP/2 is selected.

It runs **before** a pool lookup or connector call. `Client::pool_key` is a thin fallible
convenience over the same plan. A redirect re-plans the next target; it does not reuse a plan
whose authority or scheme has changed.

### 2. Connection identity and request wire profiles are separate types

`ConnectionIdentity` contains only properties fixed at connection establishment. The pool key
is `(authority, identity)`.

`H1WireProfile` and `H2Fingerprint` request-level parts are not in the pool key:

- HTTP/1 header order and casing are applied per request;
- HTTP/2 pseudo-header order is applied per request;
- HTTP/2 SETTINGS and the connection window remain connection identity.

A custom H1 profile can never cause a socket to be pooled or evicted differently; a custom H2
SETTINGS profile does participate in the identity because it is fixed at handshake.

### 3. Profiles are resolved through registries

`ProfileId` is a stable name. `H1Registry` and `H2Registry` expose the same `resolve(&ProfileId)`
contract for built-ins and caller-supplied profiles:

```rust
let client = Client::new(connector, pool, config)
    .with_h1_profile(H1WireProfile::new(
        "my-browser",
        HeaderCasing::TitleCase,
        ["host", "user-agent", "accept"],
    ))
    .with_h2_profile("my-chrome", H2Fingerprint::chrome());
```

`Target::with_h1_profile` / `Target::with_h2_profile` select a name. Unknown names return
`NetError::Connect` from `Client::plan`; there is no fallback to a default. Defaults exist only
when the caller did not select a name: H1 uses `netune`, H2 uses the TLS-paired built-in.

### 4. H1 profiles are applied at the last responsible moment

`H1WireProfile::apply` converts `RequestHead::headers` into ordered `raw_headers` with the
profile's casing, after the client has materialized `Host`, `User-Agent` and `Content-Length`.
An existing `raw_headers` value is left untouched: explicit caller bytes are the final word.

### 5. The trace envelope records the resolved connection identity

`RequestTrace::identity` is built from `ConnectionPlan::identity`, including the resolved H2
profile ID and socket/route shape. A request-only H1 profile is not a connection identity and
is not put in the envelope as one; it is a property of the request that the orchestrator applied.

## Invariants & Behavioral Boundaries

- **`[INV-CUSTOM-08]` Plan Before Connect**: every profile name used by an attempt is resolved
  by `Client::plan` before a pool lookup or connector call. An unknown profile is a hard error,
  never a default. *Enforced by*: `Client::plan` is the only constructor of `ConnectionPlan`, and
  `plan` tests cover unknown H1/H2 names.

- **`[INV-CUSTOM-09]` Connection vs Request Identity**: `PoolKey` contains only
  connection-fixed identity. H1 header order/casing and H2 pseudo-header order are request
  profiles and must not key the pool. *Enforced by*: `ConnectionPlan` holds them separately;
  `ConnectionIdentity` has no H1 field, and H2 identity contains only connection-level profile
  data.

- **`[INV-CUSTOM-10]` One Registry Path**: built-in and caller-supplied profiles resolve through
  the same `H1Registry`/`H2Registry` API. A caller can add a profile without patching the crate.
  *Enforced by*: `Client::with_h1_profile` / `Client::with_h2_profile`, plus resolution tests.

- **`[INV-CUSTOM-11]` Explicit Bytes Win**: a `RequestHead` that already carries
  `raw_headers` is not rewritten by `H1WireProfile::apply`. *Enforced by*: the
  `an_explicit_raw_head_is_not_rewritten` test in `profile.rs`.

---

## Consequences

- **Positive**:
  - Unknown profiles fail before DNS/TCP/TLS; no half-open socket for a typo.
  - H1 header order/casing becomes a named, reusable profile instead of an implicit HeaderMap
    artifact.
  - H2 profile selection is extensible and recorded in the trace identity.
  - The pool key can be audited: it is the plan's connection identity, not a formatted string.
- **Negative & Trade-offs**:
  - Breaking change: `Client::pool_key` is fallible; `Target` gains `h1_profile`;
    profile resolution can fail.
  - `H1WireProfile` cannot know every browser's exact casing; it provides deterministic
    order/casing for the headers it names, with explicit `raw_headers` as the escape hatch.
  - H2 request-level pseudo-header order lived inside the `H2Fingerprint` value at the time of
    this ADR; [ADR-0020](0020-split-multiplexed-profiles.md) splits it into
    `H2RequestProfile`, leaving the pair only as a preset convenience.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep the TLS-name `match` for H2

That makes a custom TLS profile silently select a built-in H2 identity, or vice versa. It also
gives callers no way to register a new pairing. The registry is the minimum mechanism that keeps
the choice explicit.

### Option 2 (Rejected): put H1 header order in `ConnectionIdentity`

HTTP/1 header order is per message. Putting it in the pool key would split one socket's reuse
across request cosmetics and would falsely imply that the hello on the wire changes. The request
profile is applied per request; the pool key stays connection-fixed.

### Option 3 (Rejected): fall back to a default on an unknown profile

A typo in a fingerprint name is an assertion about what the peer will see. Falling back changes
the wire identity silently, which is exactly the failure ADR-0004 and ADR-0006 exist to prevent.

---

## Evidence

- `crates/netune/src/profile.rs`: `ProfileId`, `H1WireProfile`, `H1Registry`, `H2Registry`,
  `ConnectionPlan`.
- `crates/netune/src/client.rs`: `Client::plan`, `with_h1_profile`, `with_h2_profile`.
- `crates/netune/src/connect.rs`: `Target::h1_profile` and `with_h2_profile`.
- Tests: `an_unknown_h1_profile_fails_while_planning`,
  `a_custom_h2_profile_is_resolved_and_recorded`,
  `an_unknown_h2_profile_fails_while_planning`,
  `h1_profile_orders_and_spells_headers`,
  `an_explicit_raw_head_is_not_rewritten`.

---

## Links

- Related ADRs: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md),
  [ADR-0006](0006-transport-customizability-wire-evasion.md),
  [ADR-0017](0017-tiered-observation-and-connection-identity.md),
  [ADR-0018](0018-one-trace-collector-per-attempt.md)
