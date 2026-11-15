---
id: ADR-0046
title: "HTTP/2 Regular-Header Order Is a Per-Request Policy"
status: accepted
date: 2026-11-15
scope: [protocol/http2, transport/customizability, trace/model]
superseded_by: null
---

# 0046. HTTP/2 Regular-Header Order Is a Per-Request Policy

- Status: Accepted
- Date: 2026-11-15
- Deciders: Ming Li
- Amends: [ADR-0020](0020-split-multiplexed-profiles.md)
- Related: [ADR-0019](0019-connection-plan-and-wire-profile-registry.md)

---

## Context and Problem Statement

`H2Fingerprint::go()` already reproduces the Go `net/http` connection framing
exactly (measured against the Antigravity CLI's Clearcut traffic), but it
covers only the *pseudo*-header order (`:authority, :method, :path, :scheme`).
For regular headers, `order_request_headers` passes the caller's list through
unchanged — so a netune h2 request presents a *fixed* regular-header order
across every request on a connection.

Go does not have a fixed regular-header order. `net/http` writes regular
headers by iterating a map, so each request emits them in a fresh random order
(captured on the Clearcut path: `content-type, authorization, content-length,
accept-encoding, user-agent`). The fingerprint documentation already states
the conclusion: "there is no stable regular-header ordering to impersonate,
and a stack that emits a *fixed* order is the outlier."

A strict server-side fingerprint (JA4H-class) reads the regular-header order.
The current behaviour is therefore worse than no emulation: it is a
deterministic outlier in the one dimension the connection profile does not
cover.

## Decision Drivers

- The request profile must decide regular-header order as *policy data*, not
  leave it to caller accident.
- Matching a randomized behaviour means matching the distribution, not any
  single capture; the emulation must vary per request.
- Determinism in tests: every wire decision must be reproducible from a seed,
  not from wall-clock entropy ([`INV-TRACE-01`] spirit: no unexplained
  nondeterminism on the wire path).
- No new dependency: the workspace has no `rand` dependency and the PRNG is
  protocol logic, not a domain needing an external crate.

## Considered Options

- Option 1: Preserve caller order (today's behaviour).
- Option 2: Fixed canonical order for all stacks.
- Option 3: A named `RegularHeaderOrder` policy on `H2RequestProfile`, with a
  per-request randomized variant seeded by a caller-supplied value.

## Decision Outcome

Chosen option: "Option 3". `H2RequestProfile` gains a
`regular_header_order` field, breaking the derived structure:

```text
pub enum RegularHeaderOrder {
    /// Emit regular headers in the caller's order, unchanged.
    CallerOrder,
    /// Shuffle regular headers per request (Go map-iteration emulation).
    /// `seed` selects the permutation; the same seed yields the same order.
    GoMapRandom,
    /// Emit regular headers in a fixed declared order.
    Fixed(&'static [&'static str]),
}
```

`order_request_headers` takes the seed as a parameter; the connection carries
a per-connection seed and derives per-request values, so a seeded test
reproduces the exact wire sequence. `H2Fingerprint::go()` selects
`GoMapRandom`; browser profiles keep an explicit policy instead of inheriting
whatever the caller does.

### Honesty boundary: distribution equivalence, not byte equality

Randomizing regular headers makes netune's traffic *indistinguishable in
distribution* from Go's, not equal to any given capture. No single request
matches any single captured request — and Go's own requests have the same
property. Documentation states this explicitly; the claim is on the
distribution, never on individual bytes.

## Invariants & Behavioral Boundaries

- **`[INV-CUSTOM-21]` Regular-Header Order Is Named Policy**: the regular
  (non-pseudo) header order of an h2 request is a named variant of
  `RegularHeaderOrder` on `H2RequestProfile`, never a boolean, never ambient
  caller accident. *Enforced by*: the type and its exhaustive use in
  `order_request_headers`.

- **`[INV-CUSTOM-22]` The Go Profile Does Not Present a Fixed Order**: a
  request profile named `go-nethttp` emits regular headers in per-request
  randomized order derived from its seed; two requests on one connection
  present different orders with probability 1 for three or more headers.
  *Enforced by*: `H2Fingerprint::go()` construction and the seeded-shuffle
  tests in `crates/netune-http2`.

## Consequences

- **Positive**:
  - The h2 request identity no longer contains a deterministic outlier.
  - The policy is testable: a seed reproduces the exact permutation.
- **Negative & Trade-offs**:
  - **Breaking**: `H2RequestProfile` literals and `order_request_headers`
    callers must supply the policy and the seed (the `0.0.x` line is already
    patch-breaking by policy).
  - The emulation is behavioural, not byte-exact: a fingerprinting regime that
    correlates header order *across* requests from one connection may still
    distinguish a seeded PRNG from Go's map iteration with enough samples.
    That limit is stated rather than hidden.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): preserve caller order

- **Why considered**: zero code change; Go's order is random, so any order is
  "compatible".
- **Why rejected**: a fixed order across requests is the one property Go never
  has; it is a positive fingerprint signal, and the crate's own documentation
  already declared it the outlier.

### Option 2 (Rejected): fixed canonical order for all stacks

- **Why considered**: simplest policy, no PRNG.
- **Why rejected**: same failure as Option 1, with the order now canonically
  netune's instead of the caller's; and it erases the `CallerOrder` case where
  a caller genuinely wants exact control (raw headers remain the final word).

## Links

- Related ADRs: [ADR-0019](0019-connection-plan-and-wire-profile-registry.md),
  [ADR-0020](0020-split-multiplexed-profiles.md)
- Tests: `crates/netune-http2/src/fingerprint.rs`
