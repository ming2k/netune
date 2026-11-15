---
id: ADR-0047
title: "The Antigravity CLI Identity Splits Into Unary and Stream Profiles"
status: accepted
date: 2026-11-15
scope: [transport/tls, protocol/http2, transport/customizability, workspace/topology]
superseded_by: null
---

# 0047. The Antigravity CLI Identity Splits Into Unary and Stream Profiles

- Status: Accepted
- Date: 2026-11-15
- Deciders: Ming Li
- Amends: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md)
- Related: [ADR-0019](0019-connection-plan-and-wire-profile-registry.md), [ADR-0020](0020-split-multiplexed-profiles.md), [ADR-0045](0045-owned-egress-tls-engine.md)

---

## Context and Problem Statement

The single `antigravity-cli` TLS preset claims one identity for what the
upstream client (`agy` 1.5.9) presents as *two*. Measured on the wire:

| Path | ALPN offer | UA | h2 |
| :--- | :--- | :--- | :--- |
| Unary Cloud Code API (`/v1internal:*` JSON calls) | `http/1.1` only (`stripHTTP2NextProto`) | `antigravity/cli/1.5.9 (…)` | none |
| Clearcut telemetry + model streaming | `h2, http/1.1` | `Go-http-client/2.0` | go-nethttp framing |

The preset keeps the stream offer (`h2, http/1.1`) and documents that a caller
mimicking the unary path must override ALPN via `with_alpn`. That pushes the
correctness of the identity onto every call site: a caller who forgets the
override emits a unary-shaped request over a stream-shaped connection —
exactly the cross-path mismatch the server side can detect.

The user-agent differs per path too (`antigravity/cli/…` vs
`Go-http-client/2.0`), which confirms the split is a product-level identity,
not a TLS detail.

## Decision Drivers

- A preset name must reproduce the identity of the path it names; the current
  name reproduces neither path exactly.
- Wire-profile selection is resolved before connect (ADR-0019); the path
  split belongs in that resolution, not in per-request overrides.
- No backward-compat shims: the old single preset is removed, not deprecated
  (the `0.0.x` line is patch-breaking by policy).

## Considered Options

- Option 1: Keep one preset; document the `with_alpn` override.
- Option 2: Split into `antigravity-cli-unary` and `antigravity-cli-stream`,
  remove `antigravity-cli`, and pair each through the registries.

## Decision Outcome

Chosen option: "Option 2". The single preset is replaced by two:

- `antigravity-cli-unary` — ALPN offers exactly `http/1.1`; pairs with no h2
  connection profile (the unary path never opens h2).
- `antigravity-cli-stream` — ALPN offers `h2, http/1.1`; pairs with the
  `go-nethttp` H2 fingerprint through `default_for_tls`, matching the
  Clearcut/streaming paths.

Both share the same measured TLS knobs (13-suite offer minus the four CBC
suites rustls cannot offer, hybrid-first group order, Go's signature list);
only the ALPN offer and the h2 pairing differ. The user-agent per path stays
the caller's H1/request surface; the preset governs the connection identity.

## Invariants & Behavioral Boundaries

- **`[INV-TLS-10]` A Path-Named Preset Offers Exactly That Path's ALPN**: a
  preset whose name claims a specific product traffic path offers the ALPN
  list measured for that path, and the wire-profile registry pairs it with the
  H2 identity of the same path — a unary-named preset pairs with no h2
  connection profile, and a stream-named preset pairs with its measured
  fingerprint. *Enforced by*: the preset unit tests and
  `H2Registry::default_for_tls`.

## Consequences

- **Positive**:
  - Path selection is resolved before connect, in one place, instead of
    relying on per-request overrides.
  - The registry mapping gives the pooled connection the correct h2 identity
    automatically (ADR-0019).
- **Negative & Trade-offs**:
  - **Breaking**: `Preset::AntigravityCli` and the name `"antigravity-cli"`
    are removed; callers migrate to the explicit unary/stream preset.
  - Two presets share most data; a drift between them must stay an intentional
    act, covered by the shared-construction test.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): one preset plus a documented `with_alpn` override

- **Why considered**: smallest change; the doc comment already explains the
  two offers.
- **Why rejected**: correctness depends on every call site remembering an
  override; the failure is silent (a valid but mismatched connection), which
  is the worst kind for an identity layer.

## Links

- Related ADRs: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md),
  [ADR-0019](0019-connection-plan-and-wire-profile-registry.md),
  [ADR-0045](0045-owned-egress-tls-engine.md)
- Tests: `crates/netune/src/tls_profile.rs`, `crates/netune/src/profile.rs`
