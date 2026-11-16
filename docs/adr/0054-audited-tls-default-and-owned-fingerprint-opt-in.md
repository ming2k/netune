---
id: ADR-0054
title: "Audited TLS by Default, Owned Fingerprint Engine by Explicit Opt-In"
status: accepted
date: 2026-11-16
scope: [security/tls, transport/egress, crypto/provider]
superseded_by: null
---

# 0054. Audited TLS by Default, Owned Fingerprint Engine by Explicit Opt-In

- Status: Accepted
- Date: 2026-11-16
- Deciders: Ming Li
- Amends: [ADR-0045](0045-owned-egress-tls-engine.md)

---

## Context and Problem Statement

ADR-0045 replaced rustls on the egress TCP-TLS path with the owned engine so
that a `TlsProfile` could reproduce a measured ClientHello byte-for-byte. That
is the right architecture for fingerprinting, but it created a production
question the implementation status did not answer: a security-critical TLS
stack that has not completed an independent external audit must not be the
silent default for every consumer.

The owned engine has strong evidence — RFC 8448 vectors, openssl-derived CBC
goldens, live rustls differential handshakes, in-workspace fuzzing and a
record/handshake soak target — but evidence is not an audit. A consumer that
does not need a fingerprint should get the audited, widely deployed engine;
a consumer that does need one should make that choice explicitly and know the
audit status.

## Decision Drivers

- A safe default must not depend on an unaudited security-critical component.
- Fingerprint identities still need the owned engine; they are a product
  capability, not an accident.
- A profile is a wire identity: silently replacing it with rustls would change
  what the peer sees.
- Engine choice is connection identity and must stay in the pool key.
- The default must be testable and visible in the trace and documentation.

## Decision Outcome

Chosen option: "rustls by default, owned engine by explicit profile or engine
selection".

1. **Plain TLS targets use rustls.** A `Target::tls` with no `TlsProfile` and no
   explicit engine handshakes with rustls using the platform certificate
   verifier. This is the production default.
2. **A profile selects the owned engine.** A target that names a profile with
   `Target::with_tls_profile` (including a custom profile registered through
   `TlsRouterConnector::with_profile_named`) uses `netune-tls`. The profile is a
   declarative ClientHello blueprint and cannot be reproduced by rustls, so
   this selection is never downgraded.
3. **An explicit engine wins only when it is compatible.** `netune-tls` selects
   the owned engine; `rustls` selects rustls. A profile plus `rustls` is an
   error, as is a connector configured with an owned verifier plus `rustls`.
   An unknown engine name is a named error, never a fallback.
4. **Engine choice remains connection identity.** `ConnectionIdentity` already
   carries `tls_engine`; the pool never mixes connections from the two engines.
5. **Owned TLS stays Preview until audit.** The stability page lists the
   independent audit scope. The default change does not relax that gate; it
   removes the unaudited engine from the path of consumers who did not ask for
   it.

### Invariants & Behavioral Boundaries

- `[INV-TLS-12]` A plain TLS target uses the audited rustls path; the owned
  engine is reachable only by an explicit profile or `netune-tls` selection.
  *Enforced by*: `TlsRouterConnector` engine dispatch,
  `a_plain_tls_target_uses_the_rustls_production_engine`,
  `the_profile_selection_reaches_the_wire_per_request`, and
  `ARCH-013`.
- `[INV-TLS-04]` is amended: the egress graph may contain the ratified rustls
  production path and the owned engine; it may not contain any other TLS
  engine, and an owned profile is never silently replaced by rustls.
- `[INV-TLS-09]` continues to hold: the selected engine is part of the pool key
  and the trace identity.

## Considered Options

### Keep the owned engine as the default (Rejected)

- **Why considered**: preserves the "fully owned from DNS to HTTP" story and
  avoids maintaining two egress TLS configurations.
- **Why rejected**: it makes an unaudited security-critical stack the default
  for every consumer, including those who never asked for a fingerprint.

### Use rustls exclusively and drop the owned engine (Rejected)

- **Why considered**: one engine, one audit surface, less code.
- **Why rejected**: it deletes the measured-identity capability and the reason
  ADR-0045 exists; profiles would become documentation rather than wire data.

### Require every consumer to choose an engine (Rejected)

- **Why considered**: no hidden default.
- **Why rejected**: a mandatory choice turns a safe default into configuration
  work and makes the easy path the unsafe one when a caller guesses.

## Consequences

- **Positive**: the default is audited; fingerprinting remains an explicit,
  visible capability; the trace and pool key record which engine was used.
- **Negative & Trade-offs**: two egress TLS paths to maintain; a plain target
  no longer reproduces `netune-default`'s Go-shaped hello unless it selects the
  profile; the owned engine remains Preview until the external audit closes.
- **Migration**: callers that relied on the owned engine's default hello must
  select `Target::with_tls_profile(Preset::NetuneDefault.name())` or
  `Target::with_tls_engine("netune-tls")`.

## Links

- Related ADRs: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md),
  [ADR-0015](0015-self-terminated-tls.md),
  [ADR-0028](0028-owned-quic.md),
  [ADR-0045](0045-owned-egress-tls-engine.md),
  [ADR-0048](0048-declarative-clienthello-blueprints.md)
- Stability gates: [Stability and Production Boundaries](../reference/stability.md)
