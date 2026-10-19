---
id: ADR-0004
title: "TLS Fingerprint Profiles and Connection Pool Isolation"
status: accepted
date: 2026-09-11
scope: [tls/fingerprint, pool/isolation]
superseded_by: null
---

# 0004. TLS Fingerprint Profiles and Connection Pool Isolation

- Status: Accepted
- Date: 2026-09-11
- Deciders: Ming Li

---

## Context and Problem Statement

When operating across diverse cloud providers, APIs, and edge gateways, network egress must present predictable TLS identities (JA3/JA4 fingerprints) matching specific product profiles (e.g. standard Codex CLI reqwest/hyper-rustls stacks vs network proxies). Standard TLS client setups configure TLS options globally during client construction. This prevents dynamic, per-request fingerprint selection and risks connection cross-contamination if the connection pool reuses an existing socket that completed a TLS handshake under a different TLS fingerprint.

We need a mechanism to specify TLS parameters as pure data, route per-request profiles dynamically, and strictly isolate pooled connections across identities.

## Decision Drivers

- Pure data representation of TLS client parameters (`TlsProfile`).
- Named presets (`netune-default`, `codex-reqwest`, `codex-network-proxy`) matching observed runtime environments.
- Per-request selection via `Target::with_tls_profile`.
- Absolute pool isolation: zero socket reuse across different TLS profiles.
- Fail-fast validation: unknown profile names must fail immediately rather than silently downgrading.

## Considered Options

- Option 1: Instantiate a distinct `Client` instance for each desired TLS configuration.
- Option 2: Introduce `TlsRouterConnector` with pure-data `TlsProfile` definitions, lazy compilation, and `authority#profile` pool slicing.

## Decision Outcome

Chosen option: "Option 2: Introduce `TlsRouterConnector` with pure-data `TlsProfile` and `authority#profile` pool slicing".

`TlsProfile` is pure data describing ALPN protocols, supported TLS versions, cipher suite allowlists, key-exchange group allowlists, and certificate verifier selection. Profiles compile lazily into shared `rustls::ClientConfig` instances, preserving session resumption within an identity while isolating the connection pool by composite keys (`format!("{authority}#{profile}")`).

### Invariants & Behavioral Boundaries

- **`[INV-TLS-01]` Pool Profile Isolation**: A pooled connection established under profile $P_1$ must never be reused for a target requesting profile $P_2$, even when connecting to the exact same network authority.
- **`[INV-TLS-02]` Loud Rejection of Unknown Profiles**: Specifying an unregistered or misspelled profile name must yield an explicit `NetError::Connect` listing registered profile names; silent fallback or downgrade to a default profile is strictly prohibited.
- **`[INV-TLS-03]` Immutable Wire Identity**: Predefined presets must maintain continuous JA4 fingerprint stability across dependency updates, as verified by automated baseline regression tests.

### Consequences

- **Positive**:
  - Request dispatchers can dynamically vary TLS fingerprints per call without client rebuilding.
  - Sockets and TLS session caches remain isolated per identity, preventing cross-tenant or cross-profile side-channels.
  - Clear error diagnostics when an requested fingerprint preset is missing.
- **Negative & Trade-offs**:
  - Pool capacity is partitioned across profiles, potentially increasing handshake count when multiple profiles query the same host.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Dedicated Client Instance per Identity

- **Why considered**: Simplest conceptual model; relies on standard client construction.
- **Why rejected**: Prohibits request-level routing behind a unified client façade. Callers would be forced to maintain parallel client registries, multiplying socket management overhead and preventing clean middleware encapsulation.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md)
