---
id: ADR-0006
title: "Transport Customizability, DNS and Wire Evasion Architecture"
status: accepted
date: 2026-10-15
scope: [transport/customizability, dns/resolver, security/evasion]
superseded_by: null
---

# 0006. Transport Customizability, DNS and Wire Evasion Architecture

- Status: Accepted
- Date: 2026-10-15
- Deciders: Ming Li

---

## Context and Problem Statement

`netune` was initially designed ([ADR-0001](0001-owned-transport-trace-model.md)) as an owned, observable, and intervention-capable network stack. While [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md) introduced `TlsProfile` for selecting ALPN protocols and cipher suite allowlists within `rustls`, deep packet inspection (DPI) devices, middlebox firewalls, and active fingerprinting systems (JA4, p0f OS fingerprinting, SNI inspection) require capabilities far beyond standard client defaults.

Specifically:
1. **L3/L4 OS Fingerprint Leakage**: Default OS socket options leak host kernel TCP characteristics (TTL=64 on Linux vs 128 on Windows, initial window sizes, MSS).
2. **DNS Attribution Leakage**: Default resolution delegates to blocking `getaddrinfo`, leaking queries over unencrypted UDP and preventing custom split-horizon routing.
3. **Wire Segmentation & Anti-Censorship**: Defeating middlebox SNI inspection requires sub-record TLS fragmentation and deterministic byte segmentation.
4. **HTTP Header Casing & Duplicate Smuggling**: `http::HeaderMap` automatically lowercases header names and merges duplicates, which breaks JA4H HTTP-layer fingerprint preservation and title-cased browser impersonation.

We need an architectural substrate that decouples transport configuration, DNS resolution, and header formatting while preserving zero-blackbox observability.

## Decision Drivers

- **Uncompromising Wire Control**: Provide byte-level determinism over socket options, DNS resolution, and protocol framing.
- **Owned Stack Continuity**: Keep third-party blackbox runtimes out of the critical path; all abstractions must integrate natively with `netune-trace`'s non-allocating `Recorder`.
- **Extensible Fingerprint Models**: Support declarative customization across L3/L4 (socket tuning), L5 (TLS), and L7 (HTTP raw headers).

## Considered Options

- Option 1: Wrap an external C/Go library (e.g. `curl-impersonate` / `uTLS` via CGo/FFI).
- Option 2: Pluggable transport and protocol layering with declarative customization:
  - Extensible `SocketConfig` at L3/L4 (TTL, buffer sizes, MSS, TCP_NODELAY).
  - Asynchronous, injectable `DnsResolver` trait (`SystemResolver`, `StaticResolver`).
  - Wire write slicing via `SegmentingIo` for SNI segmentation.
  - Raw header casing and duplication preservation via `RequestHead::with_raw_header`.

## Decision Outcome

Chosen option: "Option 2: Pluggable transport and protocol layering with declarative customization".

### Invariants & Behavioral Boundaries

- **`[INV-CUSTOM-01] Wire Determinism`**: Every configurable transport property (socket flags, TTL, buffer sizes, header casing, write chunking) must either be explicitly configured or derive from a deterministically documented profile.
- **`[INV-CUSTOM-02] Observability Parity`**: Custom DNS resolution, socket configuration, and wire segmentation must emit structured events into the attempt's `Recorder` without introducing synthetic measurement bias.
- **`[INV-CUSTOM-03] Raw Header Fidelity`**: When `RequestHead::raw_headers` is populated, `write_request` must serialize exact caller casing and preserved duplicate lines verbatim without lowercase transformation.

### Consequences

- **Positive**:
  - Full control over L3/L4 TCP parameters (TTL, MSS, socket buffers) to align with target OS fingerprints.
  - Asynchronous, mockable DNS resolution (`StaticResolver`) that prevents upstream DNS leakage.
  - Middlebox SNI evasion via `SegmentingIo`.
  - Byte-for-byte HTTP header casing and order matching browser profiles.
- **Negative & Trade-offs**:
  - Raw header vectors require separate memory when explicitly activated alongside `HeaderMap`.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Wrap External FFI Libraries (curl-impersonate / uTLS)

- **Why considered**: Provides pre-packaged browser fingerprint impersonation.
- **Why rejected**: Destroys [ADR-0001](0001-owned-transport-trace-model.md)'s primary invariant (an owned Rust stack without opaque buffers); makes asynchronous cancellation and `TimedIo` nanosecond syscall tracing impossible.

## Links

- Related PRs / Commits: raw header and socket tuning commits
- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md)
