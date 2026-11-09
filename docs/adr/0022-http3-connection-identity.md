---
id: ADR-0022
title: "HTTP/3 Connection Identity Is the QUIC Profile"
status: accepted
date: 2026-11-09
scope: [protocol/http3, transport/quic, transport/customizability, trace/model]
superseded_by: null
---

# 0022. HTTP/3 Connection Identity Is the QUIC Profile

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0016](0016-quic-and-http3-transport.md), [ADR-0021](0021-named-quic-profiles.md)
- Amended by: [ADR-0023](0023-h3-request-header-order.md) — decision 3's "no request profile" is replaced by an enforced request-order profile in the controlled h3 fork; the connection-identity decision stands.
- Amended by: [ADR-0026](0026-controlled-dynamic-qpack.md) — H3 SETTINGS gain an enforceable profile recorded separately from the QUIC profile; the QUIC connection identity remains.

---

## Context and Problem Statement

H2 has two genuinely separable identities: a connection profile (SETTINGS/window/HPACK) and a
request profile (pseudo-header order). H3 does not have the same separation:

- HTTP/3 has no independent TLS handshake. The QUIC handshake is the handshake; the resolved
  `QuicProfile` shapes the wire identity before any H3 frame exists.
- HTTP/3 header field names are lowercase on the wire. There is no casing axis to model.
- Header order inside a QPACK-encoded HEADERS block is owned by the `h3` runtime. The current
  `http::Request`/`h3::client::SendRequest` API does not expose a per-request pseudo-header
  ordering hook.

Treating "H3 request profile" as a real type today would be a declaration with no enforcement:
callers could name it, but the bytes would not change. That is exactly the architecture rot the
governing ADRs prohibit.

## Decision

### 1. The connection identity is the resolved QUIC profile

`H3Client::connect` takes a `QuicConnector`, resolves its profile, keeps the `QuicConnection`
alive, and records the profile name on the session:

```rust
let mut h3 = H3Client::connect(&connector, addr, "api.example", Some(collector)).await?;
assert_eq!(h3.quic_profile(), Some("chrome-quic"));
```

`ConnectionIdentity.h3_profile` records that resolved QUIC profile name. It does not grow a
second `H3Settings` type that the runtime cannot apply.

### 2. The H3 client owns the QUIC connection lifetime

`H3Client::connect` stores the `QuicConnection` (and therefore the endpoint) in the session;
dropping it would stop the transport underneath a live H3 driver. `H3Client::new` remains the
explicit "already established" constructor and reports `quic_profile() == None`, because it
cannot infer the profile from a bare `quinn::Connection`.

`H3ClientConfig` bounds the request, response-head and body-chunk phases separately. `send`
returns a streaming `H3ResponseStream`; `execute` is the bounded convenience that buffers the
body. A completed exchange produces a per-exchange `RequestTrace` at `Fidelity::l0()` with the
resolved QUIC profile as `identity.h3_profile`.

### 3. No fake H3 request profile

At the time of this ADR there was no `H3RequestProfile`: the upstream `h3` runtime owned the
header encoder and exposed no ordering hook. A type that only labels a request order it cannot
enforce was rejected.

[ADR-0023](0023-h3-request-header-order.md) later satisfies the condition by controlling the
pre-QPACK ordering step in a narrow h3 fork. The connection-identity decision above is unchanged;
the request-order profile is now real and request-scoped.

## Invariants & Behavioral Boundaries

- **`[INV-CUSTOM-16]` H3 Identity Is QUIC Identity**: an H3 connection's identity is the resolved
  QUIC profile; no second handshake-identity type exists. *Enforced by*:
  `H3Client::connect`, `H3Client::quic_profile`, and the H3/QUIC integration test.

- **`[INV-CUSTOM-17]` No Unenforceable Profile Type**: an H3 request-header order profile is not
  added until the encoder can enforce it. A label that does not change bytes is not a profile.
  *Enforced by*: ADR-0023's controlled h3 fork, where `RequestHeaderOrder` is consumed before
  QPACK encoding.

---

## Consequences

- **Positive**:
  - H3 connection identity is honest and matches the actual wire handshake.
  - The QUIC profile registry is reused; there is no parallel H3 profile match.
  - No caller can select an H3 request order that the runtime silently ignores.
  - Streaming, per-phase deadlines and a bounded `execute` make the client lifecycle complete
    without pretending H3 owns a request-header fingerprint it cannot enforce.
- **Negative & Trade-offs**:
  - H3 request-header order impersonation remains unavailable until an owned QPACK/H3 encoder
    exists. This is a documented capability gap, not a fake surface.
  - `H3Client::into_parts` now returns the optional `QuicConnection` so the endpoint can be
    retained; callers must keep it alive.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): an `H3ProfileRegistry` duplicating QUIC transport parameters

H3 does not perform a second handshake. Two registries for one identity create two sources of
truth and a predictable drift.

### Option 2 (Rejected): an `H3RequestProfile` passed to `h3::SendRequest`

The current `h3` API encodes the header block itself and does not accept a pseudo-header ordering
policy. A type here would be a label with no wire effect.

---

## Evidence

- `crates/netune-http3/src/client.rs`: `H3Client::connect`, `H3ClientConfig`,
  `H3ResponseStream`, per-exchange `RequestTrace`, retained `QuicConnection`.
- `crates/netune-http3/tests/http3_e2e.rs`: connects through `QuicProfile::chrome_quic`,
  asserts the resolved profile, and asserts the per-exchange L0 envelope.
- `crates/netune-quic/src/profile.rs`: `QuicProfileRegistry` and resolved profile names.

---

## Links

- Related ADRs: [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0021](0021-named-quic-profiles.md),
  [ADR-0019](0019-connection-plan-and-wire-profile-registry.md)
