---
id: ADR-0009
title: "REALITY Client Authentication Is Not a netune Capability"
status: rejected
date: 2026-10-28
scope: [tls/reality, protocol/vless, security/egress]
superseded_by: null
---

# 0009. REALITY Client Authentication Is Not a netune Capability

- Status: Rejected
- Date: 2026-10-28
- Deciders: Ming Li
- Amends: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md)

---

## Context and Problem Statement

REALITY is the transport authentication layer used by a large share of modern `vless`
nodes, and a `daer` consumer will eventually ask for it. The obvious placement question
is whether netune should grow it, since netune owns TLS identity and `daer` is forbidden
to open a handshake of its own.

A REALITY client handshake is not a normal TLS handshake with extra options. It works by
reusing fields the client is permitted to set in a way the server can authenticate:

1. The client generates an ephemeral X25519 keypair and derives a shared secret with the
   server's public key.
2. It computes `auth_key = HKDF(shared_secret, "REALITY")` and encrypts a short payload
   containing a timestamp and a short-id under AES-GCM.
3. **It places that ciphertext in the ClientHello's `legacy_session_id` field** (32 bytes).
4. It sets SNI to a real, unrelated site. The server — which holds a token for that SNI —
   verifies the tag. On success it impersonates the real site; on failure it proxies the
   handshake to the real host, so an active prober sees a valid certificate chain.
5. Certificate verification is therefore **not** the authenticator: the client must accept
   the presented certificate without a CA chain proving it, because the server may be
   relaying a certificate it does not own.

Steps 1–2 are protocol logic. Steps 3–5 are TLS-stack capabilities.

## Decision Drivers

- `daer` may not implement TLS itself (the sibling project's ADR-0002 boundary).
- netune's TLS identity is declarative and must stay reproducible (`INV-TLS-01..03`).
- A capability added to netune changes the wire behaviour of every consumer, so it must
  be a *superset* of ordinary TLS, not a mode that weakens ordinary TLS.
- Certificate verification is a security guarantee for every non-REALITY consumer.

## Considered Options

- **Option 1**: implement REALITY in netune — plumb a caller-provided `legacy_session_id`
  into the ClientHello and accept a caller-installed verifier that bypasses CA validation.
- **Option 2**: keep netune's TLS as-is and let the consumer (`daer-outbound`) supply a
  REALITY connector that owns the whole handshake.
- **Option 3**: patch or fork `rustls` to expose the two hooks and upstream the patch.

## Decision Outcome

Chosen option: **the REALITY client handshake is not a netune capability; Option 2 is
where it belongs, and it is not currently possible without a `rustls` capability that does
not exist.** The record is *rejected* rather than *accepted* because the decision is not to
build it here, and the reason is a verified upstream limitation rather than a preference.

### The verified blocker

`rustls` 0.23.37 generates `legacy_session_id` itself and offers no injection point:

- `src/client/hs.rs:116` — `None => SessionId::random(config.provider.secure_random)?`
  is the only path when a session is not being resumed; there is no config field, no
  builder method, and no trait to supply the value.
- `ClientHello`'s `session_id` field is `pub(super)`
  (`src/client/hs.rs:74`), so it is unreachable from outside the crate.
- VERIFIED GOOD NEWS: rustls **does** enforce the echo
  (`src/client/hs.rs:903-917`, `PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId`),
  so the field is a live, reliable channel once it can be set. The wire half of REALITY is
  therefore compatible; only the write side is closed.

Netune's TLS surface today is `TlsProfile` (cipher suites, key-share groups, ALPN,
extension order, GREASE, signature algorithms, ALPS) plus `Verifier::{Platform, Roots}`.
Neither can express steps 3 or 5: there is no `legacy_session_id` field, and
`Verifier::Roots` still requires a chain to *some* root — it cannot say "accept this
certificate because an out-of-band tag authenticated the server".

### Why not Option 1

Growing netune means shipping a verifier variant that disables the check the library
exists to perform. Every consumer of `Verifier` would then have to reason about whether
the bypass is in play, and `[INV-TLS-02]` — that a preset presents a stable, verifiable
identity — would need an exception carved into it. A security invariant with an exception
is not an invariant.

### Why not Option 3

Forking `rustls` puts a security-critical TLS implementation on a private branch. The
maintenance cost is not the patch (two hooks); it is tracking upstream security fixes
across a fork that every consumer of netune would inherit. That trade is worth making only
if REALITY is a first-class goal of netune, which it is not: REALITY is a *proxy protocol
feature*, and netune is a general client stack whose value is that it carries no protocol
product semantics.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected)

- **Why considered**: it keeps `daer` free of TLS code, which is the boundary's whole point.
- **Why rejected**: it dissolves the boundary in the other direction by putting an
  authentication-bypass mode into a general TLS client. The correct reading of "netune owns
  TLS identity" is *identity selection*, not *authentication policy for one proxy protocol*.

### Option 3 (Rejected)

- **Why considered**: it is the only path that makes REALITY possible without duplicating
  TLS in `daer`.
- **Why rejected**: a forked TLS stack is a permanent security liability for every consumer,
  accepted to serve one protocol's feature. If this is ever revisited it must be a separate
  ADR with an explicit maintenance plan, not a rider on a datagram or TLS-customization
  change.

## Consequences

- **`daer-outbound` cannot implement REALITY without either a `rustls` capability that does
  not exist or a TLS implementation of its own.** This is a hard, verified boundary, not an
  unimplemented feature. A `vless` node without REALITY is unaffected and remains buildable
  on netune's `Connector` seam.
- The gap is now recorded where a reader looks for decisions, so it cannot be silently
  assumed "just a matter of time".
- Ordinary TLS consumers keep an unchanged `Verifier` surface: no bypass mode exists to be
  misused, and `[INV-TLS-02]` needs no exception.
- **What would reopen this**: `rustls` gaining a supported `legacy_session_id` injection
  hook *and* a verifier that can accept an out-of-band authenticator. If that lands, this
  record should be superseded rather than edited, and the family renumbered nowhere.

## Links

- Related ADRs: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md),
  [ADR-0008](0008-datagram-transport-and-socks5-udp-association.md)
- Evidence: `rustls` 0.23.37 `src/client/hs.rs:74,116,903-917`.
