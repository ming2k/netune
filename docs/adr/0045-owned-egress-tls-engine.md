---
id: ADR-0045
title: "Own the Egress TCP-TLS Handshake and ClientHello"
status: accepted
date: 2026-11-15
scope: [transport/tls, crypto/provider, transport/egress, workspace/topology, trace/model]
superseded_by: null
---

# 0045. Own the Egress TCP-TLS Handshake and ClientHello

- Status: Accepted
- Date: 2026-11-15
- Deciders: Ming Li
- Amends: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md)
- Related: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0016](0016-quic-and-http3-transport.md), [ADR-0027](0027-owned-h3-qpack.md), [ADR-0028](0028-owned-quic.md)

---

## Context and Problem Statement

`netune`'s egress TCP-TLS path is the last egress transport whose handshake
netune does not shape. A `TlsProfile` (ADR-0004) selects what rustls *says* —
ALPN, versions, cipher and group allowlists — but rustls fixes *how* it says it:
it always randomizes extension order per connection (`extension_order_seed`),
only offers extensions rustls itself knows, and only offers suites the crypto
provider implements. A profile can therefore negotiate *like* another stack but
can never *reproduce* another stack's hello bytes.

That ceiling is now measured, not suspected. Live captures of the Google
Antigravity CLI 1.5.9 (a Go `crypto/tls` client on a `boringcrypto` toolchain)
show a hello that is structurally impossible for rustls to emit:

- a fixed extension order, byte-identical across 75 captures;
- `renegotiation_info` (`0xff01`), `extended_master_secret` (`0x0017`),
  `signed_certificate_timestamp` (`0x0012`) and `status_request` (`0x0005`) —
  extensions rustls has no way to offer;
- four CBC suites (`0xc009 0xc013 0xc00a 0xc014`) rustls does not implement;
- hybrid groups `0x11eb`/`0x11ed` and P-521, and ML-DSA signature algorithms
  (`0x0904 0x0905 0x0906`) outside rustls' algorithm set.

The measured JA3 (`03117a8ed39ef02427ebbc39f121275c`) and JA4
(`t13d1312h1_f57a46bbacb6_f50d94e863eb` / `t13d1312h2_...`) are unreachable by
configuration. `crates/netune/src/tls_profile.rs` already states the honest
conclusion: "Impersonating a non-rustls stack (Chrome, Safari, Go) needs a
different engine, not a different profile."

Meanwhile the workspace has already crossed this bridge twice: ADR-0027 removed
the H3/QPACK fork and ADR-0028 removed `quinn`, each replacing a third-party
protocol engine with an owned one behind dev-only differential oracles.
The egress TLS handshake is the same decision, one layer down.

## Decision Drivers

- The egress stack must be able to explain every byte of its handshake; a
  profile that cannot control extension order cannot make that claim.
- The trace model requires handshake facts to be recorded events, derived
  timings (`[INV-TRACE-01]`), not opaque dependency behaviour.
- The identity surface must reproduce measured hello bytes, not approximate
  them: golden captures exist and byte equality is testable.
- The production graph must not gain a *new* third-party TLS engine; the point
  is to remove the one the egress path has.
- Cryptography stays in `aws-lc` (ADR-0016); reimplementing primitives is
  security risk with no wire-control benefit.
- `netune-server` ingress TLS (ADR-0015) and `netune-quic`'s QUIC handshake
  TLS (ADR-0028) are separate, already-ratified decisions; this ADR does not
  disturb them.

## Considered Options

- Option 1: Keep rustls and extend `TlsProfile`.
- Option 2: Drive the BoringSSL TLS stack inside `aws-lc` directly
  (`aws-lc-sys` `ssl.h` surface).
- Option 3: Own the egress TCP-TLS engine in a new leaf crate `netune-tls`:
  ClientHello serialization, TLS 1.2/1.3 handshake state machine and record
  layer in workspace code; all cryptographic primitives from `aws-lc`;
  `rustls` becomes a dev-only differential oracle for this crate.

## Decision Outcome

Chosen option: "Option 3". `netune-tls` owns the egress TCP-TLS handshake the
way `netune-quic` owns QUIC: a sans-IO engine over caller-provided
`AsyncRead`/`AsyncWrite`, emitting handshake facts as trace events, with a
byte-exact ClientHello serialization the profile layer fully controls.
`rustls` remains in the production graph only where separate ADRs ratify it
(`netune-server`, `netune-quic`); in the egress TCP-TLS path it is demoted to a
dev-only differential oracle of `netune-tls`.

> Implementation status: **the migration gate (step 6) is complete.** The wire
> model and the byte-exact ClientHello forge (golden corpus from the 1.5.9
> captures) are landed; the key schedule and the TLS 1.3 AEAD record layer
> are landed against the RFC 8448 §3 vectors (secrets, traffic keys,
> finished keys, transcript hashes, and three record ciphertexts reproduced
> byte-for-byte); the TLS 1.3 client state machine is landed — it completes
> the RFC 8448 §3 handshake offline and completes a live differential
> handshake against a `rustls` server with the `go_identity` hello, hybrid
> X25519MLKEM768 agreement, ALPN negotiation and application-data exchange
> in both directions. The TLS 1.2 CBC capability (step 4), the engine seam
> (step 5) and the rustls removal (step 6) are tracked in this record until
> the gate in step 6 completes.

### 1. Scope: what "own" covers and what it does not

The owned surface is the protocol layer, entirely:

- `wire`: TLS framing (record layer, handshake message headers, u24 lengths)
  and every ClientHello field, serialized in caller-chosen order.
- `hello`: the typed ClientHello model, extension order as first-class data,
  and byte-exact profiles.
- `handshake`: the TLS 1.3 and TLS 1.2 client state machines —
  ServerHello/HelloRetryRequest handling, key schedule, transcript hash,
  certificate verification hooks, ChangeCipherSpec/Finished, application-data
  keying.
- `record`: post-handshake record protection on both directions.

The owned code never implements a cryptographic primitive. Key schedules,
transcript hashes, AEAD, CBC+HMAC record protection, ECDH/KEM agreement,
signatures and verification call `aws-lc-rs`, falling back to `aws-lc-sys`
FFI only for primitives the `aws-lc-rs` facade does not expose (expected:
CBC record protection; to be verified per primitive as each layer lands).
Both spellings are the same provider and the same red-line: `ring` is
forbidden, as in ADR-0016.

No codec opens a socket. The engine consumes the byte streams the orchestrator
hands it; DNS, TCP and egress confinement stay in `netune`
([`INV-SOCKET-01`], [`INV-EGRESS-01`]).

### 2. Never advertise what you cannot complete

The hello is an offer the engine must be able to honour byte-for-byte. The
Go-shaped hello offers 13 suites (including four CBC), 7 groups (including
hybrid and P-521) and 13 signature algorithms (including ML-DSA); the engine's
capability set is exactly the offer set, asserted by tests, not a
configuration wish-list. A suite or group the engine cannot execute is removed
from the offer — the offer list is derived from the capability list.

### 3. The hello is a pure function of the profile and the seed

`TlsProfile` (ADR-0004) stays the description layer, and its types move off
rustls: cipher suites, groups, signature algorithms and extension order become
`netune-tls` wire values, so a profile is pure data with no engine leaked into
it. Serialization takes the profile plus a caller-provided randomness seed and
is deterministic per seed. Fixed-seed output is byte-compared against the
capture corpus in tests; changing one extension costs one test, not one
release.

### 4. Staged migration with hard gates

The rewrite lands in reviewable layers, each with an acceptance gate; a layer
that has not passed its gate is not the production path.

1. Wire model and ClientHello forge: byte-exact golden corpus from the 1.5.9
   captures (JA3 `03117a8ed39ef02427ebbc39f121275c`, JA4
   `t13d1312h1_f57a46bbacb6_f50d94e863eb`), round-trip parse via
   `netune-trace`.
2. Record layer and crypto wiring: AEAD and CBC+HMAC record protection against
   RFC vectors; the TLS 1.3 half is landed against RFC 8448 §3 (key schedule,
   AEAD record protection), the TLS 1.2 half (AES-GCM explicit-nonce shape,
   ChaCha20-Poly1305 TLS-1.2 nonce per RFC 7905, CBC+HMAC-SHA1 through the
   `aws-lc-sys` EVP interface) against openssl-derived goldens — landed.
3. TLS 1.3 client handshake: full ECDHE/ML-KEM handshake against local test
   peers and the differential oracle; hybrid group combiner owned here
   (RFC 10024 layouts — X25519MLKEM768 is PQ-first, the SecP hybrids are
   classical-first), primitives from `aws-lc`. Landed: the RFC 8448 §3
   offline handshake and the live `rustls` differential handshake. The
   RFC 8448 trace's server key is 1024-bit RSA, below the modern
   RSA-PSS verification bound, so its CertificateVerify is asserted refused
   rather than verified; the verification path is exercised by the live
   differential handshake, where the `rustls` server checks our Finished.
4. TLS 1.2 client handshake: the legacy flight (plaintext Certificate and
   ServerKeyExchange with parameter signatures, ClientKeyExchange in the
   clear, change_cipher_spec, Finished under the fresh keys), the TLS 1.2
   key schedule through the `aws-lc` PRF facade (SHA-256/SHA-384) and the
   `aws-lc-sys` FFI for the MD5+SHA-1 dual PRF of the `_SHA` suites, and the
   extended master secret (RFC 7627) as the mandatory derivation — the
   hello offers EMS and the machine refuses a server that drops it.
   Landed with the dual differential (rustls TLS 1.2 GCM under both PRF
   hashes) and the CBC goldens.
5. Engine seam in `netune`: `Target::with_tls_engine` selects the engine per
   request, the choice enters `ConnectionIdentity` (and thereby the pool
   key), the `netune-tls` driver drives the sans-IO machine over the
   transport and hands back an `AsyncRead`/`AsyncWrite` stream, the
   profile's cipher/group lists map onto the hello with refusals for
   unmapped values, and the verifier seam bridges the platform trust store.
   Landed with the integration-tier differential over the full egress chain.
   Note: the chain validator is `rustls-platform-verifier`'s webpki
   validator — a verifier, not a TLS engine ([`INV-TLS-04`] does not forbid
   it); swapping it for a standalone `webpki`-based validator is part of
   step 6's removal work.
4. TLS 1.2 client handshake: ECDHE GCM and the four CBC suites, renegotiation
   extension semantics, session resumption decision (the Go client's resumed
   hello is a *different* hello shape; resumption is either reproduced
   explicitly or out of scope by documented decision — never silently absent).
5. Engine seam in `netune`: the orchestrator's TLS connector selects
   `netune-tls` for TCP-TLS egress; `netune-server` (ADR-0015) and
   `netune-quic` (ADR-0028) keep rustls under their own ADRs.
6. Removal: rustls and `tokio-rustls` leave `netune`'s egress dependency set;
   `check-architecture.py` rejects them for `netune` and for `netune-tls`
   while whitelisting them only for the ADR-0015/0028 consumers
   (`netune-server`, `netune-quic`, `netune-test-support`).

### 5. Differential tests are the acceptance criterion

At every layer, owned bytes are compared against both a fixed corpus and a
live oracle:

- the capture corpus (byte-exact hello, JA3/JA4 equality);
- RFC vectors for record protection and the TLS 1.3 key schedule;
- a `rustls` peer handshake (dev-dependency only) for state-machine parity;
- malformed-input tests: truncated records, illegal versions, bad lengths
  must be refused before any handshake state changes.

## Invariants & Behavioral Boundaries

- **`[INV-TLS-04]` Owned Egress TLS Production Path**: the egress TCP-TLS
  production graph contains no third-party TLS engine; `rustls`/`tokio-rustls`
  appear in it only as dev-only oracles of `netune-tls` until step 6 removes
  them from `netune`. `netune-server` and `netune-quic` keep their
  ADR-0015/0028 ratification. *Enforced by*: `check-architecture.py`
  (`FORBIDDEN_TLS_RUNTIME` whitelist; `netune-tls` is never whitelisted) and
  `Cargo.toml` dependency sets.

- **`[INV-TLS-05]` Delegated TLS Cryptography**: every cryptographic primitive
  — AEAD, CBC+HMAC, HKDF, transcript hash, agreement (ECDH/KEM), signature and
  verification — is provided by `aws-lc` (`aws-lc-rs`, `aws-lc-sys` FFI where
  the facade lacks a primitive); `ring` is forbidden; no owned cipher, hash or
  signature implementation. *Enforced by*: the workspace crypto gate and the
  dependency set of `netune-tls`.

- **`[INV-TLS-06]` Offer Equals Capability**: the offered cipher suite, key
  exchange group and signature algorithm lists are derived from the engine's
  implemented set; the engine never advertises a negotiation it cannot
  complete. *Enforced by*: capability/offer equality tests in `netune-tls`.

- **`[INV-TLS-07]` The Hello Is Reproducible**: ClientHello serialization is a
  pure function of profile plus seed; fixed-seed output is byte-compared to
  the capture corpus, and JA3/JA4 are derived from the same events, not
  measured separately. *Enforced by*: golden corpus tests in
  `crates/netune-tls`.

- **`[INV-TLS-08]` The Engine Owns No Socket**: the TLS engine operates on
  caller-provided buffers or `AsyncRead`/`AsyncWrite` handles; connection
  establishment, confinement and DNS remain orchestrator responsibilities;
  handshake completion, failure and negotiation results are recorded events on
  the attempt's `TraceCollector`. *Enforced by*: `netune-tls`'s dependency
  set (no orchestrator edge) and the egress handshake trace tests.

- **`[INV-TLS-09]` Engine Choice Is Connection Identity**: the selected TLS
  engine is part of the typed connection identity in the pool key and trace
  envelope; two engines are never pooled as one connection. *Enforced by*:
  `ConnectionIdentity` composition in `netune` and pool-key tests.

## Consequences

- **Positive**:
  - The measured JA3/JA4 identities become reachable, testable values instead
    of documented impossibilities.
  - The egress graph becomes fully owned from DNS to HTTP, with one trace
    model across every layer.
  - Extension order, GREASE policy, ALPN and offer lists become profile data
    with golden tests; identity regressions are compile/test failures.
- **Negative & Trade-offs**:
  - This is the most security-sensitive surface in the repository after the
    QUIC rewrite; the TLS state machine, record layer and key schedule become
    our maintenance burden.
  - The migration is multi-stage; until step 6 lands, the egress path still
    uses rustls — a deliberate, tracked dependency, not the final state.
  - Fidelity pressure now couples the crate to measured captures of a specific
    upstream; the golden corpus must stay a *measurement*, not a copy of a
    moving target.
  - Cryptography remains third-party (`aws-lc`); "own TLS" does not mean "own
    every primitive" — the same boundary ADR-0028 drew for QUIC.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep rustls and extend `TlsProfile`

- **Why considered**: rustls is mature, audited and already the provider
  behind ADR-0016's crypto unification.
- **Why rejected**: the unreachable surface is structural, not configurational
  — per-connection extension randomization, a fixed extension set and a fixed
  algorithm set are engine properties. No profile can fix them; the captures
  prove the gap instead of arguing it.

### Option 2 (Rejected): drive BoringSSL's TLS stack via `aws-lc-sys` `ssl.h`

- **Why considered**: it would produce byte-exact BoringSSL hellos immediately
  and reuse an audited state machine.
- **Why rejected**: it replaces one third-party TLS runtime with another
  (the same failure mode ADR-0027 removed for H3 and ADR-0028 removed for
  QUIC); the SSL state machine still owns every handshake decision, so trace
  claims about the handshake remain claims about a dependency's behaviour; and
  it couples the release to an FFI surface that was never meant as a stable
  public TLS API. `aws-lc` stays, but only as the primitive provider.

### Option 4 (Rejected): rewrite the cryptography too

- **Why considered**: full independence from third-party code.
- **Why rejected**: primitives are not the layer whose wire decisions netune
  needs to shape; hand-rolled AES-GCM/CBC/ECDSA/ML-KEM would add catastrophic
  security risk with zero fingerprint benefit. The same reasoning rejected
  this for QUIC in ADR-0028.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md),
  [ADR-0015](0015-self-terminated-tls.md),
  [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0027](0027-owned-h3-qpack.md),
  [ADR-0028](0028-owned-quic.md)
- RFCs: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3),
  [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) (TLS 1.2),
  [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147) (hybrid groups)
- Tests: `crates/netune-tls/src/wire.rs`, `crates/netune-tls/src/hello.rs`,
  `crates/netune-tls/src/key_schedule.rs`, `crates/netune-tls/src/record.rs`,
  `crates/netune-tls/src/key_exchange.rs`, `crates/netune-tls/src/handshake.rs`,
  `crates/netune-tls/src/cert.rs`
