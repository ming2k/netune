# Owned TLS Security Audit

This is the audit-readiness package for `netune-tls`, the owned egress TLS
engine. It is contributor-facing. The public production boundary is in
[`docs/reference/stability.md`](../../reference/stability.md) and
[`SECURITY.md`](../../../.github/SECURITY.md).

The owned engine is **Preview** until an independent audit is complete. A plain
egress TLS target uses rustls; the owned engine is selected only by a
`TlsProfile` or `netune-tls` (ADR-0054).

---

## 1. Audit target

Freeze an immutable commit/tag before the audit starts:

- crate: `crates/netune-tls`;
- engine: TLS 1.2 and TLS 1.3 client role;
- no client-certificate authentication;
- TLS 1.3 PSK resumption and session tickets;
- TLS 1.2 ECDHE GCM and the four offered CBC suites;
- RFC 8879 `compress_certificate` (zlib/brotli);
- certificate-chain validation via `rustls-webpki` + `webpki-root-certs`;
- the `aws-lc-sys` FFI boundary;
- no socket ownership (the async driver wraps a caller-provided transport).

The audit commit must not move during the engagement. Fixes are made on a
branch and supplied as a separate diff for re-review.

## 2. Threat model

### Assets

- TLS 1.3 traffic secrets and traffic keys;
- TLS 1.2 master secret, key block, MAC keys, CBC keys and IVs;
- TLS 1.3 resumption PSKs and session tickets;
- the server certificate chain being validated;
- the caller's application plaintext and its integrity.

### Adversaries

- a malicious or compromised origin;
- an active network attacker who can inject, reorder, truncate, replay or delay
  bytes;
- a malicious certificate chain or malformed DER;
- a peer that sends pathological record/hello sizes or endless interim states;
- a local attacker who can inspect process memory or crash dumps (out of scope
  for network correctness, in scope for key hygiene).

### Trust assumptions

- `aws-lc-rs` / `aws-lc-sys` primitives are correct;
- the OS RNG is correct;
- the caller supplies a verifier or trusts the configured root bundle;
- the caller does not deliberately disable certificate verification;
- system time is sane enough for certificate validity checks.

### Out of scope

- server-side TLS termination (`netune-server` uses rustls);
- QUIC packet protection (`netune-quic` has its own ADR-0028 ratification);
- side-channel attacks that require a co-resident attacker with cache
  measurement access beyond the documented model (the audit should still
  inspect constant-time code paths);
- application-level authentication or authorization above TLS.

## 3. Code and evidence map

| Layer | Module | Evidence |
| :--- | :--- | :--- |
| Wire framing | `wire`, `hello` | RFC 8448 / capture corpus, round-trip tests, fuzz |
| Key schedule | `key_schedule`, `key_exchange` | RFC 8448 §3 vectors, hybrid group tests |
| Record layer | `record`, `tls12` | RFC 8448, RFC 5246/7905, openssl CBC goldens, fuzz |
| Handshake | `handshake` | RFC 8448, live rustls differential, HRR, PSK, KeyUpdate |
| Certificate | `cert`, `verifier` | webpki chain validation, malformed DER tests |
| Async driver | `driver` | partial-I/O, fragmentation, short-read, live loopback |
| Session cache | `session` | ticket bounds, single-use, identity isolation |

Additional evidence to keep current:

- `crates/netune-tls/tests/fuzz.rs` PR and soak targets;
- `cargo nextest run -p netune-tls --all-features`;
- `cargo test --doc -p netune-tls --all-features`;
- `cargo clippy -p netune-tls --all-targets --all-features -- -D warnings`;
- `cargo deny check advisories licenses sources bans`;
- SBOM and the exact `Cargo.lock`;
- a reproducible-build recipe for the audit commit.

## 4. Unsafe and FFI inventory

The audit package must include every `unsafe` block and every `aws-lc-sys`
call. At the time of writing, the owned engine's unsafe surface is confined to:

- TLS 1.2 CBC EVP context setup and in-place encryption/decryption;
- the `aws-lc-sys` raw cipher/EVP entry points used because the safe facade
  does not expose caller-supplied IVs and the MD5+SHA1 legacy PRF.

Requirements:

- every block has a `// SAFETY:` argument naming its input invariants;
- no pointer escapes the block;
- the context is freed on every path, including error paths;
- key buffers are zeroized after use and on drop;
- `#![deny(unsafe_op_in_unsafe_fn)]` is enabled;
- `cargo miri` is not expected to execute FFI; use ASan/MSan fuzz builds for
  the unsafe path instead.

## 5. Secret lifecycle

- `Secret` (`key_schedule`) zeroizes its PRK bytes on drop.
- `TrafficKeys` zeroizes the key and static IV on drop.
- `RecordCipher12` zeroizes its MAC/key/IV material on drop.
- `ResumptionTicket` zeroizes its PSK on drop.
- The audit must verify that no `Clone` or `mem::take` path leaves an
  unzeroized copy behind, and that panic/unwind paths still run destructors.

Known audit question: `Vec` reallocation before drop leaves old allocations
unzeroized; the audit should decide whether a `zeroize`-based allocation policy
is required for key material.

## 6. Audit execution

1. **RFP and scope lock.** Send this document, the audit commit, `Cargo.lock`,
   and the build recipe to the auditor. Require TLS/crypto specialists.
2. **Kickoff.** Walk the threat model, module map, invariants, fuzz corpus and
   known gaps.
3. **Review and dynamic testing.** Auditor reviews code, runs its own harness,
   uses TLS-Attacker/tlsfuzzer-style malformed peers, checks constant-time
   behavior and key lifecycle.
4. **Findings.** Severity, reproduction, affected commit, and concrete fix.
5. **Remediation.** Every Critical/High fixed with a named regression test.
   Medium fixed or accepted with an owner and expiry.
6. **Re-audit.** The auditor reviews the fix diff and reruns the relevant
   harness.
7. **Publication.** Publish the report or an executive summary, link it from
   `SECURITY.md`, and update the stability page.

## 7. Acceptance criteria

The owned engine may move from **Preview** to **Stable** only when:

- the external report has no open Critical or High findings;
- every Medium finding is fixed or has a documented, dated risk acceptance;
- all audit action items name a test, gate, or invariant in this repository;
- the auditor re-tested the remediation diff;
- the exact audited commit and report are linked from `SECURITY.md`;
- the default engine decision is re-evaluated explicitly (rustls remains the
  default unless a separate ADR changes it);
- `cargo nextest`, doctests, clippy, deny and the TLS fuzz targets are green on
  the audited commit.

Until then, the engine remains opt-in and the public documentation says so.
