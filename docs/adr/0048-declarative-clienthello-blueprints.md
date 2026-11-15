---
id: ADR-0048
title: "Declarative ClientHello Blueprints and Universal TLS Fingerprint Shaping"
status: accepted
date: 2026-11-15
scope: [transport/tls, transport/customizability, protocol/rfc8701, protocol/rfc8879]
superseded_by: null
---

# 0048. Declarative ClientHello Blueprints and Universal TLS Fingerprint Shaping

- Status: Accepted
- Date: 2026-11-15
- Deciders: Ming Li
- Amends: [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md), [ADR-0045](0045-owned-egress-tls-engine.md)

---

## Context and Problem Statement

[ADR-0045](0045-owned-egress-tls-engine.md) replaced `rustls` on the egress
TCP-TLS path with `netune-tls`, giving `netune` full ownership of the
ClientHello wire format and handshake state machine. However, the profile layer
([`TlsProfile`](../../crates/netune/src/tls_profile.rs)) remained bound to
`ClientHello::go_identity`: it could narrow `alpn_protocols`, `cipher_suites`,
`kx_groups`, and `signature_algorithms`, but could not express:

1. **Extension composition and ordering** — fixed arbitrary extension sequences
   (Safari, Firefox, standard Go `crypto/tls`) or Chrome 106+ per-connection
   extension permutation (`Permute`).
2. **RFC 8701 GREASE** — synchronized GREASE values across cipher suites,
   `supported_groups`, `supported_versions`, `key_share`, and extension slots.
3. **RFC 7685 Padding** — dynamic padding computed from the serialized
   ClientHello length (such as BoringSSL/Chrome's 517-byte padding rule).
4. **Modern browser & Go extensions** — `session_ticket` (`0x0023`),
   `psk_key_exchange_modes` (`0x002d`), `post_handshake_auth` (`0x0031`),
   `record_size_limit` (`0x001c`), `application_settings` / ALPS (`0x4469`), and
   `compress_certificate` (`0x001b`, RFC 8879).
5. **Independent `key_share` vs `supported_groups` and `signature_algorithms_cert`** —
   clients frequently offer 7 `supported_groups` while sending `key_share`
   entries for only 1–3 of them, or omit `signature_algorithms_cert` while
   sending `signature_algorithms`.

Without these capabilities, `netune-tls` could impersonate Go 1.28
`boringcrypto` but could not act as a general-purpose, zero-compromise TLS
impersonation engine.

## Decision Outcome

`netune-tls` and `netune::TlsProfile` move cleanly (with no legacy compatibility
shacks) to **declarative ClientHello blueprints**:

1. **Typed extensions & blueprint model in `netune-tls::hello`**:
   - Typed `ExtensionBody` variants for `Grease`, `SessionTicket`, `Padding`,
     `CompressCertificate`, `RecordSizeLimit`, `PskKeyExchangeModes`,
     `PostHandshakeAuth`, and `Alps`, alongside the existing 12 extensions and
     `Raw`.
   - `ClientHelloBlueprint` describes a complete ClientHello as pure data:
     cipher suites (with optional GREASE slot), `supported_groups` (with optional
     GREASE slot), `key_share_groups` (independent of `supported_groups`, with
     optional GREASE entry), `signature_algorithms` and optional
     `signature_algorithms_cert`, `alpn`, `supported_versions` (with optional
     GREASE), `extension_slots` (ordered `ExtensionSlot` list),
     `extension_order` (`Fixed` or seeded `PermuteNonFixed`), and
     `padding` (`None`, `BoringSsl517`, or `TargetLen(usize)`).
   - `ClientHelloBlueprint::build` is a pure function of blueprint +
     per-connection randomness (`random`, `session_id`, `grease_seed`,
     `permutation_seed`, and generated `ClientKeyShare`s).
2. **`[INV-TLS-06]` upheld for every new offer**:
   - Advertising `compress_certificate` (`zlib = 0x0001`, `brotli = 0x0002`) is
     backed by RFC 8879 `CompressedCertificate` (`0x19`) decompression in
     `netune-tls::handshake` (transcript hashes the `CompressedCertificate`
     message; bounded decompression prevents zip-bombs).
   - Advertising `session_ticket` (`0x0023`) is backed by TLS 1.2
     `NewSessionTicket` (`0x04`) handling in `netune-tls::handshake` (RFC 5077).
   - `ClientHandshake::start` ignores GREASE `key_share` entries when matching
     generated `ClientKeyShare`s, while still refusing any server that attempts
     to select a GREASE value.
3. **Clean break in `netune::TlsProfile` and `Preset`**:
   - `TlsProfile` carries a `ClientHelloBlueprint` (with `alpn_protocols` and
     list/extension overrides) instead of hardcoding `ClientHello::go_identity`.
   - `Preset` ships `NetuneDefault`, `AntigravityCliStream`,
     `AntigravityCliUnary`, `GoStandard`, `ChromeCurrent`, `FirefoxCurrent`, and
     `SafariCurrent`.
4. **TLS 1.3 PSK Session Resumption (`netune-tls::session` + `TlsRouterConnector`)**:
   - `OwnedTlsStream` parses incoming `NewSessionTicket` (`0x04`) post-handshake
     messages, derives the resumption PSK from `resumption_master_secret`, and
     caches single-use tickets in `SessionCache` keyed by
     `(server_name, profile_name, alpn)` so identities never share tickets
     ([`INV-TLS-09`]).
   - Subsequent connections on blueprints offering `psk_key_exchange_modes`
     pop a cached ticket, append `pre_shared_key` (`0x0029`) with its computed
     RFC 8446 §4.2.11.2 binder, and complete the abbreviated handshake (or fall
     back to full handshake if the server declines PSK).

## Invariants

- **`[INV-TLS-11]` Seeded Hello Reproducibility**: Every per-connection
  non-deterministic choice in ClientHello construction (GREASE values, extension
  permutation, random, session id) is derived from caller-supplied seeds or
  CSPRNG inputs; fixed seeds yield byte-identical ClientHello bytes across runs.
- **`[INV-TLS-06]` Extended**: Any `compress_certificate` algorithm or
  `session_ticket` extension advertised by a blueprint is supported in the
  handshake state machine.
