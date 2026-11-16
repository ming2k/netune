//! The owned egress TLS engine ([ADR-0045](https://github.com/ming2k/netune/blob/main/docs/adr/0045-owned-egress-tls-engine.md)).
//!
//! `netune-tls` owns the egress TCP-TLS handshake the way [`netune-quic`]
//! owns QUIC: the ClientHello serialization, the TLS 1.2/1.3 handshake state
//! machine and the record layer are workspace code, so every byte a
//! connection's first flight puts on the wire is a decision this workspace can
//! explain — and a `TlsProfile` can fully control.
//!
//! A rustls profile could never reach a measured non-rustls identity: rustls
//! randomizes extension order per connection, offers only the extensions and
//! algorithms rustls implements, and cannot offer the four CBC suites or the
//! hybrid groups a Go `boringcrypto` client offers. The capture corpus pinned
//! in [`hello`] is the acceptance criterion for that gap.
//!
//! # Layer plan (ADR-0045 §4)
//!
//! 1. **Wire model and hello forge** — landed: [`wire`] (framing and the
//!    primitive value spaces) and [`hello`] (typed ClientHello, byte-exact
//!    profiles, pure serialization).
//! 2. **Record layer and crypto wiring** — landed: [`key_schedule`] (the
//!    RFC 8446 §7.1 schedule, vectors from RFC 8448) and [`record`] (framing
//!    plus TLS 1.3 AEAD protection, ciphertexts from RFC 8448). Primitives
//!    from `aws-lc` ([`INV-TLS-05`]).
//! 3. **TLS 1.3 client handshake** — landed: [`handshake`] (the sans-IO
//!    state machine with HelloRetryRequest, certificate-verify checking and
//!    Finished verification) and [`key_exchange`] (all seven groups,
//!    hybrid combiners owned). Vectors: RFC 8448 §3 end-to-end, plus a live
//!    differential handshake against a `rustls` server.
//! 4. **TLS 1.2 client handshake (GCM + CBC)** — landed: [`handshake`] and
//!    [`tls12`] cover the ten offered TLS 1.2 suites, including the CBC
//!    EVP path, with RFC 5246/7905 rules and live differential peers.
//! 5. **Engine seam in the `netune` orchestrator** — landed: [`driver`] is the
//!    async `AsyncRead`/`AsyncWrite` wrapper, and `netune` selects it per
//!    target through `TlsProfile` / `TlsRouterConnector`.
//! 6. **rustls removal from the egress path** — landed: `netune` carries no
//!    rustls; the only TLS engine on the TCP-TLS path is this crate
//!    ([`INV-TLS-04`]).
//!
//! # Boundaries
//!
//! - No socket: the engine operates on caller-provided buffers and
//!   `AsyncRead`/`AsyncWrite` handles; connection establishment stays in the
//!   orchestrator ([`INV-TLS-08`]).
//! - No primitive is implemented here: AEAD, CBC+HMAC, HKDF, transcript hash,
//!   agreement, signature and verification come from `aws-lc`
//!   ([`INV-TLS-05`]); `ring` is forbidden.
//! - Never advertise what cannot be completed ([`INV-TLS-06`]): the offer list
//!   is derived from the capability list.
//! - No third-party TLS engine ships on this path ([`INV-TLS-04`]):
//!   `rustls`/`tokio-rustls` appear only as `dev-dependencies`.
//!
//! [`netune-quic`]: https://docs.rs/netune-quic
//!
//! # A note on identity claims
//!
//! The hello reproduces the *shape* of the measured identity: field order,
//! lists, versions and the JA3/JA4 fingerprints derived from them. Key shares,
//! randomness and session ids are per-connection values in every real client,
//! including the measured one; they are supplied (and later generated)
//! per connection, not pinned by the profile.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod cert;
pub mod driver;
mod ffi;
pub mod handshake;
pub mod hello;
pub mod key_exchange;
pub mod key_schedule;
pub mod record;
pub mod session;
pub mod tls12;
pub mod verifier;
pub mod wire;
mod zeroize;

pub use driver::{
    OwnedConnectParams, OwnedTlsConnector, OwnedTlsError, OwnedTlsStream, ProtectorsKind,
};
pub use hello::{ClientHello, ExtensionBody, GoIdentity, HelloError, KeyShareEntry, fill_random};
pub use key_schedule::{
    Hash, ScheduleError, Secret, TrafficKeys, empty_transcript_hash, transcript_hash,
};
pub use record::{
    CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE,
    LEGACY_VERSION_TLS12, LEGACY_VERSION_TLS13, MAX_CIPHERTEXT_LEN, MAX_PLAINTEXT_LEN,
    RECORD_HEADER_LEN, RecordError, RecordHeader, RecordProtector13, RecordUnprotector13,
    unprotected_record,
};
pub use verifier::{ChainError, Verifier};
