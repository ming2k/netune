//! TLS wire constants and framing helpers (ADR-0045 step 1).
//!
//! This module is the value space of the engine: extension types, cipher
//! suites, key-exchange groups and signature schemes as raw wire numbers,
//! plus the record/handshake framing primitives every layer above shares.
//! Numbers are the source of truth here on purpose — the engine's identity
//! surface is bytes, and rustls-shaped enums cannot express an offer rustls
//! does not implement ([`INV-TLS-06`]).

/// `server_name` (SNI).
pub const EXT_SERVER_NAME: u16 = 0x0000;
/// `status_request` (OCSP stapling offer).
pub const EXT_STATUS_REQUEST: u16 = 0x0005;
/// `supported_groups` (key-exchange groups).
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
/// `ec_point_formats`.
pub const EXT_EC_POINT_FORMATS: u16 = 0x000b;
/// `signature_algorithms`.
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// `alpn`.
pub const EXT_ALPN: u16 = 0x0010;
/// `signed_certificate_timestamp`.
pub const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
/// `padding` (RFC 7685).
pub const EXT_PADDING: u16 = 0x0015;
/// `extended_master_secret`.
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
/// `compress_certificate` (RFC 8879).
pub const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
/// `record_size_limit` (RFC 8449).
pub const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
/// `session_ticket` (RFC 5077).
pub const EXT_SESSION_TICKET: u16 = 0x0023;
/// `supported_versions`.
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// `pre_shared_key` (RFC 8446 §4.2.11).
pub const EXT_PRE_SHARED_KEY: u16 = 0x0029;
/// `psk_key_exchange_modes` (RFC 8446 §4.2.9).
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
/// `post_handshake_auth` (RFC 8446 §4.2.6).
pub const EXT_POST_HANDSHAKE_AUTH: u16 = 0x0031;
/// `cookie` (RFC 8446 §4.2.2).
pub const EXT_COOKIE: u16 = 0x002c;
/// `signature_algorithms_cert`.
pub const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 0x0032;
/// `key_share`.
pub const EXT_KEY_SHARE: u16 = 0x0033;
/// `application_settings` (ALPS, BoringSSL/Chrome).
pub const EXT_ALPS: u16 = 0x4469;
/// `renegotiation_info` (RFC 5746 secure renegotiation).
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// RFC 8879 certificate compression: `zlib`.
pub const CERT_COMP_ZLIB: u16 = 0x0001;
/// RFC 8879 certificate compression: `brotli`.
pub const CERT_COMP_BROTLI: u16 = 0x0002;

/// RFC 8446 §4.2.9 PSK key exchange mode: `psk_dhe_ke`.
pub const PSK_DHE_KE: u8 = 0x01;

/// All 16 RFC 8701 GREASE codepoints.
pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Whether `value` is an RFC 8701 GREASE codepoint (`0x?a?a` with equal bytes).
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && ((value >> 8) == (value & 0xff))
}

/// Select an RFC 8701 GREASE codepoint deterministically from a byte.
#[must_use]
pub const fn grease_at(index: u8) -> u16 {
    GREASE_VALUES[(index as usize) & 0x0f]
}

// -- cipher suites: the Go 1.28 `boringcrypto` offer, in Go's wire order ----

/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
pub const SUITE_ECDHE_ECDSA_AES_128_GCM: u16 = 0xc02b;
/// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
pub const SUITE_ECDHE_RSA_AES_128_GCM: u16 = 0xc02f;
/// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
pub const SUITE_ECDHE_ECDSA_AES_256_GCM: u16 = 0xc02c;
/// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
pub const SUITE_ECDHE_RSA_AES_256_GCM: u16 = 0xc030;
/// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
pub const SUITE_ECDHE_ECDSA_CHACHA20_POLY1305: u16 = 0xcca9;
/// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
pub const SUITE_ECDHE_RSA_CHACHA20_POLY1305: u16 = 0xcca8;
/// `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`.
pub const SUITE_ECDHE_ECDSA_AES_128_CBC: u16 = 0xc009;
/// `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`.
pub const SUITE_ECDHE_RSA_AES_128_CBC: u16 = 0xc013;
/// `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`.
pub const SUITE_ECDHE_ECDSA_AES_256_CBC: u16 = 0xc00a;
/// `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`.
pub const SUITE_ECDHE_RSA_AES_256_CBC: u16 = 0xc014;
/// `TLS_AES_128_GCM_SHA256` (TLS 1.3).
pub const SUITE_TLS13_AES_128_GCM: u16 = 0x1301;
/// `TLS_AES_256_GCM_SHA384` (TLS 1.3).
pub const SUITE_TLS13_AES_256_GCM: u16 = 0x1302;
/// `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3).
pub const SUITE_TLS13_CHACHA20_POLY1305: u16 = 0x1303;

// -- key-exchange groups: the 7-group hybrid-first Go offer -----------------

/// `X25519MLKEM768` (hybrid; Go's first group).
pub const GROUP_X25519_ML_KEM_768: u16 = 0x11ec;
/// `SecP256r1MLKEM768` (hybrid).
pub const GROUP_SECP256R1_ML_KEM_768: u16 = 0x11eb;
/// `SecP384r1MLKEM1024` (hybrid).
pub const GROUP_SECP384R1_ML_KEM_1024: u16 = 0x11ed;
/// `x25519`.
pub const GROUP_X25519: u16 = 0x001d;
/// `secp256r1` (P-256).
pub const GROUP_SECP256R1: u16 = 0x0017;
/// `secp384r1` (P-384).
pub const GROUP_SECP384R1: u16 = 0x0018;
/// `secp521r1` (P-521).
pub const GROUP_SECP521R1: u16 = 0x0019;

// -- signature schemes: the 13-scheme Go offer ------------------------------

/// `ml_dsa44` (ML-DSA-44, TLS 1.3 registry draft value).
pub const SIG_ML_DSA_44: u16 = 0x0904;
/// `ml_dsa65` (ML-DSA-65).
pub const SIG_ML_DSA_65: u16 = 0x0905;
/// `ml_dsa87` (ML-DSA-87).
pub const SIG_ML_DSA_87: u16 = 0x0906;
/// `rsa_pss_rsae_sha256`.
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// `ecdsa_secp256r1_sha256`.
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// `ed25519`.
pub const SIG_ED25519: u16 = 0x0807;
/// `rsa_pss_rsae_sha384`.
pub const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
/// `rsa_pss_rsae_sha512`.
pub const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
/// `rsa_pkcs1_sha256`.
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
/// `rsa_pkcs1_sha384`.
pub const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
/// `rsa_pkcs1_sha512`.
pub const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;
/// `ecdsa_secp384r1_sha384`.
pub const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
/// `ecdsa_secp521r1_sha512`.
pub const SIG_ECDSA_SECP521R1_SHA512: u16 = 0x0603;

/// Append a big-endian `u16`.
pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Append a big-endian `u24` (three bytes), the TLS handshake length form.
pub(crate) fn put_u24(out: &mut Vec<u8>, value: u32) {
    debug_assert!(value <= 0x00ff_ffff, "u24 overflow");
    out.push((value >> 16) as u8);
    out.push((value >> 8) as u8);
    out.push(value as u8);
}

/// Append a vector preceded by its `u16` byte length.
pub(crate) fn put_u16_length_vector(out: &mut Vec<u8>, body: &[u8]) {
    put_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

/// Append a vector preceded by its one-byte length.
pub(crate) fn put_u8_length_vector(out: &mut Vec<u8>, body: &[u8]) {
    debug_assert!(body.len() <= u8::MAX as usize, "u8 vector overflow");
    out.push(body.len() as u8);
    out.extend_from_slice(body);
}

/// Word pairs packed big-endian: the `supported_groups`,
/// `signature_algorithms` and `signature_algorithms_cert` body shape.
pub(crate) fn put_word_list(out: &mut Vec<u8>, words: &[u16]) {
    let mut body = Vec::with_capacity(words.len() * 2);
    for &word in words {
        put_u16(&mut body, word);
    }
    put_u16_length_vector(out, &body);
}
