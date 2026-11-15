//! TLS 1.2 key derivation and suite parameters (RFC 5246, RFC 4492,
//! RFC 5288, RFC 7905).
//!
//! Everything here is protocol logic over `aws-lc` primitives
//! ([`INV-TLS-05`]): the SHA-256/SHA-384 PRFs come from the `tls_prf`
//! facade, and the MD5+SHA1 dual PRF of the legacy `_SHA` suites comes from
//! the `aws-lc-sys` FFI — the one spell the facade does not expose, exactly
//! as the ADR anticipated.

use aws_lc_rs::digest::{self, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::tls_prf::{self, P_SHA256, P_SHA384};

use crate::key_schedule::ScheduleError;

/// The PRF a TLS 1.2 suite is keyed with (RFC 5246 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf12 {
    /// `P_SHA256` — the suites named `*_SHA256`.
    Sha256,
    /// `P_SHA384` — the suites named `*_SHA384`.
    Sha384,
    /// The MD5+SHA-1 dual PRF — the suites named `*_SHA` (CBC).
    Md5Sha1,
}

/// The hash a TLS 1.2 Finished is taken over (RFC 5246 §7.4.9): the PRF's
/// own hash, or the MD5||SHA-1 pair for the dual PRF.
pub fn handshake_hash(prf: Prf12, messages: &[u8]) -> Vec<u8> {
    match prf {
        Prf12::Sha256 => digest::digest(&SHA256, messages).as_ref().to_vec(),
        Prf12::Sha384 => digest::digest(&SHA384, messages).as_ref().to_vec(),
        Prf12::Md5Sha1 => {
            let mut hash = Vec::with_capacity(36);
            hash.extend_from_slice(&md5(messages));
            hash.extend_from_slice(digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, messages).as_ref());
            hash
        }
    }
}

/// The TLS 1.2 PRF (RFC 5246 §5).
///
/// # Errors
/// [`ScheduleError::Expand`] when the primitive refuses the length or the
/// empty secret.
pub fn prf12(
    prf: Prf12,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    length: usize,
) -> Result<Vec<u8>, ScheduleError> {
    match prf {
        Prf12::Sha256 => Ok(tls_prf::Secret::new(&P_SHA256, secret)?
            .derive(label, seed, length)?
            .as_ref()
            .to_vec()),
        Prf12::Sha384 => Ok(tls_prf::Secret::new(&P_SHA384, secret)?
            .derive(label, seed, length)?
            .as_ref()
            .to_vec()),
        Prf12::Md5Sha1 => md5_sha1_prf(secret, label, seed, length),
    }
}

/// The MD5+SHA-1 dual PRF, through the `aws-lc-sys` FFI: the facade's
/// `tls_prf` exposes only the modern single-hash PRFs, and `EVP_md5_sha1`
/// is the one spell BoringSSL carries for the legacy suites.
fn md5_sha1_prf(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    length: usize,
) -> Result<Vec<u8>, ScheduleError> {
    use aws_lc_sys::{CRYPTO_tls1_prf, EVP_md5_sha1};
    if secret.is_empty() || length == 0 {
        return Err(ScheduleError::Expand(Unspecified));
    }
    let mut out = vec![0u8; length];
    // SAFETY: `out` is written by the callee within `out_len`; the label
    // bytes are read-only for the callee and outlive the call.
    let written = unsafe {
        CRYPTO_tls1_prf(
            EVP_md5_sha1(),
            out.as_mut_ptr(),
            out.len(),
            secret.as_ptr(),
            secret.len(),
            label.as_ptr().cast(),
            label.len(),
            seed.as_ptr(),
            seed.len(),
            core::ptr::null(),
            0,
        )
    };
    if written != 1 {
        return Err(ScheduleError::Expand(Unspecified));
    }
    Ok(out)
}

/// The MD5 digest, through the same FFI (the facade does not expose MD5).
fn md5(data: &[u8]) -> [u8; 16] {
    use aws_lc_sys::{EVP_Digest, EVP_md5};
    let mut out = [0u8; 16];
    let mut written = 0u32;
    // SAFETY: `out` receives exactly 16 bytes of MD5 output.
    let result = unsafe {
        EVP_Digest(
            data.as_ptr().cast(),
            data.len(),
            out.as_mut_ptr(),
            &mut written,
            EVP_md5(),
            core::ptr::null_mut(),
        )
    };
    debug_assert!(
        result == 1 && written == 16,
        "MD5 through aws-lc cannot fail"
    );
    out
}

/// The master secret (RFC 5246 §8.1): the PRF over the pre-master secret
/// with the label `master secret` and the client/server randoms as seed.
///
/// # Errors
/// [`ScheduleError::Expand`] from the PRF.
pub fn master_secret(
    prf: Prf12,
    pre_master: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Result<Vec<u8>, ScheduleError> {
    let mut seed = Vec::with_capacity(client_random.len() + server_random.len());
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf12(prf, pre_master, b"master secret", &seed, 48)
}

/// The key block (RFC 5246 §6.3): the PRF over the master secret with the
/// label `key expansion` and the server/client randoms as seed — note the
/// reversed random order.
///
/// # Errors
/// [`ScheduleError::Expand`] from the PRF.
pub fn key_block(
    prf: Prf12,
    master: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    length: usize,
) -> Result<Vec<u8>, ScheduleError> {
    let mut seed = Vec::with_capacity(server_random.len() + client_random.len());
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    prf12(prf, master, b"key expansion", &seed, length)
}

/// The record-shape parameters of one TLS 1.2 suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite12Params {
    /// The PRF the suite's keys and Finished are derived with.
    pub prf: Prf12,
    /// The AEAD key length (0 for CBC suites: the key length below).
    pub key_len: usize,
    /// The MAC length: 0 for the AEAD suites, 20 for HMAC-SHA1 CBC.
    pub mac_len: usize,
    /// The implicit IV length from the key block: 4 for AES-GCM, 12 for
    /// ChaCha20-Poly1305 (RFC 7905), 16 for CBC.
    pub fixed_iv_len: usize,
    /// The explicit-nonce seed length from the key block: 8 for AES-GCM
    /// (RFC 5288 §3 allows any per-record value; the seed keeps the carried
    /// nonce unpredictable to an off-path observer), 0 elsewhere.
    pub explicit_len: usize,
    /// The record cipher shape.
    pub kind: Cipher12,
}

/// The record cipher shape of a TLS 1.2 suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher12 {
    /// AES-GCM (RFC 5288): 128 or 256 bit.
    AesGcm {
        /// AES-128 or AES-256.
        bits: u16,
    },
    /// ChaCha20-Poly1305 (RFC 7905).
    ChaCha20,
    /// AES-CBC with HMAC-SHA1 (RFC 5246): 128 or 256 bit.
    AesCbc {
        /// AES-128 or AES-256.
        bits: u16,
    },
}

impl Suite12Params {
    /// The total key-block length: per direction, MAC key + write key +
    /// fixed IV, plus one explicit-nonce seed shared by both directions
    /// (RFC 5246 §6.3; the AES-GCM suites carry an 8-byte seed, the others
    /// none).
    #[must_use]
    pub fn key_block_len(&self) -> usize {
        2 * (self.mac_len + self.key_len + self.fixed_iv_len) + self.explicit_len
    }
}

/// The TLS 1.2 suites the hello offers, with their record parameters.
///
/// The table is the offer's capability half ([`INV-TLS-06`]): all ten TLS
/// 1.2 suites the go-shaped hello advertises, nothing more.
#[must_use]
pub fn suite12(suite: u16) -> Option<Suite12Params> {
    let gcm = |bits, prf| Suite12Params {
        prf,
        key_len: usize::from(bits / 8),
        mac_len: 0,
        fixed_iv_len: 4,
        explicit_len: 8,
        kind: Cipher12::AesGcm { bits },
    };
    match suite {
        0xc02b | 0xc02f => Some(gcm(128, Prf12::Sha256)),
        0xc02c | 0xc030 => Some(gcm(256, Prf12::Sha384)),
        0xcca9 | 0xcca8 => Some(Suite12Params {
            prf: Prf12::Sha256,
            key_len: 32,
            mac_len: 0,
            fixed_iv_len: 12,
            explicit_len: 0,
            kind: Cipher12::ChaCha20,
        }),
        0xc009 | 0xc013 => Some(Suite12Params {
            prf: Prf12::Md5Sha1,
            key_len: 16,
            mac_len: 20,
            fixed_iv_len: 16,
            explicit_len: 0,
            kind: Cipher12::AesCbc { bits: 128 },
        }),
        0xc00a | 0xc014 => Some(Suite12Params {
            prf: Prf12::Md5Sha1,
            key_len: 32,
            mac_len: 20,
            fixed_iv_len: 16,
            explicit_len: 0,
            kind: Cipher12::AesCbc { bits: 256 },
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
