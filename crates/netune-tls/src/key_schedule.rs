//! The TLS 1.3 key schedule (RFC 8446 §7.1).
//!
//! Every primitive here comes from `aws-lc`: HKDF-Expand through
//! `aws_lc_rs::hkdf`, HKDF-Extract as the RFC 5869 §2.2 HMAC identity
//! (`PRK = HMAC-Hash(salt, IKM)`) signed by `aws_lc_rs::hmac`, and the
//! transcript hash through `aws_lc_rs::digest`. No construction in this
//! module implements a cipher, a hash, or HMAC itself ([`INV-TLS-05`]).
//!
//! The surface mirrors RFC 8446 §7.1 exactly, so an implementation can be
//! checked incrementally against RFC 8448, which publishes every
//! intermediate value of worked TLS 1.3 handshakes:
//!
//! - `Secret::extract` — the HKDF-Extract step of the schedule
//!   (early/handshake/master secrets);
//! - `Secret::derive_secret` — Derive-Secret(., label, transcript hash);
//! - `Secret::traffic_keys` — `tls13 key` / `tls13 iv` expansions;
//! - `Secret::finished_key` — `tls13 finished` expansion.
//!
//! Labels are the RFC's labels without the `tls13 ` prefix (the module adds
//! it, as the RFC's wire format does).

use thiserror::Error;

use aws_lc_rs::digest;
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hkdf::{self, Algorithm as HkdfAlgorithm, HKDF_SHA256, HKDF_SHA384};
use aws_lc_rs::hmac;

/// The transcript hash a TLS 1.3 cipher suite is keyed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// SHA-256 (`*_SHA256` suites).
    Sha256,
    /// SHA-384 (`*_SHA384` suites).
    Sha384,
}

impl Hash {
    /// The HKDF algorithm for this transcript hash.
    const fn hkdf_algorithm(self) -> HkdfAlgorithm {
        match self {
            Self::Sha256 => HKDF_SHA256,
            Self::Sha384 => HKDF_SHA384,
        }
    }

    /// The digest algorithm for transcript hashes.
    const fn digest_algorithm(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
        }
    }

    /// The output length of the transcript hash.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// The HMAC algorithm of the transcript hash, for the Finished MAC.
    #[must_use]
    pub fn hmac_algorithm(self) -> hmac::Algorithm {
        self.hkdf_algorithm().hmac_algorithm()
    }
}

/// Why a key-schedule step failed.
///
/// Every variant corresponds to an `aws-lc` primitive refusing an input; the
/// schedule's own parameters (32/48-byte secrets, ≤ 255·hash-len expansions)
/// cannot produce them, so a hit is a caller bug, not a data condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScheduleError {
    /// An `aws-lc` primitive refused the operation (length outside the
    /// RFC 5869 limits).
    #[error("key schedule primitive refused the operation")]
    Expand(#[from] Unspecified),
}

/// A secret in the schedule's middle stages: an HKDF PRK, kept raw because it
/// is consumed both as an expansion root and as the salt of the next extract
/// step (RFC 8446 §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    bytes: Vec<u8>,
    hash: Hash,
}

/// The traffic keys one traffic secret expands into.
///
/// The IV is the 12-byte per-record static IV every TLS 1.3 AEAD uses;
/// the per-record nonce XORs the record sequence into it
/// (RFC 8446 §5.3, §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficKeys {
    /// The AEAD key; its length is the negotiated suite's key length.
    pub key: Vec<u8>,
    /// The 12-byte static IV.
    pub iv: [u8; 12],
}

/// An expansion length adapter: `aws-lc-rs` types its HKDF-Expand output by
/// the `KeyType` requested, so a TLS schedule that expands 16- or 12-byte
/// keys and IVs names its length explicitly instead of borrowing the
/// algorithm's digest length.
struct ExactLen(usize);

impl hkdf::KeyType for ExactLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl Secret {
    /// HKDF-Extract (RFC 5869 §2.2), one step of the schedule.
    ///
    /// # Errors
    /// Infallible for the parameters a TLS 1.3 schedule produces; the HMAC
    /// primitive cannot refuse them.
    pub fn extract(salt: &[u8], ikm: &[u8], hash: Hash) -> Self {
        // PRK = HMAC-Hash(salt, IKM) — the HKDF-Extract identity.
        let key = hmac::Key::new(hash.hkdf_algorithm().hmac_algorithm(), salt);
        let tag = hmac::sign(&key, ikm);
        Self {
            bytes: tag.as_ref().to_vec(),
            hash,
        }
    }

    /// The transcript hash this secret's suite is keyed with.
    #[must_use]
    pub const fn hash(&self) -> Hash {
        self.hash
    }

    /// The raw secret bytes: the salt of the next extract step, and what an
    /// `SSLKEYLOGFILE`-style consumer needs.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// HKDF-Expand-Label (RFC 8446 §7.1): the `tls13 `-prefixed, length-
    /// prefixed label wire format over [`Secret::expand`].
    ///
    /// # Errors
    /// [`ScheduleError::Expand`] when the primitive refuses the length.
    pub fn hkdf_expand_label(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, ScheduleError> {
        let mut info = Vec::with_capacity(5 + label.len() + 6 + context.len());
        put_u16(&mut info, length as u16);
        info.push((label.len() + 6) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());
        // The context is itself a u8-length-prefixed vector (RFC 8446 §7.1).
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.expand(&info, length)
    }

    /// Derive-Secret(., label, transcript_hash) (RFC 8446 §7.1): the next
    /// secret of the schedule, usable as a traffic-secret root.
    ///
    /// # Errors
    /// [`ScheduleError::Expand`] when the primitive refuses the length.
    pub fn derive_secret(
        &self,
        label: &str,
        transcript_hash: &[u8],
    ) -> Result<Secret, ScheduleError> {
        Ok(Secret {
            bytes: self.hkdf_expand_label(label, transcript_hash, self.hash.output_len())?,
            hash: self.hash,
        })
    }

    /// The `tls13 key` / `tls13 iv` pair this traffic secret expands into
    /// (RFC 8446 §7.3). `key_len` is the negotiated suite's AEAD key length.
    ///
    /// # Errors
    /// [`ScheduleError::Expand`] when the primitive refuses the length.
    pub fn traffic_keys(&self, key_len: usize) -> Result<TrafficKeys, ScheduleError> {
        let key = self.hkdf_expand_label("key", &[], key_len)?;
        let iv = self.hkdf_expand_label("iv", &[], 12)?;
        let mut static_iv = [0u8; 12];
        static_iv.copy_from_slice(&iv);
        Ok(TrafficKeys { key, iv: static_iv })
    }

    /// The `tls13 finished` verify data base key for this traffic secret
    /// (RFC 8446 §4.4.4): HKDF-Expand-Label with an empty context and the
    /// hash's output length.
    ///
    /// # Errors
    /// [`ScheduleError::Expand`] when the primitive refuses the length.
    pub fn finished_key(&self) -> Result<Vec<u8>, ScheduleError> {
        self.hkdf_expand_label("finished", &[], self.hash.output_len())
    }

    /// HKDF-Expand (RFC 5869 §2.3) through `aws_lc_rs::hkdf`.
    ///
    /// # Errors
    /// [`ScheduleError::Expand`] when the requested length exceeds the
    /// RFC 5869 limit.
    fn expand(&self, info: &[u8], length: usize) -> Result<Vec<u8>, ScheduleError> {
        let prk = hkdf::Prk::new_less_safe(self.hash.hkdf_algorithm(), &self.bytes);
        let info_slices = [info];
        let okm = prk.expand(&info_slices, ExactLen(length))?;
        let mut out = vec![0u8; length];
        okm.fill(&mut out)?;
        Ok(out)
    }
}

/// The transcript hash of one or more handshake messages (RFC 8446 §7.1).
#[must_use]
pub fn transcript_hash(hash: Hash, messages: &[u8]) -> Vec<u8> {
    digest::digest(hash.digest_algorithm(), messages)
        .as_ref()
        .to_vec()
}

/// The transcript hash of no messages: the digest algorithm's output over
/// the empty input, as the schedule's first `derived` step needs.
#[must_use]
pub fn empty_transcript_hash(hash: Hash) -> Vec<u8> {
    digest::digest(hash.digest_algorithm(), &[])
        .as_ref()
        .to_vec()
}

/// Append a big-endian `u16`.
fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests;
