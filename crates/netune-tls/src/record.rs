//! The TLS record layer (RFC 8446 §5, RFC 5246 §6.2.3).
//!
//! Framing lives here; the handshake layer composes it. Plain records are
//! written and parsed exactly as the wire spells them; TLS 1.3 AEAD
//! protection (RFC 8446 §5.2) is applied and removed over `aws-lc` primitives
//! ([`INV-TLS-05`]): the sequence-derived nonce (§5.3), the record header as
//! additional data, and the zero-padded inner plaintext (§5.4).
//!
//! The engine owns no socket: every function here is a pure transform over
//! caller-provided buffers ([`INV-TLS-08`]).

use thiserror::Error;

use aws_lc_rs::aead::{self, Aad, NONCE_LEN, Nonce};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hmac;

use crate::ffi::cbc_transform;
use crate::zeroize::wipe;

/// `change_cipher_spec` (the only protected-record exception allowed on the
/// wire; the handshake layer decides what to do with it).
pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
/// `alert`.
pub const CONTENT_ALERT: u8 = 21;
/// `handshake`.
pub const CONTENT_HANDSHAKE: u8 = 22;
/// `application_data`.
pub const CONTENT_APPLICATION_DATA: u8 = 23;

/// The version byte pair a TLS 1.3 record header carries: the RFC 8446 §5.1
/// `legacy_record_version` 0x0303 for all flights after the first
/// ClientHello.
pub const LEGACY_VERSION_TLS13: u16 = 0x0303;
/// The version byte pair of the first ClientHello record: 0x0301 for TLS
/// 1.2-compatible framing (RFC 8446 §5.1, RFC 5246).
pub const LEGACY_VERSION_TLS12: u16 = 0x0301;

/// The fixed record header length: content type, version, 16-bit length.
pub const RECORD_HEADER_LEN: usize = 5;
/// The plaintext fragment ceiling: 2^14 bytes (RFC 8446 §5.1, RFC 5246 §6.2.1).
pub const MAX_PLAINTEXT_LEN: usize = 0x4000;
/// The record length ceiling: 2^14 + 256 (RFC 8446 §5.2).
pub const MAX_CIPHERTEXT_LEN: usize = 0x4000 + 256;

/// Why a record cannot be framed or protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RecordError {
    /// The input is shorter than the fixed 5-byte record header.
    #[error("record header of {got} bytes is shorter than the {RECORD_HEADER_LEN}-byte minimum")]
    TruncatedHeader {
        /// The offending input length.
        got: usize,
    },
    /// The declared payload length does not match the bytes present.
    #[error("record of {got} bytes does not match its declared header length of {declared}")]
    LengthMismatch {
        /// The bytes present.
        got: usize,
        /// The header's declared total length.
        declared: usize,
    },
    /// A key does not fit the AEAD algorithm it is bound to.
    #[error("key of {got} bytes does not fit the algorithm's {expected}-byte requirement")]
    InvalidKeyLength {
        /// The algorithm's required key length.
        expected: usize,
        /// The offending key length.
        got: usize,
    },
    /// A protected record payload exceeds the RFC 8446 §5.2 limit.
    #[error("protected record payload of {len} bytes exceeds the RFC 8446 limit of {max}")]
    RecordTooLarge {
        /// The offending payload length.
        len: usize,
        /// The RFC 8446 limit.
        max: usize,
    },
    /// AEAD authentication failed: the record is corrupt or forged, and the
    /// connection cannot continue.
    #[error("record authentication failed")]
    DecryptionFailed,
    /// The inner plaintext carried only zero padding: no content type byte
    /// remains after the RFC 8446 §5.4 strip.
    #[error("the inner plaintext carried no content type after zero-padding was stripped")]
    InnerPlaintextEmpty,
    /// A protected record's outer type is not `application_data`.
    #[error("protected record outer type {got:#04x} is not application_data")]
    OuterTypeNotApplicationData {
        /// The offending outer type.
        got: u8,
    },
    /// An `aws-lc` primitive refused the operation.
    #[error("record primitive refused the operation")]
    Crypto(#[from] Unspecified),
}

/// A parsed record header: the three fields every record begins with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// The outer content type.
    pub content_type: u8,
    /// The `legacy_record_version` pair.
    pub legacy_version: u16,
    /// The declared payload length.
    pub payload_len: u16,
}

impl RecordHeader {
    /// Parse the fixed 5-byte header.
    ///
    /// # Errors
    /// [`RecordError::TruncatedHeader`] when fewer than 5 bytes are present.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let Some(header) = bytes.get(..RECORD_HEADER_LEN) else {
            return Err(RecordError::TruncatedHeader { got: bytes.len() });
        };
        Ok(Self {
            content_type: header[0],
            legacy_version: u16::from_be_bytes([header[1], header[2]]),
            payload_len: u16::from_be_bytes([header[3], header[4]]),
        })
    }

    /// Encode the fixed 5-byte header.
    #[must_use]
    pub fn encode(&self) -> [u8; RECORD_HEADER_LEN] {
        let mut encoded = [0u8; RECORD_HEADER_LEN];
        encoded[0] = self.content_type;
        encoded[1..3].copy_from_slice(&self.legacy_version.to_be_bytes());
        encoded[3..5].copy_from_slice(&self.payload_len.to_be_bytes());
        encoded
    }
}

/// Write one unprotected record: header + payload, verbatim.
///
/// This is the shape of the first ClientHello record and of every record
/// before keys exist; the payload is framed as given, never re-framed.
#[must_use]
pub fn unprotected_record(content_type: u8, legacy_version: u16, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    record.extend_from_slice(
        RecordHeader {
            content_type,
            legacy_version,
            payload_len: payload.len() as u16,
        }
        .encode()
        .as_slice(),
    );
    record.extend_from_slice(payload);
    record
}

/// The per-record nonce: the static IV with the sequence number XORed into
/// its low eight bytes (RFC 8446 §5.3).
fn record_nonce(static_iv: &[u8; NONCE_LEN], sequence: u64) -> Result<Nonce, Unspecified> {
    let mut nonce = *static_iv;
    for (index, byte) in sequence.to_be_bytes().iter().enumerate() {
        nonce[NONCE_LEN - 8 + index] ^= byte;
    }
    Nonce::try_assume_unique_for_key(&nonce)
}

/// The TLS 1.2 record cipher parameters one direction derives from the key
/// block (RFC 5246 §6.3).
#[derive(Debug)]
pub enum RecordCipher12 {
    /// AES-GCM (RFC 5288): a 4-byte implicit salt from the key block and an
    /// 8-byte explicit per-record nonce (the sequence number) carried in the
    /// record.
    AesGcm {
        /// The AEAD key (16 or 32 bytes).
        key: Vec<u8>,
        /// The 4-byte implicit salt.
        salt: [u8; 4],
        /// The 8-byte explicit-nonce seed from the key block: the carried
        /// nonce is `seed XOR sequence`, the nonce `salt || carried`.
        explicit_seed: [u8; 8],
        /// AES-128 or AES-256.
        algorithm: &'static aead::Algorithm,
    },
    /// ChaCha20-Poly1305 (RFC 7905): a 12-byte implicit write IV and **no**
    /// explicit nonce — the nonce is the sequence number XORed into the IV,
    /// exactly the TLS 1.3 construction.
    ChaCha20 {
        /// The 32-byte AEAD key.
        key: Vec<u8>,
        /// The 12-byte implicit write IV.
        iv: [u8; 12],
    },
    /// AES-CBC with HMAC-SHA1 (RFC 5246 §6.2.3.2): a 16-byte explicit IV.
    ///
    /// The explicit IV is derived per record — `HMAC-SHA1(fixed_iv,
    /// sequence_number)`, truncated to the block size — so it is
    /// unpredictable to the peer, unique per record, and reproducible from
    /// the handshake's key material in tests. The key block's fixed IV is
    /// otherwise unused in TLS 1.1+ CBC; this gives it the job.
    AesCbcSha1 {
        /// The HMAC-SHA1 key.
        mac_key: Vec<u8>,
        /// The AES write key (16 or 32 bytes).
        write_key: Vec<u8>,
        /// The key block's otherwise-unused 16-byte fixed IV, used as the
        /// HMAC key that derives the per-record explicit IVs.
        fixed_iv: [u8; 16],
        /// AES-128 or AES-256.
        algorithm: &'static aws_lc_rs::cipher::Algorithm,
    },
}

impl Drop for RecordCipher12 {
    fn drop(&mut self) {
        match self {
            Self::AesGcm {
                key, explicit_seed, ..
            } => {
                wipe(key);
                wipe(explicit_seed);
            }
            Self::ChaCha20 { key, iv } => {
                wipe(key);
                wipe(iv);
            }
            Self::AesCbcSha1 {
                mac_key,
                write_key,
                fixed_iv,
                ..
            } => {
                wipe(mac_key);
                wipe(write_key);
                wipe(fixed_iv);
            }
        }
    }
}

/// The TLS 1.2 explicit IV for one CBC record.
fn cbc_record_iv(fixed_iv: &[u8; 16], sequence: u64) -> Result<[u8; 16], Unspecified> {
    let mac = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, fixed_iv),
        &sequence.to_be_bytes(),
    );
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&mac.as_ref()[..16]);
    Ok(iv)
}

/// The two record ciphers one TLS 1.2 key block yields: client first,
/// server second (RFC 5246 §6.3 — client MAC, server MAC, client key,
/// server key, client IV, server IV, all per the suite's sizes).
///
/// # Errors
/// [`RecordError::InvalidKeyLength`] when a key does not fit its
/// algorithm, or [`RecordError::Crypto`] when the primitive refuses.
pub fn record_ciphers_from_key_block(
    params: crate::tls12::Suite12Params,
    key_block: &[u8],
) -> Result<(RecordCipher12, RecordCipher12), RecordError> {
    use crate::tls12::Cipher12;
    if key_block.len() < params.key_block_len() {
        return Err(RecordError::LengthMismatch {
            got: key_block.len(),
            declared: params.key_block_len(),
        });
    }
    let mut cursor = 0;
    let mut take = |len: usize| {
        let slice = &key_block[cursor..cursor + len];
        cursor += len;
        slice
    };
    let mac_key_c = take(params.mac_len).to_vec();
    let mac_key_s = take(params.mac_len).to_vec();
    let key_c = take(params.key_len).to_vec();
    let key_s = take(params.key_len).to_vec();
    let iv_c: [u8; 16] = {
        let mut iv = [0u8; 16];
        iv[..params.fixed_iv_len].copy_from_slice(take(params.fixed_iv_len));
        iv
    };
    let iv_s: [u8; 16] = {
        let mut iv = [0u8; 16];
        iv[..params.fixed_iv_len].copy_from_slice(take(params.fixed_iv_len));
        iv
    };
    // One explicit-nonce seed, shared by both directions (it only feeds the
    // carried bytes, which each direction transmits itself).
    let explicit_seed: [u8; 8] = if params.explicit_len == 8 {
        let mut seed = [0u8; 8];
        seed.copy_from_slice(take(params.explicit_len));
        seed
    } else {
        [0u8; 8]
    };
    let client = match params.kind {
        Cipher12::AesGcm { bits } => {
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&iv_c[..4]);
            RecordCipher12::AesGcm {
                key: key_c,
                salt,
                explicit_seed,
                algorithm: if bits == 128 {
                    &aead::AES_128_GCM
                } else {
                    &aead::AES_256_GCM
                },
            }
        }
        Cipher12::ChaCha20 => RecordCipher12::ChaCha20 {
            key: key_c,
            iv: iv_c[..12]
                .try_into()
                .map_err(|_| RecordError::Crypto(Unspecified))?,
        },
        Cipher12::AesCbc { .. } => RecordCipher12::AesCbcSha1 {
            mac_key: mac_key_c,
            write_key: key_c,
            fixed_iv: iv_c,
            algorithm: if params.key_len == 16 {
                &aws_lc_rs::cipher::AES_128
            } else {
                &aws_lc_rs::cipher::AES_256
            },
        },
    };
    let server = match params.kind {
        Cipher12::AesGcm { bits } => {
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&iv_s[..4]);
            RecordCipher12::AesGcm {
                key: key_s,
                salt,
                explicit_seed,
                algorithm: if bits == 128 {
                    &aead::AES_128_GCM
                } else {
                    &aead::AES_256_GCM
                },
            }
        }
        Cipher12::ChaCha20 => RecordCipher12::ChaCha20 {
            key: key_s,
            iv: iv_s[..12]
                .try_into()
                .map_err(|_| RecordError::Crypto(Unspecified))?,
        },
        Cipher12::AesCbc { .. } => RecordCipher12::AesCbcSha1 {
            mac_key: mac_key_s,
            write_key: key_s,
            fixed_iv: iv_s,
            algorithm: if params.key_len == 16 {
                &aws_lc_rs::cipher::AES_128
            } else {
                &aws_lc_rs::cipher::AES_256
            },
        },
    };
    Ok((client, server))
}

/// Applies TLS 1.2 record protection in one direction
/// (RFC 5246 §6.2.3, RFC 5288, RFC 7905).
#[derive(Debug)]
pub struct RecordProtector12 {
    cipher: RecordCipher12,
}

/// Removes TLS 1.2 record protection in one direction.
#[derive(Debug)]
pub struct RecordUnprotector12 {
    cipher: RecordCipher12,
}

impl RecordUnprotector12 {
    /// Bind the record cipher of one direction.
    ///
    /// # Errors
    /// [`RecordError::InvalidKeyLength`] when a key does not fit its
    /// algorithm, or [`RecordError::Crypto`] when the primitive refuses.
    pub fn new(cipher: RecordCipher12) -> Result<Self, RecordError> {
        if let RecordCipher12::AesGcm { key, algorithm, .. } = &cipher
            && key.len() != algorithm.key_len()
        {
            return Err(RecordError::InvalidKeyLength {
                expected: algorithm.key_len(),
                got: key.len(),
            });
        }
        Ok(Self { cipher })
    }

    /// Open one record and return its content type and plaintext.
    ///
    /// The explicit nonce (GCM) or IV (CBC) is consumed from the record;
    /// the MAC is checked with a constant-time comparison after full
    /// processing, and every padding or MAC failure is one uniform error —
    /// a failed record is a connection killer, never a partial read
    /// (Lucky13's oracle is not exposed).
    ///
    /// # Errors
    /// [`RecordError::OuterTypeNotApplicationData`] never fires here — TLS
    /// 1.2 protected records carry their real type — but framing errors,
    /// [`RecordError::DecryptionFailed`] for authentication or padding
    /// failures, and [`RecordError::Crypto`] when the primitive refuses do.
    pub fn open(&self, sequence: u64, record: &[u8]) -> Result<(u8, Vec<u8>), RecordError> {
        let header = RecordHeader::parse(record)?;
        if usize::from(header.payload_len) > MAX_CIPHERTEXT_LEN {
            return Err(RecordError::RecordTooLarge {
                len: usize::from(header.payload_len),
                max: MAX_CIPHERTEXT_LEN,
            });
        }
        match &self.cipher {
            RecordCipher12::AesGcm {
                key,
                salt,
                explicit_seed: _,
                algorithm,
            } => {
                if header.legacy_version != LEGACY_VERSION_TLS13
                    || header.payload_len < 8 + algorithm.tag_len() as u16
                {
                    return Err(RecordError::LengthMismatch {
                        got: record.len(),
                        declared: RECORD_HEADER_LEN + 8 + algorithm.tag_len(),
                    });
                }
                if record.len() != RECORD_HEADER_LEN + usize::from(header.payload_len) {
                    return Err(RecordError::LengthMismatch {
                        got: record.len(),
                        declared: RECORD_HEADER_LEN + usize::from(header.payload_len),
                    });
                }
                let explicit = &record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + 8];
                let mut nonce = [0u8; NONCE_LEN];
                // RFC 5288 §3: nonce = salt (implicit) || explicit nonce.
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(explicit);
                // The AAD's length field is the plaintext length: payload
                // minus the explicit nonce and the tag (RFC 5246 §6.2.3.3).
                let plain_len = usize::from(header.payload_len) - 8 - algorithm.tag_len();
                let mut aad_header = header.encode();
                aad_header[3] = (plain_len >> 8) as u8;
                aad_header[4] = plain_len as u8;
                let mut aad = Vec::with_capacity(13);
                aad.extend_from_slice(&sequence.to_be_bytes());
                aad.extend_from_slice(&aad_header);
                let mut payload = record[RECORD_HEADER_LEN + 8..].to_vec();
                let unbound = aead::UnboundKey::new(algorithm, key)?;
                aead::LessSafeKey::new(unbound)
                    .open_in_place(
                        Nonce::try_assume_unique_for_key(&nonce)?,
                        Aad::from(aad.as_slice()),
                        &mut payload,
                    )
                    .map_err(|_| RecordError::DecryptionFailed)?;
                payload.truncate(plain_len);
                Ok((header.content_type, payload))
            }
            RecordCipher12::ChaCha20 { key, iv } => {
                if header.payload_len < aead::CHACHA20_POLY1305.tag_len() as u16 {
                    return Err(RecordError::LengthMismatch {
                        got: record.len(),
                        declared: RECORD_HEADER_LEN + aead::CHACHA20_POLY1305.tag_len(),
                    });
                }
                if record.len() != RECORD_HEADER_LEN + usize::from(header.payload_len) {
                    return Err(RecordError::LengthMismatch {
                        got: record.len(),
                        declared: RECORD_HEADER_LEN + usize::from(header.payload_len),
                    });
                }
                let mut nonce = *iv;
                for (index, byte) in sequence.to_be_bytes().iter().enumerate() {
                    nonce[4 + index] ^= byte;
                }
                let mut aad = Vec::with_capacity(13);
                aad.extend_from_slice(&sequence.to_be_bytes());
                aad.extend_from_slice(&record[..RECORD_HEADER_LEN]);
                let mut payload = record[RECORD_HEADER_LEN..].to_vec();
                let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)?;
                aead::LessSafeKey::new(unbound)
                    .open_in_place(
                        Nonce::try_assume_unique_for_key(&nonce)?,
                        Aad::from(aad.as_slice()),
                        &mut payload,
                    )
                    .map_err(|_| RecordError::DecryptionFailed)?;
                Ok((header.content_type, payload))
            }
            RecordCipher12::AesCbcSha1 {
                mac_key, write_key, ..
            } => {
                let mac_len = hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY
                    .digest_algorithm()
                    .output_len;
                let bits = match write_key.len() {
                    16 => 128,
                    32 => 256,
                    _ => unreachable!("the key length was checked at construction"),
                };
                if record.len() < RECORD_HEADER_LEN + 16 + 16 {
                    return Err(RecordError::LengthMismatch {
                        got: record.len(),
                        declared: RECORD_HEADER_LEN + 16 + 16,
                    });
                }
                if record.len() != RECORD_HEADER_LEN + usize::from(header.payload_len) {
                    return Err(RecordError::LengthMismatch {
                        got: record.len(),
                        declared: RECORD_HEADER_LEN + usize::from(header.payload_len),
                    });
                }
                let Ok(record_iv) =
                    <[u8; 16]>::try_from(&record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + 16])
                else {
                    return Err(RecordError::TruncatedHeader { got: record.len() });
                };
                let ciphertext = &record[RECORD_HEADER_LEN + 16..];
                if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
                    return Err(RecordError::DecryptionFailed);
                }
                let decrypted = cbc_transform(bits, write_key, record_iv, ciphertext, false)
                    .map_err(|_| RecordError::DecryptionFailed)?;

                // Strip the padding: the last byte is the pad length, and
                // every pad byte must equal it. A malformed shape is the
                // same uniform error as a MAC failure.
                let pad_len = decrypted[decrypted.len() - 1];
                if usize::from(pad_len) + mac_len + 1 > decrypted.len()
                    || decrypted[decrypted.len() - 1 - usize::from(pad_len)..decrypted.len() - 1]
                        .iter()
                        .any(|byte| *byte != pad_len)
                {
                    return Err(RecordError::DecryptionFailed);
                }
                let fragment_len = decrypted.len() - 1 - usize::from(pad_len) - mac_len;
                let fragment = &decrypted[..fragment_len];
                let mac = &decrypted[fragment_len..fragment_len + mac_len];

                // MAC over sequence || header (fragment length) || fragment.
                let mut expected_header = header.encode();
                expected_header[3] = (fragment_len >> 8) as u8;
                expected_header[4] = fragment_len as u8;
                let mut input = Vec::with_capacity(13 + fragment.len());
                input.extend_from_slice(&sequence.to_be_bytes());
                input.extend_from_slice(&expected_header);
                input.extend_from_slice(fragment);
                let expected = hmac::sign(
                    &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, mac_key),
                    &input,
                );
                if aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_ref(), mac)
                    .is_err()
                {
                    return Err(RecordError::DecryptionFailed);
                }
                Ok((header.content_type, fragment.to_vec()))
            }
        }
    }
}

impl RecordProtector12 {
    /// Bind the record cipher of one direction.
    ///
    /// # Errors
    /// [`RecordError::InvalidKeyLength`] when a key does not fit its
    /// algorithm, or [`RecordError::Crypto`] when the primitive refuses.
    pub fn new(cipher: RecordCipher12) -> Result<Self, RecordError> {
        if let RecordCipher12::AesGcm { key, algorithm, .. } = &cipher
            && key.len() != algorithm.key_len()
        {
            return Err(RecordError::InvalidKeyLength {
                expected: algorithm.key_len(),
                got: key.len(),
            });
        }
        Ok(Self { cipher })
    }

    /// Seal one application-data record: header, explicit nonce where the
    /// suite carries one, AEAD or HMAC+CBC.
    ///
    /// # Errors
    /// [`RecordError::RecordTooLarge`] past the RFC 5246 limit, or
    /// [`RecordError::Crypto`] when the primitive refuses.
    pub fn seal(
        &self,
        sequence: u64,
        content_type: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(RecordError::RecordTooLarge {
                len: plaintext.len(),
                max: MAX_PLAINTEXT_LEN,
            });
        }
        match &self.cipher {
            RecordCipher12::AesGcm {
                key,
                salt,
                explicit_seed,
                algorithm,
            } => {
                let unbound = aead::UnboundKey::new(algorithm, key)?;
                let key = aead::LessSafeKey::new(unbound);
                // The carried explicit nonce is the key block's seed XOR the
                // sequence number (the RFC allows any per-record value; the
                // carried bytes are what the receiver uses).
                let mut explicit = sequence.to_be_bytes();
                for (index, byte) in explicit_seed.iter().enumerate() {
                    explicit[index] ^= byte;
                }
                let ciphertext_len = plaintext.len() + key.algorithm().tag_len();
                let header = RecordHeader {
                    content_type,
                    legacy_version: LEGACY_VERSION_TLS13,
                    payload_len: (8 + ciphertext_len) as u16,
                }
                .encode();
                let mut nonce = [0u8; NONCE_LEN];
                // RFC 5288 §3: nonce = salt (implicit) || explicit nonce.
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(&explicit);
                // AAD: sequence number || record header, where the header's
                // length is the PLAINTEXT fragment length (RFC 5246
                // §6.2.3.3) — not the wire length.
                let mut aad_header = header;
                aad_header[3] = (plaintext.len() >> 8) as u8;
                aad_header[4] = plaintext.len() as u8;
                let mut aad = Vec::with_capacity(13);
                aad.extend_from_slice(&sequence.to_be_bytes());
                aad.extend_from_slice(&aad_header);
                let mut inner = plaintext.to_vec();
                key.seal_in_place_append_tag(
                    Nonce::try_assume_unique_for_key(&nonce)?,
                    Aad::from(aad.as_slice()),
                    &mut inner,
                )?;
                let mut record = Vec::with_capacity(RECORD_HEADER_LEN + 8 + ciphertext_len);
                record.extend_from_slice(&header);
                record.extend_from_slice(&explicit);
                record.extend_from_slice(&inner);
                Ok(record)
            }
            RecordCipher12::ChaCha20 { key, iv } => {
                let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)?;
                let key = aead::LessSafeKey::new(unbound);
                let ciphertext_len = plaintext.len() + key.algorithm().tag_len();
                let header = RecordHeader {
                    content_type,
                    legacy_version: LEGACY_VERSION_TLS13,
                    payload_len: ciphertext_len as u16,
                }
                .encode();
                // RFC 7905 §2: the 64-bit sequence number, left-padded with
                // four zero bytes, XORed into the write IV.
                let mut nonce = *iv;
                for (index, byte) in sequence.to_be_bytes().iter().enumerate() {
                    nonce[4 + index] ^= byte;
                }
                let mut aad = Vec::with_capacity(13);
                aad.extend_from_slice(&sequence.to_be_bytes());
                aad.extend_from_slice(&header);
                let mut inner = plaintext.to_vec();
                key.seal_in_place_append_tag(
                    Nonce::try_assume_unique_for_key(&nonce)?,
                    Aad::from(aad.as_slice()),
                    &mut inner,
                )?;
                let mut record = Vec::with_capacity(RECORD_HEADER_LEN + ciphertext_len);
                record.extend_from_slice(&header);
                record.extend_from_slice(&inner);
                Ok(record)
            }
            RecordCipher12::AesCbcSha1 {
                mac_key,
                write_key,
                fixed_iv,
                ..
            } => {
                let bits = match write_key.len() {
                    16 => 128,
                    32 => 256,
                    _ => unreachable!("the key length was checked at construction"),
                };
                // MAC over sequence || header (fragment length) || fragment.
                let header = RecordHeader {
                    content_type,
                    legacy_version: LEGACY_VERSION_TLS13,
                    payload_len: plaintext.len() as u16,
                }
                .encode();
                let mac = hmac::sign(
                    &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, mac_key),
                    &{
                        let mut input = Vec::with_capacity(13 + plaintext.len());
                        input.extend_from_slice(&sequence.to_be_bytes());
                        input.extend_from_slice(&header);
                        input.extend_from_slice(plaintext);
                        input
                    },
                );
                // padding: k pad bytes of value k plus the pad-length byte,
                // sized so the encrypted unit is block-aligned; a zero k is
                // legal (RFC 5246 §6.2.3.2) and keeps the shape minimal.
                let block = 16;
                let pad_len =
                    (block - ((plaintext.len() + mac.as_ref().len() + 1) % block)) % block;
                let mut padded = plaintext.to_vec();
                padded.extend_from_slice(mac.as_ref());
                padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
                padded.push(pad_len as u8);
                let record_iv = cbc_record_iv(fixed_iv, sequence)?;
                let encrypted = cbc_transform(bits, write_key, record_iv, &padded, true)?;
                let mut record = Vec::with_capacity(RECORD_HEADER_LEN + 16 + encrypted.len());
                record.extend_from_slice(&header);
                record[3] = ((16 + encrypted.len()) >> 8) as u8;
                record[4] = (16 + encrypted.len()) as u8;
                record.extend_from_slice(&record_iv);
                record.extend_from_slice(&encrypted);
                Ok(record)
            }
        }
    }
}

/// Removes TLS 1.3 AEAD record protection in one direction.
///
/// TLS uses independent read and write keys, so the two directions are two
/// objects; a compromise of one never reaches the other's state.
#[derive(Debug)]
pub struct RecordUnprotector13 {
    key: aead::LessSafeKey,
    static_iv: [u8; NONCE_LEN],
}

/// Applies TLS 1.3 AEAD record protection in one direction (RFC 8446 §5.2).
#[derive(Debug)]
pub struct RecordProtector13 {
    key: aead::LessSafeKey,
    static_iv: [u8; NONCE_LEN],
}

impl RecordProtector13 {
    /// Bind the AEAD algorithm, key and static IV of one direction.
    ///
    /// # Errors
    /// [`RecordError::InvalidKeyLength`] when the key does not fit the
    /// algorithm, or [`RecordError::Crypto`] when the primitive refuses.
    pub fn new(
        algorithm: &'static aead::Algorithm,
        key: &[u8],
        static_iv: [u8; NONCE_LEN],
    ) -> Result<Self, RecordError> {
        if key.len() != algorithm.key_len() {
            return Err(RecordError::InvalidKeyLength {
                expected: algorithm.key_len(),
                got: key.len(),
            });
        }
        let unbound = aead::UnboundKey::new(algorithm, key)?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound),
            static_iv,
        })
    }

    /// Seal one record: header, AEAD, and the inner plaintext's appended
    /// content type (RFC 8446 §5.4) — the full wire bytes.
    ///
    /// # Errors
    /// [`RecordError::RecordTooLarge`] when the ciphertext would exceed the
    /// RFC 8446 §5.2 limit, or [`RecordError::Crypto`] when the primitive
    /// refuses.
    pub fn seal(
        &self,
        sequence: u64,
        content_type: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        // Inner plaintext (RFC 8446 §5.4): content || content_type || zero
        // padding; no padding is ever needed here because the content type
        // byte is always present.
        let mut inner = Vec::with_capacity(plaintext.len() + 1 + self.key.algorithm().tag_len());
        inner.extend_from_slice(plaintext);
        inner.push(content_type);

        let ciphertext_len = inner.len() + self.key.algorithm().tag_len();
        if ciphertext_len > MAX_CIPHERTEXT_LEN {
            return Err(RecordError::RecordTooLarge {
                len: ciphertext_len,
                max: MAX_CIPHERTEXT_LEN,
            });
        }
        let header = RecordHeader {
            content_type: CONTENT_APPLICATION_DATA,
            legacy_version: LEGACY_VERSION_TLS13,
            payload_len: ciphertext_len as u16,
        }
        .encode();

        self.key.seal_in_place_append_tag(
            record_nonce(&self.static_iv, sequence)?,
            Aad::from(&header),
            &mut inner,
        )?;

        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + ciphertext_len);
        record.extend_from_slice(&header);
        record.extend_from_slice(&inner);
        Ok(record)
    }
}

impl RecordUnprotector13 {
    /// Bind the AEAD algorithm, key and static IV of one direction.
    ///
    /// # Errors
    /// [`RecordError::InvalidKeyLength`] when the key does not fit the
    /// algorithm, or [`RecordError::Crypto`] when the primitive refuses.
    pub fn new(
        algorithm: &'static aead::Algorithm,
        key: &[u8],
        static_iv: [u8; NONCE_LEN],
    ) -> Result<Self, RecordError> {
        if key.len() != algorithm.key_len() {
            return Err(RecordError::InvalidKeyLength {
                expected: algorithm.key_len(),
                got: key.len(),
            });
        }
        let unbound = aead::UnboundKey::new(algorithm, key)?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound),
            static_iv,
        })
    }

    /// Open one full record and return its inner content type and payload.
    ///
    /// Zero padding is stripped from the end (RFC 8446 §5.4); the last
    /// non-zero byte is the inner content type.
    ///
    /// # Errors
    /// [`RecordError::OuterTypeNotApplicationData`] for a protected record
    /// whose outer type is not `application_data`, framing errors for
    /// truncated or mismatched records, [`RecordError::DecryptionFailed`]
    /// when authentication fails, and [`RecordError::InnerPlaintextEmpty`]
    /// when no content type survives the padding strip.
    pub fn open(&self, sequence: u64, record: &[u8]) -> Result<(u8, Vec<u8>), RecordError> {
        let header = RecordHeader::parse(record)?;
        if header.content_type != CONTENT_APPLICATION_DATA {
            return Err(RecordError::OuterTypeNotApplicationData {
                got: header.content_type,
            });
        }
        if usize::from(header.payload_len) > MAX_CIPHERTEXT_LEN {
            return Err(RecordError::RecordTooLarge {
                len: usize::from(header.payload_len),
                max: MAX_CIPHERTEXT_LEN,
            });
        }
        if record.len() != RECORD_HEADER_LEN + usize::from(header.payload_len) {
            return Err(RecordError::LengthMismatch {
                got: record.len(),
                declared: RECORD_HEADER_LEN + usize::from(header.payload_len),
            });
        }
        if header.payload_len < self.key.algorithm().tag_len() as u16 + 1 {
            return Err(RecordError::InnerPlaintextEmpty);
        }

        let aad = Aad::from(&record[..RECORD_HEADER_LEN]);
        let mut payload = record[RECORD_HEADER_LEN..].to_vec();
        // `open_in_place` decrypts in place and returns the plaintext slice;
        // the tag area behind it is unspecified, so the Vec must be
        // truncated to what the slice covers before anything reads the end.
        let opened = self
            .key
            .open_in_place(record_nonce(&self.static_iv, sequence)?, aad, &mut payload)
            .map_err(|_| RecordError::DecryptionFailed)?;
        let opened_len = opened.len();
        payload.truncate(opened_len);

        // Strip zero padding from the end; the last non-zero byte is the
        // inner content type.
        let mut inner_len = payload.len();
        while inner_len > 0 && payload[inner_len - 1] == 0 {
            inner_len -= 1;
        }
        if inner_len == 0 {
            return Err(RecordError::InnerPlaintextEmpty);
        }
        let content_type = payload[inner_len - 1];
        Ok((content_type, payload[..inner_len - 1].to_vec()))
    }
}

#[cfg(test)]
mod tests;
