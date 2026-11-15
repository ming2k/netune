//! Egress-side key exchange: one ClientHello share per offered group.
//!
//! The groups are the raw wire numbers the hello offers ([`INV-TLS-06`]):
//! every group the engine can offer is implemented here, hybrids included.
//! The hybrid combiners are protocol logic owned by this crate; the
//! underlying operations — ECDH and ML-KEM encapsulation/decapsulation — are
//! `aws-lc` primitives ([`INV-TLS-05`]).
//!
//! The hybrid layouts are RFC 10024's, and they are deliberately not
//! uniform: X25519MLKEM768 puts the post-quantum element first (in shares
//! and in the shared secret), while SecP256r1MLKEM768 and
//! SecP384r1MLKEM1024 put the classical element first — the RFC notes the
//! group name does not adhere to the naming convention for exactly this
//! reason. Guessing a uniform order would agree with rustls and disagree
//! with the RFC; both halves of this module are pinned to the RFC's layout.

use thiserror::Error;

use aws_lc_rs::agreement;
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::kem::{self, DecapsulationKey};

/// `x25519`.
pub const GROUP_X25519: u16 = crate::wire::GROUP_X25519;
/// `secp256r1` (P-256).
pub const GROUP_SECP256R1: u16 = crate::wire::GROUP_SECP256R1;
/// `secp384r1` (P-384).
pub const GROUP_SECP384R1: u16 = crate::wire::GROUP_SECP384R1;
/// `secp521r1` (P-521).
pub const GROUP_SECP521R1: u16 = crate::wire::GROUP_SECP521R1;
/// `X25519MLKEM768`.
pub const GROUP_X25519_ML_KEM_768: u16 = crate::wire::GROUP_X25519_ML_KEM_768;
/// `SecP256r1MLKEM768`.
pub const GROUP_SECP256R1_ML_KEM_768: u16 = crate::wire::GROUP_SECP256R1_ML_KEM_768;
/// `SecP384r1MLKEM1024`.
pub const GROUP_SECP384R1_ML_KEM_1024: u16 = crate::wire::GROUP_SECP384R1_ML_KEM_1024;

/// Why a key share cannot be generated or agreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AgreementError {
    /// The group is not implemented; the hello must not offer it
    /// ([`INV-TLS-06`]).
    #[error("key exchange group {group:#06x} is not implemented by the engine")]
    UnsupportedGroup {
        /// The offending group.
        group: u16,
    },
    /// The peer's share has the wrong shape for its group.
    #[error("peer key share for group {group:#06x} has {got} bytes, expected {expected}")]
    MalformedShare {
        /// The group the share belongs to.
        group: u16,
        /// The share length received.
        got: usize,
        /// The share length the group requires.
        expected: usize,
    },
    /// An `aws-lc` primitive failed during agreement.
    #[error("key agreement failed for group {group:#06x}")]
    Failed {
        /// The group being agreed.
        group: u16,
    },
    /// The imported private scalar does not fit the group.
    #[error("private key of {got} bytes does not fit group {group:#06x}")]
    InvalidPrivate {
        /// The group the scalar belongs to.
        group: u16,
        /// The offending scalar length.
        got: usize,
    },
}

/// The layout of one hybrid group (RFC 10024 §4).
#[derive(Clone, Copy)]
struct HybridSpec {
    classical: &'static agreement::Algorithm,
    kem: &'static kem::Algorithm<kem::AlgorithmId>,
    /// The classical element's wire length (the same for both directions:
    /// public keys for ECDH).
    classical_len: usize,
    /// The ML-KEM ciphertext length (the server's PQ element).
    ciphertext_len: usize,
    /// RFC 10024 places the ML-KEM element first in X25519MLKEM768 and the
    /// classical element first in the SecP groups — in shares and in the
    /// shared secret alike.
    pq_first: bool,
}

impl HybridSpec {
    /// The client's share: the concatenation the RFC prescribes.
    fn client_share(&self, classical_public: &[u8], encapsulation_key: &[u8]) -> Vec<u8> {
        if self.pq_first {
            [encapsulation_key, classical_public].concat()
        } else {
            [classical_public, encapsulation_key].concat()
        }
    }

    /// The peer (server) share's wire length.
    fn peer_share_len(&self) -> usize {
        self.classical_len + self.ciphertext_len
    }

    /// The shared secret: the concatenation the RFC prescribes.
    fn shared_secret(&self, classical: &[u8], ml_kem: &[u8]) -> Vec<u8> {
        if self.pq_first {
            [ml_kem, classical].concat()
        } else {
            [classical, ml_kem].concat()
        }
    }
}

fn classical_spec(group: u16) -> Option<&'static agreement::Algorithm> {
    match group {
        GROUP_X25519 => Some(&agreement::X25519),
        GROUP_SECP256R1 => Some(&agreement::ECDH_P256),
        GROUP_SECP384R1 => Some(&agreement::ECDH_P384),
        GROUP_SECP521R1 => Some(&agreement::ECDH_P521),
        _ => None,
    }
}

fn classical_share_len(group: u16) -> Option<usize> {
    match group {
        GROUP_X25519 => Some(32),
        GROUP_SECP256R1 => Some(65),
        GROUP_SECP384R1 => Some(97),
        GROUP_SECP521R1 => Some(133),
        _ => None,
    }
}

fn hybrid_spec(group: u16) -> Option<HybridSpec> {
    match group {
        GROUP_X25519_ML_KEM_768 => Some(HybridSpec {
            classical: &agreement::X25519,
            kem: &kem::ML_KEM_768,
            classical_len: 32,
            ciphertext_len: 1088,
            pq_first: true,
        }),
        GROUP_SECP256R1_ML_KEM_768 => Some(HybridSpec {
            classical: &agreement::ECDH_P256,
            kem: &kem::ML_KEM_768,
            classical_len: 65,
            ciphertext_len: 1088,
            pq_first: false,
        }),
        GROUP_SECP384R1_ML_KEM_1024 => Some(HybridSpec {
            classical: &agreement::ECDH_P384,
            kem: &kem::ML_KEM_1024,
            classical_len: 97,
            ciphertext_len: 1568,
            pq_first: false,
        }),
        _ => None,
    }
}

/// Whether the engine implements `group` ([`INV-TLS-06`]): an offer is
/// derivable from this set, and a HelloRetryRequest outside it is refused.
#[must_use]
pub fn offerable_group(group: u16) -> bool {
    classical_spec(group).is_some() || hybrid_spec(group).is_some()
}

enum Private {
    Classical(agreement::PrivateKey),
    Hybrid {
        classical: agreement::PrivateKey,
        kem: DecapsulationKey,
        spec: HybridSpec,
    },
}

/// A generated client key share: the hello's wire bytes plus the private
/// state the ServerHello needs.
pub struct ClientKeyShare {
    /// The key-exchange group this share is for.
    pub group: u16,
    /// The `key_share` entry bytes for the ClientHello.
    pub share: Vec<u8>,
    private: Private,
}

impl std::fmt::Debug for ClientKeyShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientKeyShare")
            .field("group", &self.group)
            .field("share_len", &self.share.len())
            .finish_non_exhaustive()
    }
}

impl ClientKeyShare {
    /// Generate one client share per group, in offer order.
    ///
    /// # Errors
    /// [`AgreementError::UnsupportedGroup`] for a group the engine does not
    /// implement, or [`AgreementError::Failed`] when an `aws-lc` primitive
    /// fails.
    pub fn generate(groups: &[u16]) -> Result<Vec<Self>, AgreementError> {
        groups.iter().copied().map(Self::generate_one).collect()
    }

    fn generate_one(group: u16) -> Result<Self, AgreementError> {
        let failed = |_: Unspecified| AgreementError::Failed { group };
        let private = if let Some(algorithm) = classical_spec(group) {
            Private::Classical(agreement::PrivateKey::generate(algorithm).map_err(failed)?)
        } else if let Some(spec) = hybrid_spec(group) {
            Private::Hybrid {
                classical: agreement::PrivateKey::generate(spec.classical).map_err(failed)?,
                kem: DecapsulationKey::generate(spec.kem).map_err(failed)?,
                spec,
            }
        } else {
            return Err(AgreementError::UnsupportedGroup { group });
        };
        Ok(Self {
            group,
            share: public_share(group, &private)?,
            private,
        })
    }

    /// Import a fixed x25519 scalar, for deterministic tests and replay.
    ///
    /// # Errors
    /// [`AgreementError::UnsupportedGroup`] for a non-x25519 group,
    /// [`AgreementError::InvalidPrivate`] for a scalar of the wrong length,
    /// or [`AgreementError::Failed`] when the primitive refuses the key.
    pub fn x25519_from_private(group: u16, private_key: &[u8]) -> Result<Self, AgreementError> {
        if group != GROUP_X25519 {
            return Err(AgreementError::UnsupportedGroup { group });
        }
        if private_key.len() != 32 {
            return Err(AgreementError::InvalidPrivate {
                group,
                got: private_key.len(),
            });
        }
        let key = match agreement::PrivateKey::from_private_key(&agreement::X25519, private_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(AgreementError::InvalidPrivate {
                    group,
                    got: private_key.len(),
                });
            }
        };
        let private = Private::Classical(key);
        Ok(Self {
            group,
            share: public_share(group, &private)?,
            private,
        })
    }

    /// The shared secret with the server's `key_share` entry, in RFC 10024's
    /// layout for the group.
    ///
    /// # Errors
    /// [`AgreementError::MalformedShare`] when the peer share has the wrong
    /// length for its group, [`AgreementError::Failed`] when a primitive
    /// fails, or [`AgreementError::UnsupportedGroup`] for an unknown group.
    pub fn agree(&self, peer_share: &[u8]) -> Result<Vec<u8>, AgreementError> {
        let failed = AgreementError::Failed { group: self.group };
        match &self.private {
            Private::Classical(key) => {
                let expected = classical_share_len(self.group).ok_or(failed)?;
                if peer_share.len() != expected {
                    return Err(AgreementError::MalformedShare {
                        group: self.group,
                        got: peer_share.len(),
                        expected,
                    });
                }
                let algorithm = classical_spec(self.group).ok_or(failed)?;
                agreement::agree(
                    key,
                    agreement::UnparsedPublicKey::new(algorithm, peer_share),
                    failed,
                    |secret| Ok(secret.to_vec()),
                )
            }
            Private::Hybrid {
                classical,
                kem,
                spec,
            } => {
                if peer_share.len() != spec.peer_share_len() {
                    return Err(AgreementError::MalformedShare {
                        group: self.group,
                        got: peer_share.len(),
                        expected: spec.peer_share_len(),
                    });
                }
                // Split the peer share per the group's layout; the ECDH
                // element is the same size in both directions.
                let (first, second) = peer_share.split_at(if spec.pq_first {
                    spec.ciphertext_len
                } else {
                    spec.classical_len
                });
                let (classical_part, kem_part) = if spec.pq_first {
                    (second, first)
                } else {
                    (first, second)
                };
                let classical_secret = agreement::agree(
                    classical,
                    agreement::UnparsedPublicKey::new(spec.classical, classical_part),
                    failed,
                    |secret| Ok(secret.to_vec()),
                )?;
                let ml_kem_secret = kem
                    .decapsulate(kem::Ciphertext::from(kem_part))
                    .map_err(|_| failed)?;
                Ok(spec.shared_secret(&classical_secret, ml_kem_secret.as_ref()))
            }
        }
    }
}

/// The `key_share` entry bytes this side puts in the ClientHello, in
/// RFC 10024's layout for the group.
fn public_share(group: u16, private: &Private) -> Result<Vec<u8>, AgreementError> {
    let failed = |_: Unspecified| AgreementError::Failed { group };
    match private {
        Private::Classical(key) => Ok(key.compute_public_key().map_err(failed)?.as_ref().to_vec()),
        Private::Hybrid {
            classical,
            kem,
            spec,
        } => {
            let classical_public = classical.compute_public_key().map_err(failed)?;
            let encapsulation = kem.encapsulation_key().map_err(failed)?;
            let encapsulation_bytes = encapsulation
                .key_bytes()
                .map_err(|_| AgreementError::Failed { group })?;
            Ok(spec.client_share(classical_public.as_ref(), encapsulation_bytes.as_ref()))
        }
    }
}
