//! The chain validator: trust is a policy, verification is a primitive.
//!
//! The handshake's [`ServerCertVerifier`](crate::handshake::ServerCertVerifier)
//! seam takes the trust decision; this module implements the policies:
//!
//! - [`Verifier::WebpkiRoots`] — the Mozilla root bundle
//!   (`webpki-root-certs`) validated by `webpki` (the `rustls-webpki` crate), the standalone X.509
//!   path validator. A validator is a verifier, not a TLS engine:
//!   [`INV-TLS-04`] forbids third-party TLS *engines*, not validation
//!   primitives.
//! - [`Verifier::Pinned`] — exactly one anchor certificate; the pinned-CA
//!   test and corporate-root shape.
//!
//! The owned code does not implement signature algorithms or path building:
//! both are `webpki`'s, driven by `aws-lc`'s verification algorithms
//! ([`INV-TLS-05`]).

use thiserror::Error;

use rustls_pki_types as pki_types;
use webpki::EndEntityCert;

/// Which trust anchors a chain is validated against.
#[derive(Debug, Clone)]
pub enum Verifier {
    /// The Mozilla root bundle validated by `rustls-webpki`.
    WebpkiRoots,
    /// Exactly one anchor certificate (DER); the presented chain must lead
    /// to it, and the end entity must be the anchor itself for a self-signed
    /// test identity.
    Pinned(Vec<u8>),
}

/// Why a chain was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChainError {
    /// The chain did not validate against the anchors.
    #[error("the certificate chain did not validate: {reason}")]
    Validation {
        /// The validator's reason.
        reason: String,
    },
    /// The DER does not parse as a certificate.
    #[error("the end-entity certificate does not parse")]
    Malformed,
    /// The name is not a DNS name or IP address the certificate can cover.
    #[error("the server name is not coverable: {name}")]
    UnsupportedName {
        /// The offending name.
        name: String,
    },
}

impl crate::handshake::ServerCertVerifier for Verifier {
    fn verify_chain(
        &mut self,
        server_name: &str,
        end_entity: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), String> {
        verify_chain(self, server_name, end_entity, intermediates)
            .map_err(|error| error.to_string())
    }
}

/// Validate a server chain for one name against the policy's anchors.
///
/// The chain must reach one of the anchors, be currently valid, carry the
/// server-authentication EKU, and cover `server_name` — the full RFC 5280
/// shape `rustls-webpki` enforces.
pub fn verify_chain(
    policy: &Verifier,
    server_name: &str,
    end_entity: &[u8],
    intermediates: &[Vec<u8>],
) -> Result<(), ChainError> {
    let der = pki_types::CertificateDer::from(end_entity.to_vec());
    let end = EndEntityCert::try_from(&der).map_err(|_| ChainError::Malformed)?;
    let intermediates: Vec<pki_types::CertificateDer<'_>> = intermediates
        .iter()
        .map(|der| pki_types::CertificateDer::from(der.clone()))
        .collect();
    let name = parse_name(server_name)?;

    end.verify_is_valid_for_subject_name(&name)
        .map_err(|error| ChainError::Validation {
            reason: error.to_string(),
        })?;

    let time = current_time();
    match policy {
        Verifier::WebpkiRoots => {
            let anchors: Vec<pki_types::TrustAnchor<'_>> = webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|cert| {
                    // A parse failure would be a bundle defect, not a
                    // data condition; surface it as one typed refusal.
                    webpki::anchor_from_trusted_cert(cert).map_err(|error| ChainError::Validation {
                        reason: format!("Mozilla root bundle: {error}"),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            end.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &intermediates,
                time,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map(|_| ())
            .map_err(|error| ChainError::Validation {
                reason: error.to_string(),
            })
        }
        Verifier::Pinned(anchor_der) => {
            let anchor_cert = pki_types::CertificateDer::from(anchor_der.clone());
            let anchor = webpki::anchor_from_trusted_cert(&anchor_cert).map_err(|error| {
                ChainError::Validation {
                    reason: error.to_string(),
                }
            })?;
            // A self-signed pinned identity is its own anchor: the end entity
            // must be the anchor, and its signature self-checks through the
            // path validator with an empty intermediate set.
            end.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &[anchor],
                &intermediates,
                time,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map(|_| ())
            .map_err(|error| ChainError::Validation {
                reason: error.to_string(),
            })
        }
    }
}

/// Parse a server name into webpki's name form; only DNS names and IP
/// addresses are coverable (RFC 6125).
fn parse_name(name: &str) -> Result<pki_types::ServerName<'static>, ChainError> {
    pki_types::ServerName::try_from(name.to_string()).map_err(|_| ChainError::UnsupportedName {
        name: name.to_string(),
    })
}

/// The validator's notion of "now": wall clock, RFC 5280 validity.
fn current_time() -> pki_types::UnixTime {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    pki_types::UnixTime::since_unix_epoch(now)
}
