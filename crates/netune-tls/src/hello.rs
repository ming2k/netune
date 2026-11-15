//! The typed ClientHello: identity as data, serialization as a pure function.
//!
//! A profile decides what the hello *says*; this module decides how it is
//! *written*, and never the other way around. Extension order is first-class
//! data ([`ClientHello::extensions`] is a plain `Vec`), because order is part
//! of the fingerprint: the measured Go `boringcrypto` hello carries twelve
//! extensions in a fixed order, byte-identical across every capture.
//!
//! The acceptance criterion is the 1.5.9 capture corpus (see
//! [`ClientHello::go_identity`]): serialized fixed-seed output parses back
//! into the same lists, in the same order, and produces the measured JA3
//! (`03117a8ed39ef02427ebbc39f121275c`) and JA4 fingerprints
//! (`t13d1312h1_f57a46bbacb6_f50d94e863eb` for the unary offer,
//! `t13d1312h2_…` for the stream offer).
//!
//! Serialization is fallible: a hello that cannot be encoded on the wire is
//! refused, never truncated ([`INV-TLS-07`]).

use thiserror::Error;

use crate::wire::{
    CERT_COMP_BROTLI, CERT_COMP_ZLIB, EXT_ALPN, EXT_ALPS, EXT_COMPRESS_CERTIFICATE,
    EXT_EC_POINT_FORMATS, EXT_EXTENDED_MASTER_SECRET, EXT_KEY_SHARE, EXT_PADDING,
    EXT_POST_HANDSHAKE_AUTH, EXT_PRE_SHARED_KEY, EXT_PSK_KEY_EXCHANGE_MODES, EXT_RECORD_SIZE_LIMIT,
    EXT_RENEGOTIATION_INFO, EXT_SERVER_NAME, EXT_SESSION_TICKET, EXT_SIGNATURE_ALGORITHMS,
    EXT_SIGNATURE_ALGORITHMS_CERT, EXT_SIGNED_CERTIFICATE_TIMESTAMP, EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS, EXT_SUPPORTED_VERSIONS, GROUP_SECP256R1, GROUP_SECP256R1_ML_KEM_768,
    GROUP_SECP384R1, GROUP_SECP384R1_ML_KEM_1024, GROUP_SECP521R1, GROUP_X25519,
    GROUP_X25519_ML_KEM_768, PSK_DHE_KE, SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SECP521R1_SHA512, SIG_ED25519, SIG_ML_DSA_44, SIG_ML_DSA_65, SIG_ML_DSA_87,
    SIG_RSA_PKCS1_SHA256, SIG_RSA_PKCS1_SHA384, SIG_RSA_PKCS1_SHA512, SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512, SUITE_ECDHE_ECDSA_AES_128_CBC,
    SUITE_ECDHE_ECDSA_AES_128_GCM, SUITE_ECDHE_ECDSA_AES_256_CBC, SUITE_ECDHE_ECDSA_AES_256_GCM,
    SUITE_ECDHE_ECDSA_CHACHA20_POLY1305, SUITE_ECDHE_RSA_AES_128_CBC, SUITE_ECDHE_RSA_AES_128_GCM,
    SUITE_ECDHE_RSA_AES_256_CBC, SUITE_ECDHE_RSA_AES_256_GCM, SUITE_ECDHE_RSA_CHACHA20_POLY1305,
    SUITE_TLS13_AES_128_GCM, SUITE_TLS13_AES_256_GCM, SUITE_TLS13_CHACHA20_POLY1305, grease_at,
    put_u8_length_vector, put_u16, put_u16_length_vector, put_u24, put_word_list,
};

/// Why a hello cannot be put on the wire.
///
/// Refusal beats truncation: every variant names the field that overflowed,
/// and the identity that produced the bad value can be fixed instead of
/// silently mangled.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HelloError {
    /// An extension body exceeds the 65,535-byte extension vector limit.
    #[error("extension {kind:#06x} body of {len} bytes exceeds the 65,535-byte wire limit")]
    ExtensionTooLarge {
        /// The extension's wire type.
        kind: u16,
        /// The offending body length.
        len: usize,
    },
    /// The combined extension block exceeds the 65,535-byte limit.
    #[error("extension block of {len} bytes exceeds the 65,535-byte wire limit")]
    ExtensionBlockTooLarge {
        /// The offending block length.
        len: usize,
    },
    /// The session id exceeds the 32-byte limit (RFC 5246 §7.4.1.2).
    #[error("session id of {len} bytes exceeds the 32-byte RFC 5246 limit")]
    SessionIdTooLong {
        /// The offending session id length.
        len: usize,
    },
    /// The cipher list exceeds the 65,535-byte vector limit.
    #[error("cipher list of {len} suites exceeds the 65,535-byte wire limit")]
    CipherListTooLarge {
        /// The offending suite count.
        len: usize,
    },
    /// An ALPN protocol name is empty (RFC 7301 §3.1 forbids it).
    #[error("ALPN protocol names must be non-empty (RFC 7301 §3.1)")]
    EmptyProtocolName,
    /// A key share entry is empty; a real offer never carries one.
    #[error("key share for group {group:#06x} is empty")]
    EmptyKeyShare {
        /// The group whose share is empty.
        group: u16,
    },
    /// The hello body exceeds the 16,777,215-byte handshake message limit.
    #[error("hello body of {len} bytes exceeds the 16,777,215-byte handshake limit")]
    HelloTooLarge {
        /// The offending body length.
        len: usize,
    },
}

/// One `pre_shared_key` identity entry (RFC 8446 §4.2.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskIdentity {
    /// Opaque ticket bytes.
    pub identity: Vec<u8>,
    /// `obfuscated_ticket_age` in milliseconds.
    pub obfuscated_ticket_age: u32,
}

/// One `key_share` entry: a group and its opaque share bytes.
///
/// Share contents are per-connection randomness in every real client; the
/// profile pins the *groups*, never the shares. Generation is wired with the
/// crypto layer (ADR-0045 step 2); until then callers supply measured-shape
/// shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// The key-exchange group the share belongs to.
    pub group: u16,
    /// The opaque share bytes, non-empty.
    pub share: Vec<u8>,
}

/// A ClientHello extension body.
///
/// Typed variants encode and validate themselves; `Raw` carries an explicit
/// body for extensions the engine does not yet type. The wire *type* is
/// derived from the body, so a list of [`Extension`]s is simultaneously an
/// order declaration and a well-formedness guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionBody {
    /// `server_name`: exactly one `host_name` entry.
    ServerName {
        /// The name sent as `host_name`.
        name: String,
    },
    /// `ec_point_formats`.
    EcPointFormats {
        /// One-byte point format codes, in offer order.
        formats: Vec<u8>,
    },
    /// `renegotiation_info` for an initial (non-renegotiating) hello: the
    /// one-byte empty offer every shipped stack sends — OpenSSL, BoringSSL
    /// and the RFC 8448 §3 trace all carry a single `0x00` byte.
    RenegotiationInfo,
    /// `extended_master_secret` offer: empty body.
    ExtendedMasterSecret,
    /// `signed_certificate_timestamp` offer: empty body.
    SignedCertificateTimestamp,
    /// `status_request`: OCSP status request with empty responder id list
    /// and empty request extensions (RFC 6961 shape).
    StatusRequest,
    /// `supported_groups`.
    SupportedGroups {
        /// Groups in offer order; order is part of the fingerprint.
        groups: Vec<u16>,
    },
    /// `signature_algorithms`.
    SignatureAlgorithms {
        /// Signature schemes in offer order.
        schemes: Vec<u16>,
    },
    /// `signature_algorithms_cert`.
    SignatureAlgorithmsCert {
        /// Signature schemes in offer order.
        schemes: Vec<u16>,
    },
    /// `alpn` (RFC 7301).
    Alpn {
        /// Protocol names in offer order; empty names are refused at
        /// serialization.
        protocols: Vec<Vec<u8>>,
    },
    /// `supported_versions`.
    SupportedVersions {
        /// Versions in offer order.
        versions: Vec<u16>,
    },
    /// `key_share` (RFC 8446 §4.2.8).
    KeyShare {
        /// Entries in offer order; the measured hello offers the hybrid
        /// group first, then `x25519`.
        shares: Vec<KeyShareEntry>,
    },
    /// RFC 8701 GREASE extension slot.
    Grease {
        /// An RFC 8701 GREASE codepoint (`0x?a?a`).
        kind: u16,
        /// Optional opaque body (empty or `[0x00]`).
        body: Vec<u8>,
    },
    /// `padding` (RFC 7685): `len` zero bytes.
    Padding {
        /// Number of zero bytes.
        len: usize,
    },
    /// `compress_certificate` (RFC 8879).
    CompressCertificate {
        /// Compression algorithms in preference order.
        algorithms: Vec<u16>,
    },
    /// `record_size_limit` (RFC 8449).
    RecordSizeLimit {
        /// Maximum record plaintext size in bytes.
        limit: u16,
    },
    /// `session_ticket` (RFC 5077).
    SessionTicket {
        /// Ticket bytes (empty on an initial handshake).
        ticket: Vec<u8>,
    },
    /// `psk_key_exchange_modes` (RFC 8446 §4.2.9).
    PskKeyExchangeModes {
        /// Modes in preference order (e.g. `PSK_DHE_KE = 0x01`).
        modes: Vec<u8>,
    },
    /// `post_handshake_auth` (RFC 8446 §4.2.6): empty body.
    PostHandshakeAuth,
    /// `application_settings` (ALPS, BoringSSL/Chrome).
    Alps {
        /// Supported ALPN protocol names for ALPS.
        protocols: Vec<Vec<u8>>,
    },
    /// `pre_shared_key` (RFC 8446 §4.2.11). Must be the last extension.
    PreSharedKey {
        /// Offered ticket identities.
        identities: Vec<PskIdentity>,
        /// Binders over the truncated ClientHello.
        binders: Vec<Vec<u8>>,
    },
    /// An extension the engine does not type yet, carried as opaque bytes.
    Raw {
        /// The wire extension type.
        kind: u16,
        /// The opaque body.
        body: Vec<u8>,
    },
}

/// One extension: a body whose wire type derives from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The body; the wire type is a function of it.
    pub body: ExtensionBody,
}

impl Extension {
    /// The wire extension type this body encodes as.
    #[must_use]
    pub fn kind(&self) -> u16 {
        match &self.body {
            ExtensionBody::ServerName { .. } => EXT_SERVER_NAME,
            ExtensionBody::EcPointFormats { .. } => EXT_EC_POINT_FORMATS,
            ExtensionBody::RenegotiationInfo => EXT_RENEGOTIATION_INFO,
            ExtensionBody::ExtendedMasterSecret => EXT_EXTENDED_MASTER_SECRET,
            ExtensionBody::SignedCertificateTimestamp => EXT_SIGNED_CERTIFICATE_TIMESTAMP,
            ExtensionBody::StatusRequest => EXT_STATUS_REQUEST,
            ExtensionBody::SupportedGroups { .. } => EXT_SUPPORTED_GROUPS,
            ExtensionBody::SignatureAlgorithms { .. } => EXT_SIGNATURE_ALGORITHMS,
            ExtensionBody::SignatureAlgorithmsCert { .. } => EXT_SIGNATURE_ALGORITHMS_CERT,
            ExtensionBody::Alpn { .. } => EXT_ALPN,
            ExtensionBody::SupportedVersions { .. } => EXT_SUPPORTED_VERSIONS,
            ExtensionBody::KeyShare { .. } => EXT_KEY_SHARE,
            ExtensionBody::Grease { kind, .. } => *kind,
            ExtensionBody::Padding { .. } => EXT_PADDING,
            ExtensionBody::CompressCertificate { .. } => EXT_COMPRESS_CERTIFICATE,
            ExtensionBody::RecordSizeLimit { .. } => EXT_RECORD_SIZE_LIMIT,
            ExtensionBody::SessionTicket { .. } => EXT_SESSION_TICKET,
            ExtensionBody::PskKeyExchangeModes { .. } => EXT_PSK_KEY_EXCHANGE_MODES,
            ExtensionBody::PostHandshakeAuth => EXT_POST_HANDSHAKE_AUTH,
            ExtensionBody::Alps { .. } => EXT_ALPS,
            ExtensionBody::PreSharedKey { .. } => EXT_PRE_SHARED_KEY,
            ExtensionBody::Raw { kind, .. } => *kind,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), HelloError> {
        let kind = self.kind();
        let mut body = Vec::new();
        match &self.body {
            ExtensionBody::ServerName { name } => {
                // server_name_list: one entry, type 0x00 (host_name).
                let mut entry = Vec::with_capacity(name.len() + 3);
                entry.push(0x00);
                put_u16_length_vector(&mut entry, name.as_bytes());
                put_u16_length_vector(&mut body, &entry);
            }
            ExtensionBody::EcPointFormats { formats } => {
                put_u8_length_vector(&mut body, formats);
            }
            ExtensionBody::RenegotiationInfo => {
                // The empty renegotiation offer: the one-byte form every
                // shipped stack puts on the wire — OpenSSL, BoringSSL and
                // the RFC 8448 §3 trace's ClientHello all carry a single
                // 0x00 byte here, not the 2-byte vector encoding of the
                // RFC 5746 struct. Arbitrated by the RFC 8448 capture.
                body.push(0x00);
            }
            ExtensionBody::ExtendedMasterSecret | ExtensionBody::SignedCertificateTimestamp => {}
            ExtensionBody::StatusRequest => {
                // status_type = ocsp (1), empty responder_id_list, empty
                // request extensions.
                body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
            }
            ExtensionBody::SupportedGroups { groups } => {
                put_word_list(&mut body, groups);
            }
            ExtensionBody::SignatureAlgorithms { schemes } => {
                put_word_list(&mut body, schemes);
            }
            ExtensionBody::SignatureAlgorithmsCert { schemes } => {
                put_word_list(&mut body, schemes);
            }
            ExtensionBody::Alpn { protocols } => {
                if protocols.iter().any(|protocol| protocol.is_empty()) {
                    return Err(HelloError::EmptyProtocolName);
                }
                let mut list = Vec::new();
                for protocol in protocols {
                    put_u8_length_vector(&mut list, protocol);
                }
                put_u16_length_vector(&mut body, &list);
            }
            ExtensionBody::SupportedVersions { versions } => {
                let mut list = Vec::with_capacity(versions.len() * 2);
                for &version in versions {
                    put_u16(&mut list, version);
                }
                put_u8_length_vector(&mut body, &list);
            }
            ExtensionBody::KeyShare { shares } => {
                for share in shares {
                    if share.share.is_empty() {
                        return Err(HelloError::EmptyKeyShare { group: share.group });
                    }
                }
                let mut list = Vec::new();
                for entry in shares {
                    put_u16(&mut list, entry.group);
                    put_u16_length_vector(&mut list, &entry.share);
                }
                put_u16_length_vector(&mut body, &list);
            }
            ExtensionBody::Grease { body: raw, .. } => {
                body.extend_from_slice(raw);
            }
            ExtensionBody::Padding { len } => {
                body.resize(*len, 0x00);
            }
            ExtensionBody::CompressCertificate { algorithms } => {
                let mut list = Vec::with_capacity(algorithms.len() * 2);
                for &alg in algorithms {
                    put_u16(&mut list, alg);
                }
                put_u8_length_vector(&mut body, &list);
            }
            ExtensionBody::RecordSizeLimit { limit } => {
                put_u16(&mut body, *limit);
            }
            ExtensionBody::SessionTicket { ticket } => {
                body.extend_from_slice(ticket);
            }
            ExtensionBody::PskKeyExchangeModes { modes } => {
                put_u8_length_vector(&mut body, modes);
            }
            ExtensionBody::PostHandshakeAuth => {}
            ExtensionBody::Alps { protocols } => {
                if protocols.iter().any(|protocol| protocol.is_empty()) {
                    return Err(HelloError::EmptyProtocolName);
                }
                let mut list = Vec::new();
                for protocol in protocols {
                    put_u8_length_vector(&mut list, protocol);
                }
                put_u16_length_vector(&mut body, &list);
            }
            ExtensionBody::PreSharedKey {
                identities,
                binders,
            } => {
                let mut id_list = Vec::new();
                for id in identities {
                    put_u16_length_vector(&mut id_list, &id.identity);
                    id_list.extend_from_slice(&id.obfuscated_ticket_age.to_be_bytes());
                }
                put_u16_length_vector(&mut body, &id_list);
                let mut binder_list = Vec::new();
                for binder in binders {
                    put_u8_length_vector(&mut binder_list, binder);
                }
                put_u16_length_vector(&mut body, &binder_list);
            }
            ExtensionBody::Raw { body: raw, .. } => {
                body.extend_from_slice(raw);
            }
        }
        if body.len() > u16::MAX as usize {
            return Err(HelloError::ExtensionTooLarge {
                kind,
                len: body.len(),
            });
        }
        put_u16(out, kind);
        put_u16_length_vector(out, &body);
        Ok(())
    }
}

/// A ClientHello: every field a passive observer reads, in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// The hello's `legacy_version` field — 0x0303 for the measured hello.
    pub legacy_version: u16,
    /// The 32-byte per-connection random.
    pub random: [u8; 32],
    /// The session id; bounded to 32 bytes at serialization (RFC 5246).
    pub session_id: Vec<u8>,
    /// Cipher suites in wire order. Order is identity.
    pub cipher_suites: Vec<u16>,
    /// Compression methods; the measured hello offers null compression only.
    pub compression_methods: Vec<u8>,
    /// Extensions in wire order. Order is identity.
    pub extensions: Vec<Extension>,
}

/// The serialized hello, as a TLS handshake message:
/// type byte (`client_hello`), 24-bit length, body.
impl ClientHello {
    /// Serialize the handshake message bytes.
    ///
    /// # Errors
    /// Any body that cannot be represented on the wire — a list or block
    /// over its vector limit, a session id over 32 bytes, an empty ALPN
    /// name or key share — is returned as [`HelloError`]; the hello is
    /// never silently truncated.
    pub fn serialize(&self) -> Result<Vec<u8>, HelloError> {
        if self.session_id.len() > 32 {
            return Err(HelloError::SessionIdTooLong {
                len: self.session_id.len(),
            });
        }
        if self.cipher_suites.len() * 2 > u16::MAX as usize {
            return Err(HelloError::CipherListTooLarge {
                len: self.cipher_suites.len(),
            });
        }

        let mut body =
            Vec::with_capacity(64 + self.session_id.len() + self.cipher_suites.len() * 2);
        put_u16(&mut body, self.legacy_version);
        body.extend_from_slice(&self.random);
        put_u8_length_vector(&mut body, &self.session_id);

        let mut ciphers = Vec::with_capacity(self.cipher_suites.len() * 2);
        for &suite in &self.cipher_suites {
            put_u16(&mut ciphers, suite);
        }
        put_u16_length_vector(&mut body, &ciphers);

        put_u8_length_vector(&mut body, &self.compression_methods);

        let mut extensions = Vec::new();
        for extension in &self.extensions {
            extension.encode(&mut extensions)?;
        }
        if extensions.len() > u16::MAX as usize {
            return Err(HelloError::ExtensionBlockTooLarge {
                len: extensions.len(),
            });
        }
        put_u16_length_vector(&mut body, &extensions);

        if body.len() > 0x00ff_ffff {
            return Err(HelloError::HelloTooLarge { len: body.len() });
        }

        let mut message = Vec::with_capacity(4 + body.len());
        message.push(0x01); // handshake type: client_hello
        put_u24(&mut message, body.len() as u32);
        message.extend_from_slice(&body);
        Ok(message)
    }

    /// Serialize the full TLS record that carries the hello:
    /// content type `handshake` (0x16), legacy record version 0x0301,
    /// 16-bit length, handshake message — through the shared record layer.
    ///
    /// # Errors
    /// Same as [`ClientHello::serialize`].
    pub fn serialize_record(&self) -> Result<Vec<u8>, HelloError> {
        let message = self.serialize()?;
        Ok(crate::record::unprotected_record(
            crate::record::CONTENT_HANDSHAKE,
            crate::record::LEGACY_VERSION_TLS12,
            &message,
        ))
    }

    /// Append a `pre_shared_key` extension (RFC 8446 §4.2.11) as the final
    /// extension and compute its PSK binder over the truncated ClientHello.
    ///
    /// # Errors
    /// Propagates [`HelloError`] if the resulting ClientHello exceeds wire
    /// limits.
    pub fn attach_psk_and_sign(
        &mut self,
        identity: PskIdentity,
        psk: &[u8],
        hash: crate::key_schedule::Hash,
    ) -> Result<(), HelloError> {
        let hash_len = hash.output_len();
        self.extensions
            .retain(|ext| !matches!(ext.body, ExtensionBody::PreSharedKey { .. }));

        // If a prior padding policy sized the ClientHello body to a target
        // (such as BoringSsl517's 512-byte body), rebalance or drop the
        // padding after inserting the PSK extension rather than stacking both.
        let padded_target = if self
            .extensions
            .iter()
            .any(|ext| matches!(ext.body, ExtensionBody::Padding { .. }))
        {
            Some(self.serialize()?.len().saturating_sub(4))
        } else {
            None
        };
        let pad_pos = self
            .extensions
            .iter()
            .position(|ext| matches!(ext.body, ExtensionBody::Padding { .. }));
        self.extensions
            .retain(|ext| !matches!(ext.body, ExtensionBody::Padding { .. }));

        self.extensions.push(Extension {
            body: ExtensionBody::PreSharedKey {
                identities: vec![identity],
                binders: vec![vec![0u8; hash_len]],
            },
        });

        if let (Some(target), Some(idx)) = (padded_target, pad_pos) {
            let unpadded_with_psk = self.serialize()?.len().saturating_sub(4);
            let needed = target.saturating_sub(unpadded_with_psk);
            if needed >= 4 {
                let insert_at = idx.min(self.extensions.len().saturating_sub(1));
                self.extensions.insert(
                    insert_at,
                    Extension {
                        body: ExtensionBody::Padding { len: needed - 4 },
                    },
                );
            }
        }
        self.rebind_psk_with_prefix(&[], psk, hash)
    }

    /// Recompute the PSK binder on the trailing `pre_shared_key` extension
    /// over `transcript_prefix || Truncated(ClientHello)` (RFC 8446 §4.2.11.2,
    /// including a `ClientHello2` after a `HelloRetryRequest`).
    pub(crate) fn rebind_psk_with_prefix(
        &mut self,
        transcript_prefix: &[u8],
        psk: &[u8],
        hash: crate::key_schedule::Hash,
    ) -> Result<(), HelloError> {
        let hash_len = hash.output_len();
        let binders_len = match self.extensions.last_mut() {
            Some(Extension {
                body: ExtensionBody::PreSharedKey { binders, .. },
            }) if !binders.is_empty() => {
                binders[0].resize(hash_len, 0);
                2 + binders.iter().map(|b| 1 + b.len()).sum::<usize>()
            }
            _ => return Ok(()),
        };
        let serialized = self.serialize()?;
        // Truncate right before `PskBinderEntry binders<33..2^16-1>`.
        let truncated = &serialized[..serialized.len().saturating_sub(binders_len)];
        let mut full_input = Vec::with_capacity(transcript_prefix.len() + truncated.len());
        full_input.extend_from_slice(transcript_prefix);
        full_input.extend_from_slice(truncated);
        let transcript = crate::key_schedule::transcript_hash(hash, &full_input);

        let zeros = vec![0u8; hash_len];
        let early = crate::key_schedule::Secret::extract(&zeros, psk, hash);
        let binder_key = early
            .derive_secret(
                "res binder",
                &crate::key_schedule::empty_transcript_hash(hash),
            )
            .map_err(|_| HelloError::HelloTooLarge {
                len: serialized.len(),
            })?;
        let finished_key = binder_key
            .finished_key()
            .map_err(|_| HelloError::HelloTooLarge {
                len: serialized.len(),
            })?;
        let hmac_key = aws_lc_rs::hmac::Key::new(hash.hmac_algorithm(), &finished_key);
        let binder = aws_lc_rs::hmac::sign(&hmac_key, &transcript)
            .as_ref()
            .to_vec();

        if let Some(Extension {
            body: ExtensionBody::PreSharedKey { binders, .. },
        }) = self.extensions.last_mut()
            && !binders.is_empty()
        {
            binders[0] = binder;
        }
        Ok(())
    }

    /// The measured Google Antigravity CLI 1.5.9 identity — a Go 1.28
    /// `crypto/tls` client on a `boringcrypto` toolchain — as 75 identical
    /// captures pinned it:
    ///
    /// - record version 0x0301, `legacy_version` 0x0303;
    /// - 13 cipher suites in Go's offer order, including the four CBC suites
    ///   a rustls profile can never offer ([`INV-TLS-04`]'s motivation);
    /// - 12 extensions in BoringSSL's fixed order: `server_name`,
    ///   `ec_point_formats`, `renegotiation_info`, `extended_master_secret`,
    ///   `signed_certificate_timestamp`, `status_request`,
    ///   `supported_groups`, `signature_algorithms`,
    ///   `signature_algorithms_cert`, `alpn`, `supported_versions`,
    ///   `key_share`;
    /// - 7 hybrid-first key-exchange groups, key shares for the hybrid
    ///   group and `x25519`;
    /// - 13 signature schemes, ML-DSA first, mirrored in
    ///   `signature_algorithms_cert`;
    /// - no session ticket, no PSK, no GREASE, no padding;
    /// - JA3 md5 `03117a8ed39ef02427ebbc39f121275c`; JA4
    ///   `t13d1312h1_f57a46bbacb6_f50d94e863eb` for the unary
    ///   (`http/1.1`) offer and `t13d1312h2_…` for the stream offer.
    ///
    /// Random, session id and key shares are per-connection values in the
    /// measured client too; they arrive through [`GoIdentity`], not through
    /// the profile.
    ///
    /// Two bodies are pending arbitration against the raw capture corpus and
    /// are noted where they are encoded: the `signature_algorithms_cert`
    /// list (encoded here as the mirror of `signature_algorithms`). The
    /// `renegotiation_info` payload was arbitrated by the RFC 8448 §3
    /// ClientHello: the one-byte empty offer.
    #[must_use]
    pub fn go_identity(identity: GoIdentity<'_>) -> Self {
        Self {
            legacy_version: 0x0303,
            random: identity.random,
            session_id: identity.session_id.to_vec(),
            cipher_suites: identity
                .cipher_suites
                .map(<[u16]>::to_vec)
                .unwrap_or_else(|| GO_CIPHER_SUITES.to_vec()),
            compression_methods: vec![0x00],
            extensions: vec![
                Extension {
                    body: ExtensionBody::ServerName {
                        name: identity.server_name.to_owned(),
                    },
                },
                Extension {
                    body: ExtensionBody::EcPointFormats {
                        formats: vec![0x00],
                    },
                },
                Extension {
                    body: ExtensionBody::RenegotiationInfo,
                },
                Extension {
                    body: ExtensionBody::ExtendedMasterSecret,
                },
                Extension {
                    body: ExtensionBody::SignedCertificateTimestamp,
                },
                Extension {
                    body: ExtensionBody::StatusRequest,
                },
                Extension {
                    body: ExtensionBody::SupportedGroups {
                        groups: identity
                            .kx_groups
                            .map(<[u16]>::to_vec)
                            .unwrap_or_else(|| GO_KEY_GROUPS.to_vec()),
                    },
                },
                Extension {
                    body: ExtensionBody::SignatureAlgorithms {
                        schemes: GO_SIGNATURE_SCHEMES.to_vec(),
                    },
                },
                Extension {
                    body: ExtensionBody::SignatureAlgorithmsCert {
                        schemes: GO_SIGNATURE_SCHEMES.to_vec(),
                    },
                },
                Extension {
                    body: ExtensionBody::Alpn {
                        protocols: identity
                            .alpn
                            .iter()
                            .map(|protocol| protocol.to_vec())
                            .collect(),
                    },
                },
                Extension {
                    body: ExtensionBody::SupportedVersions {
                        versions: vec![0x0304, 0x0303],
                    },
                },
                Extension {
                    body: ExtensionBody::KeyShare {
                        shares: identity.key_shares,
                    },
                },
            ],
        }
    }
}

/// The per-connection randomness a [`ClientHello::go_identity`] needs.
///
/// The profile pins *shape*; these fields carry the *values* a real client
/// changes per connection. Key-share generation is wired with the crypto
/// layer (ADR-0045 step 2); until then callers supply shares of the measured
/// shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoIdentity<'a> {
    /// The SNI `host_name`; the measured hello always carries it for the API
    /// hosts.
    pub server_name: &'a str,
    /// The ALPN offer in wire order: `["http/1.1"]` for the unary Cloud Code
    /// path, `["h2", "http/1.1"]` for telemetry and model streaming.
    pub alpn: &'a [&'a [u8]],
    /// The 32-byte per-connection random.
    pub random: [u8; 32],
    /// The per-connection session id, at most 32 bytes.
    pub session_id: &'a [u8],
    /// Key-share entries in offer order: the hybrid group (`0x11ec`) first,
    /// then `x25519` (`0x001d`) for the measured hello.
    pub key_shares: Vec<KeyShareEntry>,
    /// The cipher offer; `None` is the measured 13-suite Go list. A profile
    /// may narrow it, never below what the engine completes ([`INV-TLS-06`]).
    pub cipher_suites: Option<&'a [u16]>,
    /// The key-exchange-group offer; `None` is the measured hybrid-first
    /// 7-group list. A narrowed profile's `supported_groups` follows its
    /// share offer — offering groups without shares is the shape that
    /// forces a HelloRetryRequest round-trip.
    pub kx_groups: Option<&'a [u16]>,
}

/// Fill a buffer with per-connection randomness (`aws-lc`'s CSPRNG).
///
/// # Errors
/// The primitive refusing to fill is not a data condition; surfaced as an
/// error string.
pub fn fill_random(buffer: &mut [u8]) -> Result<(), String> {
    aws_lc_rs::rand::fill(buffer).map_err(|error| error.to_string())
}

/// The Go 1.28 `boringcrypto` cipher offer, in Go's wire order.
const GO_CIPHER_SUITES: &[u16] = &[
    SUITE_ECDHE_ECDSA_AES_128_GCM,
    SUITE_ECDHE_RSA_AES_128_GCM,
    SUITE_ECDHE_ECDSA_AES_256_GCM,
    SUITE_ECDHE_RSA_AES_256_GCM,
    SUITE_ECDHE_ECDSA_CHACHA20_POLY1305,
    SUITE_ECDHE_RSA_CHACHA20_POLY1305,
    SUITE_ECDHE_ECDSA_AES_128_CBC,
    SUITE_ECDHE_RSA_AES_128_CBC,
    SUITE_ECDHE_ECDSA_AES_256_CBC,
    SUITE_ECDHE_RSA_AES_256_CBC,
    SUITE_TLS13_AES_128_GCM,
    SUITE_TLS13_AES_256_GCM,
    SUITE_TLS13_CHACHA20_POLY1305,
];

/// The hybrid-first 7-group offer, in Go's wire order.
const GO_KEY_GROUPS: &[u16] = &[
    GROUP_X25519_ML_KEM_768,
    GROUP_SECP256R1_ML_KEM_768,
    GROUP_SECP384R1_ML_KEM_1024,
    GROUP_X25519,
    GROUP_SECP256R1,
    GROUP_SECP384R1,
    GROUP_SECP521R1,
];

/// The 13 signature schemes, ML-DSA first, in Go's wire order.
const GO_SIGNATURE_SCHEMES: &[u16] = &[
    SIG_ML_DSA_44,
    SIG_ML_DSA_65,
    SIG_ML_DSA_87,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ED25519,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PKCS1_SHA256,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PKCS1_SHA512,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SECP521R1_SHA512,
];

/// One extension slot in a [`ClientHelloBlueprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionSlot {
    /// `server_name` (`0x0000`).
    ServerName,
    /// `ec_point_formats` (`0x000b`).
    EcPointFormats,
    /// `renegotiation_info` (`0xff01`).
    RenegotiationInfo,
    /// `extended_master_secret` (`0x0017`).
    ExtendedMasterSecret,
    /// `signed_certificate_timestamp` (`0x0012`).
    SignedCertificateTimestamp,
    /// `status_request` (`0x0005`).
    StatusRequest,
    /// `supported_groups` (`0x000a`).
    SupportedGroups,
    /// `signature_algorithms` (`0x000d`).
    SignatureAlgorithms,
    /// `signature_algorithms_cert` (`0x0032`). Emitted only if configured.
    SignatureAlgorithmsCert,
    /// `alpn` (`0x0010`). Emitted only if non-empty.
    Alpn,
    /// `supported_versions` (`0x002b`).
    SupportedVersions,
    /// `key_share` (`0x0033`).
    KeyShare,
    /// `session_ticket` (`0x0023`).
    SessionTicket,
    /// `compress_certificate` (`0x001b`). Emitted only if configured.
    CompressCertificate,
    /// `record_size_limit` (`0x001c`). Emitted only if configured.
    RecordSizeLimit,
    /// `psk_key_exchange_modes` (`0x002d`). Emitted only if configured.
    PskKeyExchangeModes,
    /// `post_handshake_auth` (`0x0031`).
    PostHandshakeAuth,
    /// `application_settings` (`0x4469`). Emitted only if configured.
    Alps,
    /// RFC 8701 GREASE extension slot. `slot` distinguishes multiple GREASE
    /// extensions in the same ClientHello so their wire types never collide.
    Grease {
        /// Logical slot index (0, 1, ...).
        slot: u8,
        /// Optional body (empty or `[0x00]`).
        body: Vec<u8>,
    },
    /// RFC 7685 `padding` (`0x0015`), computed according to [`PaddingPolicy`].
    Padding,
    /// Opaque raw extension.
    Raw {
        /// Wire extension type.
        kind: u16,
        /// Raw body bytes.
        body: Vec<u8>,
    },
}

impl ExtensionSlot {
    const fn is_pinned_in_permutation(&self) -> bool {
        matches!(self, Self::Grease { .. } | Self::Padding | Self::Raw { .. })
    }
}

/// Dynamic ClientHello padding policy (RFC 7685).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaddingPolicy {
    /// Do not emit a `padding` extension.
    #[default]
    None,
    /// BoringSSL/Chrome rule: if the unpadded ClientHello body length is in
    /// `256..=511` bytes, pad the body to `512` bytes.
    BoringSsl517,
    /// Pad the ClientHello body to at least `target` bytes whenever it is
    /// shorter than `target`.
    TargetBodyLen(usize),
}

/// Declarative, pure-data blueprint of a TLS ClientHello
/// ([ADR-0048](../../adr/0048-declarative-clienthello-blueprints.md)).
///
/// Every byte on the wire is determined by the blueprint plus the
/// per-connection randomness in [`BlueprintBuildParams`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloBlueprint {
    /// `legacy_version` field (normally `0x0303`).
    pub legacy_version: u16,
    /// Cipher suites in offer order (excluding GREASE).
    pub cipher_suites: Vec<u16>,
    /// Prepend an RFC 8701 GREASE cipher suite.
    pub grease_cipher_suite: bool,
    /// `supported_groups` in offer order (excluding GREASE).
    pub supported_groups: Vec<u16>,
    /// Prepend an RFC 8701 GREASE group.
    pub grease_supported_group: bool,
    /// Which groups from `supported_groups` receive initial `key_share` entries.
    pub key_share_groups: Vec<u16>,
    /// Prepend a GREASE `key_share` entry (`[0x00]`).
    pub grease_key_share: bool,
    /// `signature_algorithms` in offer order.
    pub signature_algorithms: Vec<u16>,
    /// Optional `signature_algorithms_cert` list (`None` omits the extension).
    pub signature_algorithms_cert: Option<Vec<u16>>,
    /// ALPN protocols in offer order.
    pub alpn: Vec<Vec<u8>>,
    /// `supported_versions` in offer order (excluding GREASE).
    pub supported_versions: Vec<u16>,
    /// Prepend an RFC 8701 GREASE version.
    pub grease_supported_version: bool,
    /// Optional `compress_certificate` algorithms (RFC 8879).
    pub compress_certificate: Option<Vec<u16>>,
    /// Optional `record_size_limit` (RFC 8449).
    pub record_size_limit: Option<u16>,
    /// Optional `psk_key_exchange_modes` (RFC 8446 §4.2.9).
    pub psk_key_exchange_modes: Option<Vec<u8>>,
    /// Optional `application_settings` (ALPS) protocol list.
    pub alps: Option<Vec<Vec<u8>>>,
    /// Ordered extension slots.
    pub extensions: Vec<ExtensionSlot>,
    /// When `true`, permute non-pinned extensions per connection using
    /// `permutation_seed` (Chrome 106+ behaviour).
    pub extension_permutation: bool,
    /// Dynamic padding policy (RFC 7685).
    pub padding: PaddingPolicy,
}

/// Per-connection inputs required to materialize a [`ClientHelloBlueprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlueprintBuildParams<'a> {
    /// SNI `host_name`.
    pub server_name: &'a str,
    /// 32-byte per-connection random.
    pub random: [u8; 32],
    /// Per-connection session id (0..=32 bytes).
    pub session_id: &'a [u8],
    /// Real cryptographic key shares matching `blueprint.key_share_groups`.
    pub key_shares: Vec<KeyShareEntry>,
    /// Seed bytes for RFC 8701 GREASE selection.
    pub grease_seed: [u8; 8],
    /// Seed bytes for extension permutation.
    pub permutation_seed: [u8; 32],
}

impl ClientHelloBlueprint {
    /// Measured Google Antigravity CLI 1.5.9 (Go 1.28 `boringcrypto`) shape.
    #[must_use]
    pub fn go_boringcrypto() -> Self {
        Self {
            legacy_version: 0x0303,
            cipher_suites: GO_CIPHER_SUITES.to_vec(),
            grease_cipher_suite: false,
            supported_groups: GO_KEY_GROUPS.to_vec(),
            grease_supported_group: false,
            key_share_groups: vec![GROUP_X25519_ML_KEM_768, GROUP_X25519],
            grease_key_share: false,
            signature_algorithms: GO_SIGNATURE_SCHEMES.to_vec(),
            signature_algorithms_cert: Some(GO_SIGNATURE_SCHEMES.to_vec()),
            alpn: vec![b"http/1.1".to_vec()],
            supported_versions: vec![0x0304, 0x0303],
            grease_supported_version: false,
            compress_certificate: None,
            record_size_limit: None,
            psk_key_exchange_modes: None,
            alps: None,
            extensions: vec![
                ExtensionSlot::ServerName,
                ExtensionSlot::EcPointFormats,
                ExtensionSlot::RenegotiationInfo,
                ExtensionSlot::ExtendedMasterSecret,
                ExtensionSlot::SignedCertificateTimestamp,
                ExtensionSlot::StatusRequest,
                ExtensionSlot::SupportedGroups,
                ExtensionSlot::SignatureAlgorithms,
                ExtensionSlot::SignatureAlgorithmsCert,
                ExtensionSlot::Alpn,
                ExtensionSlot::SupportedVersions,
                ExtensionSlot::KeyShare,
            ],
            extension_permutation: false,
            padding: PaddingPolicy::None,
        }
    }

    /// Standard upstream Go `crypto/tls` shape (without `boringcrypto`).
    #[must_use]
    pub fn go_standard() -> Self {
        Self {
            legacy_version: 0x0303,
            cipher_suites: vec![
                SUITE_TLS13_AES_128_GCM,
                SUITE_TLS13_CHACHA20_POLY1305,
                SUITE_TLS13_AES_256_GCM,
                SUITE_ECDHE_ECDSA_AES_128_GCM,
                SUITE_ECDHE_RSA_AES_128_GCM,
                SUITE_ECDHE_ECDSA_AES_256_GCM,
                SUITE_ECDHE_RSA_AES_256_GCM,
                SUITE_ECDHE_ECDSA_CHACHA20_POLY1305,
                SUITE_ECDHE_RSA_CHACHA20_POLY1305,
            ],
            grease_cipher_suite: false,
            supported_groups: vec![
                GROUP_X25519_ML_KEM_768,
                GROUP_X25519,
                GROUP_SECP256R1,
                GROUP_SECP384R1,
                GROUP_SECP521R1,
            ],
            grease_supported_group: false,
            key_share_groups: vec![GROUP_X25519_ML_KEM_768, GROUP_X25519],
            grease_key_share: false,
            signature_algorithms: vec![
                SIG_ECDSA_SECP256R1_SHA256,
                SIG_RSA_PSS_RSAE_SHA256,
                SIG_RSA_PKCS1_SHA256,
                SIG_ECDSA_SECP384R1_SHA384,
                SIG_RSA_PSS_RSAE_SHA384,
                SIG_RSA_PKCS1_SHA384,
                SIG_RSA_PSS_RSAE_SHA512,
                SIG_RSA_PKCS1_SHA512,
                SIG_ED25519,
            ],
            signature_algorithms_cert: None,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            supported_versions: vec![0x0304, 0x0303],
            grease_supported_version: false,
            compress_certificate: None,
            record_size_limit: None,
            psk_key_exchange_modes: Some(vec![PSK_DHE_KE]),
            alps: None,
            extensions: vec![
                ExtensionSlot::ServerName,
                ExtensionSlot::StatusRequest,
                ExtensionSlot::SupportedGroups,
                ExtensionSlot::EcPointFormats,
                ExtensionSlot::SignatureAlgorithms,
                ExtensionSlot::Alpn,
                ExtensionSlot::SignedCertificateTimestamp,
                ExtensionSlot::ExtendedMasterSecret,
                ExtensionSlot::RenegotiationInfo,
                ExtensionSlot::SupportedVersions,
                ExtensionSlot::PskKeyExchangeModes,
                ExtensionSlot::KeyShare,
                ExtensionSlot::SessionTicket,
            ],
            extension_permutation: false,
            padding: PaddingPolicy::None,
        }
    }

    /// Modern Chrome/BoringSSL shape: GREASE, `compress_certificate(brotli)`,
    /// ALPS, seeded extension permutation, and BoringSSL 517-byte padding.
    #[must_use]
    pub fn chrome_current() -> Self {
        Self {
            legacy_version: 0x0303,
            cipher_suites: vec![
                SUITE_TLS13_AES_128_GCM,
                SUITE_TLS13_AES_256_GCM,
                SUITE_TLS13_CHACHA20_POLY1305,
                SUITE_ECDHE_ECDSA_AES_128_GCM,
                SUITE_ECDHE_RSA_AES_128_GCM,
                SUITE_ECDHE_ECDSA_AES_256_GCM,
                SUITE_ECDHE_RSA_AES_256_GCM,
                SUITE_ECDHE_ECDSA_CHACHA20_POLY1305,
                SUITE_ECDHE_RSA_CHACHA20_POLY1305,
            ],
            grease_cipher_suite: true,
            supported_groups: vec![
                GROUP_X25519_ML_KEM_768,
                GROUP_X25519,
                GROUP_SECP256R1,
                GROUP_SECP384R1,
            ],
            grease_supported_group: true,
            key_share_groups: vec![GROUP_X25519_ML_KEM_768, GROUP_X25519],
            grease_key_share: true,
            signature_algorithms: vec![
                SIG_ECDSA_SECP256R1_SHA256,
                SIG_RSA_PSS_RSAE_SHA256,
                SIG_RSA_PKCS1_SHA256,
                SIG_ECDSA_SECP384R1_SHA384,
                SIG_RSA_PSS_RSAE_SHA384,
                SIG_RSA_PKCS1_SHA384,
                SIG_RSA_PSS_RSAE_SHA512,
                SIG_RSA_PKCS1_SHA512,
            ],
            signature_algorithms_cert: None,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            supported_versions: vec![0x0304, 0x0303],
            grease_supported_version: true,
            compress_certificate: Some(vec![CERT_COMP_BROTLI]),
            record_size_limit: None,
            psk_key_exchange_modes: Some(vec![PSK_DHE_KE]),
            alps: Some(vec![b"h2".to_vec()]),
            extensions: vec![
                ExtensionSlot::Grease {
                    slot: 0,
                    body: Vec::new(),
                },
                ExtensionSlot::ServerName,
                ExtensionSlot::ExtendedMasterSecret,
                ExtensionSlot::RenegotiationInfo,
                ExtensionSlot::SupportedGroups,
                ExtensionSlot::EcPointFormats,
                ExtensionSlot::SessionTicket,
                ExtensionSlot::Alpn,
                ExtensionSlot::StatusRequest,
                ExtensionSlot::SignatureAlgorithms,
                ExtensionSlot::SignedCertificateTimestamp,
                ExtensionSlot::KeyShare,
                ExtensionSlot::PskKeyExchangeModes,
                ExtensionSlot::SupportedVersions,
                ExtensionSlot::CompressCertificate,
                ExtensionSlot::Alps,
                ExtensionSlot::Grease {
                    slot: 1,
                    body: vec![0x00],
                },
                ExtensionSlot::Padding,
            ],
            extension_permutation: true,
            padding: PaddingPolicy::BoringSsl517,
        }
    }

    /// Modern Firefox/NSS shape: `record_size_limit`, `post_handshake_auth`,
    /// `compress_certificate(zlib, brotli)`, `session_ticket`.
    #[must_use]
    pub fn firefox_current() -> Self {
        Self {
            legacy_version: 0x0303,
            cipher_suites: vec![
                SUITE_TLS13_AES_128_GCM,
                SUITE_TLS13_CHACHA20_POLY1305,
                SUITE_TLS13_AES_256_GCM,
                SUITE_ECDHE_ECDSA_AES_128_GCM,
                SUITE_ECDHE_RSA_AES_128_GCM,
                SUITE_ECDHE_ECDSA_CHACHA20_POLY1305,
                SUITE_ECDHE_RSA_CHACHA20_POLY1305,
                SUITE_ECDHE_ECDSA_AES_256_GCM,
                SUITE_ECDHE_RSA_AES_256_GCM,
            ],
            grease_cipher_suite: false,
            supported_groups: vec![
                GROUP_X25519_ML_KEM_768,
                GROUP_X25519,
                GROUP_SECP256R1,
                GROUP_SECP384R1,
                GROUP_SECP521R1,
            ],
            grease_supported_group: false,
            key_share_groups: vec![GROUP_X25519_ML_KEM_768, GROUP_X25519, GROUP_SECP256R1],
            grease_key_share: false,
            signature_algorithms: vec![
                SIG_ECDSA_SECP256R1_SHA256,
                SIG_ECDSA_SECP384R1_SHA384,
                SIG_ECDSA_SECP521R1_SHA512,
                SIG_RSA_PSS_RSAE_SHA256,
                SIG_RSA_PSS_RSAE_SHA384,
                SIG_RSA_PSS_RSAE_SHA512,
                SIG_RSA_PKCS1_SHA256,
                SIG_RSA_PKCS1_SHA384,
                SIG_RSA_PKCS1_SHA512,
            ],
            signature_algorithms_cert: None,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            supported_versions: vec![0x0304, 0x0303],
            grease_supported_version: false,
            compress_certificate: Some(vec![CERT_COMP_ZLIB, CERT_COMP_BROTLI]),
            record_size_limit: Some(0x4001),
            psk_key_exchange_modes: Some(vec![PSK_DHE_KE]),
            alps: None,
            extensions: vec![
                ExtensionSlot::ServerName,
                ExtensionSlot::ExtendedMasterSecret,
                ExtensionSlot::RenegotiationInfo,
                ExtensionSlot::SupportedGroups,
                ExtensionSlot::EcPointFormats,
                ExtensionSlot::SessionTicket,
                ExtensionSlot::Alpn,
                ExtensionSlot::StatusRequest,
                ExtensionSlot::RecordSizeLimit,
                ExtensionSlot::KeyShare,
                ExtensionSlot::SupportedVersions,
                ExtensionSlot::SignatureAlgorithms,
                ExtensionSlot::PostHandshakeAuth,
                ExtensionSlot::PskKeyExchangeModes,
                ExtensionSlot::CompressCertificate,
            ],
            extension_permutation: false,
            padding: PaddingPolicy::None,
        }
    }

    /// Modern Safari/SecureTransport shape: GREASE, `compress_certificate(zlib)`,
    /// fixed extension order.
    #[must_use]
    pub fn safari_current() -> Self {
        Self {
            legacy_version: 0x0303,
            cipher_suites: vec![
                SUITE_TLS13_AES_128_GCM,
                SUITE_TLS13_AES_256_GCM,
                SUITE_TLS13_CHACHA20_POLY1305,
                SUITE_ECDHE_ECDSA_AES_256_GCM,
                SUITE_ECDHE_ECDSA_AES_128_GCM,
                SUITE_ECDHE_ECDSA_CHACHA20_POLY1305,
                SUITE_ECDHE_RSA_AES_256_GCM,
                SUITE_ECDHE_RSA_AES_128_GCM,
                SUITE_ECDHE_RSA_CHACHA20_POLY1305,
            ],
            grease_cipher_suite: true,
            supported_groups: vec![
                GROUP_X25519,
                GROUP_SECP256R1,
                GROUP_SECP384R1,
                GROUP_SECP521R1,
            ],
            grease_supported_group: true,
            key_share_groups: vec![GROUP_X25519],
            grease_key_share: true,
            signature_algorithms: vec![
                SIG_ECDSA_SECP256R1_SHA256,
                SIG_RSA_PSS_RSAE_SHA256,
                SIG_RSA_PKCS1_SHA256,
                SIG_ECDSA_SECP384R1_SHA384,
                SIG_RSA_PSS_RSAE_SHA384,
                SIG_RSA_PKCS1_SHA384,
                SIG_RSA_PSS_RSAE_SHA512,
                SIG_RSA_PKCS1_SHA512,
            ],
            signature_algorithms_cert: None,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            supported_versions: vec![0x0304, 0x0303],
            grease_supported_version: true,
            compress_certificate: Some(vec![CERT_COMP_ZLIB]),
            record_size_limit: None,
            psk_key_exchange_modes: Some(vec![PSK_DHE_KE]),
            alps: None,
            extensions: vec![
                ExtensionSlot::Grease {
                    slot: 0,
                    body: Vec::new(),
                },
                ExtensionSlot::ServerName,
                ExtensionSlot::ExtendedMasterSecret,
                ExtensionSlot::RenegotiationInfo,
                ExtensionSlot::SupportedGroups,
                ExtensionSlot::EcPointFormats,
                ExtensionSlot::Alpn,
                ExtensionSlot::StatusRequest,
                ExtensionSlot::SignatureAlgorithms,
                ExtensionSlot::SignedCertificateTimestamp,
                ExtensionSlot::KeyShare,
                ExtensionSlot::PskKeyExchangeModes,
                ExtensionSlot::SupportedVersions,
                ExtensionSlot::CompressCertificate,
                ExtensionSlot::Grease {
                    slot: 1,
                    body: vec![0x00],
                },
            ],
            extension_permutation: false,
            padding: PaddingPolicy::None,
        }
    }

    /// Materialize a [`ClientHello`] from this blueprint and per-connection
    /// randomness ([`INV-TLS-11`]).
    ///
    /// # Errors
    /// Propagates [`HelloError`] if padding measurement fails to serialize
    /// (for example an over-long session id or empty ALPN name).
    pub fn build(&self, params: BlueprintBuildParams<'_>) -> Result<ClientHello, HelloError> {
        let mut cipher_suites = Vec::with_capacity(self.cipher_suites.len() + 1);
        if self.grease_cipher_suite {
            cipher_suites.push(grease_at(params.grease_seed[0]));
        }
        cipher_suites.extend_from_slice(&self.cipher_suites);

        let mut supported_groups = Vec::with_capacity(self.supported_groups.len() + 1);
        if self.grease_supported_group {
            supported_groups.push(grease_at(params.grease_seed[1]));
        }
        supported_groups.extend_from_slice(&self.supported_groups);

        let mut supported_versions = Vec::with_capacity(self.supported_versions.len() + 1);
        if self.grease_supported_version {
            supported_versions.push(grease_at(params.grease_seed[2]));
        }
        supported_versions.extend_from_slice(&self.supported_versions);

        let mut key_shares = Vec::with_capacity(params.key_shares.len() + 1);
        if self.grease_key_share {
            key_shares.push(KeyShareEntry {
                group: grease_at(params.grease_seed[3]),
                share: vec![0x00],
            });
        }
        key_shares.extend(params.key_shares);

        let slots = if self.extension_permutation {
            permute_non_pinned(&self.extensions, &params.permutation_seed)
        } else {
            self.extensions.clone()
        };

        let mut used_grease_ext_kinds = Vec::new();
        let mut extensions = Vec::with_capacity(slots.len());
        let mut padding_index = None;
        for slot in slots {
            match slot {
                ExtensionSlot::ServerName => {
                    // RFC 6066 §3: literal IPv4/IPv6 addresses and empty host
                    // names are not permitted in the SNI HostName extension.
                    if !params.server_name.is_empty()
                        && params.server_name.parse::<std::net::IpAddr>().is_err()
                    {
                        extensions.push(Extension {
                            body: ExtensionBody::ServerName {
                                name: params.server_name.to_owned(),
                            },
                        });
                    }
                }
                ExtensionSlot::EcPointFormats => extensions.push(Extension {
                    body: ExtensionBody::EcPointFormats {
                        formats: vec![0x00],
                    },
                }),
                ExtensionSlot::RenegotiationInfo => extensions.push(Extension {
                    body: ExtensionBody::RenegotiationInfo,
                }),
                ExtensionSlot::ExtendedMasterSecret => extensions.push(Extension {
                    body: ExtensionBody::ExtendedMasterSecret,
                }),
                ExtensionSlot::SignedCertificateTimestamp => extensions.push(Extension {
                    body: ExtensionBody::SignedCertificateTimestamp,
                }),
                ExtensionSlot::StatusRequest => extensions.push(Extension {
                    body: ExtensionBody::StatusRequest,
                }),
                ExtensionSlot::SupportedGroups => extensions.push(Extension {
                    body: ExtensionBody::SupportedGroups {
                        groups: supported_groups.clone(),
                    },
                }),
                ExtensionSlot::SignatureAlgorithms => extensions.push(Extension {
                    body: ExtensionBody::SignatureAlgorithms {
                        schemes: self.signature_algorithms.clone(),
                    },
                }),
                ExtensionSlot::SignatureAlgorithmsCert => {
                    if let Some(schemes) = &self.signature_algorithms_cert {
                        extensions.push(Extension {
                            body: ExtensionBody::SignatureAlgorithmsCert {
                                schemes: schemes.clone(),
                            },
                        });
                    }
                }
                ExtensionSlot::Alpn => {
                    if !self.alpn.is_empty() {
                        extensions.push(Extension {
                            body: ExtensionBody::Alpn {
                                protocols: self.alpn.clone(),
                            },
                        });
                    }
                }
                ExtensionSlot::SupportedVersions => extensions.push(Extension {
                    body: ExtensionBody::SupportedVersions {
                        versions: supported_versions.clone(),
                    },
                }),
                ExtensionSlot::KeyShare => extensions.push(Extension {
                    body: ExtensionBody::KeyShare {
                        shares: key_shares.clone(),
                    },
                }),
                ExtensionSlot::SessionTicket => extensions.push(Extension {
                    body: ExtensionBody::SessionTicket { ticket: Vec::new() },
                }),
                ExtensionSlot::CompressCertificate => {
                    if let Some(algorithms) = &self.compress_certificate {
                        extensions.push(Extension {
                            body: ExtensionBody::CompressCertificate {
                                algorithms: algorithms.clone(),
                            },
                        });
                    }
                }
                ExtensionSlot::RecordSizeLimit => {
                    if let Some(limit) = self.record_size_limit {
                        extensions.push(Extension {
                            body: ExtensionBody::RecordSizeLimit { limit },
                        });
                    }
                }
                ExtensionSlot::PskKeyExchangeModes => {
                    if let Some(modes) = &self.psk_key_exchange_modes {
                        extensions.push(Extension {
                            body: ExtensionBody::PskKeyExchangeModes {
                                modes: modes.clone(),
                            },
                        });
                    }
                }
                ExtensionSlot::PostHandshakeAuth => extensions.push(Extension {
                    body: ExtensionBody::PostHandshakeAuth,
                }),
                ExtensionSlot::Alps => {
                    if let Some(protocols) = &self.alps {
                        extensions.push(Extension {
                            body: ExtensionBody::Alps {
                                protocols: protocols.clone(),
                            },
                        });
                    }
                }
                ExtensionSlot::Grease { slot, body } => {
                    let seed_byte = params.grease_seed[4 + ((slot as usize) & 3)];
                    let mut idx = seed_byte & 0x0f;
                    let mut kind = grease_at(idx);
                    while used_grease_ext_kinds.contains(&kind) {
                        idx = (idx + 1) & 0x0f;
                        kind = grease_at(idx);
                    }
                    used_grease_ext_kinds.push(kind);
                    extensions.push(Extension {
                        body: ExtensionBody::Grease { kind, body },
                    });
                }
                ExtensionSlot::Padding => {
                    padding_index = Some(extensions.len());
                    extensions.push(Extension {
                        body: ExtensionBody::Padding { len: 0 },
                    });
                }
                ExtensionSlot::Raw { kind, body } => extensions.push(Extension {
                    body: ExtensionBody::Raw { kind, body },
                }),
            }
        }

        let mut hello = ClientHello {
            legacy_version: self.legacy_version,
            random: params.random,
            session_id: params.session_id.to_vec(),
            cipher_suites,
            compression_methods: vec![0x00],
            extensions,
        };

        if let Some(idx) = padding_index {
            // Measure without the 4-byte padding extension header first.
            hello.extensions.remove(idx);
            let unpadded_body_len = hello.serialize()?.len().saturating_sub(4);
            let target_body_len = match self.padding {
                PaddingPolicy::None => None,
                PaddingPolicy::BoringSsl517 => {
                    if (256..512).contains(&unpadded_body_len) {
                        Some(512)
                    } else {
                        None
                    }
                }
                PaddingPolicy::TargetBodyLen(target) => {
                    if unpadded_body_len < target {
                        Some(target)
                    } else {
                        None
                    }
                }
            };
            if let Some(target) = target_body_len {
                let needed = target.saturating_sub(unpadded_body_len);
                if needed >= 4 {
                    hello.extensions.insert(
                        idx,
                        Extension {
                            body: ExtensionBody::Padding { len: needed - 4 },
                        },
                    );
                }
            }
        }

        Ok(hello)
    }
}

/// Deterministic Fisher-Yates shuffle of non-pinned extension slots.
fn permute_non_pinned(slots: &[ExtensionSlot], seed: &[u8; 32]) -> Vec<ExtensionSlot> {
    let mut result = slots.to_vec();
    let indices: Vec<usize> = result
        .iter()
        .enumerate()
        .filter_map(|(i, slot)| (!slot.is_pinned_in_permutation()).then_some(i))
        .collect();
    if indices.len() <= 1 {
        return result;
    }
    let mut state = u64::from_le_bytes(seed[0..8].try_into().unwrap_or([0; 8]))
        .wrapping_add(u64::from_le_bytes(seed[8..16].try_into().unwrap_or([0; 8])).rotate_left(13))
        ^ u64::from_le_bytes(seed[16..24].try_into().unwrap_or([0; 8])).rotate_left(29)
        ^ u64::from_le_bytes(seed[24..32].try_into().unwrap_or([0; 8])).rotate_left(47)
        ^ 0x9e37_79b9_7f4a_7c15;
    if state == 0 {
        state = 0x517c_c1b7_2722_0a95;
    }
    for i in (1..indices.len()).rev() {
        // splitmix64 step
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let j = (z as usize) % (i + 1);
        result.swap(indices[i], indices[j]);
    }
    result
}

#[cfg(test)]
mod tests;
