//! The owned TLS 1.3 client handshake state machine (RFC 8446, ADR-0045 step 3).
//!
//! The machine is sans-IO over caller-provided records: [`ClientHandshake::start`]
//! emits the ClientHello flight, [`ClientHandshake::progress`] consumes
//! whatever the transport delivered and returns either `Blocked` (more input
//! needed) or the established connection — app-data record protection in
//! both directions plus the negotiated ALPN. Every contradiction between
//! state and input is a refusal, never a guess: a ServerHello that does not
//! echo the session id, a suite or group that was not offered, an
//! out-of-order flight, a Finished that does not verify — each is a typed
//! error and the handshake is over.
//!
//! Ownership boundaries:
//!
//! - Every cryptographic operation is an `aws-lc` primitive; the state
//!   machine is protocol ([`INV-TLS-05`]).
//! - Certificate trust is the [`ServerCertVerifier`] seam; no verifier, no
//!   handshake, and no accept-all implementation exists in this crate
//!   ([`INV-TLS-08`]).
//! - The engine completes only what it offers ([`INV-TLS-06`]): the
//!   negotiated suite must be one of the three TLS 1.3 AEADs, and a server
//!   that falls back to TLS 1.2 is refused loudly until ADR-0045 step 4
//!   lands the CBC capability.
//! - Both reassembly buffers are bounded; a peer that streams without
//!   bounds is a refusal, not a memory growth.

use std::io::Read as _;

use thiserror::Error;

use aws_lc_rs::aead;
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use aws_lc_rs::signature::{UnparsedPublicKey, VerificationAlgorithm};

use crate::cert::subject_public_key_info;
use crate::hello::{ClientHello, Extension, ExtensionBody, HelloError, KeyShareEntry};
use crate::key_exchange::{self, AgreementError, ClientKeyShare};
use crate::key_schedule::{self, Hash, ScheduleError, Secret};
use crate::record::{
    CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE,
    LEGACY_VERSION_TLS12, LEGACY_VERSION_TLS13, MAX_CIPHERTEXT_LEN, MAX_PLAINTEXT_LEN,
    RECORD_HEADER_LEN, RecordError, RecordHeader, RecordProtector12, RecordProtector13,
    RecordUnprotector12, RecordUnprotector13, unprotected_record,
};
use crate::tls12::{self, Suite12Params};
use crate::wire::EXT_COOKIE;

/// The only handshake message a TLS 1.3 client may see in the clear:
/// `server_hello`, which is also how a HelloRetryRequest arrives.
const SERVER_HELLO: u8 = 2;
/// `new_session_ticket`.
pub(crate) const NEW_SESSION_TICKET: u8 = 4;
const COMPRESSED_CERTIFICATE: u8 = 25;
/// `key_update` (TLS 1.3 §4.6.3).
pub(crate) const KEY_UPDATE: u8 = 24;
/// `message_hash` synthetic handshake message for HRR transcripts (RFC 8446 §4.4.1).
const MESSAGE_HASH: u8 = 254;
/// `encrypted_extensions`.
const ENCRYPTED_EXTENSIONS: u8 = 8;
/// `certificate`.
const CERTIFICATE: u8 = 11;
/// `server_key_exchange`.
const SERVER_KEY_EXCHANGE: u8 = 12;
/// `server_hello_done`.
const SERVER_HELLO_DONE: u8 = 14;
/// `client_key_exchange`.
const CLIENT_KEY_EXCHANGE: u8 = 16;
/// `certificate_verify`.
const CERTIFICATE_VERIFY: u8 = 15;
/// `finished`.
const FINISHED: u8 = 20;

/// The special ServerHello random that marks a HelloRetryRequest
/// (RFC 8446 §4.1.3).
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The version a TLS 1.3 ServerHello's `supported_versions` selects:
/// 0x0304, distinct from the legacy 0x0303 that fills the version fields.
const TLS13_VERSION: u16 = 0x0304;

/// The 64 zero bytes that open a CertificateVerify signed content
/// (RFC 8446 §4.4.3).
const CERTIFICATE_VERIFY_PAD: [u8; 64] = [b' '; 64];
/// The server-side context string of a CertificateVerify.
const SERVER_CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// The reassembled handshake-flight bound. The reference server flight is
/// under a kilobyte; the bound turns an unbounded peer stream into a refusal.
pub(crate) const MAX_FLIGHT_BYTES: usize = 256 * 1024;
/// The raw record reassembly bound across coalesced TCP reads. Each individual
/// record header is still checked against [`MAX_CIPHERTEXT_LEN`] in
/// `take_record`, while the buffer as a whole is bounded by [`MAX_FLIGHT_BYTES`]
/// so two 16 KiB socket reads that straddle a record boundary never fail.
const RECORD_BUFFER_LIMIT: usize = MAX_FLIGHT_BYTES;
/// The HelloRetryRequest limit: one retry is the protocol's shape; two is a
/// loop.
const MAX_HELLO_RETRIES: u8 = 1;

/// Why the handshake ended without a connection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HandshakeError {
    /// A record-layer failure.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// A key-schedule primitive refusal.
    #[error(transparent)]
    Schedule(#[from] ScheduleError),
    /// A hello that cannot be serialized.
    #[error(transparent)]
    Hello(#[from] HelloError),
    /// A key-exchange failure.
    #[error(transparent)]
    Agreement(#[from] AgreementError),
    /// The raw record buffer grew past its bound.
    #[error("record buffer of {len} bytes exceeds the {max}-byte bound")]
    RecordBufferExceeded {
        /// The offending buffer length.
        len: usize,
        /// The bound.
        max: usize,
    },
    /// The reassembled flight grew past its bound.
    #[error("handshake flight of {len} bytes exceeds the {max}-byte bound")]
    FlightBufferExceeded {
        /// The offending buffer length.
        len: usize,
        /// The bound.
        max: usize,
    },
    /// A record no legal handshake state accepts.
    #[error("handshake state {state} received record content type {got:#04x}")]
    UnexpectedRecord {
        /// The state the record arrived in.
        state: &'static str,
        /// The record's content type.
        got: u8,
    },
    /// The server negotiated something the offer and capability disagree on.
    #[error("negotiation failed: {reason}")]
    NegotiationFailed {
        /// The specific disagreement.
        reason: String,
    },
    /// The server fell back to TLS 1.2, whose CBC capability lands with
    /// ADR-0045 step 4.
    #[error("server negotiated TLS 1.2; the engine cannot complete it yet (ADR-0045 step 4)")]
    Tls12Negotiated,
    /// The verifier refused the server's chain.
    #[error("the server's certificate was rejected: {reason}")]
    CertificateRejected {
        /// The verifier's reason.
        reason: String,
    },
    /// A CertificateVerify scheme the engine does not verify.
    #[error("signature scheme {scheme:#06x} is not implemented")]
    SignatureNotSupported {
        /// The offending scheme.
        scheme: u16,
    },
    /// A CertificateVerify signature that did not verify.
    #[error("the server's CertificateVerify under scheme {scheme:#06x} did not verify")]
    SignatureRejected {
        /// The scheme that failed.
        scheme: u16,
    },
    /// A Finished whose verify data did not match the transcript.
    #[error("the server's Finished did not verify")]
    FinishedMismatch,
    /// A protocol contradiction that has no more specific name.
    #[error("{reason}")]
    ProtocolViolation {
        /// What was contradicted.
        reason: String,
    },
    /// The peer aborted the handshake with an alert.
    #[error("the peer sent an alert: level {level}, description {description:#04x}")]
    AlertReceived {
        /// The alert level byte.
        level: u8,
        /// The alert description byte.
        description: u8,
    },
    /// The peer sent more HelloRetryRequests than the protocol's shape
    /// allows.
    #[error("the peer sent more than {max} HelloRetryRequests")]
    TooManyRetries {
        /// The limit that was exceeded.
        max: u8,
    },
}

/// The certificate trust policy of one handshake.
///
/// The engine never bypasses verification: a handshake cannot be started
/// without a verifier, and this crate ships no accept-all implementation —
/// the trust decision belongs to the consumer that knows the roots it
/// trusts ([`INV-TLS-08`]).
pub trait ServerCertVerifier {
    /// Verify the server's chain: `end_entity` and `intermediates` are the
    /// DER certificates in wire order, `server_name` the SNI the hello sent.
    ///
    /// Refusal aborts the handshake with
    /// [`HandshakeError::CertificateRejected`].
    ///
    /// # Errors
    /// Any refusal; the reason is carried to the caller verbatim.
    fn verify_chain(
        &mut self,
        server_name: &str,
        end_entity: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), String>;
}

/// The negotiated connection: what the transport layer drives afterwards.
#[derive(Debug)]
pub struct Established {
    /// The ALPN protocol the server selected, if one was negotiated.
    pub alpn: Option<Vec<u8>>,
    /// The record protection pair, in the negotiated version's shape.
    pub protectors: Protectors,
    /// TLS 1.3 `resumption_master_secret` (RFC 8446 §7.1) for deriving
    /// single-use PSKs from `NewSessionTicket` messages.
    pub(crate) resumption_master: Option<Secret>,
    /// TLS 1.3 client application traffic secret (for RFC 8446 §4.6.3 `KeyUpdate`).
    pub(crate) client_ap_secret: Option<Secret>,
    /// TLS 1.3 server application traffic secret (for RFC 8446 §4.6.3 `KeyUpdate`).
    pub(crate) server_ap_secret: Option<Secret>,
    /// Transcript hash of the negotiated cipher suite.
    pub(crate) hash: Hash,
    /// Negotiated wire cipher suite.
    pub(crate) cipher_suite: Option<u16>,
    /// Maximum plaintext payload per outgoing record (RFC 8449 `record_size_limit`,
    /// bounded by [`MAX_PLAINTEXT_LEN`]).
    pub(crate) max_write_plaintext: usize,
}

/// The record protection pair of an established connection.
///
/// The two versions protect records differently — TLS 1.3 pads the inner
/// plaintext and derives fresh epochs; TLS 1.2 keeps the handshake keys for
/// the connection's lifetime — so the pair is one enum, not one struct with
/// two optional halves.
#[derive(Debug)]
pub enum Protectors {
    /// TLS 1.3 (RFC 8446 §5.2): sequence-derived nonces, zero-padded inner
    /// plaintext, fresh epochs after the handshake.
    Tls13 {
        /// Client-to-server record protection.
        write: RecordProtector13,
        /// Server-to-client record protection.
        read: RecordUnprotector13,
        /// The next write sequence number: 0.
        write_seq: u64,
        /// The next read sequence number: 0.
        read_seq: u64,
    },
    /// TLS 1.2 (RFC 5246 §6.2.3): the handshake's write keys protect the
    /// connection's records for its lifetime; the Finished flights consumed
    /// sequence 0 in each direction.
    Tls12 {
        /// Client-to-server record protection.
        write: RecordProtector12,
        /// Server-to-client record protection.
        read: RecordUnprotector12,
        /// The next write sequence number: 1.
        write_seq: u64,
        /// The next read sequence number: 1.
        read_seq: u64,
    },
}

/// What one [`ClientHandshake::progress`] call produced.
#[derive(Debug)]
pub enum HandshakeProgress {
    /// More input is needed before the next state transition.
    Blocked,
    /// The handshake completed; application data may flow.
    Established(Box<Established>),
}

/// Where the server flight is, message by message.
#[derive(Debug)]
enum FlightStage {
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    AwaitFinished,
}

enum State {
    ExpectServerHello,
    /// The TLS 1.3 flight, protected after the ServerHello.
    ExpectServerFlight,
    /// The TLS 1.2 flight: plaintext until the server's change_cipher_spec.
    ExpectTls12Flight,
    Established,
}

/// Where the TLS 1.2 flight is, message by message.
#[derive(Debug)]
enum State12 {
    Certificate,
    KeyExchange,
    HelloDone,
    ServerFinished,
}

/// The client side of a TLS 1.3 handshake, between hello and application
/// data.
pub struct ClientHandshake<V: ServerCertVerifier> {
    verifier: V,
    hello: ClientHello,
    server_name: String,
    shares: Vec<ClientKeyShare>,
    offered_alpn: Vec<Vec<u8>>,
    negotiated_alpn: Option<Vec<u8>>,
    negotiated_suite: Option<u16>,
    negotiated_suite12: Option<Suite12Params>,
    state12: Option<State12>,
    server_random: Option<[u8; 32]>,
    end_entity12: Option<Vec<u8>>,
    server_key_exchange: Option<(u16, Vec<u8>)>,
    tls12_master: Option<Vec<u8>>,
    tls12_server_finished_hash: Option<Vec<u8>>,
    tls12_write: Option<RecordProtector12>,
    tls12_write_seq: u64,
    tls12_pending_read: Option<RecordUnprotector12>,
    tls12_read: Option<RecordUnprotector12>,
    tls12_read_seq: u64,
    hash: Hash,
    state: State,
    flight_stage: FlightStage,
    transcript: Vec<u8>,
    record_buffer: Vec<u8>,
    flight: Vec<u8>,
    end_entity: Option<Vec<u8>>,
    read_unprotector: Option<RecordUnprotector13>,
    read_seq: u64,
    client_hs_write: Option<RecordProtector13>,
    client_hs_write_seq: u64,
    offered_psk: Option<Vec<u8>>,
    resumed: bool,
    resumption_master: Option<Secret>,
    client_ap_secret: Option<Secret>,
    server_ap_secret: Option<Secret>,
    protectors: Option<Protectors>,
    client_hs_secret: Option<Secret>,
    server_hs_secret: Option<Secret>,
    handshake_secret: Option<Secret>,
    server_sent_ccs: bool,
    hrr_count: u8,
    hrr_suite: Option<u16>,
    hrr_group: Option<u16>,
    max_write_plaintext: usize,
    pending_output: Vec<u8>,
}

impl<V: ServerCertVerifier> ClientHandshake<V> {
    /// Start a handshake with the given hello, key shares and verifier.
    ///
    /// The hello and the shares are bound together: every share must appear
    /// in the hello's `key_share` extension with identical bytes, and every
    /// `key_share` entry must have a generated share — the machine refuses
    /// to run with an offer it cannot honour ([`INV-TLS-06`]).
    ///
    /// # Errors
    /// A hello that cannot be serialized, or an offer/share disagreement.
    pub fn start(
        hello: ClientHello,
        shares: Vec<ClientKeyShare>,
        verifier: V,
    ) -> Result<Self, HandshakeError> {
        Self::start_with_psk(hello, shares, verifier, None)
    }

    /// Start a client handshake, optionally offering a TLS 1.3 resumption PSK
    /// matching the `pre_shared_key` extension on `hello`.
    ///
    /// # Errors
    /// [`HandshakeError::Hello`] when the hello cannot serialize;
    /// [`HandshakeError::NegotiationFailed`] when `hello` and `shares`
    /// disagree.
    pub fn start_with_psk(
        hello: ClientHello,
        shares: Vec<ClientKeyShare>,
        verifier: V,
        offered_psk: Option<Vec<u8>>,
    ) -> Result<Self, HandshakeError> {
        let entries = hello_key_share_entries(&hello)?;
        if entries.len() != shares.len() {
            return Err(HandshakeError::NegotiationFailed {
                reason: format!(
                    "the hello offers {} key shares but {} were generated",
                    entries.len(),
                    shares.len()
                ),
            });
        }
        for (entry, share) in entries.iter().zip(shares.iter()) {
            if entry.group != share.group || entry.share != share.share {
                return Err(HandshakeError::NegotiationFailed {
                    reason: format!(
                        "the hello's key share for group {:#06x} does not match the generated share",
                        entry.group
                    ),
                });
            }
        }
        let server_name = hello_server_name(&hello);
        let offered_alpn = hello
            .extensions
            .iter()
            .find_map(|extension| match &extension.body {
                ExtensionBody::Alpn { protocols } => Some(protocols.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let hello_bytes = hello.serialize()?;
        Ok(Self {
            verifier,
            hello,
            server_name,
            shares,
            offered_alpn,
            negotiated_alpn: None,
            negotiated_suite: None,
            negotiated_suite12: None,
            state12: None,
            server_random: None,
            end_entity12: None,
            server_key_exchange: None,
            tls12_master: None,
            tls12_server_finished_hash: None,
            tls12_write: None,
            tls12_write_seq: 0,
            tls12_pending_read: None,
            tls12_read: None,
            tls12_read_seq: 0,
            hash: Hash::Sha256, // replaced at the ServerHello
            state: State::ExpectServerHello,
            flight_stage: FlightStage::EncryptedExtensions,
            transcript: hello_bytes.clone(),
            record_buffer: Vec::new(),
            flight: Vec::new(),
            end_entity: None,
            read_unprotector: None,
            read_seq: 0,
            client_hs_write: None,
            client_hs_write_seq: 0,
            offered_psk,
            resumed: false,
            resumption_master: None,
            client_ap_secret: None,
            server_ap_secret: None,
            protectors: None,
            client_hs_secret: None,
            server_hs_secret: None,
            handshake_secret: None,
            server_sent_ccs: false,
            hrr_count: 0,
            hrr_suite: None,
            hrr_group: None,
            max_write_plaintext: MAX_PLAINTEXT_LEN,
            pending_output: unprotected_record(
                CONTENT_HANDSHAKE,
                LEGACY_VERSION_TLS12,
                &hello_bytes,
            ),
        })
    }

    /// Override the expected server name used during certificate verification.
    ///
    /// Needed when targeting a literal IPv4 or IPv6 address: RFC 6066 §3 forbids
    /// IP literals inside the wire SNI extension, so the hello omits `server_name`
    /// while verification still checks the peer certificate against the target IP.
    #[must_use]
    pub fn with_verified_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = server_name.into();
        self
    }

    /// The bytes the transport should write next.
    #[must_use]
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_output)
    }

    /// How many bytes [`ClientHandshake::take_output`] would return.
    #[must_use]
    pub fn take_output_pending_len(&self) -> usize {
        self.pending_output.len()
    }

    /// Input bytes that arrived after the handshake completed; the
    /// application-data phase owns them now.
    #[must_use]
    pub fn take_buffered_input(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.record_buffer)
    }

    /// Drive the machine with bytes from the transport.
    ///
    /// # Errors
    /// Any refusal the machine reaches — see [`HandshakeError`]. A refusal
    /// is terminal: the handshake is over and the connection must not be
    /// reused.
    pub fn progress(&mut self, input: &[u8]) -> Result<HandshakeProgress, HandshakeError> {
        self.record_buffer.extend_from_slice(input);
        if self.record_buffer.len() > RECORD_BUFFER_LIMIT {
            return Err(HandshakeError::RecordBufferExceeded {
                len: self.record_buffer.len(),
                max: RECORD_BUFFER_LIMIT,
            });
        }
        loop {
            match self.state {
                State::ExpectServerHello => {
                    let Some(record) = self.take_record()? else {
                        return Ok(HandshakeProgress::Blocked);
                    };
                    self.consume_pre_hello_record(record)?;
                }
                State::ExpectServerFlight => {
                    let Some(record) = self.take_record()? else {
                        return Ok(HandshakeProgress::Blocked);
                    };
                    self.consume_flight_record(record)?;
                }
                State::ExpectTls12Flight => {
                    let Some(record) = self.take_record()? else {
                        return Ok(HandshakeProgress::Blocked);
                    };
                    self.consume_tls12_record(record)?;
                }
                State::Established => {
                    let established = Established {
                        alpn: self.negotiated_alpn.take(),
                        protectors: self.protectors.take().ok_or_else(|| {
                            HandshakeError::ProtocolViolation {
                                reason: "an established connection lost its protectors".into(),
                            }
                        })?,
                        resumption_master: self.resumption_master.take(),
                        client_ap_secret: self.client_ap_secret.take(),
                        server_ap_secret: self.server_ap_secret.take(),
                        hash: self.hash,
                        cipher_suite: self.negotiated_suite,
                        max_write_plaintext: self.max_write_plaintext,
                    };
                    return Ok(HandshakeProgress::Established(Box::new(established)));
                }
            }
        }
    }

    fn take_record(&mut self) -> Result<Option<Vec<u8>>, HandshakeError> {
        if self.record_buffer.len() < RECORD_HEADER_LEN {
            return Ok(None);
        }
        let header = RecordHeader::parse(&self.record_buffer)?;
        if usize::from(header.payload_len) > MAX_CIPHERTEXT_LEN {
            return Err(HandshakeError::Record(RecordError::RecordTooLarge {
                len: usize::from(header.payload_len),
                max: MAX_CIPHERTEXT_LEN,
            }));
        }
        let total = RECORD_HEADER_LEN + usize::from(header.payload_len);
        if self.record_buffer.len() < total {
            return Ok(None);
        }
        Ok(Some(self.record_buffer.drain(..total).collect()))
    }

    fn consume_pre_hello_record(&mut self, record: Vec<u8>) -> Result<(), HandshakeError> {
        let header = RecordHeader::parse(&record)?;
        let payload = &record[RECORD_HEADER_LEN..];
        match header.content_type {
            CONTENT_HANDSHAKE => {
                if payload.is_empty() {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "empty handshake record fragment (RFC 8446 §5.1)".into(),
                    });
                }
                self.flight.extend_from_slice(payload);
                if self.flight.len() > MAX_FLIGHT_BYTES {
                    return Err(HandshakeError::FlightBufferExceeded {
                        len: self.flight.len(),
                        max: MAX_FLIGHT_BYTES,
                    });
                }
                while let Some((kind, message)) = take_message(&mut self.flight) {
                    if kind != SERVER_HELLO {
                        return Err(HandshakeError::ProtocolViolation {
                            reason: format!(
                                "message type {kind:#04x} cannot precede the ServerHello"
                            ),
                        });
                    }
                    self.process_server_hello(&message)?;
                    // The negotiation may have moved the machine into a
                    // flight. In TLS 1.2 the server's remaining messages are
                    // plaintext and may already sit in the flight buffer
                    // (rustls coalesces them into the ServerHello's record);
                    // hand them straight to the 1.2 message processors. In
                    // TLS 1.3 everything after the ServerHello arrives as
                    // new protected records, so nothing more happens here.
                    if matches!(self.state, State::ExpectTls12Flight) {
                        while let Some((kind, message)) = take_message(&mut self.flight) {
                            self.process_tls12_message(kind, &message)?;
                            if matches!(self.state, State::Established) {
                                if !self.flight.is_empty() {
                                    return Err(HandshakeError::ProtocolViolation {
                                        reason:
                                            "handshake messages must not span the Finished boundary"
                                                .into(),
                                    });
                                }
                                break;
                            }
                        }
                    } else if !self.flight.is_empty() {
                        // RFC 8446 §5.1: ServerHello / HelloRetryRequest must
                        // align with a record boundary.
                        return Err(HandshakeError::ProtocolViolation {
                            reason: "handshake messages must not span a ServerHello or HelloRetryRequest record boundary".into(),
                        });
                    }
                    if !matches!(self.state, State::ExpectServerHello) {
                        break;
                    }
                }
                Ok(())
            }
            CONTENT_CHANGE_CIPHER_SPEC => {
                if !self.flight.is_empty() {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "a handshake message straddled ChangeCipherSpec".into(),
                    });
                }
                if payload != [0x01] {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "malformed change_cipher_spec record".into(),
                    });
                }
                self.server_sent_ccs = true;
                Ok(())
            }
            CONTENT_ALERT => Err(alert_error(payload)),
            got => Err(HandshakeError::UnexpectedRecord {
                state: "expect_server_hello",
                got,
            }),
        }
    }

    fn consume_flight_record(&mut self, record: Vec<u8>) -> Result<(), HandshakeError> {
        let header = RecordHeader::parse(&record)?;
        match header.content_type {
            CONTENT_CHANGE_CIPHER_SPEC => {
                if !self.flight.is_empty() {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "a handshake message straddled ChangeCipherSpec".into(),
                    });
                }
                if record[RECORD_HEADER_LEN..] != [0x01] {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "malformed change_cipher_spec record".into(),
                    });
                }
                Ok(())
            }
            CONTENT_APPLICATION_DATA => {
                let unprotector = self.read_unprotector.as_ref().ok_or_else(|| {
                    HandshakeError::ProtocolViolation {
                        reason: "a protected record arrived before handshake keys exist".into(),
                    }
                })?;
                let next_seq = self.read_seq.checked_add(1).ok_or_else(|| {
                    HandshakeError::ProtocolViolation {
                        reason: "handshake read sequence overflow".into(),
                    }
                })?;
                let (inner, payload) = unprotector.open(self.read_seq, &record)?;
                self.read_seq = next_seq;
                match inner {
                    CONTENT_HANDSHAKE => {
                        if payload.is_empty() {
                            return Err(HandshakeError::ProtocolViolation {
                                reason: "empty handshake record fragment (RFC 8446 §5.1)".into(),
                            });
                        }
                        self.flight.extend_from_slice(&payload);
                        if self.flight.len() > MAX_FLIGHT_BYTES {
                            return Err(HandshakeError::FlightBufferExceeded {
                                len: self.flight.len(),
                                max: MAX_FLIGHT_BYTES,
                            });
                        }
                        while let Some((kind, message)) = take_message(&mut self.flight) {
                            self.process_flight_message(kind, &message)?;
                            if matches!(self.state, State::Established) {
                                if !self.flight.is_empty() {
                                    return Err(HandshakeError::ProtocolViolation {
                                        reason: "handshake messages must not span the Finished key-change boundary".into(),
                                    });
                                }
                                break;
                            }
                        }
                        Ok(())
                    }
                    CONTENT_ALERT => Err(alert_error(&payload)),
                    got => Err(HandshakeError::UnexpectedRecord {
                        state: "expect_server_flight",
                        got,
                    }),
                }
            }
            got => Err(HandshakeError::UnexpectedRecord {
                state: "expect_server_flight",
                got,
            }),
        }
    }

    fn process_flight_message(&mut self, kind: u8, message: &[u8]) -> Result<(), HandshakeError> {
        match (kind, &self.flight_stage) {
            (ENCRYPTED_EXTENSIONS, FlightStage::EncryptedExtensions) => {
                self.process_encrypted_extensions(message)?;
            }
            (CERTIFICATE, FlightStage::Certificate) => {
                self.process_certificate(message)?;
            }
            (COMPRESSED_CERTIFICATE, FlightStage::Certificate) => {
                self.process_compressed_certificate(message)?;
            }
            (CERTIFICATE_VERIFY, FlightStage::CertificateVerify) => {
                self.process_certificate_verify(message)?;
            }
            (FINISHED, FlightStage::AwaitFinished) => {
                self.process_server_finished(message)?;
            }
            (NEW_SESSION_TICKET, _) | (SERVER_HELLO, _) => {
                return Err(HandshakeError::ProtocolViolation {
                    reason: format!("message type {kind:#04x} cannot appear in the server flight"),
                });
            }
            (kind, stage) => {
                return Err(HandshakeError::ProtocolViolation {
                    reason: format!(
                        "message type {kind:#04x} is out of order for flight stage {stage:?}"
                    ),
                });
            }
        }
        Ok(())
    }

    fn process_server_hello(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        let (legacy_version, rest) = take_u16(&message[4..])?;
        let (random, rest) = take_slice::<32>(rest)?;
        let (session_id, rest) = take_u8_vector(rest)?;
        let (suite, rest) = take_u16(rest)?;
        // The ServerHello carries a single compression method byte, not the
        // ClientHello's vector form (RFC 8446 §4.1.3).
        let (compression, rest) = take_byte(rest)?;

        let offered_alpn = self.offered_alpn.clone();
        let mut selected_version = None;
        let mut server_share: Option<(u16, Vec<u8>)> = None;
        let mut cookie: Option<Vec<u8>> = None;
        let mut renegotiation_info_seen = false;
        let mut extended_master_secret_seen = false;
        let mut server_alpn: Option<Vec<u8>> = None;
        let mut server_record_size_limit: Option<usize> = None;
        let mut selected_psk_identity: Option<u16> = None;
        let mut ext_kinds: Vec<u16> = Vec::new();
        if !rest.is_empty() {
            for_each_extension(rest, |kind, payload| {
                ext_kinds.push(kind);
                match kind {
                    0x0005 => {} // status_request: no stapled response is fine in TLS 1.2
                    0x000b => {} // ec_point_formats: uncompressed is assumed in TLS 1.2
                    0x0010 => {
                        let protocols = alpn_protocols(payload)?;
                        if protocols.len() != 1 {
                            return Err(HandshakeError::ProtocolViolation {
                                reason:
                                    "the server ALPN extension must select exactly one protocol"
                                        .into(),
                            });
                        }
                        let Some(selected) = protocols.first() else {
                            return Err(HandshakeError::ProtocolViolation {
                                reason: "the server sent an empty ALPN list".into(),
                            });
                        };
                        if !offered_alpn.iter().any(|protocol| protocol == selected) {
                            return Err(HandshakeError::ProtocolViolation {
                                reason: format!(
                                    "the server selected ALPN {:?}, which was not offered",
                                    String::from_utf8_lossy(selected)
                                ),
                            });
                        }
                        server_alpn = Some(selected.clone());
                    }
                    0x0017 => extended_master_secret_seen = true,
                    0x001c => {
                        if payload.len() != 2 {
                            return Err(HandshakeError::ProtocolViolation {
                                reason: "malformed ServerHello record_size_limit extension".into(),
                            });
                        }
                        let limit = u16::from_be_bytes([payload[0], payload[1]]);
                        if limit < 64 {
                            return Err(HandshakeError::ProtocolViolation {
                                reason: "record_size_limit is below the 64-byte RFC 8449 minimum"
                                    .into(),
                            });
                        }
                        server_record_size_limit = Some(usize::from(limit).min(MAX_PLAINTEXT_LEN));
                    }
                    0x0029 => {
                        if payload.len() == 2 {
                            selected_psk_identity =
                                Some(u16::from_be_bytes([payload[0], payload[1]]));
                        } else {
                            return Err(HandshakeError::ProtocolViolation {
                                reason: "malformed ServerHello pre_shared_key extension".into(),
                            });
                        }
                    }
                    0x002b => selected_version = Some(selected_version_of(payload)?),
                    EXT_COOKIE => cookie = Some(parse_cookie_extension(payload)?),
                    0x0033 => server_share = Some(single_key_share(payload)?),
                    0xff01 => renegotiation_info_seen = true,
                    _ => {}
                }
                Ok(())
            })?;
        }
        if legacy_version != LEGACY_VERSION_TLS13 {
            return Err(HandshakeError::NegotiationFailed {
                reason: format!("the ServerHello legacy version is {legacy_version:#06x}"),
            });
        }

        if *random == HELLO_RETRY_RANDOM {
            if let Some(&bad) = ext_kinds
                .iter()
                .find(|&&kind| !matches!(kind, 0x002b | EXT_COOKIE | 0x0033))
            {
                return Err(HandshakeError::ProtocolViolation {
                    reason: format!(
                        "HelloRetryRequest carries forbidden extension {bad:#06x} (RFC 8446 §4.1.4)"
                    ),
                });
            }
            return self.process_hello_retry(HelloRetryRequest {
                message,
                selected_version,
                server_share,
                cookie,
                session_id,
                suite,
                compression,
            });
        }
        if cookie.is_some() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "a ServerHello unexpectedly carries a cookie extension".into(),
            });
        }
        if selected_version.is_none() {
            if server_share.is_some() || selected_psk_identity.is_some() {
                return Err(HandshakeError::ProtocolViolation {
                    reason: "a TLS 1.2 ServerHello carries TLS 1.3 extensions".into(),
                });
            }
            return self.process_server_hello12(
                message,
                legacy_version,
                *random,
                suite,
                renegotiation_info_seen,
                extended_master_secret_seen,
                server_alpn,
                server_record_size_limit,
            );
        }
        if selected_version != Some(TLS13_VERSION) {
            return Err(HandshakeError::NegotiationFailed {
                reason: format!(
                    "the server selected version {:?}, which was not offered",
                    selected_version
                ),
            });
        }
        if let Some(&bad) = ext_kinds
            .iter()
            .find(|&&kind| !matches!(kind, 0x0029 | 0x002b | 0x0033))
        {
            return Err(HandshakeError::ProtocolViolation {
                reason: format!(
                    "TLS 1.3 ServerHello carries extension {bad:#06x} outside supported_versions/key_share/pre_shared_key (RFC 8446 §4.1.3)"
                ),
            });
        }
        if session_id != self.hello.session_id {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the ServerHello does not echo the ClientHello's session id".into(),
            });
        }
        if compression != 0x00 {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the ServerHello offers compression other than null".into(),
            });
        }
        if let Some(hrr_suite) = self.hrr_suite
            && suite != hrr_suite
        {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the ServerHello cipher suite disagrees with the HelloRetryRequest".into(),
            });
        }
        let (algorithm, hash, key_len) =
            suite_params(suite).ok_or_else(|| HandshakeError::NegotiationFailed {
                reason: format!("the server selected suite {suite:#06x}, which is not implemented"),
            })?;
        if !self.hello.cipher_suites.contains(&suite) {
            return Err(HandshakeError::NegotiationFailed {
                reason: format!("the server selected suite {suite:#06x}, which was not offered"),
            });
        }
        let Some((group, peer_share)) = server_share else {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the ServerHello carries no key_share extension".into(),
            });
        };
        if let Some(hrr_group) = self.hrr_group
            && group != hrr_group
        {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the ServerHello key_share group disagrees with the HelloRetryRequest"
                    .into(),
            });
        }
        let share = self
            .shares
            .iter()
            .find(|share| share.group == group)
            .ok_or_else(|| HandshakeError::NegotiationFailed {
                reason: format!("the server selected group {group:#06x}, which was not offered"),
            })?;
        let shared_secret = share.agree(&peer_share)?;
        self.server_random = Some(*random);
        self.transcript.extend_from_slice(message);
        self.hash = hash;
        self.negotiated_suite = Some(suite);

        // HandshakeSecret = Extract(DeriveSecret(Early, "derived", ""), DHE).
        let zeros = vec![0u8; hash.output_len()];
        let early = match selected_psk_identity {
            Some(0) => {
                let Some(psk) = self.offered_psk.as_deref() else {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "the server selected a PSK that was not offered".into(),
                    });
                };
                if psk.len() != hash.output_len() {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "the server selected a PSK whose hash does not match the suite"
                            .into(),
                    });
                }
                self.resumed = true;
                Secret::extract(&zeros, psk, hash)
            }
            Some(other) => {
                return Err(HandshakeError::ProtocolViolation {
                    reason: format!("the server selected PSK identity {other}, out of range"),
                });
            }
            None => Secret::extract(&zeros, &zeros, hash),
        };
        let derived = early.derive_secret("derived", &key_schedule::empty_transcript_hash(hash))?;
        crate::zeroize::wipe_option(&mut self.offered_psk);
        let handshake_secret = Secret::extract(derived.as_bytes(), &shared_secret, hash);
        self.handshake_secret = Some(handshake_secret.clone());

        let transcript_hash = key_schedule::transcript_hash(hash, &self.transcript);
        let client_hs = handshake_secret.derive_secret("c hs traffic", &transcript_hash)?;
        let server_hs = handshake_secret.derive_secret("s hs traffic", &transcript_hash)?;
        let client_keys = client_hs.traffic_keys(key_len)?;
        let server_keys = server_hs.traffic_keys(key_len)?;

        self.client_hs_secret = Some(client_hs);
        self.server_hs_secret = Some(server_hs);
        self.client_hs_write = Some(RecordProtector13::new(
            algorithm,
            &client_keys.key,
            client_keys.iv,
        )?);
        self.read_unprotector = Some(RecordUnprotector13::new(
            algorithm,
            &server_keys.key,
            server_keys.iv,
        )?);
        self.read_seq = 0;
        self.client_hs_write_seq = 0;
        self.state = State::ExpectServerFlight;
        self.flight_stage = FlightStage::EncryptedExtensions;

        // Compatibility mode: a server that sent a change_cipher_spec gets
        // one back before the client's second flight (RFC 8446 §5).
        if self.server_sent_ccs {
            self.pending_output.extend_from_slice(&unprotected_record(
                CONTENT_CHANGE_CIPHER_SPEC,
                LEGACY_VERSION_TLS13,
                &[0x01],
            ));
        }
        Ok(())
    }

    fn process_hello_retry(&mut self, hrr: HelloRetryRequest<'_>) -> Result<(), HandshakeError> {
        let HelloRetryRequest {
            message,
            selected_version,
            server_share,
            cookie,
            session_id,
            suite,
            compression,
        } = hrr;
        if selected_version != Some(TLS13_VERSION) {
            return Err(HandshakeError::ProtocolViolation {
                reason: "a HelloRetryRequest must offer TLS 1.3".into(),
            });
        }
        if server_share.is_none() && cookie.is_none() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "a HelloRetryRequest carries neither a key_share nor a cookie extension"
                    .into(),
            });
        }
        if compression != 0x00 || session_id != self.hello.session_id {
            return Err(HandshakeError::ProtocolViolation {
                reason: "a HelloRetryRequest must echo the first flight's parameters".into(),
            });
        }
        let (_, hash, _) =
            suite_params(suite).ok_or_else(|| HandshakeError::NegotiationFailed {
                reason: format!(
                    "the HelloRetryRequest selected suite {suite:#06x}, which is not implemented"
                ),
            })?;
        if !self.hello.cipher_suites.contains(&suite) {
            return Err(HandshakeError::NegotiationFailed {
                reason: format!(
                    "the HelloRetryRequest selected suite {suite:#06x}, which was not offered"
                ),
            });
        }
        let selected_group = if let Some((group, peer_share)) = server_share {
            if !peer_share.is_empty() {
                return Err(HandshakeError::ProtocolViolation {
                    reason: "a HelloRetryRequest's key share must be empty".into(),
                });
            }
            // The selected group must be one the first flight offered and one
            // the engine implements ([INV-TLS-06]).
            if !self.hello.extensions.iter().any(|extension| {
                matches!(&extension.body,
                    ExtensionBody::SupportedGroups { groups } if groups.contains(&group))
            }) {
                return Err(HandshakeError::NegotiationFailed {
                    reason: format!(
                        "the HelloRetryRequest selected group {group:#06x}, which was not offered"
                    ),
                });
            }
            if !key_exchange::offerable_group(group) {
                return Err(HandshakeError::NegotiationFailed {
                    reason: format!(
                        "the HelloRetryRequest selected group {group:#06x}, which the engine cannot complete"
                    ),
                });
            }
            // RFC 8446 §4.2.8: the server must not request a retry for a group
            // whose share was already sent in ClientHello1.
            if self.shares.iter().any(|share| share.group == group) {
                return Err(HandshakeError::ProtocolViolation {
                    reason: format!(
                        "the HelloRetryRequest selected group {group:#06x}, which was already shared"
                    ),
                });
            }
            Some(group)
        } else {
            None
        };
        self.hrr_count += 1;
        if self.hrr_count > MAX_HELLO_RETRIES {
            return Err(HandshakeError::TooManyRetries {
                max: MAX_HELLO_RETRIES,
            });
        }
        self.hrr_suite = Some(suite);
        self.hrr_group = selected_group;

        // RFC 8446 §4.4.1: replace ClientHello1 in the transcript with
        // `message_hash || 0x00 0x00 Hash.length || Hash(ClientHello1)`.
        let ch1_hash = key_schedule::transcript_hash(hash, &self.transcript);
        self.transcript.clear();
        self.transcript.push(MESSAGE_HASH);
        self.transcript
            .extend_from_slice(&[0x00, 0x00, ch1_hash.len() as u8]);
        self.transcript.extend_from_slice(&ch1_hash);
        self.transcript.extend_from_slice(message);

        // Rebuild the hello for ClientHello2: swap key_share if requested,
        // echo cookie before trailing padding/pre_shared_key (RFC 8446 §4.2.2),
        // and strip or rebind any pre_shared_key extension.
        let mut hello = self.hello.clone();
        if let Some(group) = selected_group {
            let replacement = ClientKeyShare::generate(&[group])?.remove(0);
            for extension in &mut hello.extensions {
                if let ExtensionBody::KeyShare { shares } = &mut extension.body {
                    *shares = vec![KeyShareEntry {
                        group,
                        share: replacement.share.clone(),
                    }];
                }
            }
            self.shares = vec![replacement];
        }
        hello.extensions.retain(|ext| {
            !matches!(
                ext.body,
                ExtensionBody::Raw {
                    kind: EXT_COOKIE,
                    ..
                }
            )
        });
        if let Some(cookie) = cookie {
            let insert_at = hello
                .extensions
                .iter()
                .position(|ext| {
                    matches!(
                        ext.body,
                        ExtensionBody::Padding { .. } | ExtensionBody::PreSharedKey { .. }
                    )
                })
                .unwrap_or(hello.extensions.len());
            hello.extensions.insert(
                insert_at,
                Extension {
                    body: ExtensionBody::Raw {
                        kind: EXT_COOKIE,
                        body: cookie,
                    },
                },
            );
        }
        if let Some(psk) = self.offered_psk.as_deref()
            && hello
                .extensions
                .iter()
                .any(|ext| matches!(ext.body, ExtensionBody::PreSharedKey { .. }))
        {
            if psk.len() != hash.output_len() {
                hello
                    .extensions
                    .retain(|ext| !matches!(ext.body, ExtensionBody::PreSharedKey { .. }));
                crate::zeroize::wipe_option(&mut self.offered_psk);
            } else {
                hello.rebind_psk_with_prefix(&self.transcript, psk, hash)?;
            }
        }
        let hello_bytes = hello.serialize()?;
        self.transcript.extend_from_slice(&hello_bytes);
        self.pending_output.extend_from_slice(&unprotected_record(
            CONTENT_HANDSHAKE,
            LEGACY_VERSION_TLS12,
            &hello_bytes,
        ));
        self.hello = hello;
        Ok(())
    }

    fn process_encrypted_extensions(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        let mut negotiated = None;
        let mut negotiated_record_size_limit = None;
        let offered = self.offered_alpn.clone();
        for_each_extension(&message[4..], |kind, payload| {
            if kind == 0x0010 {
                let protocols = alpn_protocols(payload)?;
                if protocols.len() != 1 {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "the server ALPN extension must select exactly one protocol".into(),
                    });
                }
                let Some(selected) = protocols.first() else {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "the server sent an empty ALPN list".into(),
                    });
                };
                if !offered.iter().any(|protocol| protocol == selected) {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: format!(
                            "the server selected ALPN {:?}, which was not offered",
                            String::from_utf8_lossy(selected)
                        ),
                    });
                }
                negotiated = Some(selected.clone());
            } else if kind == crate::wire::EXT_RECORD_SIZE_LIMIT {
                if payload.len() != 2 {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "malformed EncryptedExtensions record_size_limit".into(),
                    });
                }
                let limit = u16::from_be_bytes([payload[0], payload[1]]);
                if limit < 64 {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "record_size_limit is below the 64-byte RFC 8449 minimum".into(),
                    });
                }
                // RFC 8449 §4: in TLS 1.3 the limit includes the 1-byte inner content type.
                negotiated_record_size_limit = Some(usize::from(limit - 1).min(MAX_PLAINTEXT_LEN));
            }
            Ok(())
        })?;
        self.negotiated_alpn = negotiated;
        if let Some(limit) = negotiated_record_size_limit {
            self.max_write_plaintext = limit;
        }
        self.transcript.extend_from_slice(message);
        self.flight_stage = if self.resumed {
            FlightStage::AwaitFinished
        } else {
            FlightStage::Certificate
        };
        Ok(())
    }

    fn process_certificate(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        self.process_certificate_body(&message[4..], message)
    }

    /// RFC 8879 `CompressedCertificate` (type 25): decompress the certificate
    /// message body under the flight bound and hash the *compressed* handshake
    /// message into the transcript.
    fn process_compressed_certificate(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        let (algorithm, rest) = take_u16(&message[4..])?;
        let (uncompressed_len, rest) = take_u24(rest)?;
        if uncompressed_len > MAX_FLIGHT_BYTES {
            return Err(HandshakeError::FlightBufferExceeded {
                len: uncompressed_len,
                max: MAX_FLIGHT_BYTES,
            });
        }
        let (compressed_len, rest) = take_u24(rest)?;
        if compressed_len != rest.len() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the CompressedCertificate payload length does not match its bytes".into(),
            });
        }
        let mut decompressed = Vec::with_capacity(uncompressed_len.min(64 * 1024));
        let limit = u64::try_from(uncompressed_len + 1).unwrap_or(u64::MAX);
        match algorithm {
            crate::wire::CERT_COMP_ZLIB => {
                let mut decoder = flate2::read::ZlibDecoder::new(rest).take(limit);
                decoder.read_to_end(&mut decompressed).map_err(|error| {
                    HandshakeError::ProtocolViolation {
                        reason: format!("zlib certificate decompression failed: {error}"),
                    }
                })?;
            }
            crate::wire::CERT_COMP_BROTLI => {
                let mut decoder = brotli::Decompressor::new(rest, 4096).take(limit);
                decoder.read_to_end(&mut decompressed).map_err(|error| {
                    HandshakeError::ProtocolViolation {
                        reason: format!("brotli certificate decompression failed: {error}"),
                    }
                })?;
            }
            other => {
                return Err(HandshakeError::NegotiationFailed {
                    reason: format!(
                        "the server used unsupported certificate compression {other:#06x}"
                    ),
                });
            }
        }
        if decompressed.len() != uncompressed_len {
            return Err(HandshakeError::ProtocolViolation {
                reason: format!(
                    "CompressedCertificate unpacked to {} bytes, expected {uncompressed_len}",
                    decompressed.len()
                ),
            });
        }
        self.process_certificate_body(&decompressed, message)
    }

    fn process_certificate_body(
        &mut self,
        body: &[u8],
        transcript_message: &[u8],
    ) -> Result<(), HandshakeError> {
        // The certificate_request_context is a u8-length vector
        // (RFC 8446 §4.4.2).
        let (context_len, rest) = take_byte(body)?;
        if context_len != 0 {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the server requested a client certificate; this engine does not offer client authentication".into(),
            });
        }
        let (chain_len, rest) = take_u24(rest)?;
        if chain_len != rest.len() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the certificate chain length does not match its entries".into(),
            });
        }
        let mut certificates: Vec<Vec<u8>> = Vec::new();
        let mut rest = rest;
        // Each CertificateEntry is self-delimiting: a u24-prefixed
        // certificate followed by a u16-length extension block
        // (RFC 8446 §4.4.2); there is no per-entry length.
        while !rest.is_empty() {
            let (cert_len, tail) = take_u24(rest)?;
            let Some((der, tail)) = tail.split_at_checked(cert_len) else {
                return Err(HandshakeError::ProtocolViolation {
                    reason: "a certificate entry is truncated".into(),
                });
            };
            let (ext_len, tail) = take_u16(tail)?;
            let Some((_, tail)) = tail.split_at_checked(usize::from(ext_len)) else {
                return Err(HandshakeError::ProtocolViolation {
                    reason: "a certificate entry's extensions are truncated".into(),
                });
            };
            certificates.push(der.to_vec());
            rest = tail;
        }
        if certificates.is_empty() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the server sent an empty certificate chain".into(),
            });
        }
        let end_entity = certificates.remove(0);
        self.verifier
            .verify_chain(&self.server_name, &end_entity, &certificates)
            .map_err(|reason| HandshakeError::CertificateRejected { reason })?;
        self.end_entity = Some(end_entity);
        self.transcript.extend_from_slice(transcript_message);
        self.flight_stage = FlightStage::CertificateVerify;
        Ok(())
    }

    fn process_certificate_verify(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        let (scheme, rest) = take_u16(&message[4..])?;
        let (signature_len, rest) = take_u16(rest)?;
        let signature = rest;
        if usize::from(signature_len) != signature.len() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the CertificateVerify signature length does not match its bytes".into(),
            });
        }

        // The signature covers the transcript up to but excluding this
        // message (RFC 8446 §4.4.3).
        let transcript_hash = key_schedule::transcript_hash(self.hash, &self.transcript);
        let mut signed = Vec::with_capacity(
            CERTIFICATE_VERIFY_PAD.len()
                + SERVER_CERTIFICATE_VERIFY_CONTEXT.len()
                + 1
                + transcript_hash.len(),
        );
        signed.extend_from_slice(&CERTIFICATE_VERIFY_PAD);
        signed.extend_from_slice(SERVER_CERTIFICATE_VERIFY_CONTEXT);
        signed.push(0x00);
        signed.extend_from_slice(&transcript_hash);

        let Some(algorithm) = verification_algorithm(scheme) else {
            return Err(HandshakeError::SignatureNotSupported { scheme });
        };
        let end_entity =
            self.end_entity
                .as_ref()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "a CertificateVerify arrived before a Certificate".into(),
                })?;
        let Some(spki) = subject_public_key_info(end_entity) else {
            return Err(HandshakeError::CertificateRejected {
                reason: "the end-entity certificate does not parse".into(),
            });
        };
        UnparsedPublicKey::new(algorithm, spki)
            .verify(&signed, signature)
            .map_err(|_| HandshakeError::SignatureRejected { scheme })?;

        self.transcript.extend_from_slice(message);
        self.flight_stage = FlightStage::AwaitFinished;
        Ok(())
    }

    fn process_server_finished(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        if message.len() != 4 + self.hash.output_len() {
            return Err(HandshakeError::FinishedMismatch);
        }
        // The Finished MAC covers the transcript up to but excluding itself.
        let transcript_hash = key_schedule::transcript_hash(self.hash, &self.transcript);
        let server_hs =
            self.server_hs_secret
                .as_ref()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "a Finished arrived before handshake keys exist".into(),
                })?;
        let finished_key = server_hs.finished_key()?;
        let expected = hmac::sign(
            &hmac::Key::new(self.hash.hmac_algorithm(), &finished_key),
            &transcript_hash,
        );
        if verify_slices_are_equal(expected.as_ref(), &message[4..]).is_err() {
            return Err(HandshakeError::FinishedMismatch);
        }

        self.transcript.extend_from_slice(message);

        // Application secrets, from the master over the full-flight
        // transcript (RFC 8446 §7.1).
        let handshake_secret = self
            .handshake_secret
            .as_ref()
            .ok_or_else(|| HandshakeError::ProtocolViolation {
                reason: "the master derivation lost the handshake secret".into(),
            })?
            .clone();
        let hash = self.hash;
        let zeros = vec![0u8; hash.output_len()];
        let derived = handshake_secret
            .derive_secret("derived", &key_schedule::empty_transcript_hash(hash))?;
        let master = Secret::extract(derived.as_bytes(), &zeros, hash);
        let transcript_hash = key_schedule::transcript_hash(hash, &self.transcript);
        let client_ap = master.derive_secret("c ap traffic", &transcript_hash)?;
        let server_ap = master.derive_secret("s ap traffic", &transcript_hash)?;

        // The client's Finished, over the full-flight transcript with the
        // client's handshake-traffic finished key.
        let client_hs =
            self.client_hs_secret
                .as_ref()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "the client Finished lost its traffic secret".into(),
                })?;
        let finished_key = client_hs.finished_key()?;
        let verify_data = hmac::sign(
            &hmac::Key::new(hash.hmac_algorithm(), &finished_key),
            &transcript_hash,
        );
        let mut finished = Vec::with_capacity(4 + verify_data.as_ref().len());
        finished.push(FINISHED);
        let len = verify_data.as_ref().len();
        finished.push((len >> 16) as u8);
        finished.push((len >> 8) as u8);
        finished.push(len as u8);
        finished.extend_from_slice(verify_data.as_ref());
        self.transcript.extend_from_slice(&finished);
        let full_hash = key_schedule::transcript_hash(hash, &self.transcript);
        self.resumption_master = Some(master.derive_secret("res master", &full_hash)?);

        // The client flight goes out under the handshake keys.
        let protector =
            self.client_hs_write
                .take()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "the client Finished lost its write protector".into(),
                })?;
        let record = protector.seal(self.client_hs_write_seq, CONTENT_HANDSHAKE, &finished)?;
        self.pending_output.extend_from_slice(&record);

        // Application data starts fresh in both directions.
        let suite = self
            .negotiated_suite
            .ok_or_else(|| HandshakeError::ProtocolViolation {
                reason: "the server Finished arrived without a negotiated suite".into(),
            })?;
        let (algorithm, _, key_len) =
            suite_params(suite).ok_or_else(|| HandshakeError::NegotiationFailed {
                reason: format!("the negotiated suite {suite:#06x} is not implemented"),
            })?;
        let write_keys = client_ap.traffic_keys(key_len)?;
        let read_keys = server_ap.traffic_keys(key_len)?;
        self.client_ap_secret = Some(client_ap);
        self.server_ap_secret = Some(server_ap);
        self.protectors = Some(Protectors::Tls13 {
            write: RecordProtector13::new(algorithm, &write_keys.key, write_keys.iv)?,
            read: RecordUnprotector13::new(algorithm, &read_keys.key, read_keys.iv)?,
            write_seq: 0,
            read_seq: 0,
        });
        self.state = State::Established;
        Ok(())
    }

    // ---- TLS 1.2 ----------------------------------------------------------

    /// The TLS 1.2 ServerHello: no `supported_versions` extension, a suite
    /// from the TLS 1.2 table, and both of the extensions the hello offered
    /// — secure renegotiation and the extended master secret — echoed back.
    /// A server that drops either is refusing a protection the hello asked
    /// for, and that is a refusal, not a soft downgrade
    /// (RFC 5746 §3.4, triple-handshake protection).
    #[allow(clippy::too_many_arguments)]
    fn process_server_hello12(
        &mut self,
        message: &[u8],
        legacy_version: u16,
        random: [u8; 32],
        suite: u16,
        renegotiation_info_seen: bool,
        extended_master_secret_seen: bool,
        server_alpn: Option<Vec<u8>>,
        server_record_size_limit: Option<usize>,
    ) -> Result<(), HandshakeError> {
        if legacy_version != LEGACY_VERSION_TLS13 {
            return Err(HandshakeError::NegotiationFailed {
                reason: format!(
                    "the server negotiated {legacy_version:#06x}, which was not offered"
                ),
            });
        }
        let params = tls12::suite12(suite).ok_or_else(|| HandshakeError::NegotiationFailed {
            reason: format!("the server selected suite {suite:#06x}, which is not implemented"),
        })?;
        if !self.hello.cipher_suites.contains(&suite) {
            return Err(HandshakeError::NegotiationFailed {
                reason: format!("the server selected suite {suite:#06x}, which was not offered"),
            });
        }
        if !renegotiation_info_seen {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the TLS 1.2 ServerHello dropped secure renegotiation (RFC 5746)".into(),
            });
        }
        if !extended_master_secret_seen {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the TLS 1.2 ServerHello dropped the extended master secret".into(),
            });
        }

        self.server_random = Some(random);
        if let Some(alpn) = server_alpn {
            self.negotiated_alpn = Some(alpn);
        }
        if let Some(limit) = server_record_size_limit {
            self.max_write_plaintext = limit;
        }
        self.transcript.extend_from_slice(message);
        self.negotiated_suite12 = Some(params);
        self.state12 = Some(State12::Certificate);
        self.state = State::ExpectTls12Flight;
        Ok(())
    }

    fn consume_tls12_record(&mut self, record: Vec<u8>) -> Result<(), HandshakeError> {
        let header = RecordHeader::parse(&record)?;
        // Unlike TLS 1.3 — where every protected record is application_data —
        // a TLS 1.2 encrypted record keeps its real content type. Once the
        // read keys are installed (the server's change_cipher_spec has been
        // seen), a handshake or alert record is protected; before that, it is
        // plaintext.
        let protected = self.tls12_read.is_some();
        match header.content_type {
            CONTENT_CHANGE_CIPHER_SPEC if !protected => {
                if record[RECORD_HEADER_LEN..] != [0x01] {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "malformed TLS 1.2 change_cipher_spec record".into(),
                    });
                }
                if !self.flight.is_empty() {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "a TLS 1.2 handshake message straddled ChangeCipherSpec".into(),
                    });
                }
                let pending =
                    self.tls12_pending_read
                        .take()
                        .ok_or(HandshakeError::UnexpectedRecord {
                            state: "expect_tls12_flight",
                            got: CONTENT_CHANGE_CIPHER_SPEC,
                        })?;
                self.tls12_read = Some(pending);
                self.tls12_read_seq = 0;
                Ok(())
            }
            CONTENT_HANDSHAKE if !protected => {
                let payload = &record[RECORD_HEADER_LEN..];
                if payload.is_empty() {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "empty TLS 1.2 handshake record fragment".into(),
                    });
                }
                self.flight.extend_from_slice(payload);
                if self.flight.len() > MAX_FLIGHT_BYTES {
                    return Err(HandshakeError::FlightBufferExceeded {
                        len: self.flight.len(),
                        max: MAX_FLIGHT_BYTES,
                    });
                }
                while let Some((kind, message)) = take_message(&mut self.flight) {
                    self.process_tls12_message(kind, &message)?;
                    if matches!(self.state, State::Established) {
                        if !self.flight.is_empty() {
                            return Err(HandshakeError::ProtocolViolation {
                                reason: "handshake messages must not span the Finished boundary"
                                    .into(),
                            });
                        }
                        break;
                    }
                }
                Ok(())
            }
            CONTENT_ALERT if !protected => Err(alert_error(&record[RECORD_HEADER_LEN..])),
            CONTENT_HANDSHAKE | CONTENT_ALERT | CONTENT_APPLICATION_DATA if protected => {
                let unprotector =
                    self.tls12_read
                        .as_ref()
                        .ok_or_else(|| HandshakeError::ProtocolViolation {
                            reason: "a protected record arrived without read keys".into(),
                        })?;
                let next_seq = self.tls12_read_seq.checked_add(1).ok_or_else(|| {
                    HandshakeError::ProtocolViolation {
                        reason: "TLS 1.2 handshake read sequence overflow".into(),
                    }
                })?;
                let (inner, payload) = unprotector.open(self.tls12_read_seq, &record)?;
                self.tls12_read_seq = next_seq;
                match inner {
                    CONTENT_HANDSHAKE => {
                        if payload.is_empty() {
                            return Err(HandshakeError::ProtocolViolation {
                                reason: "empty TLS 1.2 handshake record fragment".into(),
                            });
                        }
                        self.flight.extend_from_slice(&payload);
                        if self.flight.len() > MAX_FLIGHT_BYTES {
                            return Err(HandshakeError::FlightBufferExceeded {
                                len: self.flight.len(),
                                max: MAX_FLIGHT_BYTES,
                            });
                        }
                        while let Some((kind, message)) = take_message(&mut self.flight) {
                            self.process_tls12_message(kind, &message)?;
                            if matches!(self.state, State::Established) {
                                if !self.flight.is_empty() {
                                    return Err(HandshakeError::ProtocolViolation {
                                        reason:
                                            "handshake messages must not span the Finished boundary"
                                                .into(),
                                    });
                                }
                                break;
                            }
                        }
                        Ok(())
                    }
                    CONTENT_ALERT => Err(alert_error(&payload)),
                    got => Err(HandshakeError::UnexpectedRecord {
                        state: "expect_tls12_flight",
                        got,
                    }),
                }
            }
            got => Err(HandshakeError::UnexpectedRecord {
                state: "expect_tls12_flight",
                got,
            }),
        }
    }

    fn process_tls12_message(&mut self, kind: u8, message: &[u8]) -> Result<(), HandshakeError> {
        let Some(stage) = self.state12.take() else {
            return Err(HandshakeError::ProtocolViolation {
                reason: "a TLS 1.2 message arrived outside a flight".into(),
            });
        };
        match (kind, stage) {
            (CERTIFICATE, State12::Certificate) => self.process_certificate12(message)?,
            (SERVER_KEY_EXCHANGE, State12::KeyExchange) => {
                self.process_server_key_exchange(message)?;
            }
            (SERVER_HELLO_DONE, State12::HelloDone) => {
                // The ServerHelloDone is a handshake message like any other:
                // it enters the transcript before the client's flight
                // (RFC 5246 §7.4.9's handshake_messages).
                self.transcript.extend_from_slice(message);
                self.send_tls12_client_flight()?;
            }
            (NEW_SESSION_TICKET, State12::ServerFinished) => {
                if self.tls12_read.is_some() {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "TLS 1.2 NewSessionTicket arrived after ChangeCipherSpec".into(),
                    });
                }
                // RFC 5077 §3.3: when session_ticket is negotiated, the server
                // sends NewSessionTicket before ChangeCipherSpec and Finished;
                // it enters the transcript.
                self.transcript.extend_from_slice(message);
                self.state12 = Some(State12::ServerFinished);
            }
            (FINISHED, State12::ServerFinished) => {
                if self.tls12_read.is_none() {
                    return Err(HandshakeError::ProtocolViolation {
                        reason: "TLS 1.2 server Finished arrived before ChangeCipherSpec".into(),
                    });
                }
                self.process_tls12_server_finished(message)?;
            }
            (0x00, _) => {
                return Err(HandshakeError::ProtocolViolation {
                    reason: "the server requested renegotiation; this engine does not renegotiate"
                        .into(),
                });
            }
            (13, _) => {
                return Err(HandshakeError::ProtocolViolation {
                    reason: "the server requested a client certificate; this engine does not offer client authentication".into(),
                });
            }
            (kind, stage) => {
                return Err(HandshakeError::ProtocolViolation {
                    reason: format!(
                        "message type {kind:#04x} is out of order for flight stage {stage:?}"
                    ),
                });
            }
        }
        Ok(())
    }

    /// The TLS 1.2 Certificate: a plain chain, each entry a u24-prefixed
    /// certificate with no extensions, in the clear (RFC 5246 §7.4.2).
    fn process_certificate12(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        let (chain_len, rest) = take_u24(&message[4..])?;
        if chain_len != rest.len() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the certificate chain length does not match its entries".into(),
            });
        }
        let mut certificates: Vec<Vec<u8>> = Vec::new();
        let mut rest = rest;
        while !rest.is_empty() {
            let (cert_len, tail) = take_u24(rest)?;
            let Some((der, tail)) = tail.split_at_checked(cert_len) else {
                return Err(HandshakeError::ProtocolViolation {
                    reason: "a certificate entry is truncated".into(),
                });
            };
            certificates.push(der.to_vec());
            rest = tail;
        }
        if certificates.is_empty() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the server sent an empty certificate chain".into(),
            });
        }
        let end_entity = certificates.remove(0);
        self.verifier
            .verify_chain(&self.server_name, &end_entity, &certificates)
            .map_err(|reason| HandshakeError::CertificateRejected { reason })?;
        self.end_entity12 = Some(end_entity);
        self.transcript.extend_from_slice(message);
        self.state12 = Some(State12::KeyExchange);
        Ok(())
    }

    /// The TLS 1.2 ServerKeyExchange for ECDHE (RFC 4492 §5.4 as updated by
    /// RFC 8422): a named curve, the server's ephemeral point, and a
    /// signature over the client random, the server random and the
    /// parameters exactly as they were transmitted.
    fn process_server_key_exchange(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        let (curve_type, rest) = take_byte(&message[4..])?;
        if curve_type != 3 {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the ServerKeyExchange is not a named-curve ECDHE exchange".into(),
            });
        }
        let (group, rest) = take_u16(rest)?;
        let (point_len, rest) = take_byte(rest)?;
        let Some((point, rest)) = rest.split_at_checked(usize::from(point_len)) else {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the ServerKeyExchange point is truncated".into(),
            });
        };
        let (scheme, rest) = take_u16(rest)?;
        let (signature_len, rest) = take_u16(rest)?;
        let signature = rest;
        if usize::from(signature_len) != signature.len() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "the ServerKeyExchange signature length does not match its bytes".into(),
            });
        }
        // The group must be one the hello offered and the engine completes
        // ([INV-TLS-06]).
        if !self.hello.extensions.iter().any(|extension| {
            matches!(&extension.body,
                ExtensionBody::SupportedGroups { groups } if groups.contains(&group))
        }) || !key_exchange::offerable_group(group)
        {
            return Err(HandshakeError::NegotiationFailed {
                reason: format!("the server selected group {group:#06x}, which was not offered"),
            });
        }

        let server_random =
            self.server_random
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "a ServerKeyExchange arrived before a ServerHello".into(),
                })?;
        // The signed content: client random || server random || params,
        // verbatim (RFC 8422 §5.4).
        let params_len = 3 + 1 + usize::from(point_len);
        let mut signed = Vec::with_capacity(32 + 32 + params_len);
        signed.extend_from_slice(&self.hello.random);
        signed.extend_from_slice(&server_random);
        signed.extend_from_slice(&message[4..4 + params_len]);

        let Some(algorithm) = verification_algorithm(scheme) else {
            return Err(HandshakeError::SignatureNotSupported { scheme });
        };
        let end_entity =
            self.end_entity12
                .as_ref()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "a ServerKeyExchange arrived before a Certificate".into(),
                })?;
        let Some(spki) = subject_public_key_info(end_entity) else {
            return Err(HandshakeError::CertificateRejected {
                reason: "the end-entity certificate does not parse".into(),
            });
        };
        UnparsedPublicKey::new(algorithm, spki)
            .verify(&signed, signature)
            .map_err(|_| HandshakeError::SignatureRejected { scheme })?;

        self.transcript.extend_from_slice(message);
        self.server_key_exchange = Some((group, point.to_vec()));
        self.state12 = Some(State12::HelloDone);
        Ok(())
    }

    /// The client flight: the key exchange in the clear, the
    /// change_cipher_spec, and the Finished under the fresh keys (RFC 5246
    /// §7.4.8-§7.4.9).
    fn send_tls12_client_flight(&mut self) -> Result<(), HandshakeError> {
        let params = self
            .negotiated_suite12
            .ok_or_else(|| HandshakeError::ProtocolViolation {
                reason: "the client flight lost its suite parameters".into(),
            })?;
        let (group, server_point) =
            self.server_key_exchange
                .take()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "the client flight lost the ServerKeyExchange".into(),
                })?;
        let share = self
            .shares
            .iter()
            .find(|share| share.group == group)
            .ok_or_else(|| HandshakeError::NegotiationFailed {
                reason: format!("the negotiated group {group:#06x} has no client share"),
            })?;
        let pre_master = share.agree(server_point.as_slice())?;
        let client_random = &self.hello.random;
        let server_random =
            self.server_random
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "the client flight lost the server random".into(),
                })?;

        // ClientKeyExchange: the client's ephemeral public key — the same
        // share the hello advertised (Go generates one key pair up front).
        let point = share.share.clone();
        let point_len =
            u8::try_from(point.len()).map_err(|_| HandshakeError::ProtocolViolation {
                reason: "TLS 1.2 client key share exceeds u8 point length".into(),
            })?;
        let mut exchange = Vec::with_capacity(4 + 1 + point.len());
        exchange.push(CLIENT_KEY_EXCHANGE);
        let body_len = 1 + usize::from(point_len);
        exchange.push((body_len >> 16) as u8);
        exchange.push((body_len >> 8) as u8);
        exchange.push(body_len as u8);
        exchange.push(point_len);
        exchange.extend_from_slice(&point);
        self.transcript.extend_from_slice(&exchange);

        // The extended master secret (RFC 7627): the handshake demanded the
        // extension and the server echoed it, so the master is derived over
        // the transcript through the ClientKeyExchange — not the legacy
        // randoms formula the extension exists to retire.
        let transcript_hash = tls12::handshake_hash(params.prf, &self.transcript);
        let master = tls12::prf12(
            params.prf,
            &pre_master,
            b"extended master secret",
            &transcript_hash,
            48,
        )?;
        let key_block = tls12::key_block(
            params.prf,
            &master,
            &server_random,
            client_random,
            params.key_block_len(),
        )?;
        let (client_cipher, server_cipher) =
            crate::record::record_ciphers_from_key_block(params, &key_block)?;

        // Finished over the handshake so far (CH .. CKE).
        let verify_data = tls12::prf12(
            params.prf,
            &master,
            b"client finished",
            &transcript_hash,
            12,
        )?;
        let mut finished = Vec::with_capacity(4 + verify_data.len());
        finished.push(FINISHED);
        finished.extend_from_slice(&[0x00, 0x00, 0x0c]);
        finished.extend_from_slice(&verify_data);
        // The server's Finished covers everything before it — including the
        // client's Finished (RFC 5246 §7.4.9, "up to but not including this
        // message") — so the snapshot is taken after the client flight is in
        // the transcript.
        self.transcript.extend_from_slice(&finished);
        self.tls12_server_finished_hash = Some(tls12::handshake_hash(params.prf, &self.transcript));
        self.tls12_master = Some(master);

        self.pending_output.extend_from_slice(&unprotected_record(
            CONTENT_HANDSHAKE,
            LEGACY_VERSION_TLS12,
            &exchange,
        ));
        self.pending_output.extend_from_slice(&unprotected_record(
            CONTENT_CHANGE_CIPHER_SPEC,
            LEGACY_VERSION_TLS13,
            &[0x01],
        ));
        let write_protector = RecordProtector12::new(client_cipher)?;
        let record = write_protector.seal(self.tls12_write_seq, CONTENT_HANDSHAKE, &finished)?;
        self.tls12_write_seq += 1;
        self.pending_output.extend_from_slice(&record);
        self.tls12_write = Some(write_protector);
        self.tls12_pending_read = Some(RecordUnprotector12::new(server_cipher)?);
        self.tls12_read_seq = 0;
        self.state12 = Some(State12::ServerFinished);
        Ok(())
    }

    /// The server's Finished, under the fresh read keys; the app-data keys
    /// are the same ones, so establishment is a state change, not a key
    /// change (RFC 5246 §7.4.9).
    fn process_tls12_server_finished(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        if message.len() != 4 + 12 {
            return Err(HandshakeError::FinishedMismatch);
        }
        let params = self
            .negotiated_suite12
            .ok_or_else(|| HandshakeError::ProtocolViolation {
                reason: "the server Finished lost its suite parameters".into(),
            })?;
        let master =
            self.tls12_master
                .as_ref()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "the server Finished lost the master secret".into(),
                })?;
        // The server's Finished covers the handshake up to but excluding
        // itself — which also excludes the client's Finished.
        let transcript_hash = self.tls12_server_finished_hash.take().ok_or_else(|| {
            HandshakeError::ProtocolViolation {
                reason: "the server Finished lost its transcript hash".into(),
            }
        })?;
        let expected = tls12::prf12(params.prf, master, b"server finished", &transcript_hash, 12)?;
        if verify_slices_are_equal(&expected, &message[4..]).is_err() {
            return Err(HandshakeError::FinishedMismatch);
        }

        self.transcript.extend_from_slice(message);
        // The 1.2 keys protect the connection for its lifetime; the
        // Finished flights consumed sequence 0 in both directions.
        self.protectors = Some(Protectors::Tls12 {
            write: self
                .tls12_write
                .take()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "the server Finished lost the write protector".into(),
                })?,
            read: self
                .tls12_read
                .take()
                .ok_or_else(|| HandshakeError::ProtocolViolation {
                    reason: "the server Finished lost the read protector".into(),
                })?,
            write_seq: self.tls12_write_seq,
            read_seq: self.tls12_read_seq,
        });
        self.state = State::Established;
        Ok(())
    }
}

/// The (AEAD algorithm, transcript hash, key length) of a TLS 1.3 suite.
pub(crate) fn suite_params(suite: u16) -> Option<(&'static aead::Algorithm, Hash, usize)> {
    match suite {
        0x1301 => Some((&aead::AES_128_GCM, Hash::Sha256, 16)),
        0x1302 => Some((&aead::AES_256_GCM, Hash::Sha384, 32)),
        0x1303 => Some((&aead::CHACHA20_POLY1305, Hash::Sha256, 32)),
        _ => None,
    }
}

/// The verification algorithm a CertificateVerify scheme maps to; the
/// engine refuses the schemes it cannot verify ([`INV-TLS-06`]).
fn verification_algorithm(scheme: u16) -> Option<&'static dyn VerificationAlgorithm> {
    use aws_lc_rs::signature as sig;
    Some(match scheme {
        0x0804 => &sig::RSA_PSS_2048_8192_SHA256,
        0x0805 => &sig::RSA_PSS_2048_8192_SHA384,
        0x0806 => &sig::RSA_PSS_2048_8192_SHA512,
        0x0401 => &sig::RSA_PKCS1_2048_8192_SHA256,
        0x0501 => &sig::RSA_PKCS1_2048_8192_SHA384,
        0x0601 => &sig::RSA_PKCS1_2048_8192_SHA512,
        0x0403 => &sig::ECDSA_P256_SHA256_ASN1,
        0x0503 => &sig::ECDSA_P384_SHA384_ASN1,
        0x0603 => &sig::ECDSA_P521_SHA512_ASN1,
        0x0807 => &sig::ED25519,
        0x0904 => &sig::ML_DSA_44,
        0x0905 => &sig::ML_DSA_65,
        0x0906 => &sig::ML_DSA_87,
        _ => return None,
    })
}

fn alert_error(payload: &[u8]) -> HandshakeError {
    match payload {
        [level, description] => HandshakeError::AlertReceived {
            level: *level,
            description: *description,
        },
        _ => HandshakeError::ProtocolViolation {
            reason: "an alert record must carry exactly two bytes".into(),
        },
    }
}

/// Parse one complete handshake message from the front of the buffer and
/// return its type together with the FULL encoded message — the transcript
/// is the concatenation of whole messages, headers included (RFC 8446
/// §7.1). `None` while fewer than the declared bytes are present.
fn take_message(buffer: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    if buffer.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, buffer[1], buffer[2], buffer[3]]) as usize;
    if buffer.len() < 4 + len {
        return None;
    }
    let kind = buffer[0];
    let message: Vec<u8> = buffer.drain(..4 + len).collect();
    Some((kind, message))
}

fn take_byte(input: &[u8]) -> Result<(u8, &[u8]), HandshakeError> {
    let Some((value, rest)) = input.split_first() else {
        return Err(truncated("a one-byte field"));
    };
    Ok((*value, rest))
}

fn take_u16(input: &[u8]) -> Result<(u16, &[u8]), HandshakeError> {
    let Some(value) = input.first_chunk::<2>() else {
        return Err(truncated("a two-byte field"));
    };
    Ok((u16::from_be_bytes(*value), &input[2..]))
}

fn take_u24(input: &[u8]) -> Result<(usize, &[u8]), HandshakeError> {
    let Some(value) = input.first_chunk::<3>() else {
        return Err(truncated("a three-byte field"));
    };
    let len = u32::from_be_bytes([0, value[0], value[1], value[2]]) as usize;
    Ok((len, &input[3..]))
}

fn take_slice<const N: usize>(input: &[u8]) -> Result<(&[u8; N], &[u8]), HandshakeError> {
    let Some(value) = input.first_chunk::<N>() else {
        return Err(truncated("a fixed-size field"));
    };
    Ok((value, &input[N..]))
}

fn take_u8_vector(input: &[u8]) -> Result<(Vec<u8>, &[u8]), HandshakeError> {
    let (&len, rest) = input.split_first().ok_or_else(|| truncated("a vector"))?;
    let Some((value, rest)) = rest.split_at_checked(usize::from(len)) else {
        return Err(truncated("a vector"));
    };
    Ok((value.to_vec(), rest))
}

fn truncated(what: &str) -> HandshakeError {
    HandshakeError::ProtocolViolation {
        reason: format!("{what} is truncated"),
    }
}

/// Iterate the type/length/value extension pairs of an extension block.
fn for_each_extension(
    block: &[u8],
    mut visit: impl FnMut(u16, &[u8]) -> Result<(), HandshakeError>,
) -> Result<(), HandshakeError> {
    let (block_len, mut rest) = take_u16(block)?;
    if usize::from(block_len) != rest.len() {
        return Err(HandshakeError::ProtocolViolation {
            reason: "an extension block length does not match its bytes".into(),
        });
    }
    let mut seen = Vec::new();
    while !rest.is_empty() {
        let (kind, tail) = take_u16(rest)?;
        if seen.contains(&kind) {
            return Err(HandshakeError::ProtocolViolation {
                reason: format!("duplicate extension {kind:#06x} in handshake message"),
            });
        }
        seen.push(kind);
        let (len, tail) = take_u16(tail)?;
        let Some((payload, tail)) = tail.split_at_checked(usize::from(len)) else {
            return Err(HandshakeError::ProtocolViolation {
                reason: "an extension is truncated".into(),
            });
        };
        visit(kind, payload)?;
        rest = tail;
    }
    Ok(())
}

struct HelloRetryRequest<'a> {
    message: &'a [u8],
    selected_version: Option<u16>,
    server_share: Option<(u16, Vec<u8>)>,
    cookie: Option<Vec<u8>>,
    session_id: Vec<u8>,
    suite: u16,
    compression: u8,
}

/// The `selected_version` of a ServerHello's `supported_versions`
/// extension — a single version, not the ClientHello's list.
fn selected_version_of(payload: &[u8]) -> Result<u16, HandshakeError> {
    match payload {
        [hi, lo] => Ok(u16::from_be_bytes([*hi, *lo])),
        _ => Err(HandshakeError::ProtocolViolation {
            reason: "malformed ServerHello supported_versions extension".into(),
        }),
    }
}

/// Parse a HelloRetryRequest `cookie` extension (`Cookie { opaque cookie<1..2^16-1>; }`).
fn parse_cookie_extension(payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let (len, rest) = take_u16(payload)?;
    if len == 0 || usize::from(len) != rest.len() {
        return Err(HandshakeError::ProtocolViolation {
            reason: "malformed HelloRetryRequest cookie extension".into(),
        });
    }
    Ok(payload.to_vec())
}

/// The single `key_share` entry of a ServerHello or HelloRetryRequest.
///
/// Unlike the ClientHello's list form, the ServerHello carries one bare
/// `KeyShareEntry`: group, share length, share (RFC 8446 §4.2.8). A
/// HelloRetryRequest's entry has an empty share, which stacks encode two
/// ways — the bare group (a 2-byte body; rustls's and BoringSSL's shape) or
/// the length-prefixed empty vector (a 4-byte body) — and both are accepted.
fn single_key_share(payload: &[u8]) -> Result<(u16, Vec<u8>), HandshakeError> {
    let (group, rest) = take_u16(payload)?;
    if rest.is_empty() {
        // The bare-group HRR shape: an empty share by omission.
        return Ok((group, Vec::new()));
    }
    let (share_len, rest) = take_u16(rest)?;
    let (share, rest) = rest
        .split_at_checked(usize::from(share_len))
        .ok_or_else(|| HandshakeError::ProtocolViolation {
            reason: "malformed ServerHello key_share extension".into(),
        })?;
    if !rest.is_empty() {
        return Err(HandshakeError::ProtocolViolation {
            reason: "trailing bytes in ServerHello key_share extension".into(),
        });
    }
    Ok((group, share.to_vec()))
}

/// The protocols of an `alpn` extension payload (RFC 7301).
fn alpn_protocols(payload: &[u8]) -> Result<Vec<Vec<u8>>, HandshakeError> {
    let (list_len, list) = take_u16(payload)?;
    if usize::from(list_len) != list.len() {
        return Err(HandshakeError::ProtocolViolation {
            reason: "the ALPN list length does not match its bytes".into(),
        });
    }
    let mut protocols = Vec::new();
    let mut rest = list;
    while !rest.is_empty() {
        let (&len, tail) = rest
            .split_first()
            .ok_or_else(|| truncated("an ALPN name"))?;
        let Some((name, tail)) = tail.split_at_checked(usize::from(len)) else {
            return Err(HandshakeError::ProtocolViolation {
                reason: "an ALPN name is truncated".into(),
            });
        };
        if name.is_empty() {
            return Err(HandshakeError::ProtocolViolation {
                reason: "an ALPN name is empty (RFC 7301 §3.1)".into(),
            });
        }
        protocols.push(name.to_vec());
        rest = tail;
    }
    Ok(protocols)
}

/// The `key_share` entries of a hello, in wire order.
fn hello_key_share_entries(hello: &ClientHello) -> Result<Vec<KeyShareEntry>, HandshakeError> {
    let mut entries = None;
    for extension in &hello.extensions {
        if let ExtensionBody::KeyShare { shares } = &extension.body {
            if entries.is_some() {
                return Err(HandshakeError::ProtocolViolation {
                    reason: "the hello carries two key_share extensions".into(),
                });
            }
            entries = Some(
                shares
                    .iter()
                    .filter(|entry| !crate::wire::is_grease(entry.group))
                    .cloned()
                    .collect(),
            );
        }
    }
    entries.ok_or_else(|| HandshakeError::NegotiationFailed {
        reason: "the hello offers no key_share extension".into(),
    })
}

/// The SNI `host_name` of a hello, if any.
fn hello_server_name(hello: &ClientHello) -> String {
    hello
        .extensions
        .iter()
        .find_map(|extension| match &extension.body {
            ExtensionBody::ServerName { name } => Some(name.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

impl<V: ServerCertVerifier> Drop for ClientHandshake<V> {
    fn drop(&mut self) {
        crate::zeroize::wipe_option(&mut self.offered_psk);
        crate::zeroize::wipe(&mut self.transcript);
        crate::zeroize::wipe(&mut self.record_buffer);
        crate::zeroize::wipe(&mut self.flight);
        crate::zeroize::wipe(&mut self.pending_output);
    }
}

#[cfg(test)]
pub(crate) mod tests;
