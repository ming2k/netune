// SPDX-License-Identifier: MIT

//! Owned WebTransport over HTTP/3, pinned to `draft-ietf-webtrans-http3-17`.
//!
//! # Experimental status
//!
//! This crate is **experimental**, not production-stable. The draft, browser
//! support, and the public API may change between `0.0.x` releases. Reliable
//! `RESET_STREAM_AT` is implemented; browser interoperability and draft-version
//! negotiation remain open gates; see `docs/reference/stability.md`.

#![cfg_attr(test, allow(clippy::expect_used))]
#![deny(missing_docs)]
//!
//! This crate owns the WebTransport wire model and product API. HTTP/3 and QUIC
//! remain RFC-owned leaves; WebTransport-specific SETTINGS, stream signals,
//! capsules, flow control and errors live here.

use bytes::{BufMut, Bytes, BytesMut};
use netune_http3::{Capsule, CapsuleError};

/// The pinned WebTransport over HTTP/3 draft version.
pub mod session;
pub use session::{
    OriginPolicy, WebTransportBidi, WebTransportClient, WebTransportOrigin, WebTransportServer,
    WebTransportSession,
};

/// The pinned WebTransport over HTTP/3 draft identifier string.
pub const DRAFT_VERSION: &str = "draft-ietf-webtrans-http3-17";

/// The WebTransport over HTTP/3 draft selected for one session.
///
/// Draft-17 is preferred. Draft-16 is the compatibility codepoint advertised
/// by older peers; selecting it does not claim draft-16 feature completeness,
/// only the shared wire subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WebTransportVersion {
    /// Draft-16 compatibility codepoint (`"draft-ietf-webtrans-http3-16"`).
    Draft16,
    /// Draft-17 (`"draft-ietf-webtrans-http3-17"`).
    Draft17,
}

impl WebTransportVersion {
    /// Return the draft identifier string for this version.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft16 => "draft-ietf-webtrans-http3-16",
            Self::Draft17 => "draft-ietf-webtrans-http3-17",
        }
    }

    /// Select the highest common version from the peer's enable codepoints.
    ///
    /// `draft17` and `draft16` are the peer's values for
    /// `SETTINGS_WT_ENABLED` and `SETTINGS_WT_ENABLED_DRAFT16`. A value other
    /// than 0 or 1 is a settings error; an absent/zero pair means the peer did
    /// not enable WebTransport.
    pub fn from_peer_settings(
        draft17: Option<u64>,
        draft16: Option<u64>,
    ) -> Result<Self, WebTransportError> {
        let enabled = |value: Option<u64>| match value {
            None => Ok(false),
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            Some(_) => Err(WebTransportError::Settings(
                "SETTINGS_WT_ENABLED must be 0 or 1".to_string(),
            )),
        };
        let draft17 = enabled(draft17)?;
        let draft16 = enabled(draft16)?;
        match (draft17, draft16) {
            (true, _) => Ok(Self::Draft17),
            (false, true) => Ok(Self::Draft16),
            (false, false) => Err(WebTransportError::Settings(
                "peer did not enable WebTransport over HTTP/3".to_string(),
            )),
        }
    }
}

/// HTTP/3 setting enabling WebTransport (`0x20b8933b`).
pub const SETTINGS_WT_ENABLED: u64 = 0x20b8_933b;
/// Draft-16 `SETTINGS_WT_ENABLED` codepoint. Draft-17 endpoints advertise both
/// codepoints when they can speak the draft-16 wire subset; the highest common
/// version is selected by the codepoint the peer sends.
pub const SETTINGS_WT_ENABLED_DRAFT16: u64 = 0x2c7c_f000;
/// HTTP/3 setting advertising the initial unidirectional stream limit (`0x2b64`).
pub const SETTINGS_WT_INITIAL_MAX_STREAMS_UNI: u64 = 0x2b64;
/// HTTP/3 setting advertising the initial bidirectional stream limit (`0x2b65`).
pub const SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI: u64 = 0x2b65;
/// HTTP/3 setting advertising the initial session data limit (`0x2b61`).
pub const SETTINGS_WT_INITIAL_MAX_DATA: u64 = 0x2b61;

/// Bidirectional stream signal type identifying a WebTransport stream (`0x41`).
pub const WT_STREAM_SIGNAL: u64 = 0x41;
/// Unidirectional stream type identifying a WebTransport stream (`0x54`).
pub const WT_UNI_STREAM_TYPE: u64 = 0x54;

/// Capsule type closing a WebTransport session (`0x2843`).
pub const WT_CLOSE_SESSION: u64 = 0x2843;
/// Capsule type requesting graceful session draining (`0x78ae`).
pub const WT_DRAIN_SESSION: u64 = 0x78ae;
/// Capsule type updating the bidirectional stream limit (`0x190b4d3f`).
pub const WT_MAX_STREAMS_BIDI: u64 = 0x190b_4d3f;
/// Capsule type updating the unidirectional stream limit (`0x190b4d40`).
pub const WT_MAX_STREAMS_UNI: u64 = 0x190b_4d40;
/// Capsule type updating the session-level data limit (`0x190b4d3d`).
pub const WT_MAX_DATA: u64 = 0x190b_4d3d;
/// Capsule type signaling session data flow-control blockage (`0x190b4d41`).
pub const WT_DATA_BLOCKED: u64 = 0x190b_4d41;
/// Capsule type signaling bidirectional stream limit blockage (`0x190b4d43`).
pub const WT_STREAMS_BLOCKED_BIDI: u64 = 0x190b_4d43;
/// Capsule type signaling unidirectional stream limit blockage (`0x190b4d44`).
pub const WT_STREAMS_BLOCKED_UNI: u64 = 0x190b_4d44;

/// HTTP/3 stream error code for rejecting buffered streams (`0x3994bd84`).
pub const WT_BUFFERED_STREAM_REJECTED: u64 = 0x3994_bd84;
/// HTTP/3 stream error code indicating the WebTransport session is gone (`0x170d7b68`).
pub const WT_SESSION_GONE: u64 = 0x170d_7b68;
/// HTTP/3 error code for WebTransport flow-control violations (`0x045d4487`).
pub const WT_FLOW_CONTROL_ERROR: u64 = 0x045d_4487;
/// HTTP/3 error code for ALPN mismatch (`0x0817b3dd`).
pub const WT_ALPN_ERROR: u64 = 0x0817_b3dd;
/// HTTP/3 error code indicating WebTransport requirements were not met (`0x212c0d48`).
pub const WT_REQUIREMENTS_NOT_MET: u64 = 0x212c_0d48;

const WT_APPLICATION_ERROR_FIRST: u64 = 0x52e4_a40f_a8db;
const WT_APPLICATION_ERROR_LAST: u64 = 0x52e5_ac98_3162;

/// WebTransport application error range mapping helpers.
pub mod error_code {
    use super::{WT_APPLICATION_ERROR_FIRST, WT_APPLICATION_ERROR_LAST};

    /// Map a 32-bit WebTransport application error into the HTTP/3 error space.
    pub fn to_http(application: u32) -> u64 {
        let application = u64::from(application);
        WT_APPLICATION_ERROR_FIRST + application + application / 0x1e
    }

    /// Map an HTTP/3 error in the WebTransport range back to an application code.
    pub fn from_http(http: u64) -> Option<u32> {
        if !(WT_APPLICATION_ERROR_FIRST..=WT_APPLICATION_ERROR_LAST).contains(&http) {
            return None;
        }
        if (http - 0x21).is_multiple_of(0x1f) {
            return None;
        }
        let shifted = http - WT_APPLICATION_ERROR_FIRST;
        u32::try_from(shifted - shifted / 0x1f).ok()
    }
}

/// A validated WebTransport session ID (a client-initiated bidirectional stream ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u64);

impl SessionId {
    /// Construct a session ID if `value` is a valid QUIC varint multiple of 4.
    pub fn new(value: u64) -> Result<Self, WebTransportError> {
        if value > (1u64 << 62) - 1 {
            return Err(WebTransportError::InvalidSessionId(value));
        }
        if !value.is_multiple_of(4) {
            return Err(WebTransportError::InvalidSessionId(value));
        }
        Ok(Self(value))
    }

    /// Return the underlying raw stream ID.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// WebTransport settings exchanged through HTTP/3 SETTINGS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebTransportSettings {
    /// Whether WebTransport is enabled.
    pub enabled: bool,
    /// Initial maximum number of peer-initiated unidirectional streams.
    pub initial_max_streams_uni: u64,
    /// Initial maximum number of peer-initiated bidirectional streams.
    pub initial_max_streams_bidi: u64,
    /// Initial maximum cumulative payload bytes across streams in the session.
    pub initial_max_data: u64,
}

impl Default for WebTransportSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_max_streams_uni: 100,
            initial_max_streams_bidi: 100,
            initial_max_data: 1 << 20,
        }
    }
}

impl WebTransportSettings {
    /// Serialize these settings as HTTP/3 `(id, value)` setting pairs.
    pub fn extra_settings(self) -> Vec<(u64, u64)> {
        let mut settings = vec![
            (SETTINGS_WT_ENABLED, u64::from(self.enabled)),
            (SETTINGS_WT_ENABLED_DRAFT16, u64::from(self.enabled)),
        ];
        if self.initial_max_streams_uni > 0 {
            settings.push((
                SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
                self.initial_max_streams_uni,
            ));
        }
        if self.initial_max_streams_bidi > 0 {
            settings.push((
                SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI,
                self.initial_max_streams_bidi,
            ));
        }
        if self.initial_max_data > 0 {
            settings.push((SETTINGS_WT_INITIAL_MAX_DATA, self.initial_max_data));
        }
        settings
    }

    /// Parse WebTransport settings from HTTP/3 `(id, value)` pairs.
    pub fn from_extra(settings: &[(u64, u64)]) -> Result<Self, WebTransportError> {
        let mut output = Self {
            enabled: false,
            initial_max_streams_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_data: 0,
        };
        for (id, value) in settings {
            match *id {
                SETTINGS_WT_ENABLED | SETTINGS_WT_ENABLED_DRAFT16 => {
                    if *value > 1 {
                        return Err(WebTransportError::Settings(
                            "SETTINGS_WT_ENABLED must be 0 or 1".to_string(),
                        ));
                    }
                    output.enabled |= *value == 1;
                }
                SETTINGS_WT_INITIAL_MAX_STREAMS_UNI => output.initial_max_streams_uni = *value,
                SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI => output.initial_max_streams_bidi = *value,
                SETTINGS_WT_INITIAL_MAX_DATA => output.initial_max_data = *value,
                _ => {}
            }
        }
        if output.initial_max_streams_uni > (1 << 60)
            || output.initial_max_streams_bidi > (1 << 60)
            || output.initial_max_data > (1 << 62) - 1
        {
            return Err(WebTransportError::Settings(
                "WebTransport flow-control setting is out of range".to_string(),
            ));
        }
        Ok(output)
    }
}

/// Encode the unidirectional WT stream header (`0x54`, session ID).
pub fn encode_uni_header(session: SessionId, out: &mut BytesMut) -> Result<(), WebTransportError> {
    netune_quic::wire::varint::encode(out, WT_UNI_STREAM_TYPE)
        .map_err(|error| WebTransportError::Wire(error.to_string()))?;
    netune_quic::wire::varint::encode(out, session.get())
        .map_err(|error| WebTransportError::Wire(error.to_string()))?;
    Ok(())
}

/// Encode the bidirectional WT stream signal (`0x41`, session ID).
pub fn encode_bidi_header(session: SessionId, out: &mut BytesMut) -> Result<(), WebTransportError> {
    netune_quic::wire::varint::encode(out, WT_STREAM_SIGNAL)
        .map_err(|error| WebTransportError::Wire(error.to_string()))?;
    netune_quic::wire::varint::encode(out, session.get())
        .map_err(|error| WebTransportError::Wire(error.to_string()))?;
    Ok(())
}

/// Decode a unidirectional WebTransport stream header, returning `None` if incomplete.
pub fn parse_uni_header(input: &[u8]) -> Result<Option<(SessionId, usize)>, WebTransportError> {
    parse_header(input, WT_UNI_STREAM_TYPE)
}

/// Decode a bidirectional WebTransport stream header, returning `None` if incomplete.
pub fn parse_bidi_header(input: &[u8]) -> Result<Option<(SessionId, usize)>, WebTransportError> {
    parse_header(input, WT_STREAM_SIGNAL)
}

fn parse_header(
    input: &[u8],
    expected: u64,
) -> Result<Option<(SessionId, usize)>, WebTransportError> {
    let mut cursor = input;
    let kind = match netune_quic::wire::varint::decode(&mut cursor) {
        Ok(kind) => kind,
        Err(netune_quic::wire::WireError::UnexpectedEnd) => return Ok(None),
        Err(error) => return Err(WebTransportError::Wire(error.to_string())),
    };
    if kind != expected {
        return Err(WebTransportError::InvalidStreamHeader(kind));
    }
    let session = match netune_quic::wire::varint::decode(&mut cursor) {
        Ok(session) => session,
        Err(netune_quic::wire::WireError::UnexpectedEnd) => return Ok(None),
        Err(error) => return Err(WebTransportError::Wire(error.to_string())),
    };
    Ok(Some((SessionId::new(session)?, input.len() - cursor.len())))
}

/// A WebTransport session-control or flow-control capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCapsule {
    /// Close the session with an application error code and UTF-8 message.
    Close {
        /// Application error code.
        code: u32,
        /// UTF-8 reason message (at most 1024 bytes).
        message: String,
    },
    /// Request graceful draining of the session.
    Drain,
    /// Increase the peer's maximum stream limit.
    MaxStreams {
        /// `true` for bidirectional streams, `false` for unidirectional streams.
        bidi: bool,
        /// Updated cumulative stream limit.
        maximum: u64,
    },
    /// Increase the peer's session-wide data limit.
    MaxData(u64),
    /// Notify the peer that opening streams is blocked at `maximum`.
    StreamsBlocked {
        /// `true` for bidirectional streams, `false` for unidirectional streams.
        bidi: bool,
        /// Stream limit at which the sender is blocked.
        maximum: u64,
    },
    /// Notify the peer that sending data is blocked at the given byte limit.
    DataBlocked(u64),
}

impl ControlCapsule {
    /// Encode this control message as an HTTP/3 [`Capsule`].
    pub fn to_capsule(&self) -> Result<Capsule, WebTransportError> {
        let (kind, value) = match self {
            Self::Close { code, message } if message.len() <= 1024 => {
                let mut value = BytesMut::with_capacity(4 + message.len());
                value.put_u32(*code);
                value.put_slice(message.as_bytes());
                (WT_CLOSE_SESSION, value.freeze())
            }
            Self::Close { .. } => {
                return Err(WebTransportError::Capsule(
                    "WT_CLOSE_SESSION message exceeds 1024 bytes".to_string(),
                ));
            }
            Self::Drain => (WT_DRAIN_SESSION, Bytes::new()),
            Self::MaxStreams { bidi, maximum } => {
                let mut value = BytesMut::new();
                encode_varint(&mut value, *maximum)?;
                (
                    if *bidi {
                        WT_MAX_STREAMS_BIDI
                    } else {
                        WT_MAX_STREAMS_UNI
                    },
                    value.freeze(),
                )
            }
            Self::MaxData(maximum) => {
                let mut value = BytesMut::new();
                encode_varint(&mut value, *maximum)?;
                (WT_MAX_DATA, value.freeze())
            }
            Self::StreamsBlocked { bidi, maximum } => {
                let mut value = BytesMut::new();
                encode_varint(&mut value, *maximum)?;
                (
                    if *bidi {
                        WT_STREAMS_BLOCKED_BIDI
                    } else {
                        WT_STREAMS_BLOCKED_UNI
                    },
                    value.freeze(),
                )
            }
            Self::DataBlocked(maximum) => {
                let mut value = BytesMut::new();
                encode_varint(&mut value, *maximum)?;
                (WT_DATA_BLOCKED, value.freeze())
            }
        };
        Ok(Capsule::new(kind, value))
    }

    /// Decode an HTTP/3 [`Capsule`] into a [`ControlCapsule`], returning `None` for unknown kinds.
    pub fn from_capsule(capsule: &Capsule) -> Result<Option<Self>, WebTransportError> {
        let out = match capsule.kind {
            WT_CLOSE_SESSION => {
                if capsule.value.len() < 4 {
                    return Err(WebTransportError::Capsule(
                        "WT_CLOSE_SESSION is shorter than its code".to_string(),
                    ));
                }
                let code = u32::from_be_bytes([
                    capsule.value[0],
                    capsule.value[1],
                    capsule.value[2],
                    capsule.value[3],
                ]);
                let message = String::from_utf8(capsule.value[4..].to_vec()).map_err(|_| {
                    WebTransportError::Capsule("WT_CLOSE_SESSION message is not UTF-8".to_string())
                })?;
                if message.len() > 1024 {
                    return Err(WebTransportError::Capsule(
                        "WT_CLOSE_SESSION message exceeds 1024 bytes".to_string(),
                    ));
                }
                Self::Close { code, message }
            }
            WT_DRAIN_SESSION => {
                if !capsule.value.is_empty() {
                    return Err(WebTransportError::Capsule(
                        "WT_DRAIN_SESSION must be empty".to_string(),
                    ));
                }
                Self::Drain
            }
            WT_MAX_STREAMS_BIDI | WT_MAX_STREAMS_UNI => Self::MaxStreams {
                bidi: capsule.kind == WT_MAX_STREAMS_BIDI,
                maximum: parse_varint(&capsule.value)?,
            },
            WT_MAX_DATA => Self::MaxData(parse_varint(&capsule.value)?),
            WT_STREAMS_BLOCKED_BIDI | WT_STREAMS_BLOCKED_UNI => Self::StreamsBlocked {
                bidi: capsule.kind == WT_STREAMS_BLOCKED_BIDI,
                maximum: parse_varint(&capsule.value)?,
            },
            WT_DATA_BLOCKED => Self::DataBlocked(parse_varint(&capsule.value)?),
            _ => return Ok(None),
        };
        if let Self::MaxStreams { maximum, .. }
        | Self::StreamsBlocked { maximum, .. }
        | Self::MaxData(maximum)
        | Self::DataBlocked(maximum) = out
            && maximum > (1 << 62) - 1
        {
            return Err(WebTransportError::Capsule(
                "WebTransport flow-control value is out of range".to_string(),
            ));
        }
        Ok(Some(out))
    }
}

fn encode_varint(out: &mut BytesMut, value: u64) -> Result<(), WebTransportError> {
    netune_quic::wire::varint::encode(out, value)
        .map_err(|error| WebTransportError::Wire(error.to_string()))
}

fn parse_varint(value: &[u8]) -> Result<u64, WebTransportError> {
    let mut cursor = value;
    let parsed = netune_quic::wire::varint::decode(&mut cursor)
        .map_err(|error| WebTransportError::Wire(error.to_string()))?;
    if !cursor.is_empty() {
        return Err(WebTransportError::Capsule(
            "flow-control capsule has trailing bytes".to_string(),
        ));
    }
    Ok(parsed)
}

/// WebTransport wire or framing error.
#[derive(Debug, thiserror::Error)]
pub enum WebTransportError {
    /// Session ID is not a valid client-initiated bidirectional stream ID.
    #[error("invalid WebTransport session ID {0}")]
    InvalidSessionId(u64),
    /// Stream header carried an unexpected type or signal varint.
    #[error("invalid WebTransport stream header {0:#x}")]
    InvalidStreamHeader(u64),
    /// Incoming or outgoing WebTransport session request or URI is invalid.
    #[error("invalid WebTransport request: {0}")]
    InvalidRequest(String),
    /// Request `Origin` header was rejected by [`OriginPolicy`].
    #[error("WebTransport origin rejected: {0}")]
    OriginRejected(String),
    /// Peer or local WebTransport HTTP/3 settings are invalid or incompatible.
    #[error("bad WebTransport SETTINGS: {0}")]
    Settings(String),
    /// Malformed or out-of-range WebTransport control capsule.
    #[error("WebTransport capsule error: {0}")]
    Capsule(String),
    /// QUIC variable-length integer encoding or decoding failure.
    #[error("WebTransport wire error: {0}")]
    Wire(String),
    /// Underlying HTTP/3 capsule framing error.
    #[error("HTTP/3 capsule error: {0}")]
    HttpCapsule(#[from] CapsuleError),
    /// Underlying HTTP/3 transport error.
    #[error("HTTP/3 error: {0}")]
    Http3(String),
    /// Underlying QUIC stream or connection error.
    #[error("QUIC error: {0}")]
    Quic(String),
    /// HTTP status, header, or response construction error.
    #[error("HTTP error: {0}")]
    Http(String),
    /// Operation attempted on a closed or draining session or reset stream.
    #[error("WebTransport session closed: {0}")]
    SessionClosed(String),
    /// WebTransport stream or data flow-control limit violated.
    #[error("WebTransport flow control error: {0}")]
    FlowControl(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_client_bidirectional_stream_ids() {
        assert!(SessionId::new(0).is_ok());
        assert!(SessionId::new(4).is_ok());
        assert!(SessionId::new(1).is_err());
        assert!(SessionId::new(2).is_err());
        assert!(SessionId::new(3).is_err());
        assert!(SessionId::new(1 << 62).is_err());
    }

    #[test]
    fn settings_round_trip() {
        let settings = WebTransportSettings {
            enabled: true,
            initial_max_streams_uni: 7,
            initial_max_streams_bidi: 9,
            initial_max_data: 1 << 20,
        };
        assert_eq!(
            WebTransportSettings::from_extra(&settings.extra_settings()).expect("settings"),
            settings
        );
        let mut extra = settings.extra_settings();
        extra.push((SETTINGS_WT_ENABLED, 2));
        assert!(WebTransportSettings::from_extra(&extra).is_err());
    }

    #[test]
    fn draft_negotiation_prefers_17_and_rejects_unknown_values() {
        assert_eq!(
            WebTransportVersion::from_peer_settings(Some(1), None).expect("draft 17"),
            WebTransportVersion::Draft17
        );
        assert_eq!(
            WebTransportVersion::from_peer_settings(None, Some(1)).expect("draft 16"),
            WebTransportVersion::Draft16
        );
        assert_eq!(
            WebTransportVersion::from_peer_settings(Some(1), Some(1)).expect("highest common"),
            WebTransportVersion::Draft17
        );
        assert!(
            WebTransportVersion::from_peer_settings(Some(0), Some(0)).is_err(),
            "a disabled peer is not a WebTransport peer"
        );
        assert!(
            WebTransportVersion::from_peer_settings(Some(2), None).is_err(),
            "values other than 0/1 are invalid"
        );
    }

    #[test]
    fn settings_negotiate_both_webtransport_codepoints() {
        let settings = WebTransportSettings {
            enabled: true,
            initial_max_streams_uni: 1,
            initial_max_streams_bidi: 1,
            initial_max_data: 1,
        };
        let extra = settings.extra_settings();
        assert!(extra.contains(&(SETTINGS_WT_ENABLED, 1)));
        assert!(extra.contains(&(SETTINGS_WT_ENABLED_DRAFT16, 1)));

        for id in [SETTINGS_WT_ENABLED, SETTINGS_WT_ENABLED_DRAFT16] {
            let negotiated = WebTransportSettings::from_extra(&[(id, 1)]).expect("peer settings");
            assert!(negotiated.enabled);
        }
    }

    #[test]
    fn stream_headers_round_trip() {
        let session = SessionId::new(8).expect("session");
        let mut uni = BytesMut::new();
        encode_uni_header(session, &mut uni).expect("uni");
        assert_eq!(
            parse_uni_header(&uni).expect("parse").expect("complete").0,
            session
        );
        let mut bidi = BytesMut::new();
        encode_bidi_header(session, &mut bidi).expect("bidi");
        assert_eq!(
            parse_bidi_header(&bidi)
                .expect("parse")
                .expect("complete")
                .0,
            session
        );
        assert!(parse_bidi_header(&uni).is_err());
    }

    #[test]
    fn application_error_mapping_skips_reserved_codepoints() {
        for application in [0, 1, 0x1e, 0x1f, 0xffff_ffff] {
            let http = error_code::to_http(application);
            assert!(!(http - 0x21).is_multiple_of(0x1f));
            assert_eq!(error_code::from_http(http), Some(application));
        }
        assert_eq!(error_code::from_http(WT_APPLICATION_ERROR_FIRST - 1), None);
    }

    #[test]
    fn control_capsules_round_trip() {
        for capsule in [
            ControlCapsule::Close {
                code: 7,
                message: "done".to_string(),
            },
            ControlCapsule::Drain,
            ControlCapsule::MaxStreams {
                bidi: true,
                maximum: 10,
            },
            ControlCapsule::MaxData(1 << 20),
            ControlCapsule::StreamsBlocked {
                bidi: false,
                maximum: 3,
            },
            ControlCapsule::DataBlocked(4096),
        ] {
            let wire = capsule.to_capsule().expect("encode");
            assert_eq!(
                ControlCapsule::from_capsule(&wire).expect("decode"),
                Some(capsule)
            );
        }
    }
}
