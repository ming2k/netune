// SPDX-License-Identifier: MIT

//! Owned WebTransport over HTTP/3, pinned to `draft-ietf-webtrans-http3-17`.

#![cfg_attr(test, allow(clippy::expect_used))]
//!
//! This crate owns the WebTransport wire model and product API. HTTP/3 and QUIC
//! remain RFC-owned leaves; WebTransport-specific SETTINGS, stream signals,
//! capsules, flow control and errors live here.

use bytes::{BufMut, Bytes, BytesMut};
use netune_http3::{Capsule, CapsuleError};

/// The pinned WebTransport over HTTP/3 draft version.
pub const DRAFT_VERSION: &str = "draft-ietf-webtrans-http3-17";

pub const SETTINGS_WT_ENABLED: u64 = 0x20b8_933b;
pub const SETTINGS_WT_INITIAL_MAX_STREAMS_UNI: u64 = 0x2b64;
pub const SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI: u64 = 0x2b65;
pub const SETTINGS_WT_INITIAL_MAX_DATA: u64 = 0x2b61;

pub const WT_STREAM_SIGNAL: u64 = 0x41;
pub const WT_UNI_STREAM_TYPE: u64 = 0x54;

pub const WT_CLOSE_SESSION: u64 = 0x2843;
pub const WT_DRAIN_SESSION: u64 = 0x78ae;
pub const WT_MAX_STREAMS_BIDI: u64 = 0x190b_4d3f;
pub const WT_MAX_STREAMS_UNI: u64 = 0x190b_4d40;
pub const WT_MAX_DATA: u64 = 0x190b_4d3d;
pub const WT_DATA_BLOCKED: u64 = 0x190b_4d41;
pub const WT_STREAMS_BLOCKED_BIDI: u64 = 0x190b_4d43;
pub const WT_STREAMS_BLOCKED_UNI: u64 = 0x190b_4d44;

pub const WT_BUFFERED_STREAM_REJECTED: u64 = 0x3994_bd84;
pub const WT_SESSION_GONE: u64 = 0x170d_7b68;
pub const WT_FLOW_CONTROL_ERROR: u64 = 0x045d_4487;
pub const WT_ALPN_ERROR: u64 = 0x0817_b3dd;
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
    pub fn new(value: u64) -> Result<Self, WebTransportError> {
        if value > (1u64 << 62) - 1 {
            return Err(WebTransportError::InvalidSessionId(value));
        }
        if !value.is_multiple_of(4) {
            return Err(WebTransportError::InvalidSessionId(value));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// WebTransport settings exchanged through HTTP/3 SETTINGS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebTransportSettings {
    pub enabled: bool,
    pub initial_max_streams_uni: u64,
    pub initial_max_streams_bidi: u64,
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
    pub fn extra_settings(self) -> Vec<(u64, u64)> {
        let mut settings = vec![(SETTINGS_WT_ENABLED, u64::from(self.enabled))];
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

    pub fn from_extra(settings: &[(u64, u64)]) -> Result<Self, WebTransportError> {
        let mut output = Self {
            enabled: false,
            initial_max_streams_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_data: 0,
        };
        for (id, value) in settings {
            match *id {
                SETTINGS_WT_ENABLED => {
                    if *value > 1 {
                        return Err(WebTransportError::Settings(
                            "SETTINGS_WT_ENABLED must be 0 or 1".to_string(),
                        ));
                    }
                    output.enabled = *value == 1;
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

pub fn parse_uni_header(input: &[u8]) -> Result<Option<(SessionId, usize)>, WebTransportError> {
    parse_header(input, WT_UNI_STREAM_TYPE)
}

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
    Close { code: u32, message: String },
    Drain,
    MaxStreams { bidi: bool, maximum: u64 },
    MaxData(u64),
    StreamsBlocked { bidi: bool, maximum: u64 },
    DataBlocked(u64),
}

impl ControlCapsule {
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
    #[error("invalid WebTransport session ID {0}")]
    InvalidSessionId(u64),
    #[error("invalid WebTransport stream header {0:#x}")]
    InvalidStreamHeader(u64),
    #[error("bad WebTransport SETTINGS: {0}")]
    Settings(String),
    #[error("WebTransport capsule error: {0}")]
    Capsule(String),
    #[error("WebTransport wire error: {0}")]
    Wire(String),
    #[error("HTTP/3 capsule error: {0}")]
    HttpCapsule(#[from] CapsuleError),
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
