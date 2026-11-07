//! HTTP/2 binary frame framing and serialization (RFC 9113).

use crate::error::H2Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Frame header length: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID.
pub const FRAME_HEADER_LEN: usize = 9;

/// Frame types (RFC 9113 Section 6).
pub const FRAME_DATA: u8 = 0x0;
pub const FRAME_HEADERS: u8 = 0x1;
pub const FRAME_PRIORITY: u8 = 0x2;
pub const FRAME_RST_STREAM: u8 = 0x3;
pub const FRAME_SETTINGS: u8 = 0x4;
pub const FRAME_PUSH_PROMISE: u8 = 0x5;
pub const FRAME_PING: u8 = 0x6;
pub const FRAME_GOAWAY: u8 = 0x7;
pub const FRAME_WINDOW_UPDATE: u8 = 0x8;
pub const FRAME_CONTINUATION: u8 = 0x9;

/// Frame flags.
pub const FLAG_ACK: u8 = 0x1;
pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_END_HEADERS: u8 = 0x4;
pub const FLAG_PADDED: u8 = 0x8;
pub const FLAG_PRIORITY: u8 = 0x20;

/// Known SETTINGS parameters.
pub const SETTING_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTING_ENABLE_PUSH: u16 = 0x2;
pub const SETTING_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTING_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTING_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTING_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// A parsed 9-byte HTTP/2 frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    /// Parse a 9-byte slice into a frame header.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < FRAME_HEADER_LEN {
            return None;
        }
        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        let frame_type = buf[3];
        let flags = buf[4];
        let stream_id = u32::from_be_bytes([buf[5] & 0x7F, buf[6], buf[7], buf[8]]);
        Some(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    /// Encode this header into a 9-byte vector.
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0] = ((self.length >> 16) & 0xFF) as u8;
        out[1] = ((self.length >> 8) & 0xFF) as u8;
        out[2] = (self.length & 0xFF) as u8;
        out[3] = self.frame_type;
        out[4] = self.flags;
        let s_bytes = (self.stream_id & 0x7FFFFFFF).to_be_bytes();
        out[5..9].copy_from_slice(&s_bytes);
        out
    }
}

/// An HTTP/2 frame representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        stream_id: u32,
        end_stream: bool,
        payload: Bytes,
    },
    Headers {
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        header_block: Bytes,
    },
    Settings {
        ack: bool,
        /// In-order parameters (critical for Akamai H2 fingerprinting!).
        settings: Vec<(u16, u32)>,
    },
    Ping {
        ack: bool,
        opaque_data: [u8; 8],
    },
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: Bytes,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    RstStream {
        stream_id: u32,
        error_code: u32,
    },
    Priority {
        stream_id: u32,
        exclusive: bool,
        stream_dependency: u32,
        weight: u8,
    },
    /// A continuation of the header block started by the preceding `HEADERS` or
    /// `PUSH_PROMISE` frame (RFC 9113 §6.10).
    Continuation {
        stream_id: u32,
        end_headers: bool,
        header_block: Bytes,
    },
    /// A server push the client did not ask for (RFC 9113 §6.6).
    PushPromise {
        stream_id: u32,
        promised_stream_id: u32,
        end_headers: bool,
        header_block: Bytes,
    },
}

impl Frame {
    /// Encode the frame into a byte buffer ready for the wire.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            Self::Data {
                stream_id,
                end_stream,
                payload,
            } => {
                let flags = if *end_stream { FLAG_END_STREAM } else { 0 };
                let header = FrameHeader {
                    length: payload.len() as u32,
                    frame_type: FRAME_DATA,
                    flags,
                    stream_id: *stream_id,
                };
                buf.extend_from_slice(&header.encode());
                buf.extend_from_slice(payload);
            }
            Self::Headers {
                stream_id,
                end_stream,
                end_headers,
                header_block,
            } => {
                let mut flags = 0;
                if *end_stream {
                    flags |= FLAG_END_STREAM;
                }
                if *end_headers {
                    flags |= FLAG_END_HEADERS;
                }
                let header = FrameHeader {
                    length: header_block.len() as u32,
                    frame_type: FRAME_HEADERS,
                    flags,
                    stream_id: *stream_id,
                };
                buf.extend_from_slice(&header.encode());
                buf.extend_from_slice(header_block);
            }
            Self::Settings { ack, settings } => {
                let flags = if *ack { FLAG_ACK } else { 0 };
                let payload_len = if *ack { 0 } else { settings.len() * 6 };
                let header = FrameHeader {
                    length: payload_len as u32,
                    frame_type: FRAME_SETTINGS,
                    flags,
                    stream_id: 0,
                };
                buf.extend_from_slice(&header.encode());
                if !*ack {
                    for (id, val) in settings {
                        buf.put_u16(*id);
                        buf.put_u32(*val);
                    }
                }
            }
            Self::Ping { ack, opaque_data } => {
                let flags = if *ack { FLAG_ACK } else { 0 };
                let header = FrameHeader {
                    length: 8,
                    frame_type: FRAME_PING,
                    flags,
                    stream_id: 0,
                };
                buf.extend_from_slice(&header.encode());
                buf.extend_from_slice(opaque_data);
            }
            Self::WindowUpdate {
                stream_id,
                increment,
            } => {
                let header = FrameHeader {
                    length: 4,
                    frame_type: FRAME_WINDOW_UPDATE,
                    flags: 0,
                    stream_id: *stream_id,
                };
                buf.extend_from_slice(&header.encode());
                buf.put_u32(*increment & 0x7FFFFFFF);
            }
            Self::RstStream {
                stream_id,
                error_code,
            } => {
                let header = FrameHeader {
                    length: 4,
                    frame_type: FRAME_RST_STREAM,
                    flags: 0,
                    stream_id: *stream_id,
                };
                buf.extend_from_slice(&header.encode());
                buf.put_u32(*error_code);
            }
            Self::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                let header = FrameHeader {
                    length: (8 + debug_data.len()) as u32,
                    frame_type: FRAME_GOAWAY,
                    flags: 0,
                    stream_id: 0,
                };
                buf.extend_from_slice(&header.encode());
                buf.put_u32(*last_stream_id & 0x7FFFFFFF);
                buf.put_u32(*error_code);
                buf.extend_from_slice(debug_data);
            }
            Self::Priority {
                stream_id,
                exclusive,
                stream_dependency,
                weight,
            } => {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FRAME_PRIORITY,
                    flags: 0,
                    stream_id: *stream_id,
                };
                buf.extend_from_slice(&header.encode());
                let dep =
                    (*stream_dependency & 0x7FFFFFFF) | if *exclusive { 0x80000000 } else { 0 };
                buf.put_u32(dep);
                buf.put_u8(*weight);
            }
            Self::Continuation {
                stream_id,
                end_headers,
                header_block,
            } => {
                let flags = if *end_headers { FLAG_END_HEADERS } else { 0 };
                let header = FrameHeader {
                    length: header_block.len() as u32,
                    frame_type: FRAME_CONTINUATION,
                    flags,
                    stream_id: *stream_id,
                };
                buf.extend_from_slice(&header.encode());
                buf.extend_from_slice(header_block);
            }
            Self::PushPromise {
                stream_id,
                promised_stream_id,
                end_headers,
                header_block,
            } => {
                let flags = if *end_headers { FLAG_END_HEADERS } else { 0 };
                let header = FrameHeader {
                    length: (4 + header_block.len()) as u32,
                    frame_type: FRAME_PUSH_PROMISE,
                    flags,
                    stream_id: *stream_id,
                };
                buf.extend_from_slice(&header.encode());
                buf.put_u32(*promised_stream_id & 0x7FFFFFFF);
                buf.extend_from_slice(header_block);
            }
        }
        buf.freeze()
    }

    /// Decode a frame given its parsed header and complete payload bytes.
    ///
    /// # Padding and priority
    ///
    /// `PADDED` and `PRIORITY` are *legal* on a client's `DATA`, `HEADERS` and `PUSH_PROMISE`
    /// frame (RFC 9113 §6.1, §6.2), and a conforming sender may use them: a
    /// privacy-preserving client pads headers on purpose to blunt traffic analysis. A decoder
    /// that returned the raw payload would hand its caller the pad-length octet as if it were
    /// a header block, so both are stripped here — once, for both roles, because a server
    /// that mishandled padding would be trivially crashable by any client that padded.
    ///
    /// # Errors
    ///
    /// A pad length longer than the payload, a `HEADERS` frame carrying `PRIORITY` with no
    /// room for its 5-octet prefix, and any frame whose own length rule is violated.
    pub fn decode(header: &FrameHeader, payload: Bytes) -> Result<Self, H2Error> {
        match header.frame_type {
            FRAME_DATA => {
                let pad = strip_pad(header.flags, &payload, "DATA")?;
                Ok(Self::Data {
                    stream_id: header.stream_id,
                    end_stream: (header.flags & FLAG_END_STREAM) != 0,
                    payload: pad,
                })
            }
            FRAME_HEADERS => {
                let mut block = payload;
                if header.flags & FLAG_PADDED != 0 {
                    block = strip_pad(header.flags, &block, "HEADERS")?;
                }
                if header.flags & FLAG_PRIORITY != 0 {
                    if block.len() < 5 {
                        return Err(H2Error::FrameSize(
                            "HEADERS with PRIORITY carries no priority fields".into(),
                        ));
                    }
                    block = block.slice(5..);
                }
                Ok(Self::Headers {
                    stream_id: header.stream_id,
                    end_stream: (header.flags & FLAG_END_STREAM) != 0,
                    end_headers: (header.flags & FLAG_END_HEADERS) != 0,
                    header_block: block,
                })
            }
            FRAME_PRIORITY => {
                if header.length != 5 {
                    return Err(H2Error::FrameSize(
                        "PRIORITY must be exactly 5 bytes".into(),
                    ));
                }
                if header.stream_id == 0 {
                    return Err(H2Error::Protocol("PRIORITY on stream 0".into()));
                }
                let dependency = payload[0..4].to_vec();
                let raw = u32::from_be_bytes([
                    dependency[0] & 0x7F,
                    dependency[1],
                    dependency[2],
                    dependency[3],
                ]);
                Ok(Self::Priority {
                    stream_id: header.stream_id,
                    exclusive: dependency[0] & 0x80 != 0,
                    stream_dependency: raw,
                    weight: payload[4],
                })
            }
            FRAME_SETTINGS => {
                let ack = (header.flags & FLAG_ACK) != 0;
                if ack {
                    if header.length != 0 {
                        return Err(H2Error::FrameSize(
                            "SETTINGS with ACK must have length 0".into(),
                        ));
                    }
                    Ok(Self::Settings {
                        ack: true,
                        settings: Vec::new(),
                    })
                } else {
                    if !header.length.is_multiple_of(6) {
                        return Err(H2Error::FrameSize(
                            "SETTINGS payload must be a multiple of 6".into(),
                        ));
                    }
                    let mut settings = Vec::new();
                    let mut p = payload;
                    while p.has_remaining() {
                        let id = p.get_u16();
                        let val = p.get_u32();
                        settings.push((id, val));
                    }
                    Ok(Self::Settings {
                        ack: false,
                        settings,
                    })
                }
            }
            FRAME_PING => {
                if header.length != 8 {
                    return Err(H2Error::FrameSize(
                        "PING frame must be exactly 8 bytes".into(),
                    ));
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&payload[0..8]);
                Ok(Self::Ping {
                    ack: (header.flags & FLAG_ACK) != 0,
                    opaque_data: data,
                })
            }
            FRAME_WINDOW_UPDATE => {
                if header.length != 4 {
                    return Err(H2Error::FrameSize("WINDOW_UPDATE must be 4 bytes".into()));
                }
                let increment =
                    u32::from_be_bytes([payload[0] & 0x7F, payload[1], payload[2], payload[3]]);
                Ok(Self::WindowUpdate {
                    stream_id: header.stream_id,
                    increment,
                })
            }
            FRAME_RST_STREAM => {
                if header.length != 4 {
                    return Err(H2Error::FrameSize("RST_STREAM must be 4 bytes".into()));
                }
                let error_code =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Self::RstStream {
                    stream_id: header.stream_id,
                    error_code,
                })
            }
            FRAME_GOAWAY => {
                if header.length < 8 {
                    return Err(H2Error::FrameSize("GOAWAY must be at least 8 bytes".into()));
                }
                let last_stream_id =
                    u32::from_be_bytes([payload[0] & 0x7F, payload[1], payload[2], payload[3]]);
                let error_code =
                    u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let debug_data = payload.slice(8..);
                Ok(Self::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                })
            }
            FRAME_CONTINUATION => Ok(Self::Continuation {
                stream_id: header.stream_id,
                end_headers: (header.flags & FLAG_END_HEADERS) != 0,
                header_block: payload,
            }),
            FRAME_PUSH_PROMISE => {
                let mut block = payload;
                if header.flags & FLAG_PADDED != 0 {
                    block = strip_pad(header.flags, &block, "PUSH_PROMISE")?;
                }
                if block.len() < 4 {
                    return Err(H2Error::FrameSize(
                        "PUSH_PROMISE must be at least 4 bytes".into(),
                    ));
                }
                let promised_stream_id =
                    u32::from_be_bytes([block[0] & 0x7F, block[1], block[2], block[3]]);
                Ok(Self::PushPromise {
                    stream_id: header.stream_id,
                    promised_stream_id,
                    end_headers: (header.flags & FLAG_END_HEADERS) != 0,
                    header_block: block.slice(4..),
                })
            }
            other => Err(H2Error::Protocol(format!("unhandled frame type {other}"))),
        }
    }
}

/// Remove `PADDED` padding from a payload, returning the unpadded bytes.
///
/// A pad length that exceeds the remaining payload is not a decoder inconvenience: a decoder
/// that sliced anyway would panic, and one that silently clamped would accept a frame the
/// sender framed illegally. It is a connection error, which is what RFC 9113 §6.1 requires.
fn strip_pad(flags: u8, payload: &Bytes, frame: &str) -> Result<Bytes, H2Error> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload.clone());
    }
    if payload.is_empty() {
        return Err(H2Error::FrameSize(format!(
            "{frame} declares padding but carries no pad length"
        )));
    }
    let pad = usize::from(payload[0]);
    if pad + 1 > payload.len() {
        return Err(H2Error::FrameSize(format!(
            "{frame} declares {pad} pad bytes in a {} byte payload",
            payload.len()
        )));
    }
    Ok(payload.slice(1..payload.len() - pad))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_round_trip() {
        let original = FrameHeader {
            length: 1234,
            frame_type: FRAME_HEADERS,
            flags: FLAG_END_STREAM | FLAG_END_HEADERS,
            stream_id: 1,
        };
        let encoded = original.encode();
        let parsed = FrameHeader::parse(&encoded).expect("parse header");
        assert_eq!(original, parsed);
    }

    #[test]
    fn settings_frame_round_trip_preserves_order() {
        let frame = Frame::Settings {
            ack: false,
            settings: vec![
                (SETTING_HEADER_TABLE_SIZE, 65536),
                (SETTING_ENABLE_PUSH, 0),
                (SETTING_INITIAL_WINDOW_SIZE, 6291456),
                (SETTING_MAX_HEADER_LIST_SIZE, 262144),
            ],
        };
        let bytes = frame.encode();
        let header = FrameHeader::parse(&bytes[..FRAME_HEADER_LEN]).expect("header");
        let decoded = Frame::decode(&header, bytes.slice(FRAME_HEADER_LEN..)).expect("decode");
        assert_eq!(frame, decoded);
    }
}
