// SPDX-License-Identifier: MIT

//! HTTP/3 wire constants (RFC 9114) and QPACK error codes (RFC 9204).

/// Frame types.
pub mod frame_type {
    /// `DATA` frame type (`0x0`, RFC 9114 Section 7.2.1).
    pub const DATA: u64 = 0x0;
    /// `HEADERS` frame type (`0x1`, RFC 9114 Section 7.2.2).
    pub const HEADERS: u64 = 0x1;
    /// `CANCEL_PUSH` frame type (`0x3`, RFC 9114 Section 7.2.3).
    pub const CANCEL_PUSH: u64 = 0x3;
    /// `SETTINGS` frame type (`0x4`, RFC 9114 Section 7.2.4).
    pub const SETTINGS: u64 = 0x4;
    /// `PUSH_PROMISE` frame type (`0x5`, RFC 9114 Section 7.2.5).
    pub const PUSH_PROMISE: u64 = 0x5;
    /// `GOAWAY` frame type (`0x7`, RFC 9114 Section 7.2.6).
    pub const GOAWAY: u64 = 0x7;
    /// `MAX_PUSH_ID` frame type (`0xd`, RFC 9114 Section 7.2.7).
    pub const MAX_PUSH_ID: u64 = 0xd;
    /// `DUPLICATE_PUSH` frame type (`0xe`, deprecated HTTP/3 draft value).
    pub const DUPLICATE_PUSH: u64 = 0xe;
}

/// Unidirectional stream types.
pub mod stream_type {
    /// Control stream type (`0x0`, RFC 9114 Section 6.2.1).
    pub const CONTROL: u64 = 0x0;
    /// Push stream type (`0x1`, RFC 9114 Section 6.2.2).
    pub const PUSH: u64 = 0x1;
    /// QPACK encoder stream type (`0x2`, RFC 9204 Section 4.2).
    pub const QPACK_ENCODER: u64 = 0x2;
    /// QPACK decoder stream type (`0x3`, RFC 9204 Section 4.2).
    pub const QPACK_DECODER: u64 = 0x3;
}

/// SETTINGS identifiers.
pub mod setting_id {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (`0x1`, RFC 9204 Section 5).
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE` (`0x6`, RFC 9114 Section 7.2.4.1).
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x6;
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` (`0x7`, RFC 9204 Section 5).
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x7;
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`0x8`, RFC 9220 Section 3).
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
    /// `SETTINGS_H3_DATAGRAM` (`0x33`, RFC 9297 Section 2.1.1).
    pub const H3_DATAGRAM: u64 = 0x33;
}

/// HTTP/3 and QPACK application error codes.
pub mod error_code {
    /// `H3_NO_ERROR` (`0x0100`, RFC 9114 Section 8.1).
    pub const H3_NO_ERROR: u64 = 0x0100;
    /// `H3_GENERAL_PROTOCOL_ERROR` (`0x0101`, RFC 9114 Section 8.1).
    pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
    /// `H3_INTERNAL_ERROR` (`0x0102`, RFC 9114 Section 8.1).
    pub const H3_INTERNAL_ERROR: u64 = 0x0102;
    /// `H3_STREAM_CREATION_ERROR` (`0x0103`, RFC 9114 Section 8.1).
    pub const H3_STREAM_CREATION_ERROR: u64 = 0x0103;
    /// `H3_CLOSED_CRITICAL_STREAM` (`0x0104`, RFC 9114 Section 8.1).
    pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;
    /// `H3_FRAME_UNEXPECTED` (`0x0105`, RFC 9114 Section 8.1).
    pub const H3_FRAME_UNEXPECTED: u64 = 0x0105;
    /// `H3_FRAME_ERROR` (`0x0106`, RFC 9114 Section 8.1).
    pub const H3_FRAME_ERROR: u64 = 0x0106;
    /// `H3_EXCESSIVE_LOAD` (`0x0107`, RFC 9114 Section 8.1).
    pub const H3_EXCESSIVE_LOAD: u64 = 0x0107;
    /// `H3_ID_ERROR` (`0x0108`, RFC 9114 Section 8.1).
    pub const H3_ID_ERROR: u64 = 0x0108;
    /// `H3_SETTINGS_ERROR` (`0x0109`, RFC 9114 Section 8.1).
    pub const H3_SETTINGS_ERROR: u64 = 0x0109;
    /// `H3_MESSAGE_ERROR` (`0x010e`, RFC 9114 Section 8.1).
    pub const H3_MESSAGE_ERROR: u64 = 0x010e;
    /// `H3_MISSING_SETTINGS` (`0x010a`, RFC 9114 Section 8.1).
    pub const H3_MISSING_SETTINGS: u64 = 0x010a;
    /// `H3_REQUEST_REJECTED` (`0x010b`, RFC 9114 Section 8.1).
    pub const H3_REQUEST_REJECTED: u64 = 0x010b;
    /// `H3_REQUEST_CANCELLED` (`0x010c`, RFC 9114 Section 8.1).
    pub const H3_REQUEST_CANCELLED: u64 = 0x010c;
    /// `H3_REQUEST_INCOMPLETE` (`0x010d`, RFC 9114 Section 8.1).
    pub const H3_REQUEST_INCOMPLETE: u64 = 0x010d;
    /// `H3_CONNECT_ERROR` (`0x010f`, RFC 9114 Section 8.1).
    pub const H3_CONNECT_ERROR: u64 = 0x010f;
    /// `H3_VERSION_FALLBACK` (`0x0110`, RFC 9114 Section 8.1).
    pub const H3_VERSION_FALLBACK: u64 = 0x0110;
    /// `QPACK_DECOMPRESSION_FAILED` (`0x0200`, RFC 9204 Section 6).
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
    /// `QPACK_ENCODER_STREAM_ERROR` (`0x0201`, RFC 9204 Section 6).
    pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x0201;
    /// `QPACK_DECODER_STREAM_ERROR` (`0x0202`, RFC 9204 Section 6).
    pub const QPACK_DECODER_STREAM_ERROR: u64 = 0x0202;
}

/// True for a client-initiated bidirectional stream.
pub fn is_client_bidi(stream_id: u64) -> bool {
    stream_id & 0x3 == 0
}

/// True for a server-initiated bidirectional stream.
pub fn is_server_bidi(stream_id: u64) -> bool {
    stream_id & 0x3 == 1
}

/// True for a client-initiated unidirectional stream.
pub fn is_client_uni(stream_id: u64) -> bool {
    stream_id & 0x3 == 2
}

/// True for a server-initiated unidirectional stream.
pub fn is_server_uni(stream_id: u64) -> bool {
    stream_id & 0x3 == 3
}

/// Reserved (GREASE) frame types are `0x1f * N + 0x21`.
pub fn is_grease(value: u64) -> bool {
    value >= 0x21 && (value - 0x21).is_multiple_of(0x1f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_id_roles_follow_the_low_two_bits() {
        assert!(is_client_bidi(0));
        assert!(is_server_bidi(1));
        assert!(is_client_uni(2));
        assert!(is_server_uni(3));
        assert!(is_client_bidi(4));
        assert!(!is_client_bidi(1));
    }

    #[test]
    fn grease_values_are_reserved() {
        for n in 0..8 {
            assert!(is_grease(0x1f * n + 0x21));
        }
        assert!(!is_grease(0x20));
        assert!(!is_grease(0x22));
    }
}
