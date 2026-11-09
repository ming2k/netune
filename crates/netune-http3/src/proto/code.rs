// SPDX-License-Identifier: MIT

//! HTTP/3 wire constants (RFC 9114) and QPACK error codes (RFC 9204).

/// Frame types.
pub mod frame_type {
    pub const DATA: u64 = 0x0;
    pub const HEADERS: u64 = 0x1;
    pub const CANCEL_PUSH: u64 = 0x3;
    pub const SETTINGS: u64 = 0x4;
    pub const PUSH_PROMISE: u64 = 0x5;
    pub const GOAWAY: u64 = 0x7;
    pub const MAX_PUSH_ID: u64 = 0xd;
    pub const DUPLICATE_PUSH: u64 = 0xe;
}

/// Unidirectional stream types.
pub mod stream_type {
    pub const CONTROL: u64 = 0x0;
    pub const PUSH: u64 = 0x1;
    pub const QPACK_ENCODER: u64 = 0x2;
    pub const QPACK_DECODER: u64 = 0x3;
}

/// SETTINGS identifiers.
pub mod setting_id {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x6;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x7;
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
    pub const H3_DATAGRAM: u64 = 0x33;
}

/// HTTP/3 and QPACK application error codes.
pub mod error_code {
    pub const H3_NO_ERROR: u64 = 0x0100;
    pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
    pub const H3_INTERNAL_ERROR: u64 = 0x0102;
    pub const H3_STREAM_CREATION_ERROR: u64 = 0x0103;
    pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;
    pub const H3_FRAME_UNEXPECTED: u64 = 0x0105;
    pub const H3_FRAME_ERROR: u64 = 0x0106;
    pub const H3_EXCESSIVE_LOAD: u64 = 0x0107;
    pub const H3_ID_ERROR: u64 = 0x0108;
    pub const H3_SETTINGS_ERROR: u64 = 0x0109;
    pub const H3_MESSAGE_ERROR: u64 = 0x010e;
    pub const H3_MISSING_SETTINGS: u64 = 0x010a;
    pub const H3_REQUEST_REJECTED: u64 = 0x010b;
    pub const H3_REQUEST_CANCELLED: u64 = 0x010c;
    pub const H3_REQUEST_INCOMPLETE: u64 = 0x010d;
    pub const H3_CONNECT_ERROR: u64 = 0x010f;
    pub const H3_VERSION_FALLBACK: u64 = 0x0110;
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
    pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x0201;
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
