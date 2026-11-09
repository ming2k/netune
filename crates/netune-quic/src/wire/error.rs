// SPDX-License-Identifier: MIT

//! Errors for the owned QUIC wire codec.

/// A malformed QUIC value or frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("unexpected end of QUIC input")]
    UnexpectedEnd,

    #[error("QUIC varint exceeds 2^62-1")]
    IntegerOverflow,

    #[error("invalid QUIC packet: {0}")]
    InvalidPacket(String),

    #[error("invalid QUIC frame: {0}")]
    InvalidFrame(String),

    #[error("unknown QUIC frame type 0x{0:x}")]
    UnknownFrame(u64),

    #[error("invalid transport parameter 0x{0:x}: {1}")]
    InvalidTransportParameter(u64, String),

    #[error("duplicate transport parameter 0x{0:x}")]
    DuplicateTransportParameter(u64),

    #[error("field {0} exceeds {1} bytes")]
    FieldTooLarge(&'static str, usize),
}
