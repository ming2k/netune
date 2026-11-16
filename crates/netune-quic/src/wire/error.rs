// SPDX-License-Identifier: MIT

//! Errors for the owned QUIC wire codec.

/// A malformed QUIC value or frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Input buffer ended before a complete value could be read.
    #[error("unexpected end of QUIC input")]
    UnexpectedEnd,

    /// Variable-length integer exceeded the 62-bit QUIC maximum (`2^62 - 1`).
    #[error("QUIC varint exceeds 2^62-1")]
    IntegerOverflow,

    /// Packet header or payload violated QUIC packet syntax rules.
    #[error("invalid QUIC packet: {0}")]
    InvalidPacket(String),

    /// Frame payload violated QUIC frame syntax or constraints.
    #[error("invalid QUIC frame: {0}")]
    InvalidFrame(String),

    /// Frame type identifier is not recognized by this codec.
    #[error("unknown QUIC frame type 0x{0:x}")]
    UnknownFrame(u64),

    /// Transport parameter failed validation for its parameter ID.
    #[error("invalid transport parameter 0x{0:x}: {1}")]
    InvalidTransportParameter(u64, String),

    /// Transport parameter ID appeared more than once in the extension.
    #[error("duplicate transport parameter 0x{0:x}")]
    DuplicateTransportParameter(u64),

    /// Length-prefixed or bounded field exceeded the configured maximum size.
    #[error("field {0} exceeds {1} bytes")]
    FieldTooLarge(&'static str, usize),
}
