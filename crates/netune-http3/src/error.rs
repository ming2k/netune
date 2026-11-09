// SPDX-License-Identifier: MIT

//! Error types for HTTP/3 client and server operations.

use crate::proto::frame::FrameError;
use crate::proto::headers::HeaderError;
use crate::qpack::QpackError;

/// Errors arising during HTTP/3 connection, framing, or request execution.
#[derive(Debug, thiserror::Error)]
pub enum H3Error {
    /// QUIC transport error.
    #[error("quic transport error: {0}")]
    Quic(#[from] netune_quic::QuicError),

    /// HTTP/3 handshake or framing error.
    #[error("http3 error: {0}")]
    H3(String),

    /// The peer or local endpoint closed the connection with an H3 error code.
    #[error("http3 connection closed with {code:#x}: {message}")]
    Connection { code: u64, message: String },

    /// HTTP request construction or validation failed.
    #[error("http error: {0}")]
    Http(#[from] http::Error),

    /// A field section was malformed or contained a forbidden field.
    #[error("http3 field error: {0}")]
    Header(#[from] HeaderError),

    /// A frame was malformed.
    #[error("http3 frame error: {0}")]
    Frame(#[from] FrameError),

    /// A capsule was malformed or oversized.
    #[error("capsule error: {0}")]
    Capsule(#[from] crate::proto::capsule::CapsuleError),

    /// QPACK encoding or decoding failed.
    #[error("qpack error: {0}")]
    Qpack(#[from] QpackError),

    /// A profile name was not registered.
    #[error("profile error: {0}")]
    Profile(String),

    /// One request phase exceeded its configured deadline.
    #[error("http3 {0} timed out")]
    Timeout(&'static str),

    /// A buffered response exceeded the configured body ceiling.
    #[error("http3 response body exceeded {limit} bytes")]
    BodyTooLarge { limit: usize },
}

impl H3Error {
    /// The application error code to send when this error closes a connection.
    pub fn connection_code(&self) -> u64 {
        match self {
            Self::Connection { code, .. } => *code,
            Self::Qpack(QpackError::MissingInsertions { .. })
            | Self::Qpack(QpackError::ReferenceOutsideSection { .. })
            | Self::Qpack(QpackError::InvalidDynamicIndex(_)) => {
                crate::proto::code::error_code::QPACK_DECOMPRESSION_FAILED
            }
            Self::Qpack(QpackError::EncoderStream) => {
                crate::proto::code::error_code::QPACK_ENCODER_STREAM_ERROR
            }
            Self::Qpack(QpackError::DecoderStream) => {
                crate::proto::code::error_code::QPACK_DECODER_STREAM_ERROR
            }
            Self::Header(_) | Self::Frame(_) | Self::Http(_) | Self::Capsule(_) => {
                crate::proto::code::error_code::H3_MESSAGE_ERROR
            }
            _ => crate::proto::code::error_code::H3_INTERNAL_ERROR,
        }
    }
}
