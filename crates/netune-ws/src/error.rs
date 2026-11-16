use std::fmt;

use crate::frame::CloseCode;

/// WebSocket protocol and codec errors.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum WsError {
    /// A violation of RFC 6455 framing, opcode, masking, or control frame invariants.
    Protocol {
        /// Diagnostic message describing the violation.
        message: String,
        /// Close code corresponding to the protocol error.
        code: CloseCode,
    },
    /// A frame or reassembled message exceeded the configured byte ceiling.
    PayloadTooLarge {
        /// Observed byte length.
        length: usize,
        /// Configured ceiling in bytes.
        max: usize,
    },
    /// Text frame or close reason is not valid UTF-8.
    InvalidUtf8,
    /// Handshake negotiation failed (non-101 status, invalid headers, or key mismatch).
    HandshakeFailed(String),
    /// Connection stream terminated prematurely.
    UnexpectedEof,
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol { message, code } => {
                write!(f, "WebSocket protocol error ({:?}): {message}", code.0)
            }
            Self::PayloadTooLarge { length, max } => {
                write!(
                    f,
                    "WebSocket payload too large: {length} bytes (limit {max})"
                )
            }
            Self::InvalidUtf8 => write!(f, "WebSocket text payload contains invalid UTF-8"),
            Self::HandshakeFailed(reason) => write!(f, "WebSocket handshake failed: {reason}"),
            Self::UnexpectedEof => write!(f, "WebSocket connection closed unexpectedly"),
        }
    }
}

impl std::error::Error for WsError {}

impl WsError {
    /// Construct a [`WsError::Protocol`] with a message and close code.
    pub fn protocol(msg: impl Into<String>, code: CloseCode) -> Self {
        Self::Protocol {
            message: msg.into(),
            code,
        }
    }
}
