//! HTTP/2 error types (RFC 9113).

use std::fmt;
use std::io;

/// An HTTP/2 protocol or transport error.
#[derive(Debug)]
pub enum H2Error {
    /// An I/O error occurred on the transport.
    Io(io::Error),
    /// A connection-level protocol violation.
    Protocol(String),
    /// Frame payload length exceeded negotiated maximum frame size.
    FrameSize(String),
    /// An HPACK decompression or compression failure.
    Hpack(String),
    /// The peer sent a GOAWAY frame closing the connection.
    GoAway {
        error_code: u32,
        debug_data: Vec<u8>,
    },
    /// A stream-level reset occurred.
    StreamReset { stream_id: u32, error_code: u32 },
    /// Unexpected EOF before receiving a complete frame or message.
    UnexpectedEof,
}

impl fmt::Display for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "HTTP/2 I/O error: {err}"),
            Self::Protocol(msg) => write!(f, "HTTP/2 protocol error: {msg}"),
            Self::FrameSize(msg) => write!(f, "HTTP/2 frame size error: {msg}"),
            Self::Hpack(msg) => write!(f, "HTTP/2 HPACK error: {msg}"),
            Self::GoAway { error_code, .. } => write!(
                f,
                "HTTP/2 peer closed with GOAWAY (error code {error_code})"
            ),
            Self::StreamReset {
                stream_id,
                error_code,
            } => write!(
                f,
                "HTTP/2 stream {stream_id} reset with error code {error_code}"
            ),
            Self::UnexpectedEof => write!(f, "HTTP/2 unexpected EOF on stream"),
        }
    }
}

impl std::error::Error for H2Error {}

impl From<io::Error> for H2Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
