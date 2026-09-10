//! Typed failures. The codec never panics on malformed input: every rejection is
//! one of these, so a hostile or broken peer cannot take the process down.

use std::fmt;

/// A protocol, limit or transport failure while reading a response.
#[derive(Debug)]
pub enum HttpError {
    /// The peer's bytes are not valid HTTP/1.x.
    Protocol(&'static str),
    /// A configured limit was exceeded. The peer is either broken or hostile.
    LimitExceeded(&'static str),
    /// The transport failed.
    Io(std::io::Error),
}

impl HttpError {
    /// A stable, greppable classification for retry decisions.
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Protocol(_) => "protocol",
            Self::LimitExceeded(_) => "limit",
            Self::Io(_) => "io",
        }
    }

    /// Whether a retry could plausibly succeed. Only transport failures are
    /// retryable; a peer speaking broken HTTP will speak it again.
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Io(_))
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(what) => write!(f, "invalid HTTP response: {what}"),
            Self::LimitExceeded(what) => write!(f, "HTTP response exceeded {what}"),
            Self::Io(error) => write!(f, "transport error: {error}"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for HttpError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
