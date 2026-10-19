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
    /// The peer's stream ended before the message was complete.
    ///
    /// Distinct from [`HttpError::Protocol`] because the peer did not speak
    /// broken HTTP — it stopped speaking. That is a transient condition at the
    /// connection level (the socket died, an idle-culled keep-alive was reused,
    /// a gateway cut a long stream) rather than a judgement about the peer's
    /// syntax, and the two demand opposite retry verdicts. Folding them together
    /// made one physical event — a peer closing a socket — retryable or terminal
    /// depending on how politely it closed.
    Incomplete(&'static str),
    /// The transport failed.
    Io(std::io::Error),
}

impl HttpError {
    /// A stable, greppable classification for retry decisions.
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Protocol(_) => "protocol",
            Self::LimitExceeded(_) => "limit",
            Self::Incomplete(_) => "incomplete",
            Self::Io(_) => "io",
        }
    }

    /// Whether a retry could plausibly succeed.
    ///
    /// Transport failures and premature end-of-stream qualify: a fresh
    /// connection is a different connection, so the same request may well be
    /// answered. A peer speaking broken HTTP will speak it again, a limit will
    /// be exceeded again, and an unsupported encoding will stay unsupported.
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Incomplete(_))
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(what) => write!(f, "invalid HTTP response: {what}"),
            Self::LimitExceeded(what) => write!(f, "HTTP response exceeded {what}"),
            Self::Incomplete(what) => write!(
                f,
                "connection closed before the response was complete: {what}"
            ),
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
