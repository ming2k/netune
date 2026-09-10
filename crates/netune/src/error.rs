//! Typed transport failures with an explicit retry verdict.

use netune_http1::HttpError;

/// Why a request could not be completed at the transport layer.
#[derive(Debug)]
pub enum NetError {
    /// The authority could not be resolved.
    Resolve(String),
    /// TCP (or TLS) could not be established.
    Connect(String),
    /// The peer spoke broken HTTP, exceeded a limit, or the stream ended early.
    Http(HttpError),
    /// The transport failed.
    Io(std::io::Error),
    /// The response used a `Content-Encoding` this client cannot decode.
    UnsupportedEncoding(String),
    /// A `Content-Encoding` stream was corrupt or truncated.
    Decode(String),
    /// The redirect chain exceeded the configured limit.
    TooManyRedirects(u8),
    /// Blocked by egress security policy (non-public / SSRF address).
    Security(String),
}

impl NetError {
    /// Stable classification for retry policy and telemetry.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Resolve(_) => "resolve",
            Self::Connect(_) => "connect",
            Self::Http(error) => error.class(),
            Self::Io(_) => "io",
            Self::UnsupportedEncoding(_) => "encoding",
            Self::Decode(_) => "decode",
            Self::TooManyRedirects(_) => "redirect",
            Self::Security(_) => "security",
        }
    }

    /// Whether another attempt could plausibly succeed.
    ///
    /// A broken HTTP peer will speak the same broken HTTP again, a corrupt body
    /// will decode to garbage again, and an unsupported encoding will stay
    /// unsupported: only resolution, connect and transport failures are worth
    /// retrying. This mirrors the retry discipline the previous client derived
    /// from `reqwest`'s error kinds.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Resolve(_) | Self::Connect(_) | Self::Io(_) => true,
            Self::Http(error) => error.is_retryable(),
            Self::UnsupportedEncoding(_)
            | Self::Decode(_)
            | Self::TooManyRedirects(_)
            | Self::Security(_) => false,
        }
    }
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(what) => write!(f, "resolve failed: {what}"),
            Self::Connect(what) => write!(f, "connect failed: {what}"),
            Self::Http(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "transport error: {error}"),
            Self::UnsupportedEncoding(encoding) => {
                write!(f, "unsupported content-encoding: {encoding}")
            }
            Self::Decode(what) => write!(f, "could not decode response body: {what}"),
            Self::TooManyRedirects(limit) => write!(f, "more than {limit} redirects"),
            Self::Security(what) => write!(f, "security policy: {what}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<HttpError> for NetError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

impl From<std::io::Error> for NetError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
