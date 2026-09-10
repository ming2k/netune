//! Request and response message heads.

use http::{HeaderMap, Method, StatusCode, Version};

/// A request head: method, origin-form target and headers.
///
/// The body is passed separately to [`crate::write_request`] so the caller
/// controls its length; a `Content-Length` header is written for a present body
/// and never for an absent one.
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: Method,
    /// Origin-form target (`/v1/chat/completions`); the authority lives in the
    /// connection, not the message.
    pub target: String,
    pub headers: HeaderMap,
}

impl RequestHead {
    pub fn new(method: Method, target: impl Into<String>) -> Self {
        Self {
            method,
            target: target.into(),
            headers: HeaderMap::new(),
        }
    }

    /// Insert a header. `expect`-free: an invalid name or value is a programming
    /// error in the caller's own literal, and is reported as `false` rather than
    /// panicking.
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::try_from(name.as_ref()),
            http::header::HeaderValue::try_from(value.as_ref()),
        ) {
            self.headers.insert(name, value);
        }
        self
    }
}

/// How the response body is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// No body at all: `HEAD`, `1xx`, `204`, `304`.
    Empty,
    /// Exactly this many bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Delimited by connection close (no length, no chunking).
    UntilClose,
}

/// A parsed response head.
#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub version: Version,
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: BodyKind,
}

impl ResponseHead {
    /// `true` when the status carries no body by definition.
    pub fn status_forbids_body(status: StatusCode) -> bool {
        status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_head_writes_headers_it_was_given() {
        let head = RequestHead::new(Method::POST, "/v1/chat/completions")
            .with_header("content-type", "application/json")
            .with_header("authorization", "Bearer secret");
        assert_eq!(head.target, "/v1/chat/completions");
        assert_eq!(
            head.headers
                .get("content-type")
                .map(|v| v.to_str().unwrap()),
            Some("application/json")
        );
    }

    #[test]
    fn no_body_statuses_are_recognized() {
        assert!(ResponseHead::status_forbids_body(StatusCode::NO_CONTENT));
        assert!(ResponseHead::status_forbids_body(StatusCode::NOT_MODIFIED));
        assert!(ResponseHead::status_forbids_body(StatusCode::CONTINUE));
        assert!(!ResponseHead::status_forbids_body(StatusCode::OK));
        assert!(!ResponseHead::status_forbids_body(StatusCode::BAD_REQUEST));
    }
}
