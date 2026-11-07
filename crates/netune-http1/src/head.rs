//! Message heads, named by direction of construction.
//!
//! Four types, and the naming rule is the whole point:
//!
//! | Type | Role | Built or parsed |
//! | :--- | :--- | :--- |
//! | [`RequestHead`] | client | built — the client decides what it sends |
//! | [`IncomingResponse`] | client | parsed — the origin decides |
//! | [`IncomingRequest`] | server | parsed — the peer decides |
//! | [`ResponseHead`] | server | built — the server decides |
//!
//! A `*Head` is a head this side of the wire authors, so it carries what an
//! author controls: raw wire headers with caller casing, a chosen reason phrase,
//! a declared body framing. An `Incoming*` is a head this side of the wire
//! *receives*, so it carries what a peer controls: the version it actually spoke,
//! the exact target bytes, and no ability to influence its own header casing.
//!
//! Keeping that split in the type names rather than in documentation is what
//! stops a server from serializing a parsed head (and emitting a peer's header
//! order back at it) or a client from trusting a field only an author may set.

use http::{HeaderMap, Method, StatusCode, Version};

/// A request head the client role builds.
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
    /// Explicit raw wire headers preserving caller-defined casing and order.
    /// When `Some`, [`crate::write_request`] serializes these exact bytes
    /// instead of lowercasing through [`http::HeaderMap`].
    pub raw_headers: Option<Vec<(String, String)>>,
}

impl RequestHead {
    pub fn new(method: Method, target: impl Into<String>) -> Self {
        Self {
            method,
            target: target.into(),
            headers: HeaderMap::new(),
            raw_headers: None,
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

    /// Append a raw header preserving caller's exact name casing and duplicates.
    ///
    /// This directly addresses HTTP-layer fingerprinting (JA4H) and WAF/DPI evasion:
    /// wire casing (e.g. `User-Agent`, `Host`, `Sec-CH-UA`) and multi-value
    /// repetition (e.g. repeated `Cookie` or `Set-Cookie`) are emitted byte-for-byte.
    pub fn with_raw_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name_str = name.into();
        let value_str = value.into();
        if let (Ok(hname), Ok(hval)) = (
            http::header::HeaderName::try_from(name_str.as_str()),
            http::header::HeaderValue::try_from(value_str.as_str()),
        ) {
            self.headers.append(hname, hval);
        }
        let raw = self.raw_headers.get_or_insert_with(Vec::new);
        raw.push((name_str, value_str));
        self
    }
}

/// How a message body is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// No body at all: `HEAD`, `1xx`, `204`, `304`, or a request with no framing
    /// headers.
    Empty,
    /// Exactly this many bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Delimited by connection close.
    ///
    /// Response direction only: RFC 9112 §6.3 permits it for a response and not
    /// for a request, so [`crate::Http1ServerReader`] never produces it and it is
    /// never a valid thing for a server to declare.
    UntilClose,
}

/// The reason phrase a status line carries after the status code.
///
/// Separated from [`http::StatusCode`] because the phrase is not data the status
/// implies — it is free text a server may set, replace, or omit entirely, and a
/// caller that fingerprints HTTP responses needs to control it byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReasonPhrase {
    /// Use the canonical phrase for the status code (`404` → `Not Found`), or
    /// nothing when the status has no canonical phrase.
    #[default]
    Canonical,
    /// Send this exact phrase.
    Exact(String),
    /// Send no phrase at all (`HTTP/1.1 200 \r\n`).
    ///
    /// RFC 9112 §4 permits an empty reason phrase; it is obsolete in HTTP/2 and
    /// carries no semantics in HTTP/1.1.
    Empty,
}

impl ReasonPhrase {
    /// The bytes to write after `HTTP/1.1 NNN `.
    pub(crate) fn bytes_for(&self, status: StatusCode) -> &[u8] {
        match self {
            Self::Exact(phrase) => phrase.as_bytes(),
            Self::Empty => b"",
            Self::Canonical => status.canonical_reason().unwrap_or("").as_bytes(),
        }
    }
}

/// A response head the server role builds.
#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub status: StatusCode,
    pub headers: HeaderMap,
    /// The phrase written after the status code.
    pub reason: ReasonPhrase,
    /// The framing the writer will produce. Set by the caller, never inferred
    /// from headers: a head that claims a framing it does not have is the shape
    /// that desynchronises a peer.
    pub body: BodyKind,
}

impl ResponseHead {
    /// A head with no headers, the canonical reason phrase and no body.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            reason: ReasonPhrase::default(),
            body: BodyKind::Empty,
        }
    }

    /// `true` when the status carries no body by definition.
    pub fn status_forbids_body(status: StatusCode) -> bool {
        status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
    }

    /// Insert one header, replacing any existing value of the same name.
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::try_from(name.as_ref()),
            http::header::HeaderValue::try_from(value.as_ref()),
        ) {
            self.headers.insert(name, value);
        }
        self
    }

    /// Declare a `Content-Length` body of `body.len()` bytes and serialize it with
    /// [`crate::ResponseWriter`].
    ///
    /// Clears any `Transfer-Encoding`: a message declaring both framings is refused by
    /// the writer, so re-declaring a head must not leave the previous declaration behind.
    #[must_use]
    pub fn with_body(mut self, body: &[u8]) -> Self {
        self.body = BodyKind::Length(body.len() as u64);
        self.headers.remove(http::header::TRANSFER_ENCODING);
        if let Ok(value) = http::HeaderValue::from_str(&body.len().to_string()) {
            self.headers.insert(http::header::CONTENT_LENGTH, value);
        }
        self
    }

    /// Declare a chunked body.
    ///
    /// Clears any `Content-Length`, for the same reason: a caller converting a
    /// length-delimited response into a streamed one must not have to remember to remove
    /// the old declaration, and leaving it in produces a response the peer cannot frame.
    #[must_use]
    pub fn with_chunked_body(mut self) -> Self {
        self.body = BodyKind::Chunked;
        self.headers.remove(http::header::CONTENT_LENGTH);
        self.headers.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        self
    }

    /// Whether the head declares a framing a writer can honour.
    ///
    /// The question the writer asks before it writes a body byte: *does this head
    /// say how the body ends?* A body-less head is framed by its absence and by
    /// the status, so it qualifies; a head with no length, no chunked coding and a
    /// body that claims to exist does not.
    pub fn declares_body_framing(&self) -> bool {
        match self.body {
            BodyKind::Length(_) | BodyKind::Chunked => true,
            BodyKind::Empty => ResponseHead::status_forbids_body(self.status),
            // A server may not leave a body delimited by close: only the
            // orchestrator knows whether it is closing, and a response that
            // relies on that is a response a keep-alive peer will misread.
            BodyKind::UntilClose => false,
        }
    }
}

/// A response head the client role received.
#[derive(Debug, Clone)]
pub struct IncomingResponse {
    pub version: Version,
    pub status: StatusCode,
    pub headers: HeaderMap,
    /// How the body is framed, decided by the response's own headers.
    pub body: BodyKind,
}

/// A request head the server role received.
#[derive(Debug, Clone)]
pub struct IncomingRequest {
    pub method: Method,
    /// The request-target, unmodified, as bytes. Origin-form (`/path?query`),
    /// absolute-form and authority-form (for `CONNECT`) all arrive here exactly
    /// as written; interpreting them is the handler's business, because rejecting
    /// a request for a target shape the codec dislikes would be the codec making
    /// a routing decision.
    pub target: bytes::Bytes,
    /// Which of the four RFC 9112 §3.2 forms the target is in.
    ///
    /// Recorded by the codec because the codec is what classified it: a handler that had
    /// to re-classify would be re-implementing the grammar, and an orchestrator that
    /// guessed would accept an absolute-form target as an origin path.
    pub form: crate::target::TargetForm,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: BodyKind,
}

impl IncomingRequest {
    /// The target decoded as text, when it is valid UTF-8.
    ///
    /// `None` rather than a lossy conversion: a request target that is not UTF-8
    /// is not something routing can safely invent characters for.
    pub fn target_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.target).ok()
    }

    /// The value of `Host`, decoded, when present and valid.
    pub fn host(&self) -> Option<&str> {
        self.headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
    }

    /// Whether this request asks to switch protocols (RFC 6455 upgrade, `h2c`,
    /// …).
    ///
    /// The codec answers the question; it does not act on it. Upgrading is an
    /// orchestrator decision, because an upgraded socket stops being HTTP/1.1.
    pub fn is_upgrade(&self) -> bool {
        self.headers
            .get_all(http::header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            && self.headers.contains_key(http::header::UPGRADE)
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

    #[test]
    fn reason_phrases_resolve_against_the_status() {
        assert_eq!(
            ReasonPhrase::Canonical.bytes_for(StatusCode::NOT_FOUND),
            b"Not Found"
        );
        assert_eq!(ReasonPhrase::Empty.bytes_for(StatusCode::OK), b"");
        assert_eq!(
            ReasonPhrase::Exact("Fine".into()).bytes_for(StatusCode::OK),
            b"Fine"
        );
        // A status with no canonical phrase must not fabricate one.
        let unusual = StatusCode::from_u16(599).expect("valid status");
        assert_eq!(ReasonPhrase::Canonical.bytes_for(unusual), b"");
    }

    #[test]
    fn with_body_declares_the_framing_it_will_produce() {
        let head = ResponseHead::new(StatusCode::OK).with_body(b"hello");
        assert_eq!(head.body, BodyKind::Length(5));
        assert_eq!(head.headers.get(http::header::CONTENT_LENGTH).unwrap(), "5");
        assert!(head.declares_body_framing());
    }

    #[test]
    fn with_chunked_body_declares_chunked() {
        let head = ResponseHead::new(StatusCode::OK).with_chunked_body();
        assert_eq!(head.body, BodyKind::Chunked);
        assert_eq!(
            head.headers.get(http::header::TRANSFER_ENCODING).unwrap(),
            "chunked"
        );
    }

    #[test]
    fn switching_a_body_to_chunked_clears_the_length_it_had() {
        // The regression: `Response::ok(bytes)` then `.with_chunked_body()` used to leave
        // `content-length` in place, so the writer refused the head and the peer got
        // nothing at all. Redeclaring a framing must replace it.
        let head = ResponseHead::new(StatusCode::OK)
            .with_body(b"hello")
            .with_chunked_body();
        assert_eq!(head.body, BodyKind::Chunked);
        assert!(
            !head.headers.contains_key(http::header::CONTENT_LENGTH),
            "the stale length must be gone"
        );
        assert_eq!(
            head.headers.get(http::header::TRANSFER_ENCODING).unwrap(),
            "chunked"
        );
    }

    #[test]
    fn switching_a_body_back_to_a_length_clears_chunked() {
        let head = ResponseHead::new(StatusCode::OK)
            .with_chunked_body()
            .with_body(b"hello");
        assert_eq!(head.body, BodyKind::Length(5));
        assert!(
            !head.headers.contains_key(http::header::TRANSFER_ENCODING),
            "the stale chunked coding must be gone"
        );
        assert_eq!(head.headers.get(http::header::CONTENT_LENGTH).unwrap(), "5");
    }

    #[test]
    fn a_close_delimited_response_is_not_a_framing_the_writer_honours() {
        let mut head = ResponseHead::new(StatusCode::OK);
        head.body = BodyKind::UntilClose;
        assert!(!head.declares_body_framing());
    }

    #[test]
    fn an_upgrade_request_is_recognized() {
        let mut request = IncomingRequest {
            method: Method::GET,
            target: bytes::Bytes::from_static(b"/chat"),
            form: crate::target::TargetForm::Origin,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: BodyKind::Empty,
        };
        assert!(!request.is_upgrade(), "needs both headers");
        request.headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("Upgrade"),
        );
        assert!(!request.is_upgrade(), "upgrade header still missing");
        request.headers.insert(
            http::header::UPGRADE,
            http::HeaderValue::from_static("websocket"),
        );
        assert!(request.is_upgrade());
        assert_eq!(request.target_str(), Some("/chat"));
    }
}
