//! Request-target grammar (RFC 9112 §3.2), as bytes.
//!
//! A server reads a request line from a peer it did not choose, and the target is the
//! one field on that line whose *shape* the peer fully controls. Every proxy between
//! the peer and us has opinions about that shape, so a target that two of them classify
//! differently is a request-smuggling surface (absolute-form `http://host/admin` read as
//! origin-form `/admin` by one hop and as an authority by the next).
//!
//! This module therefore does one thing: classify a target into the four forms RFC 9112
//! §3.2 defines, and refuse the bytes that are not in any of them. It does *not* parse a
//! URI into components — routing is the handler's business — and it does not
//! percent-decode, because decoding is a decision about a path and a codec holds no
//! routing policy.
//!
//! # What is refused, and why each one is a refusal rather than a normalisation
//!
//! - **Whitespace and control bytes.** `GET /a b HTTP/1.1` is not a target with a space
//!   in it; it is a line that three parsers will split three ways.
//! - **`#`.** A fragment is never sent on the wire (RFC 3986 §3.5). Accepting one means
//!   accepting a target that no origin can interpret, and it is the classic primitive for
//!   making a cache key differ from the path an origin resolves.
//! - **A target that is not one of the four forms.** "Close enough" is how a cache
//!   poisoning bug starts.

/// The form of a request target, per RFC 9112 §3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetForm {
    /// `absolute-path [ "?" query ]` — the only form an origin server serves.
    Origin,
    /// `absolute-URI` — what a client sends through a forward proxy.
    Absolute,
    /// `uri-host ":" port` — `CONNECT` only.
    Authority,
    /// `*` — `OPTIONS` only.
    Asterisk,
}

impl TargetForm {
    /// Whether a server may route on this form.
    ///
    /// An authority-form target has no path, and an absolute-form target's path has to be
    /// extracted from a URI before it can be routed; both are legitimate on the wire and
    /// neither is an origin-form path.
    pub const fn is_origin(self) -> bool {
        matches!(self, Self::Origin)
    }

    /// One short name for a trace or a log line.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::Absolute => "absolute",
            Self::Authority => "authority",
            Self::Asterisk => "asterisk",
        }
    }
}

/// Why a target is not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    /// The target is empty, which no form permits.
    Empty,
    /// A byte that may not appear in any request target (space, CTL, `#`).
    IllegalByte(u8),
    /// `*` for a method other than `OPTIONS`.
    AsteriskForOtherMethod,
    /// authority-form for a method other than `CONNECT`.
    AuthorityForOtherMethod,
    /// A form that claims to be something it is not: `/..` without a path, an
    /// `http://` with no authority, a port that is not a number.
    Malformed(&'static str),
}

impl TargetError {
    /// Stable class name for the trace's `Error` event.
    pub const fn class(self) -> &'static str {
        "protocol"
    }

    /// One line an operator can act on.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Empty => "empty request target",
            Self::IllegalByte(_) => "illegal byte in request target",
            Self::AsteriskForOtherMethod => "asterisk-form target is OPTIONS-only",
            Self::AuthorityForOtherMethod => "authority-form target is CONNECT-only",
            Self::Malformed(what) => what,
        }
    }
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason())
    }
}

impl std::error::Error for TargetError {}

/// Classify `target` for a request whose method is `method`.
///
/// # Errors
///
/// Any [`TargetError`]: an illegal byte, an empty target, a form the method may not use,
/// or a form whose own grammar is broken.
pub fn classify(method: &http::Method, target: &[u8]) -> Result<TargetForm, TargetError> {
    if target.is_empty() {
        return Err(TargetError::Empty);
    }
    if let Some(&byte) = target
        .iter()
        .find(|byte| **byte <= 0x20 || **byte == 0x7F || **byte == b'#')
    {
        return Err(TargetError::IllegalByte(byte));
    }
    if target == b"*" {
        return if method == http::Method::OPTIONS {
            Ok(TargetForm::Asterisk)
        } else {
            Err(TargetError::AsteriskForOtherMethod)
        };
    }
    // A bare `authority:port` never begins with `/` and carries no scheme separator, which
    // is what separates it from the other two forms.
    if target[0] == b'/' {
        return Ok(TargetForm::Origin);
    }
    if let Some(rest) = strip_scheme(target) {
        return validate_absolute(rest);
    }
    if method == http::Method::CONNECT {
        return validate_authority(target);
    }
    match std::str::from_utf8(target) {
        Ok(_) => Err(TargetError::Malformed(
            "target is neither origin-form nor an absolute URI",
        )),
        Err(_) => Err(TargetError::Malformed("target is not UTF-8")),
    }
}

/// The bytes after `scheme://`, when the target begins with one.
///
/// Only `http` and `https` are recognised: RFC 9112 §3.2.2 requires an absolute-form
/// target to be an absolute URI, and a server that also accepts `ftp://` is a server that
/// will forward a request to a scheme it cannot speak.
fn strip_scheme(target: &[u8]) -> Option<&[u8]> {
    for scheme in [b"http://".as_slice(), b"https://".as_slice()] {
        if target.len() >= scheme.len() && target[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return Some(&target[scheme.len()..]);
        }
    }
    None
}

/// `authority [ path-abempty ] [ "?" query ]` — the remainder of an absolute-form target.
fn validate_absolute(rest: &[u8]) -> Result<TargetForm, TargetError> {
    let authority_end = rest
        .iter()
        .position(|byte| *byte == b'/' || *byte == b'?')
        .unwrap_or(rest.len());
    validate_authority(&rest[..authority_end])?;
    Ok(TargetForm::Absolute)
}

/// Validate a `Host` header field's value: `uri-host [ ":" port ]` (RFC 9110 §7.2).
///
/// The same grammar as an authority-form target, because RFC 9112 §3.2 compares them: a request whose
/// `Host` and whose absolute-form authority disagree is how two hops route one request to two origins.
///
/// # Errors
///
/// [`TargetError::Malformed`] for an empty host, userinfo, a bad IPv6 literal, or a port out of range.
pub fn validate_host_field(value: &[u8]) -> Result<(), TargetError> {
    validate_authority(value).map(|_| ())
}

/// `uri-host [ ":" port ]`, with no userinfo and no path (RFC 9112 §3.2.3).
fn validate_authority(authority: &[u8]) -> Result<TargetForm, TargetError> {
    if authority.is_empty() {
        return Err(TargetError::Malformed("authority-form target is empty"));
    }
    if authority.contains(&b'@') {
        return Err(TargetError::Malformed(
            "userinfo is not allowed in an authority-form target",
        ));
    }
    let (host, port) = match authority.iter().rposition(|byte| *byte == b':') {
        // A bracketed IPv6 literal carries its own colons; the port separator is the one
        // after the closing bracket, so only a colon *outside* brackets splits.
        Some(index) if !inside_brackets(authority, index) => {
            (&authority[..index], Some(&authority[index + 1..]))
        }
        _ => (authority, None),
    };
    validate_host_bytes(host)?;
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.iter().all(u8::is_ascii_digit) {
            return Err(TargetError::Malformed(
                "authority-form port is not a number",
            ));
        }
        let port: u32 = std::str::from_utf8(port)
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or(TargetError::Malformed(
                "authority-form port is not a number",
            ))?;
        if port == 0 || port > 65_535 {
            return Err(TargetError::Malformed(
                "authority-form port is out of range",
            ));
        }
    }
    Ok(TargetForm::Authority)
}

fn inside_brackets(bytes: &[u8], index: usize) -> bool {
    bytes[..index].iter().filter(|byte| **byte == b'[').count()
        > bytes[..index].iter().filter(|byte| **byte == b']').count()
}

/// Whether `host` is a `uri-host`: a bracketed IPv6 literal, or a registered / IPv4 name.
///
/// This is the same check a `Host` header gets, because RFC 9112 §3.2 compares them: a
/// request whose `Host` and whose absolute-form authority disagree is the shape that makes
/// two hops route to different origins.
///
/// # Errors
///
/// [`TargetError::Malformed`] for an empty host, a stray bracket, a bad IPv6 literal, or a
/// byte that is not allowed in a registered name.
pub fn validate_host_bytes(host: &[u8]) -> Result<(), TargetError> {
    if host.is_empty() {
        return Err(TargetError::Malformed("host is empty"));
    }
    if host[0] == b'[' {
        if host.last() != Some(&b']') || host.len() < 3 {
            return Err(TargetError::Malformed("unterminated IPv6 literal"));
        }
        let literal = &host[1..host.len() - 1];
        return std::str::from_utf8(literal)
            .ok()
            .and_then(|text| text.parse::<std::net::Ipv6Addr>().ok())
            .map(|_| ())
            .ok_or(TargetError::Malformed("invalid IPv6 literal"));
    }
    // RFC 3986 §3.2.2: reg-name = *( unreserved / pct-encoded / sub-delims ).
    let mut index = 0;
    while index < host.len() {
        let byte = host[index];
        if byte == b'%' {
            let escaped = host
                .get(index + 1..index + 3)
                .ok_or(TargetError::Malformed("truncated percent-encoding in host"))?;
            if !escaped.iter().all(u8::is_ascii_hexdigit) {
                return Err(TargetError::Malformed("invalid percent-encoding in host"));
            }
            index += 3;
            continue;
        }
        let allowed = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
            );
        if !allowed {
            return Err(TargetError::Malformed("illegal byte in host"));
        }
        index += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn an_absolute_path_is_origin_form() {
        assert_eq!(
            classify(&Method::GET, b"/v1/models").expect("origin"),
            TargetForm::Origin
        );
        assert_eq!(
            classify(&Method::GET, b"/search?q=hello%20world&n=1").expect("origin"),
            TargetForm::Origin
        );
        assert_eq!(
            classify(&Method::GET, b"/").expect("origin"),
            TargetForm::Origin
        );
    }

    #[test]
    fn a_space_in_the_target_is_refused_not_trimmed() {
        // `GET /a b HTTP/1.1` splits into two different requests depending on which parser
        // reads it. Refusing the byte is the only answer that cannot be reinterpreted.
        assert_eq!(
            classify(&Method::GET, b"/a b").expect_err("must refuse"),
            TargetError::IllegalByte(b' ')
        );
    }

    #[test]
    fn a_fragment_is_refused() {
        assert_eq!(
            classify(&Method::GET, b"/page#section").expect_err("must refuse"),
            TargetError::IllegalByte(b'#')
        );
    }

    #[test]
    fn a_control_byte_is_refused() {
        assert_eq!(
            classify(&Method::GET, b"/a\x00b").expect_err("must refuse"),
            TargetError::IllegalByte(0)
        );
        assert_eq!(
            classify(&Method::GET, b"/a\x7fb").expect_err("must refuse"),
            TargetError::IllegalByte(0x7F)
        );
    }

    #[test]
    fn asterisk_is_options_only() {
        assert_eq!(
            classify(&Method::OPTIONS, b"*").expect("asterisk"),
            TargetForm::Asterisk
        );
        assert_eq!(
            classify(&Method::GET, b"*").expect_err("must refuse"),
            TargetError::AsteriskForOtherMethod
        );
    }

    #[test]
    fn authority_form_is_connect_only() {
        assert_eq!(
            classify(&Method::CONNECT, b"example.com:443").expect("authority"),
            TargetForm::Authority
        );
        assert_eq!(
            classify(&Method::GET, b"example.com:443").expect_err("must refuse"),
            TargetError::Malformed("target is neither origin-form nor an absolute URI")
        );
    }

    #[test]
    fn an_absolute_uri_is_recognised_and_its_authority_validated() {
        assert_eq!(
            classify(&Method::GET, b"http://example.com/v1/x").expect("absolute"),
            TargetForm::Absolute
        );
        assert_eq!(
            classify(&Method::GET, b"HTTPS://example.com:8443").expect("absolute"),
            TargetForm::Absolute,
            "the scheme is case-insensitive"
        );
        assert!(classify(&Method::GET, b"http:///nohost").is_err());
        assert!(classify(&Method::GET, b"ftp://example.com/x").is_err());
    }

    #[test]
    fn a_host_with_userinfo_is_refused() {
        assert!(
            classify(&Method::GET, b"http://user:pass@example.com/x").is_err(),
            "userinfo in a wire target is a routing-confusion primitive"
        );
    }

    #[test]
    fn a_bracketed_ipv6_authority_keeps_its_port() {
        assert_eq!(
            classify(&Method::CONNECT, b"[::1]:8443").expect("authority"),
            TargetForm::Authority
        );
        assert!(classify(&Method::CONNECT, b"[::1]").is_ok());
        assert!(classify(&Method::CONNECT, b"[zz]").is_err());
    }

    #[test]
    fn a_port_must_be_a_number_in_range() {
        assert!(classify(&Method::CONNECT, b"example.com:0").is_err());
        assert!(classify(&Method::CONNECT, b"example.com:65536").is_err());
        assert!(classify(&Method::CONNECT, b"example.com:https").is_err());
        assert!(classify(&Method::CONNECT, b"example.com:").is_err());
    }

    #[test]
    fn an_empty_target_is_refused() {
        assert_eq!(
            classify(&Method::GET, b"").expect_err("must refuse"),
            TargetError::Empty
        );
    }

    #[test]
    fn a_host_field_may_carry_a_port() {
        assert!(validate_host_field(b"example.com").is_ok());
        assert!(validate_host_field(b"example.com:8443").is_ok());
        assert!(validate_host_field(b"127.0.0.1:8080").is_ok());
        assert!(validate_host_field(b"[::1]:8080").is_ok());
        assert!(validate_host_field(b"example.com:").is_err());
        assert!(validate_host_field(b"user@example.com").is_err());
    }

    #[test]
    fn a_host_byte_outside_the_registered_name_set_is_refused() {
        assert!(validate_host_bytes(b"example.com").is_ok());
        assert!(validate_host_bytes(b"exa mple.com").is_err());
        assert!(validate_host_bytes(b"example.com\r").is_err());
        assert!(validate_host_bytes(b"").is_err());
        assert!(validate_host_bytes(b"%zz").is_err());
        assert!(validate_host_bytes(b"%41").is_ok());
    }
}
