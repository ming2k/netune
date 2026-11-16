//! Redirect resolution: where a `Location` points and what follows it there.
//!
//! A redirect changes the destination, never the identity the caller chose:
//! the TLS profile, the wire-shaping policy and the protocol mandate travel to
//! the new authority, and only the authority and the verified server name are
//! taken from the `Location`.

use http::StatusCode;
use netune_http1::IncomingResponse;

use crate::connect::{HttpProtocol, Target};
use crate::error::NetError;

/// The `Location` of a redirecting response, if any.
pub(crate) fn redirect_location(head: &IncomingResponse) -> Option<String> {
    match head.status.as_u16() {
        301 | 302 | 303 | 307 | 308 => head
            .headers
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        _ => None,
    }
}

/// Whether this status turns a non-`HEAD` request into a `GET` with no body.
pub(crate) fn redirect_to_get(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301..=303)
}

/// Resolve a `Location` against the request that produced it.
pub(crate) fn resolve_location(
    current: &Target,
    current_path: &str,
    location: &str,
) -> Result<(Target, String), NetError> {
    if let Some(rest) = location.strip_prefix("https://") {
        let (authority, path) = split_authority(rest, 443);
        let name = crate::connect::authority_host(&authority).to_string();
        let mut target = Target::tls(authority, name);
        // A redirect changes the destination, not the identity the caller
        // selected. Only the authority and the verified server name follow the
        // new location.
        target.identity.tls_profile = current.identity.tls_profile.clone();
        target.identity.tls_engine = current.identity.tls_engine.clone();
        target.identity.evasion = current.identity.evasion;
        target.identity.h2_profile = current.identity.h2_profile.clone();
        target.identity.h3_profile = current.identity.h3_profile.clone();
        target.identity.h3_settings_profile = current.identity.h3_settings_profile.clone();
        target.protocol = current.protocol;
        target.h1_profile = current.h1_profile.clone();
        target.h2_request_profile = current.h2_request_profile.clone();
        target.h3_request_profile = current.h3_request_profile.clone();
        return Ok((target, path));
    }
    if let Some(rest) = location.strip_prefix("http://") {
        if current.protocol == HttpProtocol::Http3 {
            return Err(NetError::Connect(crate::error::ConnectError::config(
                netune_trace::DiagnosticPhase::Dispatch,
                "cannot follow a redirect to plaintext http:// while HTTP/3 is required",
            )));
        }
        let (authority, path) = split_authority(rest, 80);
        let mut target = Target::plain(authority);
        target.identity.evasion = current.identity.evasion;
        target.identity.h2_profile = current.identity.h2_profile.clone();
        target.protocol = current.protocol;
        target.h1_profile = current.h1_profile.clone();
        target.h2_request_profile = current.h2_request_profile.clone();
        return Ok((target, path));
    }
    if let Some(rest) = location.strip_prefix("//") {
        let (authority, path) = split_authority(rest, default_port(current));
        let mut target = current.clone();
        target.authority = authority;
        if target.identity.tls_server_name.is_some() {
            target.identity.tls_server_name =
                Some(crate::connect::authority_host(&target.authority).to_string());
        }
        return Ok((target, path));
    }
    if location.starts_with('/') {
        return Ok((current.clone(), location.to_string()));
    }
    // Relative reference: replace the last path segment.
    let base = current_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    Ok((current.clone(), format!("{base}/{location}")))
}

fn default_port(target: &Target) -> u16 {
    if target.tls_server_name().is_some() {
        443
    } else {
        80
    }
}

/// Split `host[:port][/path]` into `(host:port, path)`.
fn split_authority(rest: &str, default_port: u16) -> (String, String) {
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let authority = crate::connect::normalize_authority(authority, default_port);
    (authority, path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netune_trace::EvasionPolicy;

    #[test]
    fn inv_custom_05_absolute_redirect_preserves_the_identity() {
        let original = Target::tls("a.example:443", "a.example")
            .with_tls_profile("chrome-current")
            .with_evasion(EvasionPolicy::sni_split())
            .with_protocol(HttpProtocol::Http2);

        let (next, path) = resolve_location(&original, "/start", "https://b.example/next")
            .expect("resolve absolute redirect");

        assert_eq!(path, "/next");
        assert_eq!(next.authority, "b.example:443");
        assert_eq!(next.identity.tls_profile.as_deref(), Some("chrome-current"));
        assert_eq!(next.identity.tls_server_name.as_deref(), Some("b.example"));
        assert_eq!(next.identity.evasion, EvasionPolicy::sni_split());
        assert_eq!(next.protocol, HttpProtocol::Http2);
    }

    #[test]
    fn an_absolute_downgrade_drops_tls_but_keeps_evasion() {
        let original =
            Target::tls("a.example:443", "a.example").with_evasion(EvasionPolicy::sni_split());

        let (next, path) = resolve_location(&original, "/start", "http://b.example/next")
            .expect("resolve absolute downgrade");

        assert_eq!(path, "/next");
        assert!(next.tls_server_name().is_none());
        assert_eq!(next.identity.evasion, EvasionPolicy::sni_split());
    }

    #[test]
    fn redirect_location_unbrackets_ipv6_tls_server_name() {
        let original = Target::tls("a.example:443", "a.example");
        let (next, path) = resolve_location(&original, "/start", "https://[::1]:8443/next")
            .expect("resolve ipv6 absolute redirect");
        assert_eq!(path, "/next");
        assert_eq!(next.authority, "[::1]:8443");
        assert_eq!(next.tls_server_name(), Some("::1"));

        let (rel, path) = resolve_location(&next, "/next", "//[2001:db8::9]/v2")
            .expect("resolve ipv6 protocol-relative redirect");
        assert_eq!(path, "/v2");
        assert_eq!(rel.authority, "[2001:db8::9]:443");
        assert_eq!(rel.tls_server_name(), Some("2001:db8::9"));
    }
}
