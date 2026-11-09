//! Wire-profile identities: the parts of a request that are chosen, not
//! discovered.
//!
//! A [`ConnectionIdentity`] is fixed at connection establishment. An
//! [`H1WireProfile`] is per request: HTTP/1 header order and casing do not make
//! two sockets interchangeable, so they must not key the pool. An HTTP/2
//! fingerprint is split the same way: SETTINGS and the connection window are
//! connection identity; pseudo-header order is a request profile.
//!
//! The registries are cold-path values. Unknown profile names fail in
//! [`crate::Client::plan`] before a socket is opened.

use std::collections::HashMap;
use std::fmt;

use netune_http1::RequestHead;
use netune_trace::ConnectionIdentity;

use crate::connect::Target;
use crate::error::NetError;
use crate::pool::PoolKey;

/// A stable name for a wire profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProfileId(String);

impl ProfileId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<&str> for ProfileId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// How an HTTP/1 profile spells header names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCasing {
    Lowercase,
    TitleCase,
}

/// A declarative HTTP/1 wire identity.
///
/// `order` is a list of lower-case header names. Headers not named in it keep
/// their relative order after the named ones. The profile is applied only when
/// the caller has not already supplied `raw_headers`; an explicit raw head is
/// the caller's final word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H1WireProfile {
    id: ProfileId,
    casing: HeaderCasing,
    order: Vec<String>,
}

impl H1WireProfile {
    pub fn new(
        id: impl Into<ProfileId>,
        casing: HeaderCasing,
        order: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            id: id.into(),
            casing,
            order: order.into_iter().map(Into::into).collect(),
        }
    }

    pub fn id(&self) -> &ProfileId {
        &self.id
    }

    /// The project's quiet, lower-case HTTP/1 identity.
    pub fn netune() -> Self {
        Self::new(
            "netune",
            HeaderCasing::Lowercase,
            [
                "host",
                "user-agent",
                "accept",
                "content-type",
                "content-length",
                "connection",
            ],
        )
    }

    /// A browser-shaped title-case identity for the common request headers.
    pub fn browser() -> Self {
        Self::new(
            "browser",
            HeaderCasing::TitleCase,
            [
                "host",
                "user-agent",
                "accept",
                "accept-language",
                "accept-encoding",
                "content-type",
                "content-length",
                "connection",
            ],
        )
    }

    /// Chromium's common HTTP/1.1 request-header order.
    pub fn chrome() -> Self {
        Self::new(
            "chrome",
            HeaderCasing::TitleCase,
            [
                "host",
                "connection",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "upgrade-insecure-requests",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-user",
                "sec-fetch-dest",
                "referer",
                "accept-encoding",
                "accept-language",
                "cookie",
                "content-type",
                "content-length",
            ],
        )
    }

    /// Apply this profile to `head` in place.
    ///
    /// A head that already carries `raw_headers` is left untouched: the caller
    /// explicitly opted into exact bytes, and a profile must not silently
    /// rewrite them.
    pub fn apply(&self, head: &mut RequestHead) {
        if head.raw_headers.is_some() {
            return;
        }

        let mut entries: Vec<(String, String)> = head
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        entries.sort_by_key(|(name, _)| self.position(name));

        head.raw_headers = Some(
            entries
                .into_iter()
                .map(|(name, value)| (self.spell(&name), value))
                .collect(),
        );
    }

    fn position(&self, name: &str) -> usize {
        self.order
            .iter()
            .position(|candidate| candidate.eq_ignore_ascii_case(name))
            .unwrap_or(self.order.len())
    }

    fn spell(&self, name: &str) -> String {
        match self.casing {
            HeaderCasing::Lowercase => name.to_ascii_lowercase(),
            HeaderCasing::TitleCase => title_case(name),
        }
    }
}

fn title_case(name: &str) -> String {
    // A few names have casing that title-casing cannot infer. They are the
    // headers a browser fingerprint actually cares about.
    match name {
        "sec-ch-ua" => return "Sec-CH-UA".to_string(),
        "sec-ch-ua-mobile" => return "Sec-CH-UA-Mobile".to_string(),
        "sec-ch-ua-platform" => return "Sec-CH-UA-Platform".to_string(),
        "etag" => return "ETag".to_string(),
        "www-authenticate" => return "WWW-Authenticate".to_string(),
        "dnt" => return "DNT".to_string(),
        "accept-ch" => return "Accept-CH".to_string(),
        "te" => return "TE".to_string(),
        "content-md5" => return "Content-MD5".to_string(),
        _ => {}
    }
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// The resolved plan for one request.
///
/// The plan is built before a socket is opened. It contains the connection
/// identity (which keys the pool) and the per-request wire profiles (which do
/// not).
#[derive(Debug, Clone)]
pub struct ConnectionPlan {
    pub target: Target,
    pub identity: ConnectionIdentity,
    pub h1: H1WireProfile,
    #[cfg(feature = "http2")]
    pub h2: Option<netune_http2::H2Fingerprint>,
    /// The request half, when an H2 connection is planned. It is deliberately
    /// separate from `identity`: it changes a HEADERS block, not a socket.
    #[cfg(feature = "http2")]
    pub h2_request: Option<netune_http2::H2RequestProfile>,
}

impl ConnectionPlan {
    pub fn pool_key(&self) -> PoolKey {
        PoolKey::new(self.target.authority.clone(), self.identity.clone())
    }
}

/// Built-in and caller-supplied HTTP/1 wire profiles.
#[derive(Debug, Clone)]
pub struct H1Registry {
    profiles: HashMap<ProfileId, H1WireProfile>,
}

impl Default for H1Registry {
    fn default() -> Self {
        let mut profiles = HashMap::new();
        for profile in [
            H1WireProfile::netune(),
            H1WireProfile::browser(),
            H1WireProfile::chrome(),
        ] {
            profiles.insert(profile.id().clone(), profile);
        }
        Self { profiles }
    }
}

impl H1Registry {
    pub fn with_profile(mut self, profile: H1WireProfile) -> Self {
        self.profiles.insert(profile.id().clone(), profile);
        self
    }

    pub fn resolve(&self, id: &ProfileId) -> Result<&H1WireProfile, NetError> {
        self.profiles.get(id).ok_or_else(|| {
            NetError::Connect(format!(
                "unknown HTTP/1 wire profile {id:?}; registered: {}",
                self.names().join(", ")
            ))
        })
    }

    pub fn default_profile(&self) -> &H1WireProfile {
        match self.profiles.get(&ProfileId::new("netune")) {
            Some(profile) => profile,
            // The constructor always registers this profile; a registry that
            // loses it is a construction bug, not a runtime condition.
            None => unreachable!("the built-in netune H1 profile is always registered"),
        }
    }

    fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(ProfileId::as_str).collect();
        names.sort_unstable();
        names
    }
}

/// Built-in and caller-supplied HTTP/2 connection profiles.
#[cfg(feature = "http2")]
#[derive(Debug, Clone)]
pub struct H2Registry {
    profiles: HashMap<ProfileId, netune_http2::H2Fingerprint>,
}

#[cfg(feature = "http2")]
impl Default for H2Registry {
    fn default() -> Self {
        let mut profiles = HashMap::new();
        for fingerprint in [
            netune_http2::H2Fingerprint::chrome(),
            netune_http2::H2Fingerprint::safari(),
            netune_http2::H2Fingerprint::firefox(),
            netune_http2::H2Fingerprint::go(),
        ] {
            profiles.insert(ProfileId::new(fingerprint.connection.name), fingerprint);
        }
        Self { profiles }
    }
}

/// Built-in and caller-supplied HTTP/2 request profiles.
#[cfg(feature = "http2")]
#[derive(Debug, Clone)]
pub struct H2RequestRegistry {
    profiles: HashMap<ProfileId, netune_http2::H2RequestProfile>,
}

#[cfg(feature = "http2")]
impl Default for H2RequestRegistry {
    fn default() -> Self {
        let mut profiles = HashMap::new();
        for fingerprint in [
            netune_http2::H2Fingerprint::chrome(),
            netune_http2::H2Fingerprint::safari(),
            netune_http2::H2Fingerprint::firefox(),
            netune_http2::H2Fingerprint::go(),
        ] {
            profiles.insert(
                ProfileId::new(fingerprint.request.name),
                fingerprint.request,
            );
        }
        Self { profiles }
    }
}

#[cfg(feature = "http2")]
impl H2RequestRegistry {
    pub fn with_profile(
        mut self,
        id: impl Into<ProfileId>,
        profile: netune_http2::H2RequestProfile,
    ) -> Self {
        self.profiles.insert(id.into(), profile);
        self
    }

    pub fn resolve(&self, id: &ProfileId) -> Result<&netune_http2::H2RequestProfile, NetError> {
        self.profiles.get(id).ok_or_else(|| {
            NetError::Connect(format!(
                "unknown HTTP/2 request profile {id:?}; registered: {}",
                self.names().join(", ")
            ))
        })
    }

    fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(ProfileId::as_str).collect();
        names.sort_unstable();
        names
    }
}

#[cfg(feature = "http2")]
impl H2Registry {
    pub fn with_profile(
        mut self,
        id: impl Into<ProfileId>,
        profile: netune_http2::H2Fingerprint,
    ) -> Self {
        self.profiles.insert(id.into(), profile);
        self
    }

    pub fn resolve(&self, id: &ProfileId) -> Result<&netune_http2::H2Fingerprint, NetError> {
        self.profiles.get(id).ok_or_else(|| {
            NetError::Connect(format!(
                "unknown HTTP/2 profile {id:?}; registered: {}",
                self.names().join(", ")
            ))
        })
    }

    /// The H2 identity paired with a TLS profile name.
    pub fn default_for_tls(
        &self,
        tls_profile: Option<&str>,
    ) -> Option<(&ProfileId, &netune_http2::H2Fingerprint)> {
        let id = match tls_profile {
            Some("safari-current") => "safari-18",
            Some("firefox-current") => "firefox-132",
            Some("antigravity-cli") => "go-nethttp",
            _ => "chrome-130",
        };
        self.profiles.get_key_value(&ProfileId::new(id))
    }

    fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(ProfileId::as_str).collect();
        names.sort_unstable();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn h1_profile_orders_and_spells_headers() {
        let mut head = RequestHead::new(Method::GET, "/")
            .with_header("accept", "*/*")
            .with_header("user-agent", "netune")
            .with_header("host", "example.test");
        H1WireProfile::browser().apply(&mut head);
        let raw = head.raw_headers.expect("raw head");
        assert_eq!(
            raw,
            vec![
                ("Host".to_string(), "example.test".to_string()),
                ("User-Agent".to_string(), "netune".to_string()),
                ("Accept".to_string(), "*/*".to_string()),
            ]
        );
    }

    #[test]
    fn an_explicit_raw_head_is_not_rewritten() {
        let mut head = RequestHead::new(Method::GET, "/").with_raw_header("X-Exact", "yes");
        H1WireProfile::browser().apply(&mut head);
        assert_eq!(
            head.raw_headers,
            Some(vec![("X-Exact".to_string(), "yes".to_string())])
        );
    }

    #[test]
    fn unknown_profile_names_fail_loudly() {
        let registry = H1Registry::default();
        let error = registry
            .resolve(&ProfileId::new("does-not-exist"))
            .expect_err("unknown profile must fail");
        assert!(error.to_string().contains("unknown HTTP/1 wire profile"));
    }

    #[cfg(feature = "http2")]
    #[test]
    fn h2_defaults_follow_the_tls_pairing_and_custom_profiles_are_first_class() {
        let registry = H2Registry::default();
        assert_eq!(
            registry
                .default_for_tls(Some("safari-current"))
                .map(|(id, _)| id.as_str()),
            Some("safari-18")
        );
        assert_eq!(
            registry
                .default_for_tls(Some("antigravity-cli"))
                .map(|(id, _)| id.as_str()),
            Some("go-nethttp")
        );
        assert_eq!(
            registry.default_for_tls(None).map(|(id, _)| id.as_str()),
            Some("chrome-130")
        );

        let registry = registry.with_profile("my-chrome", netune_http2::H2Fingerprint::chrome());
        assert!(registry.resolve(&ProfileId::new("my-chrome")).is_ok());
    }
}
