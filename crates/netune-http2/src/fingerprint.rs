//! Akamai HTTP/2 fingerprinting and browser impersonation profiles.
//!
//! Web Application Firewalls (WAFs) and bot-management services (Cloudflare,
//! Akamai, DataDome) inspect the initial HTTP/2 negotiation signature:
//! 1. The exact sequence and values of the initial `SETTINGS` frame.
//! 2. The initial connection-level `WINDOW_UPDATE` increment.
//! 3. The ordering of HTTP/2 pseudo-headers (`:method`, `:authority`, `:scheme`, `:path`).
//! 4. Stream priority dependencies and headers framing flags.
//!
//! [`H2Fingerprint`] is a pure declarative model allowing exact replication of
//! major modern browser fingerprints.

use crate::frame::*;

/// Declared HTTP/2 pseudo-header order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoHeaderOrder {
    /// Chrome / Chromium: `:method`, `:authority`, `:scheme`, `:path`.
    MethodAuthoritySchemePath,
    /// Firefox: `:method`, `:path`, `:authority`, `:scheme`.
    MethodPathAuthorityScheme,
    /// Safari: `:method`, `:scheme`, `:authority`, `:path`.
    MethodSchemeAuthorityPath,
    /// Go `net/http` (golang.org/x/net/http2): `:authority`, `:method`, `:path`,
    /// `:scheme`. Go writes `:authority` first — the one major stack that does —
    /// which makes the pseudo-header order alone a Go marker.
    AuthorityMethodPathScheme,
    /// Custom explicit order.
    Custom(&'static [&'static str]),
}

impl PseudoHeaderOrder {
    /// Return the list of pseudo-header names in order.
    pub fn names(&self) -> &'static [&'static str] {
        match self {
            Self::MethodAuthoritySchemePath => &[":method", ":authority", ":scheme", ":path"],
            Self::MethodPathAuthorityScheme => &[":method", ":path", ":authority", ":scheme"],
            Self::MethodSchemeAuthorityPath => &[":method", ":scheme", ":authority", ":path"],
            Self::AuthorityMethodPathScheme => &[":authority", ":method", ":path", ":scheme"],
            Self::Custom(list) => list,
        }
    }
}

/// The connection-fixed half of an HTTP/2 identity.
///
/// This is what a peer observes during the preface and SETTINGS exchange, and
/// therefore what can make two HTTP/2 connections non-interchangeable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2ConnectionProfile {
    /// Name of the connection profile (e.g. "chrome-130", "go-nethttp").
    pub name: &'static str,
    /// In-order initial SETTINGS key-value parameters.
    pub settings: Vec<(u16, u32)>,
    /// Connection-level initial WINDOW_UPDATE size increment.
    pub initial_connection_window_update: Option<u32>,
    /// Header Table Size advertised to the peer's HPACK encoder.
    pub header_table_size: u32,
    /// Whether to send connection preface with priority frames.
    pub send_priority_frames: bool,
}

/// The request-fixed half of an HTTP/2 identity.
///
/// Pseudo-header order changes one HEADERS block, not the connection. It must
/// not key a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2RequestProfile {
    pub name: &'static str,
    pub pseudo_headers_order: PseudoHeaderOrder,
}

/// A connection profile paired with the request profile it normally uses.
///
/// The pair is a convenience for presets. The connection half keys the pool;
/// the request half can be applied per exchange without opening a new socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Fingerprint {
    pub connection: H2ConnectionProfile,
    pub request: H2RequestProfile,
}

impl H2Fingerprint {
    /// Modern Chromium baseline (Chrome 130+).
    ///
    /// Akamai H2 Hash: `1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p`
    pub fn chrome() -> Self {
        Self {
            connection: H2ConnectionProfile {
                name: "chrome-130",
                settings: vec![
                    (SETTING_HEADER_TABLE_SIZE, 65536),
                    (SETTING_ENABLE_PUSH, 0),
                    (SETTING_MAX_CONCURRENT_STREAMS, 1000),
                    (SETTING_INITIAL_WINDOW_SIZE, 6291456),
                    (SETTING_MAX_HEADER_LIST_SIZE, 262144),
                ],
                initial_connection_window_update: Some(15663105),
                header_table_size: 65536,
                send_priority_frames: false,
            },
            request: H2RequestProfile {
                name: "chrome-130",
                pseudo_headers_order: PseudoHeaderOrder::MethodAuthoritySchemePath,
            },
        }
    }

    /// Modern Safari baseline (macOS / iOS Safari 18+).
    ///
    /// Akamai H2 Hash: `2:0,4:2097152,3:100|10485760|0|m,s,a,p`
    pub fn safari() -> Self {
        Self {
            connection: H2ConnectionProfile {
                name: "safari-18",
                settings: vec![
                    (SETTING_ENABLE_PUSH, 0),
                    (SETTING_INITIAL_WINDOW_SIZE, 2097152),
                    (SETTING_MAX_CONCURRENT_STREAMS, 100),
                ],
                initial_connection_window_update: Some(10485760),
                header_table_size: 4096,
                send_priority_frames: false,
            },
            request: H2RequestProfile {
                name: "safari-18",
                pseudo_headers_order: PseudoHeaderOrder::MethodSchemeAuthorityPath,
            },
        }
    }

    /// Modern Firefox baseline (Firefox 132+).
    ///
    /// Akamai H2 Hash: `1:65536,4:131072,5:16384|12517377|0|m,p,a,s`
    pub fn firefox() -> Self {
        Self {
            connection: H2ConnectionProfile {
                name: "firefox-132",
                settings: vec![
                    (SETTING_HEADER_TABLE_SIZE, 65536),
                    (SETTING_INITIAL_WINDOW_SIZE, 131072),
                    (SETTING_MAX_FRAME_SIZE, 16384),
                ],
                initial_connection_window_update: Some(12517377),
                header_table_size: 65536,
                send_priority_frames: true,
            },
            request: H2RequestProfile {
                name: "firefox-132",
                pseudo_headers_order: PseudoHeaderOrder::MethodPathAuthorityScheme,
            },
        }
    }

    /// The Go `net/http` client identity (`golang.org/x/net/http2`).
    ///
    /// Live-captured from Google Antigravity CLI 1.5.3 (`agy`, Go 1.28) on its
    /// first request to `daily-cloudcode-pa.googleapis.com`; the same framing is
    /// what every Go binary that uses `net/http` over HTTP/2 puts on the wire
    /// (the values are `golang.org/x/net/http2` defaults, not the CLI's):
    ///
    /// - `SETTINGS`: `ENABLE_PUSH=0`, `INITIAL_WINDOW_SIZE=4194304`,
    ///   `MAX_FRAME_SIZE=1048576`, `MAX_HEADER_LIST_SIZE=10485760` — in that
    ///   order, which is Go's `writeSettings` order.
    /// - connection `WINDOW_UPDATE` of `1073741824` (Go's 1 GiB transport cap).
    /// - no `HEADER_TABLE_SIZE` setting (HPACK decoder table stays the 4096
    ///   default) and no `MAX_CONCURRENT_STREAMS` (Go never sends it).
    /// - no PRIORITY frames (Go never sends them).
    /// - pseudo-headers in Go's order: `:authority`, `:method`, `:path`,
    ///   `:scheme`.
    /// - **regular headers are emitted in Go map-iteration order**, i.e. they
    ///   differ per request; there is no stable regular-header ordering to
    ///   impersonate, and a stack that emits a *fixed* order is the outlier.
    ///
    /// Akamai H2 Hash: `2:0,4:4194304,5:1048576,6:10485760|1073741824|0|a,m,p,s`
    pub fn go() -> Self {
        Self {
            connection: H2ConnectionProfile {
                name: "go-nethttp",
                settings: vec![
                    (SETTING_ENABLE_PUSH, 0),
                    (SETTING_INITIAL_WINDOW_SIZE, 4_194_304),
                    (SETTING_MAX_FRAME_SIZE, 1_048_576),
                    (SETTING_MAX_HEADER_LIST_SIZE, 10_485_760),
                ],
                initial_connection_window_update: Some(1_073_741_824),
                header_table_size: 4096,
                send_priority_frames: false,
            },
            request: H2RequestProfile {
                name: "go-nethttp",
                pseudo_headers_order: PseudoHeaderOrder::AuthorityMethodPathScheme,
            },
        }
    }

    /// Sort pseudo-headers and regular headers according to this fingerprint's policy.
    pub fn order_request_headers<'a>(
        &self,
        method: &'a str,
        authority: &'a str,
        scheme: &'a str,
        path: &'a str,
        extra_headers: &'a [(String, String)],
    ) -> Vec<(&'a str, &'a str)> {
        let mut ordered = Vec::with_capacity(4 + extra_headers.len());

        for name in self.request.pseudo_headers_order.names() {
            match *name {
                ":method" => ordered.push((":method", method)),
                ":authority" => ordered.push((":authority", authority)),
                ":scheme" => ordered.push((":scheme", scheme)),
                ":path" => ordered.push((":path", path)),
                _ => {}
            }
        }

        for (k, v) in extra_headers {
            ordered.push((k.as_str(), v.as_str()));
        }

        ordered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_pseudo_header_ordering() {
        let fp = H2Fingerprint::chrome();
        let extra = [("user-agent".into(), "Mozilla/5.0".into())];
        let headers =
            fp.order_request_headers("GET", "example.com", "https", "/index.html", &extra);

        assert_eq!(headers[0], (":method", "GET"));
        assert_eq!(headers[1], (":authority", "example.com"));
        assert_eq!(headers[2], (":scheme", "https"));
        assert_eq!(headers[3], (":path", "/index.html"));
        assert_eq!(headers[4], ("user-agent", "Mozilla/5.0"));
    }

    #[test]
    fn firefox_pseudo_header_ordering() {
        let fp = H2Fingerprint::firefox();
        let headers = fp.order_request_headers("POST", "api.local", "https", "/v1/submit", &[]);
        assert_eq!(headers[0], (":method", "POST"));
        assert_eq!(headers[1], (":path", "/v1/submit"));
        assert_eq!(headers[2], (":authority", "api.local"));
        assert_eq!(headers[3], (":scheme", "https"));
    }

    /// The Go identity is the one stack that leads with `:authority`, and its
    /// SETTINGS set is four entries in Go's `writeSettings` order — the values
    /// live-captured from the 1.5.3 `agy` client. Freezing them here means a
    /// change to `go()` can only be a deliberate one.
    #[test]
    fn go_identity_matches_the_captured_antigravity_cli_framing() {
        let fp = H2Fingerprint::go();
        assert_eq!(fp.connection.name, "go-nethttp");
        assert_eq!(
            fp.connection.settings,
            vec![(2, 0), (4, 4_194_304), (5, 1_048_576), (6, 10_485_760)]
        );
        assert_eq!(
            fp.connection.initial_connection_window_update,
            Some(1_073_741_824)
        );
        assert!(
            !fp.connection.send_priority_frames,
            "Go never sends PRIORITY frames"
        );

        let extra = [("authorization".to_string(), "Bearer x".to_string())];
        let headers = fp.order_request_headers(
            "POST",
            "daily-cloudcode-pa.googleapis.com",
            "https",
            "/v1internal:loadCodeAssist",
            &extra,
        );
        assert_eq!(
            headers[0],
            (":authority", "daily-cloudcode-pa.googleapis.com")
        );
        assert_eq!(headers[1], (":method", "POST"));
        assert_eq!(headers[2], (":path", "/v1internal:loadCodeAssist"));
        assert_eq!(headers[3], (":scheme", "https"));
        assert_eq!(headers[4], ("authorization", "Bearer x"));
    }
}
