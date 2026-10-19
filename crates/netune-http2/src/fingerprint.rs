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
            Self::Custom(list) => list,
        }
    }
}

/// A comprehensive HTTP/2 client fingerprint profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Fingerprint {
    /// Name of the profile (e.g. "chrome-130", "safari-18", "firefox-132").
    pub name: &'static str,
    /// In-order initial SETTINGS key-value parameters.
    pub settings: Vec<(u16, u32)>,
    /// Connection-level initial WINDOW_UPDATE size increment.
    pub initial_connection_window_update: Option<u32>,
    /// Ordering of HTTP/2 pseudo-headers.
    pub pseudo_headers_order: PseudoHeaderOrder,
    /// Header Table Size update in HPACK dynamic table.
    pub header_table_size: u32,
    /// Whether to send connection preface with priority frames.
    pub send_priority_frames: bool,
}

impl H2Fingerprint {
    /// Modern Chromium baseline (Chrome 130+).
    ///
    /// Akamai H2 Hash: `1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p`
    pub fn chrome() -> Self {
        Self {
            name: "chrome-130",
            settings: vec![
                (SETTING_HEADER_TABLE_SIZE, 65536),
                (SETTING_ENABLE_PUSH, 0),
                (SETTING_MAX_CONCURRENT_STREAMS, 1000),
                (SETTING_INITIAL_WINDOW_SIZE, 6291456),
                (SETTING_MAX_HEADER_LIST_SIZE, 262144),
            ],
            initial_connection_window_update: Some(15663105),
            pseudo_headers_order: PseudoHeaderOrder::MethodAuthoritySchemePath,
            header_table_size: 65536,
            send_priority_frames: false,
        }
    }

    /// Modern Safari baseline (macOS / iOS Safari 18+).
    ///
    /// Akamai H2 Hash: `2:0,4:2097152,3:100|10485760|0|m,s,a,p`
    pub fn safari() -> Self {
        Self {
            name: "safari-18",
            settings: vec![
                (SETTING_ENABLE_PUSH, 0),
                (SETTING_INITIAL_WINDOW_SIZE, 2097152),
                (SETTING_MAX_CONCURRENT_STREAMS, 100),
            ],
            initial_connection_window_update: Some(10485760),
            pseudo_headers_order: PseudoHeaderOrder::MethodSchemeAuthorityPath,
            header_table_size: 4096,
            send_priority_frames: false,
        }
    }

    /// Modern Firefox baseline (Firefox 132+).
    ///
    /// Akamai H2 Hash: `1:65536,4:131072,5:16384|12517377|0|m,p,a,s`
    pub fn firefox() -> Self {
        Self {
            name: "firefox-132",
            settings: vec![
                (SETTING_HEADER_TABLE_SIZE, 65536),
                (SETTING_INITIAL_WINDOW_SIZE, 131072),
                (SETTING_MAX_FRAME_SIZE, 16384),
            ],
            initial_connection_window_update: Some(12517377),
            pseudo_headers_order: PseudoHeaderOrder::MethodPathAuthorityScheme,
            header_table_size: 65536,
            send_priority_frames: true,
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

        for name in self.pseudo_headers_order.names() {
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
}
