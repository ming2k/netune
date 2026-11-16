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

/// How regular (non-pseudo) headers are ordered within a HEADERS block
/// ([ADR-0046](https://github.com/ming2k/netune/blob/main/docs/adr/0046-h2-regular-header-order-policy.md)).
///
/// The order is named policy, never ambient caller accident
/// ([`INV-CUSTOM-21`]). Note the honesty boundary for [`RegularHeaderOrder::GoMapRandom`]:
/// it matches Go's behaviour as a *distribution*, not as any single capture —
/// no one request matches any captured request, and Go's own requests have the
/// same property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegularHeaderOrder {
    /// Emit regular headers in the caller's order, unchanged. The right
    /// policy for a stack with a fixed, fingerprintable order the caller
    /// controls explicitly (browsers), and the escape hatch for a caller
    /// that wants exact control.
    CallerOrder,
    /// Shuffle regular headers per request, emulating Go `net/http`'s
    /// map-iteration order. The seed is the connection's header-order seed
    /// mixed with the stream id, so two requests on one connection present
    /// different orders ([`INV-CUSTOM-22`]). The same seed yields the same
    /// order: every wire decision is reproducible.
    GoMapRandom,
    /// Emit regular headers in a fixed declared order; headers not named in
    /// the list keep their relative order after the named ones.
    Fixed(&'static [&'static str]),
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
/// Pseudo-header and regular-header order change one HEADERS block, not the
/// connection. They must not key a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2RequestProfile {
    /// Human-readable profile name.
    pub name: &'static str,
    /// Pseudo-header emission order for `HEADERS`.
    pub pseudo_headers_order: PseudoHeaderOrder,
    /// How regular (non-pseudo) headers are ordered ([`INV-CUSTOM-21`]).
    pub regular_header_order: RegularHeaderOrder,
}

impl H2RequestProfile {
    /// Construct a custom HTTP/2 request header-ordering profile.
    pub const fn new(
        name: &'static str,
        pseudo_headers_order: PseudoHeaderOrder,
        regular_header_order: RegularHeaderOrder,
    ) -> Self {
        Self {
            name,
            pseudo_headers_order,
            regular_header_order,
        }
    }
}

/// A connection profile paired with the request profile it normally uses.
///
/// The pair is a convenience for presets. The connection half keys the pool;
/// the request half can be applied per exchange without opening a new socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Fingerprint {
    /// Connection-scoped SETTINGS and initial window profile.
    pub connection: H2ConnectionProfile,
    /// Per-request header-ordering profile.
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
                regular_header_order: RegularHeaderOrder::CallerOrder,
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
                regular_header_order: RegularHeaderOrder::CallerOrder,
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
                regular_header_order: RegularHeaderOrder::CallerOrder,
            },
        }
    }

    /// The Go `net/http` client identity (`golang.org/x/net/http2`).
    ///
    /// Live-captured from Google Antigravity CLI 1.5.3 (`agy`, Go 1.28) and
    /// re-verified on 1.5.9 (2026-11): the CLI's unary Cloud Code API is
    /// HTTP/1.1-only (`stripHTTP2NextProto`), so this framing is what its *h2*
    /// connections put on the wire — Clearcut telemetry to
    /// `play.googleapis.com`, and the model-streaming transport. It is the same
    /// framing every Go binary that uses `net/http` over HTTP/2 emits (the
    /// values are `golang.org/x/net/http2` defaults, not the CLI's):
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
    /// - **regular headers are randomized per request** ([`RegularHeaderOrder::GoMapRandom`]):
    ///   Go `net/http` writes them by map iteration, so every request carries
    ///   a fresh order. The request seed is the connection's header-order seed
    ///   mixed with the stream id, so the sequence is reproducible from a
    ///   fixed seed and differs between requests on one connection
    ///   ([`INV-CUSTOM-22`]). This matches Go's behaviour as a *distribution*,
    ///   not as any single capture — the same is true of Go's own requests.
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
                regular_header_order: RegularHeaderOrder::GoMapRandom,
            },
        }
    }

    /// Order the pseudo-headers and regular headers of one request according
    /// to this fingerprint's policy.
    ///
    /// `seed` is the connection's header-order seed; under
    /// [`RegularHeaderOrder::GoMapRandom`] it is mixed with the stream id by
    /// the caller (`seed ^ stream_id`), so two requests on one connection
    /// present different orders and a fixed seed reproduces the exact
    /// permutation.
    pub fn order_request_headers<'a>(
        &self,
        method: &'a str,
        authority: &'a str,
        scheme: &'a str,
        path: &'a str,
        extra_headers: &'a [(String, String)],
        seed: u64,
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

        let mut regular: Vec<(&str, &str)> = extra_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        apply_regular_header_order(&mut regular, self.request.regular_header_order, seed);
        ordered.extend(regular);

        ordered
    }
}

/// Apply a [`RegularHeaderOrder`] policy to regular headers in place.
pub(crate) fn apply_regular_header_order(
    regular: &mut [(&str, &str)],
    order: RegularHeaderOrder,
    seed: u64,
) {
    match order {
        RegularHeaderOrder::CallerOrder => {}
        RegularHeaderOrder::GoMapRandom => {
            shuffle_by_seed(regular, seed);
        }
        RegularHeaderOrder::Fixed(names) => {
            regular.sort_by_key(|(name, _)| {
                names
                    .iter()
                    .position(|candidate| candidate.eq_ignore_ascii_case(name))
                    .unwrap_or(names.len())
            });
        }
    }
}

/// Shuffle deterministically: Fisher-Yates driven by a splitmix64 stream.
///
/// The PRNG is an emulation choice, not a claim about Go's `math/rand`: what
/// is emulated is *per-request variation over the same multiset*, and that is
/// what the tests pin.
pub(crate) fn shuffle_by_seed<T>(items: &mut [T], seed: u64) {
    let mut state = seed;
    for index in (1..items.len()).rev() {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let swap_with = (z % (index as u64 + 1)) as usize;
        items.swap(index, swap_with);
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
            fp.order_request_headers("GET", "example.com", "https", "/index.html", &extra, 0);

        assert_eq!(headers[0], (":method", "GET"));
        assert_eq!(headers[1], (":authority", "example.com"));
        assert_eq!(headers[2], (":scheme", "https"));
        assert_eq!(headers[3], (":path", "/index.html"));
        assert_eq!(headers[4], ("user-agent", "Mozilla/5.0"));
    }

    #[test]
    fn firefox_pseudo_header_ordering() {
        let fp = H2Fingerprint::firefox();
        let headers = fp.order_request_headers("POST", "api.local", "https", "/v1/submit", &[], 0);
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

        let extra = [
            ("authorization".to_string(), "Bearer x".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("accept-encoding".to_string(), "gzip".to_string()),
        ];
        let headers = fp.order_request_headers(
            "POST",
            "daily-cloudcode-pa.googleapis.com",
            "https",
            "/v1internal:loadCodeAssist",
            &extra,
            0,
        );
        assert_eq!(
            headers[0],
            (":authority", "daily-cloudcode-pa.googleapis.com")
        );
        assert_eq!(headers[1], (":method", "POST"));
        assert_eq!(headers[2], (":path", "/v1internal:loadCodeAssist"));
        assert_eq!(headers[3], (":scheme", "https"));
        // Regular headers follow the go-nethttp policy: per-request randomized
        // order over the same multiset ([INV-CUSTOM-22]).
        assert_eq!(headers.len(), 7);
        let mut regular: Vec<&str> = headers[4..].iter().map(|(name, _)| *name).collect();
        regular.sort_unstable();
        assert_eq!(
            regular,
            ["accept-encoding", "authorization", "content-type"]
        );
    }

    /// [INV-CUSTOM-22]: the go-nethttp profile randomizes regular-header order
    /// per request. Same seed, same permutation; different request seed (the
    /// client mixes the stream id in), different permutation; and the
    /// multiset never changes.
    #[test]
    fn go_regular_header_order_varies_per_request_and_is_reproducible() {
        let fp = H2Fingerprint::go();
        let extra = [
            ("authorization".to_string(), "Bearer x".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("accept-encoding".to_string(), "gzip".to_string()),
            ("user-agent".to_string(), "Go-http-client/2.0".to_string()),
        ];

        let first = fp.order_request_headers("POST", "a", "https", "/p", &extra, 7);
        let first_again = fp.order_request_headers("POST", "a", "https", "/p", &extra, 7);
        assert_eq!(
            first, first_again,
            "a seed reproduces the exact permutation"
        );

        // stream 1 vs stream 3 on the same connection seed: different orders
        // (over four headers a fixed order is the outlier we must not be).
        let stream_one = fp.order_request_headers("POST", "a", "https", "/p", &extra, 7 ^ 1);
        let stream_three = fp.order_request_headers("POST", "a", "https", "/p", &extra, 7 ^ 3);
        assert_ne!(stream_one[4..], stream_three[4..]);

        // The multiset is preserved by every permutation.
        for headers in [first, stream_one, stream_three] {
            let mut names: Vec<&str> = headers[4..].iter().map(|(name, _)| *name).collect();
            names.sort_unstable();
            assert_eq!(
                names,
                [
                    "accept-encoding",
                    "authorization",
                    "content-type",
                    "user-agent"
                ]
            );
        }
    }

    /// [INV-CUSTOM-21]: `Fixed` is a named policy — named headers lead in the
    /// declared order, unnamed headers keep their relative order after them.
    #[test]
    fn fixed_regular_header_order_is_declared_policy() {
        let mut fp = H2Fingerprint::chrome();
        fp.request.regular_header_order = RegularHeaderOrder::Fixed(&["content-type", "host"]);
        let extra = [
            ("x-custom".to_string(), "1".to_string()),
            ("host".to_string(), "a".to_string()),
            ("content-type".to_string(), "json".to_string()),
            ("x-other".to_string(), "2".to_string()),
        ];
        let headers = fp.order_request_headers("GET", "a", "https", "/", &extra, 0);
        let regular: Vec<&str> = headers[4..].iter().map(|(name, _)| *name).collect();
        assert_eq!(regular, ["content-type", "host", "x-custom", "x-other"]);
    }
}
