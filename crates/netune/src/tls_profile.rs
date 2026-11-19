//! TLS fingerprint profiles: the ClientHello as *configurable* wire data.
//!
//! Under the owned engine ([ADR-0045](../../adr/0045-owned-egress-tls-engine.md)
//! and [ADR-0048](../../adr/0048-declarative-clienthello-blueprints.md)), a
//! profile is pure declarative data backed by [`ClientHelloBlueprint`]: cipher
//! suites, key-exchange groups, independent `key_share` groups, signature
//! schemes, extension order, seeded extension permutation, RFC 8701 GREASE,
//! RFC 7685 dynamic padding, RFC 8879 `compress_certificate`, ALPS, and
//! `session_ticket`.
//!
//! Built-in presets:
//!
//! - `netune-default` — Go-shaped hello, HTTP/1.1 ALPN only.
//! - `antigravity-cli-stream` — Antigravity CLI h2 paths (Clearcut
//!   telemetry to `play.googleapis.com`, the auto-updater): `h2, http/1.1`
//!   ALPN, Go 1.28 `boringcrypto` shape.
//! - `antigravity-cli-unary` — Antigravity CLI HTTP/1.1 paths: every
//!   `/v1internal:*` Cloud Code call **including the streaming model
//!   lane** (`http/1.1` ALPN only, Go 1.28 `boringcrypto` shape).
//! - `go-standard` — upstream Go `crypto/tls` (without `boringcrypto`).
//! - `chrome-current` — Chrome/BoringSSL (GREASE, `compress_certificate`,
//!   ALPS, seeded extension permutation, BoringSSL 517-byte padding).
//! - `firefox-current` — Firefox/NSS (`record_size_limit`,
//!   `post_handshake_auth`, `compress_certificate`, `session_ticket`).
//! - `safari-current` — Safari/SecureTransport (GREASE,
//!   `compress_certificate(zlib)`, fixed extension order).

use netune_tls::hello::{
    BlueprintBuildParams, ClientHello, ClientHelloBlueprint, ExtensionSlot, KeyShareEntry,
    PaddingPolicy,
};
use netune_tls::key_exchange::ClientKeyShare;

/// The built-in presets, selectable by name at request time
/// ([`crate::Target::with_tls_profile`], [`crate::TlsRouterConnector`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// netune's shipped identity: the Go-shaped hello, HTTP/1.1 ALPN only.
    NetuneDefault,
    /// The Google Antigravity CLI (`agy`) identity — a **Go `crypto/tls`**
    /// client (Go 1.28, `boringcrypto` build tag) on its **h2** paths.
    /// As of the live 1.5.12 capture (2026-11-19) the h2 paths are the
    /// Clearcut telemetry lane (`play.googleapis.com /log`) and the
    /// auto-updater (`*.run.app`): ALPN `h2, http/1.1`, paired with the
    /// `go-nethttp` H2 fingerprint and Go's stock default UA
    /// (`Go-http-client/2.0`). The CLI's Cloud Code calls — unary *and*
    /// model-streaming — are HTTP/1.1 and ride the [`AntigravityCliUnary`]
    /// identity instead.
    AntigravityCliStream,
    /// The Google Antigravity CLI (`agy`) identity on its **HTTP/1.1** paths:
    /// every `/v1internal:*` Cloud Code call *including the
    /// `:streamGenerateContent?alt=sse` model lane* (live 1.5.12 capture,
    /// 2026-11-19 — the streaming lane moved off h2 in this lineage),
    /// `http/1.1` ALPN only (`stripHTTP2NextProto`), brand UA
    /// `antigravity/cli/…`, chunked uploads on the streaming call.
    /// ([`INV-TLS-10`])
    AntigravityCliUnary,
    /// Upstream Go `crypto/tls` (without `boringcrypto`).
    GoStandard,
    /// Modern Chrome/BoringSSL identity.
    ChromeCurrent,
    /// Modern Firefox/NSS identity.
    FirefoxCurrent,
    /// Modern Safari/SecureTransport identity.
    SafariCurrent,
}

impl Preset {
    /// Every preset, in registry order.
    pub fn all() -> &'static [Preset] {
        &[
            Preset::NetuneDefault,
            Preset::AntigravityCliStream,
            Preset::AntigravityCliUnary,
            Preset::GoStandard,
            Preset::ChromeCurrent,
            Preset::FirefoxCurrent,
            Preset::SafariCurrent,
        ]
    }

    /// The name requests select this preset by.
    pub const fn name(self) -> &'static str {
        match self {
            Preset::NetuneDefault => "netune-default",
            Preset::AntigravityCliStream => "antigravity-cli-stream",
            Preset::AntigravityCliUnary => "antigravity-cli-unary",
            Preset::GoStandard => "go-standard",
            Preset::ChromeCurrent => "chrome-current",
            Preset::FirefoxCurrent => "firefox-current",
            Preset::SafariCurrent => "safari-current",
        }
    }

    /// Look a preset up by name; `None` for names that are not registered.
    pub fn by_name(name: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|preset| preset.name() == name)
    }

    /// The profile this preset presents.
    #[must_use]
    pub fn profile(self) -> TlsProfile {
        match self {
            Preset::NetuneDefault => TlsProfile {
                name: "netune-default",
                blueprint: ClientHelloBlueprint::go_boringcrypto(),
            },
            Preset::AntigravityCliStream => {
                let mut blueprint = ClientHelloBlueprint::go_boringcrypto();
                blueprint.alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                TlsProfile {
                    name: "antigravity-cli-stream",
                    blueprint,
                }
            }
            Preset::AntigravityCliUnary => TlsProfile {
                name: "antigravity-cli-unary",
                blueprint: ClientHelloBlueprint::go_boringcrypto(),
            },
            Preset::GoStandard => TlsProfile {
                name: "go-standard",
                blueprint: ClientHelloBlueprint::go_standard(),
            },
            Preset::ChromeCurrent => TlsProfile {
                name: "chrome-current",
                blueprint: ClientHelloBlueprint::chrome_current(),
            },
            Preset::FirefoxCurrent => TlsProfile {
                name: "firefox-current",
                blueprint: ClientHelloBlueprint::firefox_current(),
            },
            Preset::SafariCurrent => TlsProfile {
                name: "safari-current",
                blueprint: ClientHelloBlueprint::safari_current(),
            },
        }
    }
}

/// A TLS identity as pure declarative wire data ([`INV-TLS-07`], [`INV-TLS-11`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsProfile {
    /// Human-facing name, reported in traces and test failures.
    pub name: &'static str,
    /// Full ClientHello blueprint fed to `netune-tls`.
    pub blueprint: ClientHelloBlueprint,
}

impl TlsProfile {
    /// The profile's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name
    }

    /// Override the ALPN offer, in order.
    #[must_use]
    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.blueprint.alpn = protocols.iter().map(|protocol| protocol.to_vec()).collect();
        self
    }

    /// Override the offered cipher suites, in order.
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: Vec<u16>) -> Self {
        self.blueprint.cipher_suites = suites;
        self
    }

    /// Override the `supported_groups` list, in order.
    #[must_use]
    pub fn with_supported_groups(mut self, groups: Vec<u16>) -> Self {
        self.blueprint.supported_groups = groups;
        self
    }

    /// Override the initial `key_share` groups, in order.
    #[must_use]
    pub fn with_key_share_groups(mut self, groups: Vec<u16>) -> Self {
        self.blueprint.key_share_groups = groups;
        self
    }

    /// Override the `signature_algorithms` list, in order.
    #[must_use]
    pub fn with_signature_algorithms(mut self, schemes: Vec<u16>) -> Self {
        self.blueprint.signature_algorithms = schemes;
        self
    }

    /// Override (or omit with `None`) `signature_algorithms_cert`.
    #[must_use]
    pub fn with_signature_algorithms_cert(mut self, schemes: Option<Vec<u16>>) -> Self {
        self.blueprint.signature_algorithms_cert = schemes;
        self
    }

    /// Override the ordered extension slots.
    #[must_use]
    pub fn with_extensions(mut self, extensions: Vec<ExtensionSlot>) -> Self {
        self.blueprint.extensions = extensions;
        self
    }

    /// Enable or disable per-connection extension permutation.
    #[must_use]
    pub fn with_extension_permutation(mut self, enabled: bool) -> Self {
        self.blueprint.extension_permutation = enabled;
        self
    }

    /// Set the RFC 7685 padding policy.
    #[must_use]
    pub fn with_padding(mut self, policy: PaddingPolicy) -> Self {
        self.blueprint.padding = policy;
        self
    }

    /// Materialize the ClientHello and key shares for `server_name`.
    ///
    /// # Errors
    /// [`crate::error::NetError::Connect`] when randomness, key shares, or
    /// blueprint serialization fails.
    pub fn connect_params(
        &self,
        server_name: &str,
    ) -> Result<(ClientHello, Vec<ClientKeyShare>), crate::error::NetError> {
        let mut random = [0u8; 32];
        netune_tls::hello::fill_random(&mut random).map_err(|error| {
            crate::error::NetError::Connect(crate::error::ConnectError::tls(
                server_name,
                format!("TLS randomness: {error}"),
            ))
        })?;
        let mut session_id = [0u8; 32];
        netune_tls::hello::fill_random(&mut session_id).map_err(|error| {
            crate::error::NetError::Connect(crate::error::ConnectError::tls(
                server_name,
                format!("TLS randomness: {error}"),
            ))
        })?;
        let mut grease_seed = [0u8; 8];
        netune_tls::hello::fill_random(&mut grease_seed).map_err(|error| {
            crate::error::NetError::Connect(crate::error::ConnectError::tls(
                server_name,
                format!("TLS randomness: {error}"),
            ))
        })?;
        let mut permutation_seed = [0u8; 32];
        netune_tls::hello::fill_random(&mut permutation_seed).map_err(|error| {
            crate::error::NetError::Connect(crate::error::ConnectError::tls(
                server_name,
                format!("TLS randomness: {error}"),
            ))
        })?;

        let shares =
            ClientKeyShare::generate(&self.blueprint.key_share_groups).map_err(|error| {
                crate::error::NetError::Connect(crate::error::ConnectError::tls(
                    server_name,
                    error.to_string(),
                ))
            })?;
        let entries = shares
            .iter()
            .map(|share| KeyShareEntry {
                group: share.group,
                share: share.share.clone(),
            })
            .collect();
        let hello = self
            .blueprint
            .build(BlueprintBuildParams {
                server_name,
                random,
                session_id: &session_id,
                key_shares: entries,
                grease_seed,
                permutation_seed,
            })
            .map_err(|error| {
                crate::error::NetError::Connect(crate::error::ConnectError::tls(
                    server_name,
                    format!("TLS hello: {error}"),
                ))
            })?;
        Ok((hello, shares))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_registered_and_unique() {
        let mut names: Vec<&str> = Preset::all().iter().map(|preset| preset.name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "preset names are unique");
    }

    /// [`INV-TLS-10`]: a path-named preset offers exactly that path's ALPN.
    #[test]
    fn path_named_presets_offer_their_path_alpn() {
        assert_eq!(
            Preset::AntigravityCliStream.profile().blueprint.alpn,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "the stream paths offer h2 first"
        );
        assert_eq!(
            Preset::AntigravityCliUnary.profile().blueprint.alpn,
            vec![b"http/1.1".to_vec()],
            "the unary path offers http/1.1 only"
        );
        assert_eq!(
            Preset::NetuneDefault.profile().blueprint.alpn,
            vec![b"http/1.1".to_vec()],
            "the shipped identity is HTTP/1.1 only"
        );
        assert!(Preset::by_name("antigravity-cli").is_none());
    }

    /// Every preset's hello encodes on the wire and parses cleanly
    /// ([`INV-TLS-06`], [`INV-TLS-07`], [`INV-TLS-11`]).
    #[test]
    fn every_preset_builds_and_parses() {
        for preset in Preset::all() {
            let (hello, _shares) = preset
                .profile()
                .connect_params("profile.example")
                .expect("the preset's offer is completable");
            let bytes = hello.serialize().expect("the preset hello encodes");
            let parsed = netune_trace::ClientHello::parse(&bytes).expect("the hello parses");
            assert!(
                !parsed.extensions.is_empty(),
                "{}: extensions non-empty",
                preset.name()
            );
            assert!(
                !parsed.cipher_suites.is_empty(),
                "{}: cipher suites non-empty",
                preset.name()
            );
        }
    }
}
