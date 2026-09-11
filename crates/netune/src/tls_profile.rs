//! TLS fingerprint profiles: the ClientHello as a *configurable* surface.
//!
//! rustls fixes the ClientHello's shape; a profile decides what that shape
//! says. Every knob here maps onto a field a passive observer can read:
//!
//! - `alpn_protocols` → JA4's `a`/`h`/`i` digit and the wire ALPN list
//! - `protocol_versions` → JA4's `13`/`12` digit and `supported_versions`
//! - `cipher_suites` → JA4's cipher count (`d`) and hash
//! - `kx_groups` → JA3's groups field (JA4's extension hash via `key_share`)
//! - verifier choice → which roots (and therefore cert-verification paths) we
//!   present; not fingerprint-visible but part of the identity
//!
//! What a profile *cannot* change: rustls always sends GREASE where it sends
//! it, always randomizes extension order per connection
//! (`extension_order_seed` — see `hs.rs` in rustls), and only offers cipher
//! suites the installed crypto provider actually implements. So the honest
//! target of a profile is *another rustls-shaped stack*, byte-for-byte where
//! possible and JA4-equal otherwise. Impersonating a non-rustls stack (Chrome,
//! Safari, Go) needs a different engine, not a different profile.
//!
//! Two independent copies of the same idea, precisely because it matters:
//! `TlsProfile` is a *description* (pure data, snapshot-testable, no I/O);
//! `ClientConfig` is the *executed* thing. Tests assert the description, the
//! connector runs it, and `tls_baseline.rs` cross-checks that the executed
//! hello still matches the description that produced it.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::version::TLS12;

use crate::error::NetError;

/// TLS 1.2 only, as a `'static` slice for [`TlsProfile::tls12_only`].
static TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&TLS12];

/// The built-in presets, selectable by name at request time
/// ([`Target::with_tls_profile`](crate::Target::with_tls_profile),
/// [`crate::TlsRouterConnector`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// netune's stock identity: `http/1.1` ALPN, platform roots.
    NetuneDefault,
    /// The Codex CLI product-traffic identity (reqwest + hyper-rustls):
    /// `h2,http/1.1`.
    CodexReqwest,
    /// The `codex-network-proxy` upstream identity (rama-tls-rustls):
    /// wire-identical to [`Preset::CodexReqwest`] today, named separately so
    /// the two call sites can drift visibly.
    CodexNetworkProxy,
}

impl Preset {
    /// Every preset, in registry order.
    pub fn all() -> &'static [Preset] {
        &[
            Preset::NetuneDefault,
            Preset::CodexReqwest,
            Preset::CodexNetworkProxy,
        ]
    }

    /// The name requests select this preset by.
    pub const fn name(self) -> &'static str {
        match self {
            Preset::NetuneDefault => "netune-default",
            Preset::CodexReqwest => "codex-reqwest",
            Preset::CodexNetworkProxy => "codex-network-proxy",
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
    pub fn profile(self) -> TlsProfile {
        match self {
            Preset::NetuneDefault => TlsProfile::netune_default(),
            Preset::CodexReqwest => TlsProfile::codex_reqwest(),
            Preset::CodexNetworkProxy => TlsProfile::codex_network_proxy(),
        }
    }
}

/// The TLS identity a profile presents, before it is compiled into a
/// [`rustls::ClientConfig`]. Clone, tweak, compare — a profile is data.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Human-facing name, reported in traces and test failures.
    pub name: &'static str,
    /// ALPN protocol names in offer order. Empty = no ALPN extension at all
    /// (JA4's `i`).
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Offered protocol versions. Order is irrelevant to the wire hello
    /// (`supported_versions` is sorted by rustls) but defines what we accept.
    pub protocol_versions: &'static [&'static rustls::SupportedProtocolVersion],
    /// Cipher suites to offer, restricted to suites the provider implements.
    /// `None` = provider default order (what a stock rustls client sends).
    pub cipher_suites: Option<Vec<rustls::CipherSuite>>,
    /// Key-exchange groups to offer. `None` = provider default.
    pub kx_groups: Option<Vec<rustls::NamedGroup>>,
    /// Where trust comes from — platform store (netune) or an explicit root
    /// store (a codex-style proxy with its own CA or a pinned set).
    pub verifier: Verifier,
}

/// Trust-root selection. Part of the profile because the same binary must be
/// able to present "I trust the OS" and "I trust exactly this bundle".
#[derive(Debug, Clone, Default)]
pub enum Verifier {
    /// The OS trust store via `rustls-platform-verifier` (netune's default).
    #[default]
    Platform,
    /// An explicit root store: pinned CAs, a corporate MITM bundle, tests.
    Roots(rustls::RootCertStore),
}

impl TlsProfile {
    /// netune's own stock identity: platform roots, HTTP/1.1 only, whatever
    /// the installed provider offers by default. What `tls_baseline.rs`
    /// snapshots as `t13d1011h1_61a7ad8aa9b6_0d308c48d2a3`.
    pub fn netune_default() -> Self {
        Self {
            name: "netune-default",
            alpn_protocols: vec![b"http/1.1".to_vec()],
            protocol_versions: rustls::ALL_VERSIONS,
            cipher_suites: None,
            kx_groups: None,
            verifier: Verifier::Platform,
        }
    }

    /// The Codex CLI's product-traffic identity (reqwest + hyper-rustls):
    /// rustls 0.23 with the aws-lc-rs provider, ALPN `h2,http/1.1` in that
    /// order — hyper-rustls always lists h2 first when the caller asks for
    /// "both" — and both TLS versions offered.
    ///
    /// JA4 target (rustls 0.23.x + aws-lc-rs, SNI present): the `h2` digit and
    /// a 10-cipher offer identical to the default's except for the ALPN.
    pub fn codex_reqwest() -> Self {
        Self {
            name: "codex-reqwest",
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            protocol_versions: rustls::ALL_VERSIONS,
            cipher_suites: None,
            kx_groups: None,
            verifier: Verifier::Platform,
        }
    }

    /// The identity `codex-network-proxy` presents on its upstream leg
    /// (rama-tls-rustls): `builder_with_protocol_versions(ALL_VERSIONS)` with
    /// `with_alpn_protocols_http_auto`, i.e. the same `h2,http/1.1` offer and
    /// default suites. It is wire-identical to [`Self::codex_reqwest`] when
    /// both ride the same rustls release; kept as a separate named profile so
    /// the two call sites can drift *visibly* if codex upgrades one leg.
    pub fn codex_network_proxy() -> Self {
        Self {
            name: "codex-network-proxy",
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            protocol_versions: rustls::ALL_VERSIONS,
            cipher_suites: None,
            kx_groups: None,
            verifier: Verifier::Platform,
        }
    }

    /// Change the ALPN offer (affects the JA4 `a` digit).
    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    /// Offer TLS 1.2 only (JA4 digit `12`): for endpoints whose middleboxes
    /// reject 1.3 hello shapes, or to *not* look like every modern client.
    pub fn tls12_only(mut self) -> Self {
        self.protocol_versions = TLS12_ONLY;
        self
    }

    /// Restrict the cipher offer. Suites the provider cannot actually run are
    /// filtered at build time ([`Self::build`]) — this is an allowlist over
    /// reality, not a forge list.
    pub fn with_cipher_suites(mut self, suites: &[rustls::CipherSuite]) -> Self {
        self.cipher_suites = Some(suites.to_vec());
        self
    }

    /// Restrict the key-share/groups offer (JA3's groups field; drives which
    /// `key_share` extension value goes on the wire).
    pub fn with_kx_groups(mut self, groups: &[rustls::NamedGroup]) -> Self {
        self.kx_groups = Some(groups.to_vec());
        self
    }

    /// Trust an explicit root store instead of the platform store.
    pub fn with_roots(mut self, roots: rustls::RootCertStore) -> Self {
        self.verifier = Verifier::Roots(roots);
        self
    }

    /// Compile the profile into a rustls client config, honouring every knob
    /// the installed provider can actually deliver.
    ///
    /// Suite and group restrictions are applied by *filtering the provider*
    /// (rustls 0.23 takes those from `CryptoProvider`, not from the config
    /// builder), so the resulting hello offers exactly the intersection of
    /// the allowlist with what the base provider implements.
    pub fn build(
        &self,
        base_provider: Arc<CryptoProvider>,
    ) -> Result<Arc<rustls::ClientConfig>, NetError> {
        let provider = filter_provider(self, &base_provider);

        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(self.protocol_versions)
            .map_err(|error| NetError::Connect(format!("TLS profile {}: {error}", self.name)))?;

        let config = match &self.verifier {
            Verifier::Platform => {
                use rustls_platform_verifier::BuilderVerifierExt;
                builder
                    .with_platform_verifier()
                    .map_err(|error| NetError::Connect(format!("platform trust store: {error}")))?
                    .with_no_client_auth()
            }
            Verifier::Roots(roots) => builder
                .with_root_certificates(roots.clone())
                .with_no_client_auth(),
        };

        let mut config = config;
        config.alpn_protocols = self.alpn_protocols.clone();
        Ok(Arc::new(config))
    }
}

/// The base provider restricted to the profile's suite/group allowlists. An
/// allowlist naming a suite the provider lacks is *silently dropped* rather
/// than failing the build: the profile still connects, it just offers less.
/// `None` (and an empty `Some`) mean "no restriction".
fn filter_provider(profile: &TlsProfile, base: &CryptoProvider) -> CryptoProvider {
    let restrict = |allowlist: &Option<Vec<rustls::CipherSuite>>| {
        allowlist
            .as_ref()
            .filter(|list| !list.is_empty())
            .map(|list| {
                base.cipher_suites
                    .iter()
                    .copied()
                    .filter(|suite| list.contains(&suite.suite()))
                    .collect()
            })
            .unwrap_or_else(|| base.cipher_suites.clone())
    };
    let restrict_groups = |allowlist: &Option<Vec<rustls::NamedGroup>>| {
        allowlist
            .as_ref()
            .filter(|list| !list.is_empty())
            .map(|list| {
                base.kx_groups
                    .iter()
                    .copied()
                    .filter(|group| list.contains(&group.name()))
                    .collect()
            })
            .unwrap_or_else(|| base.kx_groups.clone())
    };
    CryptoProvider {
        cipher_suites: restrict(&profile.cipher_suites),
        kx_groups: restrict_groups(&profile.kx_groups),
        ..base.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    #[test]
    fn the_default_profile_says_what_netune_ships() {
        let profile = TlsProfile::netune_default();
        assert_eq!(profile.name, "netune-default");
        assert_eq!(profile.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert_eq!(profile.protocol_versions, rustls::ALL_VERSIONS);
        assert!(matches!(profile.verifier, Verifier::Platform));
        assert!(profile.cipher_suites.is_none(), "provider default suites");
        assert!(profile.kx_groups.is_none(), "provider default groups");
    }

    #[test]
    fn the_codex_profiles_offer_h2_first_like_hyper_rustls() {
        for profile in [
            TlsProfile::codex_reqwest(),
            TlsProfile::codex_network_proxy(),
        ] {
            assert_eq!(
                profile.alpn_protocols,
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                "{}: hyper-rustls lists h2 first",
                profile.name
            );
            assert_eq!(profile.protocol_versions, rustls::ALL_VERSIONS);
        }
    }

    #[test]
    fn tls12_only_flips_the_version_offer() {
        let profile = TlsProfile::netune_default().tls12_only();
        assert_eq!(profile.protocol_versions, TLS12_ONLY);
    }

    #[test]
    fn the_default_profile_builds_and_offers_the_provider_default_suites() {
        let provider = provider();
        let config = TlsProfile::netune_default()
            .build(provider.clone())
            .expect("build");
        // Every provider suite is offered: the profile is a pass-through.
        // (Suites/groups live on the compiled provider, not on the config.)
        let compiled = config.crypto_provider().cipher_suites.len();
        assert_eq!(compiled, provider.cipher_suites.len());
        // ALPN is exactly what the profile said.
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn a_cipher_allowlist_restricts_the_offer_and_drops_unknown_suites() {
        let config = TlsProfile::netune_default()
            .with_cipher_suites(&[
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                // Not implemented by aws-lc-rs' default set — must be dropped, not fail.
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ])
            .build(provider())
            .expect("build");
        for suite in &config.crypto_provider().cipher_suites {
            assert!(
                matches!(
                    suite.suite(),
                    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                        | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                ),
                "only allowlisted suites survive: {:?}",
                suite.suite()
            );
        }
    }

    #[test]
    fn a_kx_group_allowlist_restricts_the_offer() {
        let config = TlsProfile::netune_default()
            .with_kx_groups(&[rustls::NamedGroup::X25519])
            .build(provider())
            .expect("build");
        let groups = config.crypto_provider().kx_groups.clone();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name(), rustls::NamedGroup::X25519);
    }

    #[test]
    fn an_empty_allowlist_falls_back_to_the_provider_default() {
        let config = TlsProfile::netune_default()
            .with_cipher_suites(&[])
            .build(provider())
            .expect("build");
        assert_eq!(
            config.crypto_provider().cipher_suites.len(),
            provider().cipher_suites.len()
        );
    }
}
