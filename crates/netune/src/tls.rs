//! TLS: the handshake is a phase of the attempt, and a measured one.
//!
//! The connector wraps another [`Connector`] rather than replacing it, so the
//! trace keeps `DnsStart/End` → `TcpStart/End` → `TlsStart/End` as distinct
//! phases. That separation is the point: on a cold connection the old client
//! folded a DNS lookup, a TCP handshake, a TLS handshake, an OAuth token refresh
//! and the request upload into one number labelled "Connect & Handshake".
//!
//! Trust roots come from the platform store ([`rustls_platform_verifier`]) so a
//! corporate root or an OS trust change is honoured without shipping our own
//! bundle; ALPN advertises HTTP/1.1 only, which is what this client speaks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use netune_trace::{Alpn, EventKind, Recorder};
use rustls::pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio_rustls::TlsConnector as RustlsConnector;

use crate::connect::{Connector, Established, Target};
use crate::error::NetError;
use crate::tls_profile::{Preset, TlsProfile};

/// Build the client TLS configuration: platform roots, HTTP/1.1 ALPN, and the
/// process-wide aws-lc-rs provider.
///
/// Session resumption uses rustls' default in-memory cache, so a resumed
/// handshake stays fast across requests that share this config — which is why
/// the config is built once and shared, not per request.
pub fn platform_client_config() -> Result<Arc<rustls::ClientConfig>, NetError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| NetError::Connect(format!("TLS provider: {error}")))?
        .with_platform_verifier()
        .map_err(|error| NetError::Connect(format!("platform trust store: {error}")))?
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A connector that establishes TLS on top of an inner connector.
pub struct TlsConnector<C: Connector> {
    inner: C,
    config: Arc<rustls::ClientConfig>,
}
impl<C: Connector> TlsConnector<C> {
    pub fn new(inner: C, config: Arc<rustls::ClientConfig>) -> Self {
        Self { inner, config }
    }

    /// Build a connector trusting the platform store.
    pub fn platform(inner: C) -> Result<Self, NetError> {
        Ok(Self::new(inner, platform_client_config()?))
    }

    /// Build a connector from a [`TlsProfile`] with the default
    /// (aws-lc-rs) provider — the seam for fingerprint work: pick a preset,
    /// tweak it, and this connector presents exactly that identity.
    pub fn with_profile(inner: C, profile: &TlsProfile) -> Result<Self, NetError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        Ok(Self::new(inner, profile.build(provider)?))
    }
}

/// The shared TLS handshake, used by [`TlsConnector`] and
/// [`TlsRouterConnector`]: bracket `TlsStart`/`TlsEnd`, record the negotiated
/// ALPN and version, and hand the stream back as [`Established`].
async fn handshake(
    config: &Arc<rustls::ClientConfig>,
    established: Established,
    target: &Target,
    recorder: &Arc<Mutex<Recorder>>,
) -> Result<Established, NetError> {
    let Some(server_name) = target.tls_server_name.clone() else {
        // A plaintext target passes straight through.
        return Ok(established);
    };

    {
        let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
        recorder.mark(EventKind::TlsStart, 0, 0);
    }
    let name = ServerName::try_from(server_name.clone())
        .map_err(|error| NetError::Connect(format!("invalid TLS server name: {error}")))?;
    let connector = RustlsConnector::from(Arc::clone(config));
    let stream = connector
        .connect(name, established.stream)
        .await
        .map_err(|error| NetError::Connect(format!("TLS handshake with {server_name}: {error}")))?;

    let (alpn, version) = {
        let (_, connection) = stream.get_ref();
        (
            Alpn::from_name(connection.alpn_protocol()),
            connection.protocol_version(),
        )
    };
    let version_code = match version {
        Some(rustls::ProtocolVersion::TLSv1_3) => 13u32,
        Some(rustls::ProtocolVersion::TLSv1_2) => 12u32,
        _ => 0u32,
    };
    {
        let mut recorder = recorder.lock().unwrap_or_else(|e| e.into_inner());
        recorder.mark(EventKind::TlsEnd, 0, 0);
        recorder.mark(EventKind::TlsInfo, u32::from(alpn.code()), version_code);
    }

    Ok(Established {
        stream: Box::new(stream),
        local_port: established.local_port,
        socket: established.socket,
    })
}

impl<C: Connector> Connector for TlsConnector<C> {
    async fn connect(
        &self,
        target: &Target,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, NetError> {
        let established = self.inner.connect(target, recorder).await?;
        handshake(&self.config, established, target, recorder).await
    }
}

/// A connector that presents a *per-request* TLS identity: the target's
/// [`Target::tls_profile`] name selects which compiled profile handshakes.
///
/// Profiles are compiled lazily on first use and cached — a config is built
/// once per identity and then shared by every connection that names it (which
/// is also what lets rustls session resumption work across those connections).
/// An unknown name is a [`NetError::Connect`] at connect time, not a silent
/// fallback to the default: choosing a fingerprint is an assertion about what
/// the peer will see, and a typo must not quietly downgrade it.
///
/// Targets without a selection present [`Preset::NetuneDefault`]; plaintext
/// targets pass through untouched (there is no hello to shape).
pub struct TlsRouterConnector<C: Connector> {
    inner: C,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Custom profiles registered ahead of the built-in presets; a custom
    /// name may override a preset name (drift experiments, CA-pinned tests).
    custom: HashMap<String, TlsProfile>,
    configs: Mutex<HashMap<String, Arc<rustls::ClientConfig>>>,
}

impl<C: Connector> TlsRouterConnector<C> {
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            custom: HashMap::new(),
            configs: Mutex::new(HashMap::new()),
        }
    }

    /// Register (or override) a named profile, selectable at request time via
    /// [`Target::with_tls_profile`]. This is the "compose your own identity"
    /// path: assemble a [`TlsProfile`] from presets and knobs, name it, and
    /// requests can pick it like any built-in preset.
    pub fn with_profile_named(mut self, name: impl Into<String>, profile: TlsProfile) -> Self {
        self.custom.insert(name.into(), profile);
        self
    }

    /// The profile behind a name: custom registrations first, then presets.
    fn resolve(&self, name: &str) -> Option<TlsProfile> {
        if let Some(profile) = self.custom.get(name) {
            return Some(profile.clone());
        }
        Preset::by_name(name).map(|preset| preset.profile())
    }

    /// The compiled config for a profile name, building it on first use.
    fn config_for(&self, name: &str) -> Result<Arc<rustls::ClientConfig>, NetError> {
        if let Some(config) = self
            .configs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
        {
            return Ok(Arc::clone(config));
        }
        let profile = self
            .resolve(name)
            .ok_or_else(|| unknown_profile_error(name))?;
        let config = profile.build(Arc::clone(&self.provider))?;
        let mut configs = self.configs.lock().unwrap_or_else(|e| e.into_inner());
        // A racing caller may have compiled it first; either way, one entry.
        Ok(configs.entry(name.to_string()).or_insert(config).clone())
    }
}

fn unknown_profile_error(name: &str) -> NetError {
    let known = Preset::all()
        .iter()
        .map(|preset| preset.name())
        .collect::<Vec<_>>()
        .join(", ");
    NetError::Connect(format!(
        "unknown TLS profile {name:?} (not a built-in preset: {known}, nor registered with \
         with_profile_named)"
    ))
}

impl<C: Connector> Connector for TlsRouterConnector<C> {
    async fn connect(
        &self,
        target: &Target,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, NetError> {
        if target.tls_server_name.is_none() {
            return self.inner.connect(target, recorder).await;
        }
        let name = target
            .tls_profile
            .as_deref()
            .unwrap_or(Preset::NetuneDefault.name());
        let config = self.config_for(name)?;
        let established = self.inner.connect(target, recorder).await?;
        handshake(&config, established, target, recorder).await
    }
}
