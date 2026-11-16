//! TLS: the handshake is a phase of the attempt, and a measured one.
//!
//! The connector wraps another [`Connector`] rather than replacing it, so the
//! trace keeps `DnsStart/End` → `TcpStart/End` → `TlsStart/End` as distinct
//! phases. That separation is the point: on a cold connection the old client
//! folded a DNS lookup, a TCP handshake, a TLS handshake, an OAuth token refresh
//! and the request upload into one number labelled "Connect & Handshake".
//!
//! There are two engines. A plain TLS target uses **rustls with the platform
//! verifier**, the audited production path. A target that selects a
//! [`TlsProfile`] or explicitly asks for `netune-tls` uses the owned engine
//! ([ADR-0045](../../adr/0045-owned-egress-tls-engine.md)), whose blueprint
//! reproduces the measured ClientHello wire identity. The owned engine is
//! under the audit gate in `docs/reference/stability.md`; selecting a profile
//! is an explicit opt-in, and the engine never silently downgrades a profile
//! to rustls. The handshake itself is bounded (10 s by default); a peer that
//! accepts the TCP connection and then stops answering is reported as a
//! connection failure rather than holding the attempt open indefinitely; use
//! [`TlsRouterConnector::with_handshake_timeout`] to change the bound.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use netune_trace::{
    Alpn, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EventKind, TraceCollector,
};
use rustls::pki_types::ServerName;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::connect::{Connector, Established, Target, Transport};
use crate::error::{ConnectError, NetError};
use crate::handshake::{DEFAULT_HANDSHAKE_TIMEOUT, bound};
use crate::tls_profile::{Preset, TlsProfile};

/// The certificate trust policy the owned engine verifies chains with: the
/// verifier seam ([`INV-TLS-08`]), re-exported from [`netune_tls`]'s
/// verifier module (`webpki` is the validator, not a TLS engine).
pub use netune_tls::verifier::Verifier as OwnedVerifier;

/// A connector that presents a *per-request* TLS identity.
///
/// A target with no profile or engine uses rustls with the platform verifier.
/// A target that names a [`TlsProfile`] (or `netune-tls`) uses the owned
/// engine and its declarative ClientHello blueprint.
///
/// An unknown profile or engine name is a [`NetError::Connect`] at connect
/// time, not a silent fallback to a default: choosing a fingerprint is an
/// assertion about what the peer will see, and a typo must not quietly
/// downgrade it.
///
/// Targets without a selection present [`Preset::NetuneDefault`]; plaintext
/// targets pass through untouched (there is no hello to shape).
pub struct TlsRouterConnector<C: Connector> {
    inner: C,
    /// Custom profiles registered ahead of the built-in presets; a custom
    /// name may override a preset name (drift experiments, CA-pinned tests).
    custom: HashMap<String, TlsProfile>,
    /// The trust policy the owned engine verifies chains with.
    verifier: netune_tls::Verifier,
    /// A caller-supplied rustls configuration. `None` uses the platform
    /// verifier with safe defaults.
    rustls_config: Option<Arc<rustls::ClientConfig>>,
    /// The owned engine was selected explicitly (for example by a pinned
    /// verifier or a profile), so the default rustls path is not used.
    force_owned: bool,
    handshake_timeout: Option<Duration>,
    /// Per-(server, profile, alpn) TLS 1.3 resumption ticket cache.
    session_cache: netune_tls::session::SessionCache,
}

impl<C: Connector> TlsRouterConnector<C> {
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            custom: HashMap::new(),
            verifier: netune_tls::Verifier::WebpkiRoots,
            rustls_config: None,
            force_owned: false,
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
            session_cache: netune_tls::session::SessionCache::new(),
        }
    }

    /// Replace the handshake bound. `None` removes it; only do that when an
    /// outer deadline exists that reports the stall as a connection failure.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set the trust policy the owned engine verifies chains with, and select
    /// the owned engine.
    ///
    /// The owned engine is under the audit gate described in
    /// `docs/reference/stability.md`; use it when a pinning policy or a
    /// fingerprint identity requires it, not as the default production path.
    #[must_use]
    pub fn with_verifier(mut self, verifier: netune_tls::Verifier) -> Self {
        self.verifier = verifier;
        self.force_owned = true;
        self
    }

    /// Use a caller-supplied rustls configuration for the default engine.
    ///
    /// The configuration is used only when the target does not select a TLS
    /// profile or explicitly request `netune-tls`; those selections are wire
    /// identities and cannot be silently downgraded to a different engine.
    #[must_use]
    pub fn with_rustls_config(mut self, config: rustls::ClientConfig) -> Self {
        self.rustls_config = Some(Arc::new(config));
        self.force_owned = false;
        self
    }

    /// Explicitly select the owned engine for targets that do not carry a
    /// profile or engine name.
    #[must_use]
    pub fn with_owned_engine(mut self) -> Self {
        self.force_owned = true;
        self
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
}

fn unknown_profile_error(name: &str) -> NetError {
    let known = Preset::all()
        .iter()
        .map(|preset| preset.name())
        .collect::<Vec<_>>()
        .join(", ");
    NetError::Connect(ConnectError::config(
        DiagnosticPhase::Tls,
        format!(
            "unknown TLS profile {name:?} (not a built-in preset: {known}, nor registered with \
             with_profile_named)"
        ),
    ))
}

impl<C: Connector> TlsRouterConnector<C> {
    /// The owned engine's handshake: bracket `TlsStart`/`TlsEnd`, drive
    /// [`netune_tls`]'s machine over the transport, and hand back the
    /// protected stream as [`Established`] — the same trace shape every
    /// egress connection records ([`INV-TLS-08`]).
    async fn owned_handshake(
        &self,
        profile: &TlsProfile,
        established: Established,
        target: &Target,
        recorder: &TraceCollector,
    ) -> Result<Established, NetError> {
        let Some(server_name) = target.tls_server_name().map(str::to_owned) else {
            // A plaintext target passes straight through.
            return Ok(established);
        };

        recorder.mark(EventKind::TlsStart, 0, 0);
        let (mut hello, shares) = profile.connect_params(&server_name)?;
        let session_key = netune_tls::session::SessionKey {
            server_name: server_name.clone(),
            profile_name: profile.name.to_owned(),
            alpn: profile.blueprint.alpn.clone(),
        };
        let offered_psk = if profile.blueprint.psk_key_exchange_modes.is_some()
            && let Some(ticket) = self.session_cache.take(&session_key)
            && profile
                .blueprint
                .cipher_suites
                .contains(&ticket.cipher_suite)
        {
            let age_ms = ticket.obfuscated_age_ms(std::time::Instant::now());
            hello
                .attach_psk_and_sign(
                    netune_tls::hello::PskIdentity {
                        identity: ticket.ticket.clone(),
                        obfuscated_ticket_age: age_ms,
                    },
                    &ticket.psk,
                    ticket.hash,
                )
                .map_err(|error| {
                    NetError::Connect(ConnectError::tls(
                        server_name.clone(),
                        format!("TLS PSK binder: {error}"),
                    ))
                })?;
            Some(ticket.psk.clone())
        } else {
            None
        };

        let connector = netune_tls::OwnedTlsConnector;
        let session_store = if profile.blueprint.psk_key_exchange_modes.is_some() {
            Some((self.session_cache.clone(), session_key))
        } else {
            None
        };
        let connecting = async {
            connector
                .connect_for_server(
                    established.stream,
                    netune_tls::OwnedConnectParams { hello, shares },
                    self.verifier.clone(),
                    Some(server_name.as_str()),
                    offered_psk,
                    session_store,
                )
                .await
        };
        let stream = bound(
            self.handshake_timeout,
            DiagnosticPhase::Tls,
            "TLS handshake",
            &server_name,
            recorder,
            connecting,
        )
        .await?
        .map_err(|error| {
            let message = format!("TLS handshake with {server_name}: {error}");
            recorder.record_error(
                DiagnosticRecord::new(DiagnosticCode::EGRESS_TLS_FAILED)
                    .with_phase(DiagnosticPhase::Tls)
                    .with_message(message.clone()),
            );
            NetError::Connect(ConnectError::tls(server_name.clone(), message).with_source(error))
        })?;

        let alpn = match stream.alpn() {
            Some(b"http/1.1") => Alpn::Http11,
            Some(b"h2") => Alpn::H2,
            _ => Alpn::Unknown,
        };
        let alpn_protocol = stream.alpn().map(<[u8]>::to_vec);
        // Which version's protectors the connection carries is the recorded
        // version fact: 13 for a TLS 1.3 connection, 12 for a TLS 1.2 one.
        let version_code = match stream.protectors_kind() {
            netune_tls::ProtectorsKind::Tls13 => 13u32,
            netune_tls::ProtectorsKind::Tls12 => 12u32,
        };
        recorder.mark(EventKind::TlsEnd, 0, 0);
        recorder.mark(EventKind::TlsInfo, u32::from(alpn.code()), version_code);

        Ok(Established {
            stream: Box::new(stream),
            local_port: established.local_port,
            socket: established.socket,
            alpn: Some(alpn),
            alpn_protocol,
        })
    }
}

impl<C: Connector> TlsRouterConnector<C> {
    /// The audited production path: rustls with the platform verifier.
    ///
    /// The owned engine remains available for fingerprint identities, but it
    /// is not selected by a plain TLS target.
    async fn rustls_handshake(
        &self,
        established: Established,
        target: &Target,
        recorder: &TraceCollector,
    ) -> Result<Established, NetError> {
        let Some(server_name) = target.tls_server_name().map(str::to_owned) else {
            return Ok(established);
        };
        recorder.mark(EventKind::TlsStart, 0, 0);

        let config = match &self.rustls_config {
            Some(config) => Arc::clone(config),
            None => {
                let mut config =
                    rustls::ClientConfig::with_platform_verifier().map_err(|error| {
                        NetError::Connect(ConnectError::config(
                            DiagnosticPhase::Tls,
                            format!("rustls platform verifier: {error}"),
                        ))
                    })?;
                if config.alpn_protocols.is_empty() {
                    // The connector cannot see ClientConfig::enable_http2, so
                    // the default must be the conservative H1-only offer. A
                    // caller that needs h2 supplies a rustls config (or uses
                    // the owned profile path).
                    config.alpn_protocols = vec![b"http/1.1".to_vec()];
                }
                Arc::new(config)
            }
        };
        let connector = tokio_rustls::TlsConnector::from(config);
        let domain = ServerName::try_from(server_name.clone()).map_err(|error| {
            NetError::Connect(ConnectError::config(
                DiagnosticPhase::Tls,
                format!("invalid TLS server name {server_name:?}: {error}"),
            ))
        })?;
        let connecting = connector.connect(domain, established.stream);
        let stream = bound(
            self.handshake_timeout,
            DiagnosticPhase::Tls,
            "TLS handshake",
            &server_name,
            recorder,
            connecting,
        )
        .await?
        .map_err(|error| {
            let message = format!("TLS handshake with {server_name}: {error}");
            recorder.record_error(
                DiagnosticRecord::new(DiagnosticCode::EGRESS_TLS_FAILED)
                    .with_phase(DiagnosticPhase::Tls)
                    .with_message(message.clone()),
            );
            NetError::Connect(ConnectError::tls(server_name.clone(), message).with_source(error))
        })?;

        let (_, session) = stream.get_ref();
        let alpn = match session.alpn_protocol() {
            Some(b"http/1.1") => Alpn::Http11,
            Some(b"h2") => Alpn::H2,
            _ => Alpn::Unknown,
        };
        let alpn_protocol = session.alpn_protocol().map(<[u8]>::to_vec);
        let version_code = match session.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => 13,
            Some(rustls::ProtocolVersion::TLSv1_2) => 12,
            _ => 0,
        };
        recorder.mark(EventKind::TlsEnd, 0, 0);
        recorder.mark(EventKind::TlsInfo, u32::from(alpn.code()), version_code);

        Ok(Established {
            stream: Box::new(RustlsTransport { inner: stream }),
            local_port: established.local_port,
            socket: established.socket,
            alpn: Some(alpn),
            alpn_protocol,
        })
    }
}

/// A rustls stream that still exposes the underlying socket tap.
struct RustlsTransport<S> {
    inner: tokio_rustls::client::TlsStream<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RustlsTransport<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RustlsTransport<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: Transport> Transport for RustlsTransport<S> {
    fn socket_tap(&mut self) -> Option<&mut netune_trace::SocketTap> {
        self.inner.get_mut().0.socket_tap()
    }
}

impl<C: Connector> Connector for TlsRouterConnector<C> {
    fn socket_shape(&self) -> Option<String> {
        self.inner.socket_shape()
    }

    fn route_shape(&self) -> Option<String> {
        self.inner.route_shape()
    }

    fn egress_confinement(&self) -> Option<crate::connect::EgressConfinement> {
        self.inner.egress_confinement()
    }

    async fn connect(
        &self,
        target: &Target,
        recorder: &TraceCollector,
    ) -> Result<Established, NetError> {
        if target.tls_server_name().is_none() {
            return self.inner.connect(target, recorder).await;
        }
        // The engine name is a request-visible identity surface
        // ([`INV-TLS-09`]); an unknown name is a refusal, never a fallback.
        let engine = target.tls_engine();
        if let Some(engine) = engine
            && engine != "rustls"
            && engine != "netune-tls"
        {
            return Err(NetError::Connect(ConnectError::config(
                DiagnosticPhase::Tls,
                format!(
                    "unknown TLS engine {engine:?} (known engines: \"rustls\", \"netune-tls\")"
                ),
            )));
        }
        let has_profile = target.tls_profile().is_some();
        if has_profile && engine == Some("rustls") {
            return Err(NetError::Connect(ConnectError::config(
                DiagnosticPhase::Tls,
                "a TLS profile is an owned-engine wire identity; it cannot be run on \"rustls\"",
            )));
        }
        if engine == Some("rustls") && self.force_owned {
            return Err(NetError::Connect(ConnectError::config(
                DiagnosticPhase::Tls,
                "the connector is configured with an owned-engine verifier and cannot run \
                 \"rustls\"",
            )));
        }
        let use_owned = engine == Some("netune-tls") || has_profile || self.force_owned;
        let established = self.inner.connect(target, recorder).await?;
        if use_owned {
            let name = target.tls_profile().unwrap_or(Preset::NetuneDefault.name());
            let profile = self
                .resolve(name)
                .ok_or_else(|| unknown_profile_error(name))?;
            self.owned_handshake(&profile, established, target, recorder)
                .await
        } else {
            self.rustls_handshake(established, target, recorder).await
        }
    }
}
