//! TLS: the handshake is a phase of the attempt, and a measured one.
//!
//! The connector wraps another [`Connector`] rather than replacing it, so the
//! trace keeps `DnsStart/End` → `TcpStart/End` → `TlsStart/End` as distinct
//! phases. That separation is the point: on a cold connection the old client
//! folded a DNS lookup, a TCP handshake, a TLS handshake, an OAuth token refresh
//! and the request upload into one number labelled "Connect & Handshake".
//!
//! The handshake is the owned engine's ([ADR-0045](../../adr/0045-owned-egress-tls-engine.md)):
//! the [`TlsProfile`] description maps onto the Go-shaped hello, the engine
//! drives the handshake over the transport, and the connection comes back as
//! an `AsyncRead`/`AsyncWrite` whose record protection is the engine's
//! ([`INV-TLS-08`]). The handshake itself is bounded (10 s by default); a peer
//! that accepts the TCP connection and then stops answering is reported as a
//! connection failure rather than holding the attempt open indefinitely; use
//! [`TlsRouterConnector::with_handshake_timeout`] to change the bound.

use std::collections::HashMap;
use std::time::Duration;

use netune_trace::{
    Alpn, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EventKind, TraceCollector,
};

use crate::connect::{Connector, Established, Target};
use crate::error::{ConnectError, NetError};
use crate::handshake::{DEFAULT_HANDSHAKE_TIMEOUT, bound};
use crate::tls_profile::{Preset, TlsProfile};

/// The certificate trust policy the owned engine verifies chains with: the
/// verifier seam ([`INV-TLS-08`]), re-exported from [`netune_tls`]'s
/// verifier module (`webpki` is the validator, not a TLS engine).
pub use netune_tls::verifier::Verifier as OwnedVerifier;

/// A connector that presents a *per-request* TLS identity: the target's
/// [`Target::tls_profile`] name selects which preset handshakes, and the
/// owned engine handshakes the transport.
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
    /// The trust policy the engine verifies chains with.
    verifier: netune_tls::Verifier,
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

    /// Set the trust policy the engine verifies chains with. The default is
    /// the Mozilla root bundle via `webpki`.
    #[must_use]
    pub fn with_verifier(mut self, verifier: netune_tls::Verifier) -> Self {
        self.verifier = verifier;
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
                        identity: ticket.ticket,
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
            Some(ticket.psk)
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
        if let Some(engine) = target.tls_engine()
            && engine != "netune-tls"
        {
            return Err(NetError::Connect(ConnectError::config(
                DiagnosticPhase::Tls,
                format!("unknown TLS engine {engine:?} (the owned engine is \"netune-tls\")"),
            )));
        }
        let name = target.tls_profile().unwrap_or(Preset::NetuneDefault.name());
        let profile = self
            .resolve(name)
            .ok_or_else(|| unknown_profile_error(name))?;
        let established = self.inner.connect(target, recorder).await?;
        self.owned_handshake(&profile, established, target, recorder)
            .await
    }
}
