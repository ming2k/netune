// SPDX-License-Identifier: MIT

//! QUIC connector and established connection management.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use netune_egress::EgressConfinement;
use netune_trace::{EventKind, TraceCollector};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::error::QuicError;
use crate::owned::{ClientConfigOwned, Connection, Endpoint, SessionCache};
use crate::profile::{QuicProfile, QuicProfileRegistry};
use crate::socket::{QuicSocketConfig, QuicUdpSocketFactory, TokioUdpSocketFactory};
use crate::wire::transport_parameters::TransportParameters;

/// Establishes and shapes QUIC connections.
#[derive(Clone)]
pub struct QuicConnector {
    profile: QuicProfile,
    socket_config: QuicSocketConfig,
    confinement: EgressConfinement,
    custom_tls: Option<rustls::ClientConfig>,
    socket_factory: Arc<dyn QuicUdpSocketFactory>,
    congestion_factory: Option<Arc<dyn crate::CongestionControllerFactory>>,
    session_cache: SessionCache,
    client_tls: Arc<std::sync::Mutex<Option<Arc<rustls::ClientConfig>>>>,
}

impl std::fmt::Debug for QuicConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConnector")
            .field("profile", &self.profile.name)
            .field("socket_config", &self.socket_config)
            .finish_non_exhaustive()
    }
}

impl Default for QuicConnector {
    fn default() -> Self {
        Self::new(QuicProfile::default())
    }
}

impl QuicConnector {
    /// Creates a new `QuicConnector` configured with the specified profile.
    pub fn new(profile: QuicProfile) -> Self {
        Self {
            profile,
            socket_config: QuicSocketConfig::default(),
            confinement: EgressConfinement::Unrestricted,
            custom_tls: None,
            socket_factory: Arc::new(TokioUdpSocketFactory),
            congestion_factory: None,
            session_cache: SessionCache::new(),
            client_tls: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Resolve a named profile through a registry, then construct the connector.
    pub fn from_registry(registry: &QuicProfileRegistry, name: &str) -> Result<Self, QuicError> {
        Ok(Self::new(registry.resolve(name)?.clone()))
    }

    /// The resolved profile name, for identity and diagnostics.
    pub fn profile_name(&self) -> &'static str {
        self.profile.name
    }

    /// Sets the socket configuration (applied before any packet is sent, [INV-SOCKET-01]).
    pub fn with_socket_config(mut self, config: QuicSocketConfig) -> Self {
        self.socket_config = config;
        self
    }

    /// Sets the egress confinement policy checked before any socket is created
    /// ([INV-EGRESS-01], [INV-QUIC-02]).
    pub fn with_confinement(mut self, confinement: EgressConfinement) -> Self {
        self.confinement = confinement;
        self
    }

    /// Refuse every non-public target (convenience for
    /// [`with_confinement`](Self::with_confinement)).
    pub fn strict_public(self) -> Self {
        self.with_confinement(EgressConfinement::StrictPublic)
    }

    /// Overrides the TLS client configuration (must use `aws-lc-rs`, [INV-QUIC-01]).
    pub fn with_tls_config(mut self, tls: rustls::ClientConfig) -> Self {
        self.custom_tls = Some(tls);
        self.client_tls = Arc::new(std::sync::Mutex::new(None));
        self
    }

    /// Uses a caller-supplied factory for the UDP socket stack.
    ///
    /// This is the seam for protocol-specific datagram transforms such as
    /// obfuscation and port hopping. The factory is invoked once per new
    /// connection, after egress confinement has accepted the target and before
    /// the first Initial packet. It receives the connector's
    /// [`QuicSocketConfig`], so the custom stack can honour or reject every
    /// pre-connect option.
    pub fn with_socket_factory(mut self, factory: Arc<dyn QuicUdpSocketFactory>) -> Self {
        self.socket_factory = factory;
        self
    }

    /// Uses a caller-supplied congestion controller instead of the profile's
    /// built-in algorithm. The factory is consulted once per connection.
    pub fn with_congestion_factory(
        mut self,
        factory: Arc<dyn crate::CongestionControllerFactory>,
    ) -> Self {
        self.congestion_factory = Some(factory);
        self
    }

    /// Establishes a QUIC connection to the target address and server name.
    ///
    /// Resolves once the handshake completes. Use [`connect_early`](Self::connect_early)
    /// when a resumed session may send 0-RTT data before the handshake.
    pub async fn connect(
        &self,
        target_addr: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
    ) -> Result<QuicConnection, QuicError> {
        let connection = self
            .connect_early(target_addr, server_name, recorder.clone())
            .await?;
        if let Err(error) = connection.connection().wait_established().await {
            if let Some(rec) = &recorder {
                rec.mark(EventKind::QuicEnd, 0, 0);
            }
            return Err(error);
        }
        if let Some(rec) = &recorder {
            rec.mark(EventKind::QuicEnd, 1, 0);
        }
        Ok(connection)
    }

    /// Starts a QUIC connection without waiting for the handshake.
    ///
    /// When the connector has a resumed TLS session and a cached set of peer
    /// transport parameters, streams can be opened and 0-RTT frames emitted
    /// immediately. Use [`QuicConnection::connection`]`::early_data_available`
    /// to decide whether to send early application data.
    pub async fn connect_early(
        &self,
        target_addr: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
    ) -> Result<QuicConnection, QuicError> {
        if let Some(rec) = &recorder {
            rec.mark(EventKind::QuicStart, 0, 0);
        }
        let result = self
            .connect_early_inner(target_addr, server_name, recorder.clone())
            .await;
        if result.is_err()
            && let Some(rec) = &recorder
        {
            rec.mark(EventKind::QuicEnd, 0, 0);
        }
        result
    }

    async fn connect_early_inner(
        &self,
        target_addr: SocketAddr,
        server_name: &str,
        recorder: Option<TraceCollector>,
    ) -> Result<QuicConnection, QuicError> {
        // Confinement strictly precedes socket creation ([INV-EGRESS-01], [INV-QUIC-02]).
        self.confinement
            .check(target_addr.ip())
            .map_err(|refused| QuicError::Connect(refused.to_string()))?;
        if self.profile.keep_alive == Some(Duration::ZERO) {
            return Err(QuicError::Config(
                "keep_alive must be greater than zero".to_string(),
            ));
        }

        let tls = self.build_tls_config()?;
        let transport = self.transport_parameters();
        let udp = self
            .socket_factory
            .create(target_addr, &self.socket_config)
            .map_err(QuicError::Socket)?;
        let endpoint = Endpoint::client_with_socket(udp).await?;
        let connection = endpoint
            .connect_early(
                target_addr,
                server_name,
                ClientConfigOwned {
                    tls,
                    transport,
                    versions: vec![
                        crate::wire::packet::VERSION_1,
                        crate::wire::packet::VERSION_2,
                    ],
                    congestion: self.profile.congestion,
                    congestion_factory: self.congestion_factory.clone(),
                    enable_early_data: self.profile.enable_0rtt,
                    keep_alive: self.profile.keep_alive,
                    session_cache: Some(self.session_cache.clone().into()),
                },
            )
            .await?;

        Ok(QuicConnection {
            _endpoint: endpoint,
            connection,
            recorder,
        })
    }

    fn build_tls_config(&self) -> Result<Arc<rustls::ClientConfig>, QuicError> {
        let mut cached = self
            .client_tls
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(tls) = cached.as_ref() {
            return Ok(tls.clone());
        }
        let mut tls = if let Some(tls) = &self.custom_tls {
            tls.clone()
        } else {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| QuicError::Tls(error.to_string()))?
                .with_platform_verifier()
                .map_err(|error| QuicError::Tls(error.to_string()))?
                .with_no_client_auth()
        };
        if !self.profile.alpn.is_empty() {
            tls.alpn_protocols = self.profile.alpn.clone();
        }
        tls.enable_early_data = self.profile.enable_0rtt;
        let tls = Arc::new(tls);
        *cached = Some(tls.clone());
        Ok(tls)
    }

    fn transport_parameters(&self) -> TransportParameters {
        let parameters = &self.profile.transport_parameters;
        TransportParameters {
            max_idle_timeout: parameters
                .max_idle_timeout
                .map(|duration| duration.as_millis() as u64),
            max_udp_payload_size: parameters.max_udp_payload_size.map(u64::from),
            initial_max_data: Some(parameters.initial_max_data),
            initial_max_stream_data_bidi_local: Some(parameters.initial_max_stream_data_bidi_local),
            initial_max_stream_data_bidi_remote: Some(
                parameters.initial_max_stream_data_bidi_remote,
            ),
            initial_max_stream_data_uni: Some(parameters.initial_max_stream_data_uni),
            initial_max_streams_bidi: Some(parameters.initial_max_streams_bidi),
            initial_max_streams_uni: Some(parameters.initial_max_streams_uni),
            active_connection_id_limit: Some(parameters.active_connection_id_limit),
            max_datagram_frame_size: if parameters.enable_datagrams {
                Some(65_535)
            } else {
                None
            },
            reset_stream_at: parameters.reset_stream_at,
            ..TransportParameters::default()
        }
    }
}

/// An established QUIC connection.
pub struct QuicConnection {
    _endpoint: Endpoint,
    connection: Connection,
    recorder: Option<TraceCollector>,
}

impl std::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConnection")
            .field("remote_address", &self.connection.remote_address())
            .finish_non_exhaustive()
    }
}

impl QuicConnection {
    /// Borrows the owned QUIC connection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Borrows the endpoint that owns the UDP socket.
    pub fn endpoint(&self) -> &Endpoint {
        &self._endpoint
    }

    /// Obtains an RFC 9221 datagram session over this connection.
    pub fn datagram_session(&self) -> crate::datagram::QuicDatagramSession {
        crate::datagram::QuicDatagramSession::new(self.connection.clone())
    }

    /// Opens a new bidirectional stream and records the trace boundary.
    pub async fn open_stream(
        &self,
    ) -> Result<(crate::owned::SendStream, crate::owned::RecvStream), QuicError> {
        let (send, recv) = self.connection.open_bi().await?;
        if let Some(rec) = &self.recorder {
            rec.mark(EventKind::QuicStreamOpen, send.id() as u32, 1);
        }
        Ok((send, recv))
    }

    /// Current smoothed round-trip time, when at least one ACK sample exists.
    pub fn rtt(&self) -> Option<Duration> {
        self.connection.rtt()
    }

    /// The path MTU validated by DPLPMTUD, in bytes.
    pub fn path_mtu(&self) -> usize {
        self.connection.path_mtu()
    }

    /// The peer's certificate chain after rustls verification.
    ///
    /// netune does not implement pinning; a consumer that needs it checks this
    /// chain before sending sensitive application data.
    pub fn peer_certificates(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        self.connection.peer_certificates()
    }
}
