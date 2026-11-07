// SPDX-License-Identifier: MIT

//! QUIC connector and established connection management.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune_egress::EgressConfinement;
use netune_trace::{EventKind, Recorder};
use quinn::congestion::ControllerFactory;
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, TokioRuntime};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::datagram::QuicDatagramSession;
use crate::error::QuicError;
use crate::profile::QuicProfile;
use crate::socket::QuicSocketConfig;
use crate::stream::QuicStream;

/// Establishes and shapes QUIC connections.
#[derive(Clone)]
pub struct QuicConnector {
    profile: QuicProfile,
    socket_config: QuicSocketConfig,
    confinement: EgressConfinement,
    custom_socket: Option<Arc<dyn AsyncUdpSocket>>,
    custom_congestion: Option<Arc<dyn ControllerFactory + Send + Sync>>,
    custom_tls: Option<rustls::ClientConfig>,
    custom_transport: Option<Arc<quinn::TransportConfig>>,
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
            custom_socket: None,
            custom_congestion: None,
            custom_tls: None,
            custom_transport: None,
        }
    }

    /// Sets the socket configuration (applied before any packet is sent, [INV-SOCKET-01]).
    pub fn with_socket_config(mut self, config: QuicSocketConfig) -> Self {
        self.socket_config = config;
        self
    }

    /// Sets the egress confinement policy checked before any socket is created
    /// ([INV-EGRESS-01], [INV-QUIC-02]).
    ///
    /// Depth of defence matters here as much as on the TCP path: a caller that
    /// reaches `netune-quic` with an attacker-influenced address must not be
    /// able to open a QUIC socket to loopback or a cloud-metadata endpoint.
    /// The check runs on the resolved address *before* `create_tokio_socket`,
    /// so no packet can leave the host to a refused address.
    pub fn with_confinement(mut self, confinement: EgressConfinement) -> Self {
        self.confinement = confinement;
        self
    }

    /// Refuse every non-public target (convenience for
    /// [`with_confinement`](Self::with_confinement)).
    pub fn strict_public(self) -> Self {
        self.with_confinement(EgressConfinement::StrictPublic)
    }

    /// Sets a custom `AsyncUdpSocket` implementation (e.g. for packet obfuscation or port hopping).
    pub fn with_custom_socket(mut self, socket: Arc<dyn AsyncUdpSocket>) -> Self {
        self.custom_socket = Some(socket);
        self
    }

    /// Sets a custom congestion controller factory.
    pub fn with_congestion_factory(
        mut self,
        factory: Arc<dyn ControllerFactory + Send + Sync>,
    ) -> Self {
        self.custom_congestion = Some(factory);
        self
    }

    /// Overrides the low-level QUIC transport configuration directly.
    pub fn with_transport_config(mut self, config: Arc<quinn::TransportConfig>) -> Self {
        self.custom_transport = Some(config);
        self
    }

    /// Overrides the TLS client configuration (must use `aws-lc-rs` provider, [INV-QUIC-01]).
    pub fn with_tls_config(mut self, tls: rustls::ClientConfig) -> Self {
        self.custom_tls = Some(tls);
        self
    }

    /// Builds a Quinn `ClientConfig` matching this connector's profile and settings.
    pub fn build_client_config(&self) -> Result<quinn::ClientConfig, QuicError> {
        let transport_config = if let Some(tc) = &self.custom_transport {
            tc.clone()
        } else {
            self.profile
                .to_quinn_transport_config(self.custom_congestion.clone())?
        };

        let mut tls_config = if let Some(tls) = &self.custom_tls {
            tls.clone()
        } else {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| QuicError::Tls(e.to_string()))?
                .with_platform_verifier()
                .map_err(|e| QuicError::Tls(e.to_string()))?
                .with_no_client_auth()
        };

        if !self.profile.alpn.is_empty() {
            tls_config.alpn_protocols = self.profile.alpn.clone();
        }

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| QuicError::Tls(e.to_string()))?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(transport_config);

        Ok(client_config)
    }

    /// Establishes a QUIC connection to the target address and server name.
    pub async fn connect(
        &self,
        target_addr: SocketAddr,
        server_name: &str,
        recorder: Option<Arc<Mutex<Recorder>>>,
    ) -> Result<QuicConnection, QuicError> {
        if let Some(r) = &recorder
            && let Ok(mut rec) = r.lock()
        {
            rec.mark(EventKind::QuicStart, 0, 0);
        }

        // Confinement strictly precedes socket creation ([INV-EGRESS-01], [INV-QUIC-02]):
        // the refused address never reaches `create_tokio_socket`, so no packet is sent.
        self.confinement
            .check(target_addr.ip())
            .map_err(|refused| QuicError::Connect(refused.to_string()))?;

        let client_config = self.build_client_config()?;

        let endpoint = if let Some(custom_sock) = &self.custom_socket {
            Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                custom_sock.clone(),
                Arc::new(TokioRuntime),
            )
            .map_err(|e| QuicError::Connect(format!("create endpoint with custom socket: {e}")))?
        } else {
            let tokio_sock = self.socket_config.create_tokio_socket(target_addr)?;
            let std_sock = tokio_sock.into_std()?;
            Endpoint::new(
                EndpointConfig::default(),
                None,
                std_sock,
                Arc::new(TokioRuntime),
            )
            .map_err(|e| QuicError::Connect(format!("create client endpoint: {e}")))?
        };

        let connecting = endpoint
            .connect_with(client_config, target_addr, server_name)
            .map_err(|e| {
                if let Some(r) = &recorder
                    && let Ok(mut rec) = r.lock()
                {
                    rec.mark(EventKind::QuicEnd, 0, 0);
                }
                QuicError::Connect(format!("quic dial init: {e}"))
            })?;

        let connection = match connecting.await {
            Ok(conn) => {
                if let Some(r) = &recorder
                    && let Ok(mut rec) = r.lock()
                {
                    rec.mark(EventKind::QuicEnd, 1, 0);
                }
                conn
            }
            Err(e) => {
                if let Some(r) = &recorder
                    && let Ok(mut rec) = r.lock()
                {
                    rec.mark(EventKind::QuicEnd, 0, 0);
                }
                return Err(QuicError::Connect(format!("quic handshake: {e}")));
            }
        };

        Ok(QuicConnection {
            _endpoint: endpoint,
            connection,
            recorder,
        })
    }
}

/// An established QUIC connection.
#[derive(Clone)]
pub struct QuicConnection {
    _endpoint: Endpoint,
    connection: quinn::Connection,
    recorder: Option<Arc<Mutex<Recorder>>>,
}

impl std::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConnection")
            .field("remote_address", &self.connection.remote_address())
            .field("rtt", &self.connection.rtt())
            .finish_non_exhaustive()
    }
}

impl QuicConnection {
    /// Borrows the underlying Quinn `Connection`.
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// Borrows the underlying Quinn `Endpoint`.
    pub fn endpoint(&self) -> &Endpoint {
        &self._endpoint
    }

    /// Current smoothed round-trip time.
    pub fn rtt(&self) -> Duration {
        self.connection.rtt()
    }

    /// Transport counters for this connection.
    ///
    /// Congestion window and packet loss are *state*, not ordered boundaries, so they are
    /// sampled here on demand rather than recorded as trace events; a trace stays a
    /// reproducible sequence of phase boundaries.
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }

    /// Opens a new bidirectional stream satisfying `AsyncRead + AsyncWrite + Send + Unpin`.
    pub async fn open_stream(&self) -> Result<QuicStream, QuicError> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| QuicError::Stream(format!("open bidirectional stream: {e}")))?;

        if let Some(r) = &self.recorder
            && let Ok(mut rec) = r.lock()
        {
            rec.mark(
                EventKind::QuicStreamOpen,
                send.id().index() as u32,
                1, // 1 = bidi
            );
        }

        Ok(QuicStream::new(send, recv))
    }

    /// Obtains an RFC 9221 datagram session over this connection.
    pub fn datagram_session(&self) -> QuicDatagramSession {
        QuicDatagramSession::new(self.connection.clone())
    }
}
