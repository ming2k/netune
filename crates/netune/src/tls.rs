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

use std::sync::{Arc, Mutex};

use netune_trace::{Alpn, EventKind, Recorder};
use rustls::pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio_rustls::TlsConnector as RustlsConnector;

use crate::connect::{Connector, Established, Target};
use crate::error::NetError;

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
}

impl<C: Connector> Connector for TlsConnector<C> {
    async fn connect(
        &self,
        target: &Target,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, NetError> {
        let established = self.inner.connect(target, recorder).await?;
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
        let connector = RustlsConnector::from(Arc::clone(&self.config));
        let stream = connector
            .connect(name, established.stream)
            .await
            .map_err(|error| {
                NetError::Connect(format!("TLS handshake with {server_name}: {error}"))
            })?;

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
}
