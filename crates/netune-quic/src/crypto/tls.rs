// SPDX-License-Identifier: MIT

//! `rustls` QUIC handshake wrapper.
//!
//! This is the only place where the owned engine touches the TLS state
//! machine. TLS records never cross the QUIC wire; `write_hs` bytes become
//! CRYPTO frame payloads and `read_hs` consumes peer CRYPTO payloads.

use std::sync::Arc;

use rustls::quic::{KeyChange, Version};
use rustls::{ClientConfig, ServerConfig};

use super::packet::CryptoError;

/// A client or server QUIC TLS session.
pub enum TlsSession {
    /// Client-side `rustls` QUIC connection state.
    Client(rustls::quic::ClientConnection),
    /// Server-side `rustls` QUIC connection state.
    Server(rustls::quic::ServerConnection),
}

impl TlsSession {
    /// Create a client TLS session. `transport_parameters` is the encoded
    /// QUIC transport-parameters extension.
    pub fn client(
        config: Arc<ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        transport_parameters: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        Self::client_with_version(
            config,
            server_name,
            transport_parameters,
            crate::wire::packet::VERSION_1,
        )
    }

    /// Create a client TLS session for a specific QUIC version.
    pub fn client_with_version(
        config: Arc<ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        transport_parameters: Vec<u8>,
        version: u32,
    ) -> Result<Self, CryptoError> {
        let session = rustls::quic::ClientConnection::new(
            config,
            rustls_version(version)?,
            server_name,
            transport_parameters,
        )
        .map_err(CryptoError::from)?;
        Ok(Self::Client(session))
    }

    /// Create a server TLS session.
    pub fn server(
        config: Arc<ServerConfig>,
        transport_parameters: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        Self::server_with_version(config, transport_parameters, crate::wire::packet::VERSION_1)
    }

    /// Create a server TLS session for a specific QUIC version.
    pub fn server_with_version(
        config: Arc<ServerConfig>,
        transport_parameters: Vec<u8>,
        version: u32,
    ) -> Result<Self, CryptoError> {
        let session = rustls::quic::ServerConnection::new(
            config,
            rustls_version(version)?,
            transport_parameters,
        )
        .map_err(CryptoError::from)?;
        Ok(Self::Server(session))
    }

    /// Feed peer CRYPTO bytes into TLS.
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Client(session) => session.read_hs(data),
            Self::Server(session) => session.read_hs(data),
        }
        .map_err(CryptoError::from)
    }

    /// Emit TLS handshake bytes and any new key set.
    pub fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        match self {
            Self::Client(session) => session.write_hs(out),
            Self::Server(session) => session.write_hs(out),
        }
    }

    /// The peer's transport-parameters extension, once authenticated.
    pub fn peer_transport_parameters(&self) -> Option<Vec<u8>> {
        match self {
            Self::Client(session) => session.quic_transport_parameters(),
            Self::Server(session) => session.quic_transport_parameters(),
        }
        .map(Vec::from)
    }

    /// The peer's certificate chain, when the handshake presented one.
    pub fn peer_certificates(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        match self {
            Self::Client(session) => session.peer_certificates(),
            Self::Server(session) => session.peer_certificates(),
        }
        .map(<[rustls::pki_types::CertificateDer<'static>]>::to_vec)
    }

    /// Early data keys if the resumed session offers 0-RTT.
    pub fn zero_rtt_keys(&self) -> Option<rustls::quic::DirectionalKeys> {
        match self {
            Self::Client(session) => session.zero_rtt_keys(),
            Self::Server(session) => session.zero_rtt_keys(),
        }
    }

    /// Whether the server accepted the client's 0-RTT data.
    pub fn is_early_data_accepted(&self) -> bool {
        match self {
            Self::Client(session) => session.is_early_data_accepted(),
            Self::Server(session) => session.zero_rtt_keys().is_some(),
        }
    }

    /// True until TLS reports the handshake complete.
    pub fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(session) => session.is_handshaking(),
            Self::Server(session) => session.is_handshaking(),
        }
    }

    /// The fatal alert, if TLS failed.
    pub fn alert(&self) -> Option<rustls::AlertDescription> {
        match self {
            Self::Client(session) => session.alert(),
            Self::Server(session) => session.alert(),
        }
    }
}

fn rustls_version(version: u32) -> Result<Version, CryptoError> {
    match version {
        crate::wire::packet::VERSION_1 => Ok(Version::V1),
        crate::wire::packet::VERSION_2 => Ok(Version::V2),
        _ => Err(CryptoError::NoQuicSuite),
    }
}

#[cfg(test)]
mod tests;
