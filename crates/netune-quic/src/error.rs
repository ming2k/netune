// SPDX-License-Identifier: MIT

//! Error types for QUIC transport operations.

/// Errors arising during QUIC endpoint, connection, stream, or datagram operations.
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    /// DNS resolution failed for the remote endpoint.
    #[error("dns resolution failed for {host}: {detail}")]
    Dns { host: String, detail: String },

    /// Socket binding or option configuration failed.
    #[error("socket configuration failed: {0}")]
    Socket(#[from] std::io::Error),

    /// Connection failed or was terminated by peer.
    #[error("connection failed: {0}")]
    Connect(String),

    /// The operation timed out.
    #[error("quic operation timed out")]
    Timeout,

    /// Stream operation failed (reset or closed by peer).
    #[error("quic stream error: {0}")]
    Stream(String),

    /// Datagram payload exceeded the negotiated maximum datagram size (RFC 9221, [INV-QUIC-04]).
    #[error("datagram payload too large: {size} bytes exceeds maximum allowed {max} bytes")]
    DatagramTooLarge { max: usize, size: usize },

    /// Datagrams are not supported by the remote peer.
    #[error("datagrams are not supported or enabled on this quic connection")]
    DatagramsNotSupported,

    /// TLS configuration error.
    #[error("tls configuration error: {0}")]
    Tls(String),

    /// General configuration or parameter error.
    #[error("quic configuration error: {0}")]
    Config(String),

    /// Protocol violation or malformed owned-QUIC state.
    #[error("quic protocol error: {0}")]
    Protocol(String),

    /// The connection has been closed.
    #[error("quic connection closed: {0}")]
    Closed(String),
}

impl From<crate::crypto::CryptoError> for QuicError {
    fn from(error: crate::crypto::CryptoError) -> Self {
        match error {
            crate::crypto::CryptoError::Handshake(message) => Self::Tls(message),
            other => Self::Protocol(other.to_string()),
        }
    }
}
