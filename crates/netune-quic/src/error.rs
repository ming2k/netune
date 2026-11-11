// SPDX-License-Identifier: MIT

//! Error types for QUIC transport operations.

use netune_trace::{Diagnose, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, RetryVerdict};

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

impl Diagnose for QuicError {
    fn diagnostic(&self) -> DiagnosticRecord {
        let (code, phase, retry) = match self {
            Self::Dns { .. } => (
                DiagnosticCode::EGRESS_DNS_FAILED,
                DiagnosticPhase::Dns,
                RetryVerdict::Retryable,
            ),
            Self::Socket(_) => (
                DiagnosticCode::EGRESS_IO,
                DiagnosticPhase::Tcp,
                RetryVerdict::Retryable,
            ),
            Self::Connect(_) => (
                DiagnosticCode::EGRESS_QUIC_FAILED,
                DiagnosticPhase::Quic,
                RetryVerdict::Retryable,
            ),
            Self::Timeout => (
                DiagnosticCode::EGRESS_TIMEOUT,
                DiagnosticPhase::Quic,
                RetryVerdict::Retryable,
            ),
            Self::Stream(_) => (
                DiagnosticCode::EGRESS_QUIC_FAILED,
                DiagnosticPhase::Quic,
                RetryVerdict::Conditional,
            ),
            Self::DatagramTooLarge { .. } | Self::DatagramsNotSupported => (
                DiagnosticCode::EGRESS_CONFIG,
                DiagnosticPhase::Quic,
                RetryVerdict::Terminal,
            ),
            Self::Tls(_) => (
                DiagnosticCode::EGRESS_TLS_FAILED,
                DiagnosticPhase::Tls,
                RetryVerdict::Terminal,
            ),
            Self::Config(_) | Self::Protocol(_) => (
                DiagnosticCode::EGRESS_QUIC_FAILED,
                DiagnosticPhase::Quic,
                RetryVerdict::Terminal,
            ),
            Self::Closed(_) => (
                DiagnosticCode::EGRESS_QUIC_FAILED,
                DiagnosticPhase::Quic,
                RetryVerdict::Conditional,
            ),
        };
        let mut record = DiagnosticRecord::new(code)
            .with_phase(phase)
            .with_retry(retry)
            .with_message(self.to_string());
        if let Self::DatagramTooLarge { max, size } = self {
            record = record
                .with_field("max", max.to_string())
                .with_field("size", size.to_string());
        }
        record
    }
}

impl QuicError {
    /// The registered diagnostic for this failure.
    pub fn diagnostic(&self) -> DiagnosticRecord {
        <Self as Diagnose>::diagnostic(self)
    }
}

impl From<crate::crypto::CryptoError> for QuicError {
    fn from(error: crate::crypto::CryptoError) -> Self {
        match error {
            crate::crypto::CryptoError::Handshake(message) => Self::Tls(message),
            other => Self::Protocol(other.to_string()),
        }
    }
}
