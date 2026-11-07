// SPDX-License-Identifier: MIT

//! Error types for HTTP/3 client operations.

/// Errors arising during HTTP/3 client connection, framing, or request execution.
#[derive(Debug, thiserror::Error)]
pub enum H3Error {
    /// QUIC transport error.
    #[error("quic transport error: {0}")]
    Quic(#[from] netune_quic::QuicError),

    /// HTTP/3 handshake or framing error.
    #[error("http3 error: {0}")]
    H3(String),

    /// HTTP request construction or validation failed.
    #[error("http error: {0}")]
    Http(#[from] http::Error),

    /// Request execution timed out.
    #[error("http3 request timed out")]
    Timeout,
}
