// SPDX-License-Identifier: MIT

//! Unreliable datagram transport over QUIC (RFC 9221).
//!
//! Enforces `[INV-QUIC-04]`: an attempt to transmit a datagram payload exceeding the
//! peer's advertised maximum datagram size fails predictably with
//! `QuicError::DatagramTooLarge` rather than silently vanishing.

use bytes::Bytes;

use crate::error::QuicError;

/// Manages unreliable datagram transmission and reception for a QUIC connection.
#[derive(Debug, Clone)]
pub struct QuicDatagramSession {
    connection: quinn::Connection,
}

impl QuicDatagramSession {
    /// Creates a new datagram session wrapping an established connection.
    pub fn new(connection: quinn::Connection) -> Self {
        Self { connection }
    }

    /// Maximum datagram payload size supported by the remote peer.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Sends an unreliable datagram to the peer (RFC 9221).
    pub fn send(&self, data: &[u8]) -> Result<(), QuicError> {
        let max = self
            .connection
            .max_datagram_size()
            .ok_or(QuicError::DatagramsNotSupported)?;

        if data.len() > max {
            return Err(QuicError::DatagramTooLarge {
                max,
                size: data.len(),
            });
        }

        self.connection
            .send_datagram(Bytes::copy_from_slice(data))
            .map_err(|e| QuicError::Stream(format!("send datagram failed: {e}")))
    }

    /// Receives an unreliable datagram from the peer.
    pub async fn recv(&self) -> Result<Bytes, QuicError> {
        self.connection
            .read_datagram()
            .await
            .map_err(|e| QuicError::Stream(format!("read datagram failed: {e}")))
    }
}
