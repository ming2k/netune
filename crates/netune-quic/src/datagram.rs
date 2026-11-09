// SPDX-License-Identifier: MIT

//! RFC 9221 unreliable datagrams over the owned QUIC connection.

use bytes::Bytes;

use crate::error::QuicError;
use crate::owned::Connection;

/// An unreliable datagram session bound to one connection.
#[derive(Clone)]
pub struct QuicDatagramSession {
    connection: Connection,
}

impl QuicDatagramSession {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Maximum datagram payload accepted by the peer, if datagrams are enabled.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Send one unreliable datagram.
    pub async fn send(&self, data: &[u8]) -> Result<(), QuicError> {
        self.connection
            .send_datagram(Bytes::copy_from_slice(data))
            .await
    }

    /// Receive one unreliable datagram.
    pub async fn recv(&self) -> Result<Bytes, QuicError> {
        self.connection.recv_datagram().await
    }
}
