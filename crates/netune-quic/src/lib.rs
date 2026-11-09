// SPDX-License-Identifier: MIT

//! First-class QUIC transport (RFC 9000, RFC 9221) for netune.
//!
//! Provides identity-shaped QUIC endpoints (`QuicProfile`), pre-connect socket
//! configuration (`[INV-SOCKET-01]`, `[INV-EGRESS-01]`), RFC 9221 datagrams,
//! bidirectional byte streams (`QuicStream`), and full trace event observability.
//!
//! Enforces `[INV-QUIC-01]`: all components compile strictly against `aws-lc-rs`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod connector;
pub mod datagram;
pub mod error;
pub mod profile;
pub mod socket;
pub mod stream;

/// The owned QUIC wire codec and, eventually, the owned engine (ADR-0028).
#[cfg(feature = "owned-quic")]
pub mod wire;

/// The owned QUIC packet-protection layer (ADR-0028).
#[cfg(feature = "owned-quic")]
pub mod crypto;

pub use connector::{QuicConnection, QuicConnector};
pub use datagram::QuicDatagramSession;
pub use error::QuicError;
pub use netune_egress::EgressConfinement;
pub use profile::{CongestionAlgorithm, QuicProfile, QuicProfileRegistry, QuicTransportParameters};
pub use socket::{AsyncUdpSocket, QuicSocketConfig, RecvMeta, Transmit, UdpPoller};
pub use stream::QuicStream;

// Re-export underlying engine types needed by advanced consumers.
pub use quinn;
pub use quinn_proto;
