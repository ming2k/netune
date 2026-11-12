// SPDX-License-Identifier: MIT

//! First-class QUIC transport (RFC 9000, RFC 9221) for netune.
//!
//! Provides identity-shaped QUIC endpoints (`QuicProfile`), pre-connect socket
//! configuration (`[INV-SOCKET-01]`, `[INV-EGRESS-01]`), owned handshake and
//! stream state (ADR-0028), and deterministic trace boundaries.
//!
//! Enforces `[INV-QUIC-01]`: all components compile strictly against `aws-lc-rs`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod connector;
pub mod datagram;
pub mod error;
pub mod profile;
pub mod socket;

pub mod crypto;
pub mod owned;
pub mod wire;

pub use connector::{QuicConnection, QuicConnector, QuicResolver, SystemQuicResolver};
pub use datagram::QuicDatagramSession;
pub use error::QuicError;
pub use netune_egress::EgressConfinement;
pub use owned::congestion::{CongestionController, CongestionControllerFactory};
pub use profile::{CongestionAlgorithm, QuicProfile, QuicProfileRegistry, QuicTransportParameters};
pub use socket::{QuicSocketConfig, QuicUdpSocket, QuicUdpSocketFactory, TokioUdpSocketFactory};
