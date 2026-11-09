// SPDX-License-Identifier: MIT

//! Owned QUIC engine (ADR-0028).
//!
//! The production surface is built in layers: `core` is the sans-IO state
//! machine, `endpoint` owns UDP I/O and the async handles.

pub(crate) mod congestion;
pub(crate) mod core;
pub mod endpoint;

pub use endpoint::{
    ClientConfigOwned, Connection, Endpoint, RecvStream, SendStream, ServerConfigOwned,
};
