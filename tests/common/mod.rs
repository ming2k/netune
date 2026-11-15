//! Shared fixtures for the workspace's external suites.
//!
//! An external test lives here when it exercises a socket, a real handshake or
//! both orchestrators together. Pure codec corpora and differential oracles
//! stay beside their crate. The split is deliberate: these modules are linked
//! into one integration binary and one end-to-end binary, so a new case adds a
//! module instead of a second executable and a second link step.

#![allow(dead_code, unused_imports)]

pub mod net;
pub mod server;
pub mod tls;

pub use netune_test_support::{ScriptedIo, http1};
