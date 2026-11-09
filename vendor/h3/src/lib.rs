//! HTTP/3 client and server
#![deny(missing_docs, clippy::self_named_module_files)]
#![allow(clippy::derive_partial_eq_without_eq)]
// Vendored upstream warnings retained by the narrow ADR-0023 fork. The fork's
// behavioural diff is limited to request-header ordering; these are upstream
// lints, not new code.
#![allow(dead_code, unused_variables, mismatched_lifetime_syntaxes)]

pub mod client;

/// Explicit request-header order for the client QPACK encoder.
pub use proto::headers::RequestHeaderOrder;

mod config;
//pub mod error;
pub mod ext;
pub mod quic;

pub mod server;

//pub use error::Error;

mod buf;

mod shared_state;

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
pub use shared_state::{ConnectionState, SharedState};

pub mod error;

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
#[allow(missing_docs)]
pub mod connection;
#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
#[allow(missing_docs)]
pub mod frame;
#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
#[allow(missing_docs)]
pub mod proto;
#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
#[allow(missing_docs)]
pub mod stream;
#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
#[allow(missing_docs)]
pub mod webtransport;

#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
mod connection;
#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
mod frame;
#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
mod proto;
#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
mod stream;
#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
mod webtransport;

#[allow(dead_code)]
mod qpack;
// Upstream integration tests import the sibling `h3-quinn` checkout by a
// relative path that does not exist in this vendored layout. They are opt-in;
// the fork's own header-order unit tests live beside the code they exercise.
#[cfg(all(test, feature = "upstream-tests"))]
mod tests;
#[cfg(test)]
extern crate self as h3;
