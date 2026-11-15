//! Test-only infrastructure shared by the workspace suites.
//!
//! This crate is a `dev-dependency` everywhere it appears. It exists so a test
//! states the behaviour it proves instead of re-deriving the same scripted
//! transport, loopback pair or self-signed TLS identity. Nothing here ships.
//!
//! Three rules keep it infrastructure rather than a second product:
//!
//! * it depends on no workspace crate, so it cannot encode transport policy;
//! * no production manifest may name it, which the architecture gate enforces;
//! * helpers are deterministic and hermetic: loopback only, no live network and
//!   no sleep-based synchronisation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod fuzz;
pub mod http1;
pub mod net;
pub mod scripted;
pub mod tls;

pub use http1::{CHUNKED_RESPONSE, CONTENT_LENGTH_RESPONSE, UNTIL_CLOSE_RESPONSE};
pub use scripted::ScriptedIo;
