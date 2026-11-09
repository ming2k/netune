// SPDX-License-Identifier: MIT

//! HTTP/3 client and server transport adapter (RFC 9114) for netune.
//!
//! The client exposes buffered and streaming requests; the server module exposes
//! the narrow adapter the ingress orchestrator drives, so `netune-server` never
//! imports the `h3` runtime directly.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod client;
pub mod error;
pub mod profile;
pub mod server;

pub use client::{
    H3Client, H3ClientConfig, H3RequestBody, H3Response, H3ResponseStream, H3TraceContext,
};
pub use error::H3Error;
pub use profile::{H3RequestProfile, H3RequestRegistry, H3SettingsProfile, H3SettingsRegistry};
pub use server::{H3ServerConnection, H3ServerRequest, H3ServerStream};

pub use h3;
pub use h3_quinn;
