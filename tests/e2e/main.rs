//! End-to-end suite: a complete client or server lifecycle over a real socket,
//! including QUIC/HTTP/3 and WebTransport.
//!
//! Every module below is compiled into this one test binary, so the number of
//! link steps is the number of tiers, not the number of scenarios.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod http3_client;
mod http3_ingress;
mod interop;
mod quic_owned_endpoint;
mod quic_owned_server;
mod quic_transport;
mod request_lifecycle;
mod soak;
mod tls;
mod websocket;
mod websocket_guide;
mod websocket_session;
mod webtransport_security;
mod webtransport_session;
