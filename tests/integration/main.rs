//! External integration suite: codecs and orchestrators against hermetic
//! loopback peers, TLS fixtures and both sides of a scripted exchange.
//!
//! Every module below is compiled into this one test binary. Adding a case
//! means adding a module, not a second executable and a second link step.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod client_h2_integration;
mod diagnostics;
mod evasion;
mod http2_server;
mod ingress;
mod listener_events;
mod mock;
mod overhead;
mod owned_tls;
mod policy;
mod pool_runtime_affinity;
mod production;
mod proxy;
mod serve_http_guide;
mod server_tls;
mod tls_router;
mod udp_socks5;
