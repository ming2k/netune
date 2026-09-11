//! `netune`: the egress path we own (ADR-0200).
//!
//! This crate is the substrate under and around the HTTP codec: resolution,
//! sockets, the byte-level tap, the connection pool and the request lifecycle.
//! `netune-http1` turns bytes into messages; `netune-trace` records what happened.
//! Nothing here is a third-party HTTP implementation.
//!
//! # Current slice
//!
//! Implemented and tested: DNS + TCP establishment with per-phase trace events,
//! TLS via rustls with the platform trust store, [`TimedIo`] recording every
//! read/write syscall boundary, a keep-alive pool whose reuse is recorded as
//! [`netune_trace::EventKind::ConnectReused`], `TCP_INFO` sampling for RTT and
//! retransmits, redirect following with credential rules, streaming
//! `Content-Encoding` decoding, and [`Client::send`] driving the codec end to
//! end.
//!
//! Not yet in: proxies and the L2 probe. Each is additive at an existing seam,
//! not a redesign.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod client;
mod connect;
mod decompress;
mod error;
mod fault;
mod io;
mod pool;
mod proxy;
mod tcp_info;
mod tls;
mod tls_profile;

/// Capacity of the throwaway trace ring a [`Client::request`] uses.
pub const DEFAULT_TRACE_CAPACITY: usize = 1024;

pub use client::{BodyStream, Client, ClientConfig, Response};
pub use connect::{
    Connector, EgressConfinement, Established, Target, TcpConnector, Transport, is_public_ip,
};
pub use decompress::Decoder;
pub use error::NetError;
pub use fault::{Fault, FaultIo, FaultScript};
pub use http::{HeaderMap, Method};
pub use io::TimedIo;
pub use netune_http1::{BodyKind, RequestHead, ResponseHead};
pub use pool::{IdleConnection, Pool, PoolConfig};
pub use proxy::{Proxy, ProxyConnector};
pub use tcp_info::{SAMPLE_INTERVAL, Sampler, TcpSample, sample as sample_tcp_info};
pub use tls::{TlsConnector, TlsRouterConnector, platform_client_config};
pub use tls_profile::{Preset, TlsProfile, Verifier};
