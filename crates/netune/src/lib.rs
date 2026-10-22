//! `netune`: the egress path we own (ADR-0001).
//!
//! This crate is the substrate under and around the HTTP codec: resolution,
//! sockets, the byte-level tap, the connection pool and the request lifecycle.
//! `netune-http1` turns bytes into messages; `netune-trace` records what happened.
//! Nothing here is a third-party HTTP implementation.
//!
//! # Current slice
//!
//! Implemented and tested: DNS + TCP establishment with per-phase trace events,
//! TLS via rustls with the platform trust store or configurable profiles
//! ([`TlsProfile`], [`Preset`], [`TlsRouterConnector`]), [`TimedIo`] recording every
//! read/write syscall boundary, a keep-alive pool ([`Pool`]) with profile isolation
//! and transparent stale-connection recovery (`INV-TRANSPORT-01`), `TCP_INFO` sampling
//! for RTT and retransmits, HTTP `CONNECT` and SOCKS5 proxies ([`Proxy`], [`ProxyConnector`]),
//! redirect following with credential rules, streaming `Content-Encoding` decoding,
//! in-process chaos testing ([`FaultIo`]), and [`Client::send`] driving the codec end to end.
//!
//! L2 frame parsing, forging, and optional injection are housed in the companion
//! crate `netune-probe`. HTTP/2 framing is reserved in `netune-http2`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod client;
mod connect;
mod decompress;
mod dns;
mod error;
mod evasion;
mod fault;
#[cfg(feature = "http2")]
mod h2_client;
mod io;
mod pool;
mod proxy;
mod socket;
mod tcp_info;
mod tls;
mod tls_profile;
#[cfg(feature = "ws")]
mod ws;
#[cfg(feature = "ws")]
mod ws_session;

/// Capacity of the throwaway trace ring a [`Client::request`] uses.
pub const DEFAULT_TRACE_CAPACITY: usize = 1024;

pub use client::{BodyStream, Client, ClientConfig, Response};
pub use connect::{
    Connector, EgressConfinement, Established, Target, TcpConnector, Transport, is_public_ip,
};
pub use decompress::Decoder;
pub use dns::{DnsResolver, StaticResolver, SystemResolver};
pub use error::NetError;
pub use evasion::SegmentingIo;
pub use fault::{Fault, FaultIo, FaultScript};
#[cfg(feature = "http2")]
pub use h2_client::H2Client;
pub use http::{HeaderMap, Method};
pub use io::TimedIo;
pub use netune_http1::{BodyKind, RequestHead, ResponseHead};
#[cfg(feature = "http2")]
pub use netune_http2::{H2Connection, H2Fingerprint, H2Response, PseudoHeaderOrder};
#[cfg(feature = "ws")]
pub use netune_ws::{CloseCode, CloseReason, Message as WsMessage, Opcode as WsOpcode};
pub use pool::{IdleConnection, Pool, PoolConfig};
pub use proxy::{Proxy, ProxyConnector};
pub use socket::SocketConfig;
pub use tcp_info::{SAMPLE_INTERVAL, Sampler, TcpSample, sample as sample_tcp_info};
pub use tls::{TlsConnector, TlsRouterConnector, platform_client_config};
pub use tls_profile::{Preset, TlsProfile, Verifier};
#[cfg(feature = "ws")]
pub use ws::{WsHandshake, WsLimits, WsStream};
#[cfg(feature = "ws")]
pub use ws_session::{WsSession, WsSessionConfig};
