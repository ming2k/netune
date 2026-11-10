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
//! Datagrams are a second, parallel path rather than a mode of the first
//! ([`DatagramConnector`], [`DatagramTransport`], [`UdpConnector`],
//! [`Socks5DatagramConnector`]). A session is connected to one peer, decided when it
//! opens, so egress confinement stays a precondition of opening a socket instead of a
//! per-datagram filter. See `docs/adr/0008`.
//!
//! REALITY client authentication is deliberately absent: it needs a caller-chosen
//! ClientHello `legacy_session_id` and a verifier that accepts a certificate without a
//! CA chain, and neither is expressible through `rustls`' public API. See
//! `docs/adr/0009` for the evidence and for what would reopen the question.
//!
//! L2 frame parsing, capture, forging and optional injection are housed in the companion
//! crate `netune-probe`; nothing there is linked by default. HTTP/2 is implemented in
//! `netune-http2` and driven through [`H2Client`] when the `http2` feature is on.
//!
//! # This crate is one direction of travel
//!
//! `netune` opens sockets outward. It never listens, accepts, or keeps a server
//! session table; those belong to `netune-server`, the peer orchestrator, which
//! depends on the same codec and trace leaves and on no crate here
//! (ADR-0011). The byte-path instrumentation both directions need
//! ([`TimedIo`], [`FaultIo`]) is re-exported from `netune-io` rather than
//! defined here, so honoring that boundary costs a consumer nothing.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// The documentation's Rust examples are compiled by doctest; see this module
// for why, and for the one rule it imposes on how a guide fences its code.
#[cfg(doctest)]
mod doc_examples;

mod client;
mod connect;
mod decompress;
mod dns;
mod error;
mod evasion;
#[cfg(feature = "http2")]
mod h2_client;
mod handshake;
mod pool;
mod profile;
mod proxy;
mod socket;
mod tcp_info;
mod tls;
mod tls_profile;
mod udp;
#[cfg(feature = "ws")]
mod ws;
#[cfg(feature = "ws")]
mod ws_session;

/// Capacity of the throwaway trace ring a [`Client::request`] uses.
pub const DEFAULT_TRACE_CAPACITY: usize = 1024;

pub use client::{BodyStream, Client, ClientConfig, Observation, Response, TraceConfig};
pub use connect::{
    ConfinementRefused, Connector, EgressConfinement, Established, Target, TcpConnector, Transport,
    is_public_ip,
};
pub use decompress::Decoder;
pub use dns::{DnsResolver, StaticResolver, SystemResolver};
pub use error::NetError;
pub use evasion::SegmentingIo;
#[cfg(feature = "http2")]
pub use h2_client::H2Client;
pub use http::{HeaderMap, Method};
pub use netune_http1::{BodyKind, RequestHead, ResponseHead};
#[cfg(feature = "http2")]
pub use netune_http2::{
    H2ClientConnection, H2ConnectionProfile, H2Fingerprint, H2RequestProfile, H2Response,
    PseudoHeaderOrder,
};
/// The byte-path instrumentation, re-exported so a consumer of `netune` reaches
/// [`TimedIo`] and [`FaultIo`] without naming the leaf crate. They live in
/// `netune-io` because ingress needs the identical tap and the two
/// orchestrators must not depend on each other (ADR-0011).
pub use netune_io::{Fault, FaultIo, FaultScript, RingIo, TimedIo};
pub use netune_trace::{ConnectionIdentity, EvasionPolicy, Fidelity, RequestTrace, TraceCollector};
#[cfg(feature = "ws")]
pub use netune_ws::{CloseCode, CloseReason, Message as WsMessage, Opcode as WsOpcode};
pub use pool::{IdleConnection, Pool, PoolConfig, PoolKey};
pub use profile::{ConnectionPlan, H1Registry, H1WireProfile, HeaderCasing, ProfileId};
#[cfg(feature = "http2")]
pub use profile::{H2Registry, H2RequestRegistry};
pub use proxy::{Proxy, ProxyConnector};
pub use socket::SocketConfig;
pub use tcp_info::{SAMPLE_INTERVAL, Sampler, TcpSample, sample as sample_tcp_info};
pub use tls::{TlsConnector, TlsRouterConnector, platform_client_config};
pub use tls_profile::{Preset, TlsProfile, Verifier};
pub use udp::{
    DatagramConnector, DatagramTransport, EstablishedDatagrams, Socks5DatagramConnector,
    UdpConnector,
};
#[cfg(feature = "ws")]
pub use ws::{WsHandshake, WsLimits, WsStream};
#[cfg(feature = "ws")]
pub use ws_session::{WsSession, WsSessionConfig};

#[cfg(feature = "quic")]
pub mod quic {
    pub use netune_quic::*;
}

#[cfg(feature = "http3")]
pub mod http3 {
    pub use netune_http3::*;
}
