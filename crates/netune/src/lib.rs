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
//! TLS via rustls by default, or the owned engine when a fingerprint profile
//! is selected ([`TlsProfile`], [`Preset`], [`TlsRouterConnector`]), [`TimedIo`] recording every
//! read/write syscall boundary, a keep-alive pool ([`Pool`]) with profile isolation
//! and replay-safe stale-connection recovery (`INV-TRANSPORT-01..06`), `TCP_INFO` sampling
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
//! crate `netune-probe`; nothing there is linked by default. [`Client`] executes HTTP/1.1,
//! HTTP/2 (via [`netune_http2::H2ClientSession`] when `http2` is enabled), and HTTP/3 (via
//! [`netune_http3::H3Session`] when `http3` is enabled) uniformly behind [`RoundTrip`]
//! ([`Wire`] for real connections and [`mock::Mock`] for scripted tests), with buffered or
//! streaming [`RequestBody`] uploads and a shared [`Pool`].
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
#![deny(missing_docs)]

// The documentation's Rust examples are compiled by doctest; see this module
// for why, and for the one rule it imposes on how a guide fences its code.
#[cfg(doctest)]
mod doc_examples;

mod body;
mod client;
mod connect;
mod decompress;
mod dns;
mod error;
mod evasion;
mod exchange;
mod fault;
mod handshake;
pub mod mock;
mod pool;
mod profile;
mod proxy;
mod redirect;
mod socket;
mod tcp_info;
mod tls;
mod tls_profile;
mod udp;
mod wire;
#[cfg(feature = "ws")]
mod ws;
#[cfg(feature = "ws")]
mod ws_session;

/// Capacity of the throwaway trace ring a [`Client::request`] uses.
pub const DEFAULT_TRACE_CAPACITY: usize = 1024;

pub use body::{Body, BodyState};
pub use client::{Client, ClientBuilder, ClientConfig, Observation, Response, TraceConfig};
pub use connect::{
    ConfinementRefused, Connector, EgressConfinement, Established, HttpProtocol, TappedSocket,
    Target, TcpConnector, Transport, Untapped, is_public_ip,
};
pub use decompress::Decoder;
pub use dns::{DnsResolver, StaticResolver, SystemResolver};
pub use error::{
    AttemptError, ConnectError, ConnectErrorKind, NetError, ResolveError, ResolveErrorKind,
};
pub use evasion::SegmentingIo;
pub use exchange::{
    Attempt, BodySource, BoxFuture, Exchange, ObservationLevel, Released, Request, RequestBody,
    RequestBodySource, RequestStream, RoundTrip,
};
pub use fault::FaultConnector;
pub use http::{HeaderMap, Method};
pub use netune_http1::{BodyKind, Limits, RequestHead, ResponseHead};
#[cfg(feature = "http2")]
pub use netune_http2::{
    H2ClientConnection, H2ConnectionProfile, H2Fingerprint, H2RequestProfile, H2Response,
    PseudoHeaderOrder,
};
/// The byte-path instrumentation, re-exported so a consumer of `netune` reaches
/// [`TimedIo`] and [`FaultIo`] without naming the leaf crate. They live in
/// `netune-io` because ingress needs the identical tap and the two
/// orchestrators must not depend on each other (ADR-0011).
pub use netune_io::{Fault, FaultIo, FaultScript, TimedIo};
pub use netune_tls::handshake::ServerCertVerifier;
pub use netune_trace::{
    ConnectionIdentity, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EvasionPolicy, Fidelity,
    RequestTrace, SocketTap, TapArtifact, TraceCollector,
};
#[cfg(feature = "ws")]
pub use netune_ws::{CloseCode, CloseReason, Message as WsMessage, Opcode as WsOpcode};
pub use pool::{IdleConnection, Pool, PoolConfig, PoolKey};
pub use profile::{
    ConnectionPlan, H1Registry, H1WireProfile, HeaderCasing, Http2Mode, PlannedTransport, ProfileId,
};
#[cfg(feature = "http2")]
pub use profile::{H2Registry, H2RequestRegistry};
pub use proxy::{Proxy, ProxyConnector};
pub use socket::SocketConfig;
pub use tcp_info::{SAMPLE_INTERVAL, Sampler, TcpSample, sample as sample_tcp_info};
pub use tls::{OwnedVerifier, TlsRouterConnector};
pub use tls_profile::{Preset, TlsProfile};
pub use udp::{
    DatagramConnector, DatagramTransport, EstablishedDatagrams, Socks5DatagramConnector,
    UdpConnector,
};
pub use wire::Wire;
#[cfg(feature = "ws")]
pub use ws::{WsHandshake, WsIo, WsLimits, WsStream};
#[cfg(feature = "ws")]
pub use ws_session::{WsSession, WsSessionConfig};

/// Re-exported QUIC transport types when `--features quic` is enabled.
#[cfg(feature = "quic")]
pub mod quic {
    pub use netune_quic::*;
}

/// Re-exported HTTP/3 client and server types when `--features http3` is enabled.
#[cfg(feature = "http3")]
pub mod http3 {
    pub use netune_http3::*;
}
