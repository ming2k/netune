//! `netune-server`: the ingress path we own — HTTP/1.1, HTTP/2, and optional HTTP/3, over one handler.
//!
//! This is the peer orchestrator to `netune`. Where `netune` opens sockets outward — resolution,
//! confinement, TLS identity, pooling — this crate accepts them inward and answers. Neither depends on
//! the other; both draw on the same leaves (`netune-http1`, `netune-http2`, `netune-trace`,
//! `netune-io`), which is what makes a request served here and a request sent by `netune` measurable
//! on one clock ([ADR-0011]).
//!
//! # What this crate is, and what it refuses to be
//!
//! It is a **transport**: a listener with admission control, slow-peer bounds, per-connection tracing,
//! graceful drain, and all supported application protocols. HTTP/3 is a peer QUIC listener
//! ([ADR-0025](../../docs/adr/0025-h3-ingress-peer-transport.md)), not a mode of the TCP `Server`. It is **not a web framework**: there is no routing
//! table, no extractor, no middleware stack, no `#[get]` macro, and no JSON. A request arrives, a
//! [`Handler`] is called with the head and a body reader, and a [`Response`] is written. Everything
//! above that — which path maps to which function, what a body means, whether a route exists — is the
//! application's business, and putting it here would make the transport opinionated about things it
//! cannot see.
//!
//! # One handler, three protocols
//!
//! ```text
//!        ALPN `h2` or a `PRI *` preface          ┌────────────────────┐
//!   ───────────────────────────────────────────► │ netune-http2       │ ──┐
//!                                                │  hpack, framing,   │   │
//!        everything else                         │  flow control      │   │
//!   ───────────────────────────────────────────► │ netune-http1       │ ──┤──► Handler::handle
//!                                                │  both roles        │   │      one function
//!                                                └────────────────────┘   │
//!                                                                         ▼
//!                                                                    Response
//! ```
//!
//! The protocol is chosen once per connection, from the first bytes or from ALPN — never upgraded in
//! place, because an in-place upgrade is both a request-smuggling surface and a second parser on one
//! socket. Above that decision an application writes one handler: the [`IncomingRequest`] it receives
//! carries the same method, target, headers and body framing whichever wire it arrived on, and a
//! `Host`/`:authority` mismatch is synthesised away so exactly one field names the authority.
//!
//! HTTP/3 is a peer listener (the `H3Server` type, feature `http3`) rather than a branch in the TCP protocol
//! selector, but it calls the same [`Handler`] with the same [`IncomingRequest`] and [`RequestBody`].
//!
//! # The order of operations, and why it is that order
//!
//! ```text
//! accept ─► permit ─► record ─► protocol ─► head (bounded) ─► handler ─► response ─► reuse?
//!   │         │         │           │            │              │           │
//!   │         │         │           │            └── timeouts ──┘           │
//!   │         │         │           └── decided from the first bytes       │
//!   │         │         └── ingress trace begins here                      │
//!   │         └── concurrency cap: shed, do not queue unboundedly          └── drain waits here
//!   └── kernel handover: the earliest fact a server can know
//! ```
//!
//! A request is fully bounded *before* the handler runs (`[INV-SERVER-03]`), so a hostile peer can
//! consume neither worker time nor memory the operator did not grant. The timeouts bracket each phase
//! separately, because "the client is slow to start", "the client is slow to upload", "the handler is
//! slow" and "the client will not read" are four different problems with four different responses.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use netune_server::{Handler, HandlerFuture, RequestBody, Response, Server, ServerConfig};
//! use netune_server::IncomingRequest;
//!
//! struct Echo;
//!
//! impl Handler for Echo {
//!     fn handle<'a>(
//!         &'a self,
//!         _request: IncomingRequest,
//!         mut body: RequestBody<'a>,
//!     ) -> HandlerFuture<'a> {
//!         Box::pin(async move {
//!             let bytes = body.read_to_end().await.unwrap_or_default();
//!             Response::ok(bytes)
//!         })
//!     }
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let server = Server::bind("127.0.0.1:0", ServerConfig::default(), Arc::new(Echo)).await?;
//! println!("listening on {}", server.local_addr());
//! // `serve` returns when its shutdown future resolves and every in-flight request has drained or the
//! // drain deadline expired.
//! server.serve(async { /* a signal future */ }).await;
//! # Ok(())
//! # }
//! ```
//!
//! # Streaming
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use netune_server::{Handler, HandlerFuture, RequestBody, Response, Server, ServerConfig};
//! use netune_server::IncomingRequest;
//!
//! struct Tokens;
//!
//! impl Handler for Tokens {
//!     fn handle<'a>(
//!         &'a self,
//!         _request: IncomingRequest,
//!         _body: RequestBody<'a>,
//!     ) -> HandlerFuture<'a> {
//!         Box::pin(async move {
//!             // The transport pulls from this receiver: each token reaches the peer as it is produced,
//!             // framed chunked on HTTP/1.1 and as `DATA` frames on HTTP/2.
//!             let (tx, rx) = tokio::sync::mpsc::channel(4);
//!             tokio::spawn(async move {
//!                 for word in ["hello", " ", "world"] {
//!                     if tx.send(bytes::Bytes::from_static(word.as_bytes())).await.is_err() {
//!                         return;
//!                     }
//!                 }
//!             });
//!             Response::stream(http::StatusCode::OK, rx)
//!         })
//!     }
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let server = Server::bind("127.0.0.1:0", ServerConfig::default(), Arc::new(Tokens)).await?;
//! server.serve(async {}).await;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// The documentation's Rust examples are compiled by doctest; see this module for why, and for the one
// rule it imposes on how a guide fences its code.
#[cfg(doctest)]
mod doc_examples;

mod body;
mod config;
mod date;
mod h1;
#[cfg(feature = "http2")]
mod h2;
#[cfg(feature = "http3")]
mod h3;
mod handler;
mod panic;
mod service;
#[cfg(feature = "tls")]
mod tls;
mod write_deadline;

pub use body::RequestBody;
pub use config::{
    CollectingObserver, H2Ingress, Protocols, ServerConfig, SinkObserver, TraceObserver,
    log_from_events,
};
#[cfg(feature = "tls")]
pub use config::{ConfigSelector, TlsTermination};
#[cfg(feature = "http3")]
pub use h3::H3Server;
pub use handler::{
    BodyStream, ChunkFuture, ChunkResult, Handler, HandlerFuture, Response, ResponseBody,
};
#[cfg(feature = "http3")]
pub use netune_http3::H3SettingsProfile;
pub use service::{BindError, DiscardingObserver, IngressTrace, ServedProtocol, Server};

/// The stable numeric codes an ingress trace carries for a terminal failure.
///
/// Codes, not strings: an aggregate filters on them without parsing English, and they survive a trace
/// being serialized and read elsewhere. Exposed because a consumer that counts failures has to know
/// what it is counting.
pub use h1::{
    ERROR_BODY_TIMEOUT, ERROR_HANDLER_PANIC, ERROR_HANDLER_TIMEOUT, ERROR_HEAD_TIMEOUT,
    ERROR_INCOMPLETE, ERROR_INVALID_REQUEST, ERROR_IO, ERROR_LIMIT, ERROR_PROTOCOL,
    ERROR_TLS_HANDSHAKE,
};

/// The HTTP/1.1 request type this crate serves.
///
/// Re-exported rather than redefined: a consumer that already speaks `netune-http1` must not discover
/// a second, subtly different request.
pub use netune_http1::{BodyKind, IncomingRequest, Limits, ReasonPhrase, ResponseHead, TargetForm};

/// The HTTP/2 session vocabulary, for a consumer that wants to build its own protocol adapter.
#[cfg(feature = "http2")]
pub use netune_http2::server::{
    H2Request, H2Response as H2ServerResponse, H2ResponseBody, SessionEnd, StreamEvent,
};
