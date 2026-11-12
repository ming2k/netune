//! A bidirectional HTTP/1.1 codec we own.
//!
//! ADR-0001 removes every third-party HTTP implementation from the production
//! path because the request trace must map *bytes* to *frames* without a foreign
//! buffer in between. ADR-0011 adds the other direction of travel without
//! duplicating the wire format. This crate is that codec: it serializes and
//! parses message heads and decodes body framing — in both roles. It holds no
//! connection, no pool, no policy, no listener and no clock.
//!
//! # Two roles, one framing core
//!
//! ```text
//!                       ┌──────────────────────────┐
//!                       │ stream::Stream           │
//!   Http1Reader ───────►│  bounded line reader     │◄─────── Http1ServerReader
//!   (response direction)│  chunked decoder         │        (request direction)
//!                       │  trailers, limits        │
//!                       └──────────────────────────┘
//!        ▼                                                ▼
//!   IncomingResponse                              IncomingRequest
//!
//!   RequestHead  ──► write_request
//!   ResponseHead ──► ResponseWriter::start ──► write ──► finish
//! ```
//!
//! The body state machine is direction-agnostic, so the chunked decoder exists
//! once (`[INV-SERVER-04]`). What differs between the roles is the start line and
//! the framing *decision*, both of which live in the role's own module — the
//! request role refusing what RFC 9112 forbids a request (a close-delimited body,
//! a final coding that is not `chunked`) and the response role refusing what a
//! response may not do (a body under `204`, a `HEAD` body).
//!
//! # Scope, stated exactly
//!
//! Supported (RFC 9112):
//!
//! - request line + header serialization with a length-delimited body;
//! - status line + header serialization with a caller-chosen framing
//!   (`Content-Length`, chunked, or none), including a caller-chosen reason
//!   phrase;
//! - response status line and header parsing (case-insensitive names, duplicate
//!   headers preserved, obsolete line folding rejected);
//! - request line and header parsing, with the target preserved as raw bytes;
//! - body framing in both directions: `Content-Length`,
//!   `Transfer-Encoding: chunked` (chunk extensions and trailers), close-delimited
//!   response bodies, and the no-body cases (`HEAD`, `1xx`, `204`, `304`);
//! - hard limits on head size, header count and chunk size, with typed errors and
//!   no panics — with tighter defaults for a listener ([`Limits::for_ingress`]).
//!
//! Deliberately out of scope: HTTP/2 and above, content negotiation, routing,
//! redirects, compression, connection pooling, and listening. Those live in an
//! orchestrator (`netune` for egress, `netune-server` for ingress) or are simply
//! not needed.
//!
//! # Why `http` is still a dependency
//!
//! `http` is a *data-type* crate: `Method`, `StatusCode`, `HeaderMap`. It carries
//! no parsing, no I/O and no policy, so keeping it does not put foreign behaviour
//! in the measurement path. Everything that turns bytes into state is here.
//!
//! # Correctness posture
//!
//! Both roles are accepted against a differential oracle (hyper) over a recorded
//! corpus — hyper as *server* for our client role, hyper as *client* for our
//! server role — fuzzed for panics, and bounded by [`Limits`]. See
//! `tests/differential.rs` and `tests/differential_server.rs`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod head;
mod reader;
mod response;
mod server;
mod stream;
mod target;
mod writer;

pub use error::HttpError;
pub use head::{
    BodyKind, IncomingRequest, IncomingResponse, ReasonPhrase, RequestHead, ResponseHead,
};
pub use reader::Http1Reader;
pub use response::{ResponseWriter, write_interim};
pub use server::Http1ServerReader;
pub use stream::Limits;
pub use target::{
    TargetError, TargetForm, classify as classify_target, validate_host_bytes, validate_host_field,
};
pub use writer::{write_request, write_request_head};
