//! A modern, fingerprint-aware HTTP/2 implementation we own (RFC 9113, RFC 7541).
//!
//! # Two roles, one connection machine
//!
//! ```text
//!                    ┌───────────────────────────────┐
//!   client::H2Client │ connection::H2Connection      │ server::ServerSession
//!   (preface, odd    │  frame read/write, SETTINGS,  │ (stream table, receive
//!    stream ids,     │  PING, GOAWAY, HPACK table,   │  window, dispatch)
//!    fingerprint)    │  CONTINUATION reassembly      │
//!                    └───────────────────────────────┘
//! ```
//!
//! The connection layer is direction-agnostic in every place where a bug is expensive — frame
//! bounds, `CONTINUATION` contiguity, SETTINGS application, flow-control accounting — and takes
//! the [`connection::Role`] as a parameter. A second implementation of those rules would be a
//! second place a fix can be forgotten, which is the argument ADR-0011 made for HTTP/1.1's
//! chunked decoder and it holds here for frame sequencing.
//!
//! # Scope
//!
//! Supported (RFC 9113, RFC 7541):
//!
//! - the connection preface, `SETTINGS` exchange with acknowledgement, `PING` echo and
//!   `GOAWAY` bookkeeping, in both roles;
//! - `HEADERS` / `CONTINUATION` writing split at the peer's `MAX_FRAME_SIZE`, and reading with
//!   contiguity enforced;
//! - `PADDED` and `PRIORITY` flags on `DATA` / `HEADERS` / `PUSH_PROMISE`, stripped once for both
//!   roles, so a padding client cannot crash a server and a padded response cannot corrupt a
//!   decoder;
//! - HPACK with a dynamic table in both directions, including size updates and the RFC's "at most
//!   two, before the first field" rule;
//! - per-stream and connection-level flow control, with the peer's
//!   `INITIAL_WINDOW_SIZE` change applied retroactively to open streams;
//! - a server stream table with `REFUSED_STREAM` shedding, `RST_STREAM` cancellation, and
//!   contiguous `DATA` delivery to a handler;
//! - Akamai fingerprint impersonation for the client role (ordered `SETTINGS`, initial window
//!   update, pseudo-header order).
//!
//! Deliberately out of scope: server push (never sent, `ENABLE_PUSH=0`), priority *scheduling*
//! (`PRIORITY` frames are accepted and ignored, as §5.3.1 permits), `h2c` upgrade (a plaintext
//! connection is prior-knowledge HTTP/2 or HTTP/1.1, never both), and HTTP/3.
//!
//! # Observability
//!
//! This crate records nothing itself: it is a codec, and a codec that read a clock would break
//! `INV-TRACE-01`. The server role accepts a `Recorder` because a multiplexed connection's facts
//! must carry their stream identity, and only the layer that knows the stream can attach it.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod client;
pub mod connection;
pub mod error;
pub mod fingerprint;
pub mod frame;
pub mod hpack;
pub mod huffman;
mod huffman_table;
pub mod server;

pub use client::{
    H2ClientConnection, H2Response, H2ResponseEvent, H2ResponseHead, H2ResponseStream,
};
pub use connection::{
    CLIENT_PREFACE, DEFAULT_MAX_FRAME_SIZE, DEFAULT_WINDOW, LocalSettings, MAX_MAX_FRAME_SIZE,
    MIN_MAX_FRAME_SIZE, PeerSettings, Role, error_code,
};
pub use error::H2Error;
pub use fingerprint::{H2Fingerprint, PseudoHeaderOrder};
pub use frame::{
    FRAME_CONTINUATION, FRAME_DATA, FRAME_GOAWAY, FRAME_HEADERS, FRAME_PING, FRAME_PRIORITY,
    FRAME_PUSH_PROMISE, FRAME_RST_STREAM, FRAME_SETTINGS, FRAME_WINDOW_UPDATE, Frame, FrameHeader,
    SETTING_ENABLE_PUSH, SETTING_HEADER_TABLE_SIZE, SETTING_INITIAL_WINDOW_SIZE,
    SETTING_MAX_CONCURRENT_STREAMS, SETTING_MAX_FRAME_SIZE, SETTING_MAX_HEADER_LIST_SIZE,
};
pub use hpack::{HpackDecoder, HpackEncoder};
pub use server::{
    H2Body, H2Handler, H2Request, H2Response as H2ServerResponse, H2ResponseBody, NoObserver,
    ServerSession, ServerSessionConfig, SessionEnd, SessionObserver, StreamEvent,
};
