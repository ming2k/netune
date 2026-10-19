//! A modern, fingerprint-aware HTTP/2 wire protocol implementation (RFC 9113, ADR-0006).
//!
//! Provides byte-level framing, HPACK header compression (RFC 7541), client connection
//! lifecycle management, and full declarative Akamai HTTP/2 fingerprint impersonation
//! (Chrome, Safari, Firefox).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod connection;
pub mod error;
pub mod fingerprint;
pub mod frame;
pub mod hpack;
pub mod huffman;

pub use connection::{CLIENT_PREFACE, H2Connection, H2Response};
pub use error::H2Error;
pub use fingerprint::{H2Fingerprint, PseudoHeaderOrder};
pub use frame::{
    FRAME_DATA, FRAME_HEADERS, FRAME_PING, FRAME_SETTINGS, FRAME_WINDOW_UPDATE, Frame, FrameHeader,
    SETTING_ENABLE_PUSH, SETTING_HEADER_TABLE_SIZE, SETTING_INITIAL_WINDOW_SIZE,
    SETTING_MAX_CONCURRENT_STREAMS, SETTING_MAX_FRAME_SIZE, SETTING_MAX_HEADER_LIST_SIZE,
};
pub use hpack::{HpackDecoder, HpackEncoder};
