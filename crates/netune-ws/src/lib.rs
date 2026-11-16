//! Pure, owned RFC 6455 WebSocket wire protocol implementation.
//!
//! Designed for the `netune` network stack:
//! - **Pure wire codec**: Zero ambient I/O runtime dependencies, zero third-party HTTP/WS crates (`[INV-TRANSPORT-00]`).
//! - **SIMD / 64-bit accelerated in-place masking** (`apply_mask`).
//! - **RFC 6455 compliance**: Control frame bounds, interleaving, and client-role masking enforcement.
//! - **Self-contained SHA-1 handshake digest** (`compute_accept_key`, `verify_handshake`).
//!
//! # Example
//!
//! ```rust
//! use netune_ws::{Limits, compute_accept_key};
//!
//! let accept = compute_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
//! assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
//! let _limits = Limits::default().with_max_frame_bytes(1024 * 1024);
//! ```

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![deny(missing_docs)]

/// Frame encoder and decoder implementations.
pub mod codec;
/// WebSocket error types.
pub mod error;
/// Wire frame vocabulary, opcodes, close codes, and codec limits.
pub mod frame;
/// RFC 6455 opening handshake key computation and verification.
pub mod handshake;
/// Frame payload masking utilities.
pub mod mask;
/// Fragmented message reassembly and close-reason parsing.
pub mod message;

pub use codec::{FrameDecoder, FrameEncoder};
pub use error::WsError;
pub use frame::{CloseCode, Frame, Limits, Opcode, Role};
pub use handshake::{
    WS_GUID, compute_accept_key, generate_key, generate_nonce, sha1, verify_handshake,
};
pub use mask::{apply_mask, generate_mask};
pub use message::{CloseReason, DataOpcode, Message, MessageAssembler};
