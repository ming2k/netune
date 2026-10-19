//! Pure, owned RFC 6455 WebSocket wire protocol implementation.
//!
//! Designed for the `netune` network stack:
//! - **Pure wire codec**: Zero ambient I/O runtime dependencies, zero third-party HTTP/WS crates (`[INV-TRANSPORT-00]`).
//! - **SIMD / 64-bit accelerated in-place masking** (`apply_mask`).
//! - **RFC 6455 compliance**: Control frame bounds, interleaving, and client-role masking enforcement.
//! - **Self-contained SHA-1 handshake digest** (`compute_accept_key`, `verify_handshake`).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod codec;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod mask;
pub mod message;

pub use codec::{FrameDecoder, FrameEncoder};
pub use error::WsError;
pub use frame::{CloseCode, Frame, Limits, Opcode, Role};
pub use handshake::{
    WS_GUID, compute_accept_key, generate_key, generate_nonce, sha1, verify_handshake,
};
pub use mask::{apply_mask, generate_mask};
pub use message::{CloseReason, Message, MessageAssembler};
