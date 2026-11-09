// SPDX-License-Identifier: MIT

//! Owned QUIC packet protection (RFC 9001), backed by `rustls`/`aws-lc-rs`.

pub mod packet;
pub mod retry;
pub mod tls;

pub use retry::{decode_retry, encode_retry};
pub use tls::TlsSession;

pub use packet::{
    CryptoError, initial_keys, initial_keys_for_version, long_header_info, protect_long,
    protect_short, protect_short_with, unprotect_long, unprotect_short, unprotect_short_with,
};
