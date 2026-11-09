// SPDX-License-Identifier: MIT

//! Owned QUIC packet protection (RFC 9001), backed by `rustls`/`aws-lc-rs`.

pub mod packet;
pub mod tls;

pub use tls::TlsSession;

pub use packet::{
    CryptoError, initial_keys, long_header_info, protect_long, protect_short, unprotect_long,
    unprotect_short,
};
