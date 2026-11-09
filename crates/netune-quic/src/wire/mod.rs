// SPDX-License-Identifier: MIT

//! Owned QUIC wire codec (RFC 9000/9001/9221).
//!
//! This module is the first layer of the owned QUIC engine (ADR-0028). It is
//! pure: it never opens a socket and never owns connection state.

pub mod error;
pub mod frame;
pub mod packet;
pub mod transport_parameters;
pub mod varint;

pub use error::WireError;
pub use frame::{AckFrame, AckRange, EcnCounts, Frame};
pub use packet::{
    LongPacket, LongType, ShortPacket, VERSION_1, VERSION_2, VersionNegotiation,
    decode_packet_number,
};
pub use transport_parameters::{PreferredAddress, TransportParameters};
