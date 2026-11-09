// SPDX-License-Identifier: MIT

//! Owned QPACK (RFC 9204) codec.
//!
//! The codec is split into a synchronous table/field layer and the connection
//! owner in `crate::connection`. Encoder and decoder tables are independent, as
//! the RFC requires.

pub mod decoder;
pub mod dynamic;
pub mod encoder;
pub mod error;
pub mod huffman;
pub mod instructions;
pub mod prefix;
pub mod static_table;

pub use decoder::{DecodedSection, Decoder};
pub use dynamic::{DynamicTable, HeaderField};
pub use encoder::{EncodedSection, Encoder};
pub use error::QpackError;
pub use instructions::{DecoderInstruction, EncoderInstruction};
