// SPDX-License-Identifier: MIT

//! QPACK (RFC 9204) errors.

/// A QPACK encoding or decoding failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QpackError {
    /// The input ended in the middle of an integer, string, or instruction.
    #[error("unexpected end of QPACK input")]
    UnexpectedEnd,

    /// A prefixed integer exceeded the implementation limit.
    #[error("QPACK integer overflow")]
    IntegerOverflow,

    /// The instruction prefix does not name a known representation.
    #[error("invalid QPACK prefix 0x{0:02x}")]
    InvalidPrefix(u8),

    /// A static-table index is outside the 99-entry table.
    #[error("invalid QPACK static-table index {0}")]
    InvalidStaticIndex(usize),

    /// A dynamic-table reference does not identify a live entry.
    #[error("invalid QPACK dynamic-table index {0}")]
    InvalidDynamicIndex(usize),

    /// A dynamic reference points at or beyond the declared Required Insert Count.
    #[error("QPACK dynamic reference {reference} is outside required insert count {required}")]
    ReferenceOutsideSection { reference: u64, required: u64 },

    /// A Reference Insert Count cannot be reconstructed from the prefix.
    #[error("invalid QPACK Required Insert Count encoding")]
    InvalidRequiredInsertCount,

    /// The encoder attempted to set a capacity above the decoder's setting.
    #[error("QPACK capacity {0} exceeds maximum {1}")]
    CapacityTooLarge(usize, usize),

    /// An entry is larger than the dynamic table capacity.
    #[error("QPACK entry size {0} exceeds table capacity {1}")]
    EntryTooLarge(usize, usize),

    /// Eviction would remove an entry that is still referenced or unacknowledged.
    #[error("QPACK dynamic table insertion would evict a live entry")]
    TableFull,

    /// The decoder waited for an insertion that the encoder never sent.
    #[error("QPACK required insert count {required} exceeds received {received}")]
    MissingInsertions { required: u64, received: u64 },

    /// More streams are blocked than the advertised budget.
    #[error("QPACK blocked-stream budget {limit} exceeded")]
    TooManyBlockedStreams { limit: usize },

    /// The huffman bit stream is malformed.
    #[error("invalid HPACK huffman code")]
    InvalidHuffman,

    /// The huffman padding is longer than seven bits.
    #[error("invalid HPACK huffman padding")]
    InvalidHuffmanPadding,

    /// The huffman string contains the EOS symbol.
    #[error("HPACK huffman EOS symbol is forbidden")]
    HuffmanEos,

    /// A decoded field section exceeds the configured maximum size.
    #[error("QPACK field section exceeds {limit} bytes")]
    HeaderTooLarge { limit: usize },

    /// An encoder-stream instruction is invalid.
    #[error("invalid QPACK encoder instruction")]
    EncoderStream,

    /// A decoder-stream instruction is invalid.
    #[error("invalid QPACK decoder instruction")]
    DecoderStream,

    /// A Section Acknowledgement does not match an outstanding block.
    #[error("QPACK acknowledgement for stream {0} has no outstanding section")]
    UnexpectedAcknowledgement(u64),

    /// An Insert Count Increment exceeds the encoder's insert count.
    #[error("QPACK Insert Count Increment exceeds the encoder insert count")]
    InvalidInsertCountIncrement,

    /// A stream cancellation does not match an outstanding block.
    #[error("QPACK cancellation for stream {0} has no outstanding section")]
    UnexpectedCancellation(u64),
}
