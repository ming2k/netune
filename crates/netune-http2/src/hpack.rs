//! HPACK header compression and decompression (RFC 7541).

use crate::error::H2Error;
use crate::huffman;
use bytes::Bytes;

/// RFC 7541 Static Table (Index 1..=61).
pub const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Encode an HPACK integer with a 1..=8 bit prefix (RFC 7541 Section 5.1).
pub fn encode_integer(mut value: usize, prefix_bits: u8, prefix_mask: u8, dst: &mut Vec<u8>) {
    let max_prefix = (1 << prefix_bits) - 1;
    if value < max_prefix {
        dst.push(prefix_mask | (value as u8));
    } else {
        dst.push(prefix_mask | (max_prefix as u8));
        value -= max_prefix;
        while value >= 128 {
            dst.push((value % 128 + 128) as u8);
            value /= 128;
        }
        dst.push(value as u8);
    }
}

/// Decode an HPACK integer with a 1..=8 bit prefix.
pub fn decode_integer(prefix_bits: u8, src: &mut &[u8]) -> Result<usize, H2Error> {
    if src.is_empty() {
        return Err(H2Error::Hpack("unexpected end of integer bytes".into()));
    }
    let max_prefix = (1usize << prefix_bits) - 1;
    let first = src[0] as usize & max_prefix;
    *src = &src[1..];
    if first < max_prefix {
        return Ok(first);
    }

    let mut value = first;
    let mut m = 0;
    while !src.is_empty() {
        let b = src[0] as usize;
        *src = &src[1..];
        value += (b & 0x7F) << m;
        m += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        if m > 28 {
            return Err(H2Error::Hpack("integer overflow".into()));
        }
    }
    Err(H2Error::Hpack("truncated integer".into()))
}

/// Encode a string literal (with optional Huffman compression).
pub fn encode_string(s: &str, huffman: bool, dst: &mut Vec<u8>) {
    if huffman {
        let mut encoded = Vec::new();
        huffman::encode(s.as_bytes(), &mut encoded);
        // Huffman is only a win when it is actually shorter. An already-random token (a
        // nonce, a base64 signature) would otherwise grow the block.
        if encoded.len() < s.len() {
            encode_integer(encoded.len(), 7, 0x80, dst);
            dst.extend_from_slice(&encoded);
            return;
        }
    }
    encode_integer(s.len(), 7, 0x00, dst);
    dst.extend_from_slice(s.as_bytes());
}

/// Decode a string literal.
pub fn decode_string(src: &mut &[u8]) -> Result<String, H2Error> {
    if src.is_empty() {
        return Err(H2Error::Hpack("unexpected end of string bytes".into()));
    }
    let is_huffman = (src[0] & 0x80) != 0;
    let len = decode_integer(7, src)?;
    if src.len() < len {
        return Err(H2Error::Hpack("truncated string literal".into()));
    }
    let raw = &src[..len];
    *src = &src[len..];

    if is_huffman {
        // Decode Huffman bytes
        decode_huffman_string(raw)
    } else {
        String::from_utf8(raw.to_vec())
            .map_err(|e| H2Error::Hpack(format!("invalid utf-8 in header: {e}")))
    }
}

fn decode_huffman_string(raw: &[u8]) -> Result<String, H2Error> {
    // The tree walk lives in `huffman::decode`: one branch per input bit rather than a scan
    // of all 257 symbols per emitted byte, which made a large block quadratic.
    let bytes = huffman::decode(raw).map_err(H2Error::Hpack)?;
    String::from_utf8(bytes)
        .map_err(|error| H2Error::Hpack(format!("invalid utf-8 in huffman: {error}")))
}

/// The dynamic table (RFC 7541 §2.3.2).
///
/// Entries are newest-first, so index 62 is the most recent insertion: that makes eviction
/// a pop from the back and a lookup an offset from the front.
#[derive(Debug)]
pub struct DynamicTable {
    entries: std::collections::VecDeque<(String, String)>,
    /// Current size in the RFC's accounting: `sum(name.len() + value.len() + 32)`.
    size: usize,
    /// The peer's declared maximum.
    max_size: usize,
}

/// The entry-overhead constant (RFC 7541 §4.1).
const ENTRY_OVERHEAD: usize = 32;

/// The dynamic table's initial maximum (RFC 7541 §4.2).
pub const DEFAULT_TABLE_SIZE: usize = 4096;

impl Default for DynamicTable {
    fn default() -> Self {
        Self::new(DEFAULT_TABLE_SIZE)
    }
}

impl DynamicTable {
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    /// Inserts `(name, value)` as the newest entry, evicting oldest-first (§4.4).
    ///
    /// An entry larger than the table clears it and is not stored, which is what the RFC
    /// requires rather than an error.
    pub fn insert(&mut self, name: String, value: String) {
        let cost = name.len() + value.len() + ENTRY_OVERHEAD;
        if cost > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }
        while self.size + cost > self.max_size {
            match self.entries.pop_back() {
                Some((old_name, old_value)) => {
                    self.size -= old_name.len() + old_value.len() + ENTRY_OVERHEAD;
                }
                None => break,
            }
        }
        self.size += cost;
        self.entries.push_front((name, value));
    }

    /// Resizes the table, evicting as needed (§4.3), *without* a ceiling.
    ///
    /// This is the encoder's path: the peer's `SETTINGS_HEADER_TABLE_SIZE` is a permission to use a
    /// table that large, so "growing past the current size" is precisely what it asks for.
    pub fn resize(&mut self, max_size: usize) {
        self.max_size = max_size;
        while self.size > self.max_size {
            match self.entries.pop_back() {
                Some((name, value)) => {
                    self.size -= name.len() + value.len() + ENTRY_OVERHEAD;
                }
                None => break,
            }
        }
    }

    /// Resizes the table from a *decoded* size update, evicting as needed (§4.3).
    ///
    /// # Errors
    ///
    /// Returns an error when `max_size` exceeds what this end advertised: a peer may shrink its
    /// encoder's table, never grow it past the ceiling we published.
    pub fn set_max_size(&mut self, max_size: usize) -> Result<(), H2Error> {
        if max_size > self.max_size {
            return Err(H2Error::Hpack(format!(
                "dynamic table size update to {max_size} exceeds the advertised {}",
                self.max_size
            )));
        }
        self.resize(max_size);
        Ok(())
    }

    /// The entry at a dynamic index (1-based, newest first).
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&(String, String)> {
        index
            .checked_sub(1)
            .and_then(|offset| self.entries.get(offset))
    }

    fn find(&self, name: &str, value: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|(n, v)| n == name && v == value)
            .map(|offset| offset + 1)
    }

    fn find_name(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|(n, _)| n == name)
            .map(|offset| offset + 1)
    }
}

/// An HPACK header compressor over a dynamic table.
#[derive(Debug)]
pub struct HpackEncoder {
    pub use_huffman: bool,
    table: DynamicTable,
}

impl Default for HpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackEncoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            use_huffman: true,
            table: DynamicTable::default(),
        }
    }

    /// Encode headers in the exact order given.
    ///
    /// Order is preserved because a fingerprint declares it; reordering would defeat the
    /// point of impersonation even though the wire permits any order.
    pub fn encode<'a, I>(&mut self, headers: I) -> Bytes
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut out = Vec::new();
        for (name, value) in headers {
            if let Some(index) = static_full_match(name, value) {
                encode_integer(index, 7, 0x80, &mut out);
                continue;
            }
            if let Some(offset) = self.table.find(name, value) {
                encode_integer(STATIC_TABLE.len() + offset, 7, 0x80, &mut out);
                continue;
            }
            let name_index = static_name_match(name).or_else(|| {
                self.table
                    .find_name(name)
                    .map(|offset| STATIC_TABLE.len() + offset)
            });

            // Literal with incremental indexing (`01`): the value is worth remembering,
            // which is the normal case for a repeated header like `:authority`.
            match name_index {
                Some(index) => encode_integer(index, 6, 0x40, &mut out),
                None => {
                    out.push(0x40);
                    encode_string(name, self.use_huffman, &mut out);
                }
            }
            encode_string(value, self.use_huffman, &mut out);
            self.table.insert(name.to_owned(), value.to_owned());
        }
        Bytes::from(out)
    }

    /// The encoder's dynamic table, for tests and diagnostics.
    #[must_use]
    pub const fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Resizes the encoder's table, emitting the §4.2 size update that must precede the next block.
    ///
    /// The peer's `SETTINGS_HEADER_TABLE_SIZE` is the authority here: growing the encoder's table to
    /// it is exactly what the peer asked for, so this is infallible.
    pub fn set_max_size(&mut self, max_size: usize, out: &mut Vec<u8>) {
        self.table.resize(max_size);
        encode_integer(max_size, 5, 0x20, out);
    }
}

fn static_full_match(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| n.eq_ignore_ascii_case(name) && *v == value)
        .map(|index| index + 1)
}

fn static_name_match(name: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|index| index + 1)
}

/// An HPACK header decompressor over a dynamic table.
#[derive(Debug)]
pub struct HpackDecoder {
    table: DynamicTable,
    /// Size updates seen in the current block; RFC 7541 §4.2 allows at most two.
    size_updates: u8,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: DynamicTable::default(),
            size_updates: 0,
        }
    }

    /// A decoder whose table is capped at `max_size`.
    #[must_use]
    pub fn with_max_table_size(max_size: usize) -> Self {
        Self {
            table: DynamicTable::new(max_size),
            size_updates: 0,
        }
    }

    /// Decode one header block.
    ///
    /// # Errors
    ///
    /// Returns an error for an index beyond both tables, a malformed literal, a size update
    /// exceeding the advertised cap, or a size update after the first field.
    pub fn decode(&mut self, payload: &[u8]) -> Result<Vec<(String, String)>, H2Error> {
        self.decode_with_limit(payload, usize::MAX)
    }

    /// Decode one header block and refuse a decoded list larger than `max_size`.
    ///
    /// `max_size` is the receiver's advertised `SETTINGS_MAX_HEADER_LIST_SIZE`, counted
    /// with the RFC 7541 §4.1 accounting (`name + value + 32` per field). The raw block is
    /// already bounded by the caller; this bound catches a block that is small on the wire
    /// but expands through the Huffman decoder or the dynamic table.
    ///
    /// # Errors
    ///
    /// As [`Self::decode`], plus a header list whose accounted size exceeds `max_size`.
    pub fn decode_with_limit(
        &mut self,
        mut payload: &[u8],
        max_size: usize,
    ) -> Result<Vec<(String, String)>, H2Error> {
        let mut headers = Vec::new();
        let mut saw_field = false;
        let mut list_size = 0usize;
        self.size_updates = 0;

        while !payload.is_empty() {
            let first = payload[0];
            let (name, value) = if first & 0x80 != 0 {
                // Indexed Header Field.
                let index = decode_integer(7, &mut payload)?;
                self.lookup(index)?
            } else if first & 0x40 != 0 {
                // Literal with incremental indexing: the entry enters the dynamic table.
                let index = decode_integer(6, &mut payload)?;
                let name = self.resolve_name(index, &mut payload)?;
                let value = decode_string(&mut payload)?;
                self.table.insert(name.clone(), value.clone());
                (name, value)
            } else if first & 0x20 != 0 {
                // Dynamic Table Size Update.
                if saw_field {
                    return Err(H2Error::Hpack(
                        "dynamic table size update after a header field".into(),
                    ));
                }
                if self.size_updates >= 2 {
                    return Err(H2Error::Hpack(
                        "more than two size updates in one block".into(),
                    ));
                }
                self.size_updates += 1;
                let max_size = decode_integer(5, &mut payload)?;
                self.table.set_max_size(max_size)?;
                continue;
            } else {
                // Literal without indexing (`0000`) or never indexed (`0001`): neither
                // changes the table.
                let index = decode_integer(4, &mut payload)?;
                let name = self.resolve_name(index, &mut payload)?;
                let value = decode_string(&mut payload)?;
                (name, value)
            };
            saw_field = true;
            list_size = list_size
                .saturating_add(name.len())
                .saturating_add(value.len())
                .saturating_add(32);
            if list_size > max_size {
                return Err(H2Error::Hpack(format!(
                    "decoded header list exceeds the {max_size} byte limit"
                )));
            }
            headers.push((name, value));
        }
        Ok(headers)
    }

    /// Resolve a literal's name from an index (static, dynamic, or inline).
    fn resolve_name(&self, index: usize, payload: &mut &[u8]) -> Result<String, H2Error> {
        if index == 0 {
            return decode_string(payload);
        }
        self.lookup(index).map(|(name, _)| name)
    }

    fn lookup(&self, index: usize) -> Result<(String, String), H2Error> {
        if index == 0 {
            return Err(H2Error::Hpack("index 0 is not a valid header index".into()));
        }
        if index <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[index - 1];
            return Ok((name.to_owned(), value.to_owned()));
        }
        let dynamic_index = index - STATIC_TABLE.len();
        self.table.get(dynamic_index).cloned().ok_or_else(|| {
            H2Error::Hpack(format!(
                "index {index} is beyond both tables (static {}, dynamic {})",
                STATIC_TABLE.len(),
                self.table.len()
            ))
        })
    }

    /// The decoder's dynamic table, for tests and diagnostics.
    #[must_use]
    pub const fn table(&self) -> &DynamicTable {
        &self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_encoding_and_decoding_round_trip() {
        for value in [0, 1, 10, 127, 128, 255, 1337, 65535, 1_000_000] {
            let mut buf = Vec::new();
            encode_integer(value, 5, 0x20, &mut buf);
            let mut slice = &buf[..];
            let decoded = decode_integer(5, &mut slice).expect("decode integer");
            assert_eq!(value, decoded);
            assert!(slice.is_empty());
        }
    }

    #[test]
    fn an_integer_with_endless_continuation_is_refused() {
        let mut bytes = vec![0xffu8];
        bytes.extend_from_slice(&[0xff; 8]);
        let mut slice = &bytes[..];
        let error = decode_integer(7, &mut slice).expect_err("must refuse");
        assert!(error.to_string().contains("overflow"), "{error}");
    }

    #[test]
    fn header_block_round_trip() {
        let mut encoder = HpackEncoder::new();
        let mut decoder = HpackDecoder::new();
        let original = [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/api/v1/chat"),
            (":authority", "api.example.com"),
            ("user-agent", "netune-h2/0.1"),
            ("accept", "application/json"),
        ];
        let block = encoder.encode(original.iter().copied());
        let decoded = decoder.decode(&block).expect("decode headers");
        assert_eq!(original.len(), decoded.len());
        for ((expected_name, expected_value), (name, value)) in original.iter().zip(decoded.iter())
        {
            assert_eq!(*expected_name, name.as_str());
            assert_eq!(*expected_value, value.as_str());
        }
    }

    #[test]
    fn a_decoded_header_list_over_the_advertised_limit_is_refused() {
        let mut encoder = HpackEncoder::new();
        let mut decoder = HpackDecoder::new();
        let block = encoder.encode([("x-custom", "0123456789")]);

        // `x-custom` (8) + value (10) + the 32-byte per-field overhead = 50.
        let error = decoder
            .decode_with_limit(&block, 49)
            .expect_err("must refuse an oversized header list");
        assert!(error.to_string().contains("49 byte limit"), "{error}");

        let mut decoder = HpackDecoder::new();
        assert_eq!(
            decoder.decode_with_limit(&block, 50).expect("exactly fits"),
            vec![("x-custom".to_owned(), "0123456789".to_owned())]
        );
    }

    #[test]
    fn a_second_block_indexes_into_the_dynamic_table() {
        // The property that made the old decoder unusable against a real server: the second
        // block refers to entries the first block inserted.
        let mut encoder = HpackEncoder::new();
        let mut decoder = HpackDecoder::new();
        let pair = [("x-custom", "a-value-not-in-the-static-table")];

        let block = encoder.encode(pair.iter().copied());
        let first = decoder.decode(&block).expect("first block");
        assert_eq!(
            first,
            vec![(
                "x-custom".to_owned(),
                "a-value-not-in-the-static-table".to_owned()
            )]
        );
        assert_eq!(decoder.table().len(), 1, "the entry was indexed");

        let block = encoder.encode(pair.iter().copied());
        assert_eq!(block.len(), 1, "a repeated pair costs one octet");
        assert_eq!(decoder.decode(&block).expect("second block"), first);
    }

    #[test]
    fn the_dynamic_table_evicts_oldest_first() {
        // Each entry costs name + value + 32. With a 120-byte table, two 56-byte entries fit
        // and a third does not.
        let mut table = DynamicTable::new(120);
        table.insert("a".repeat(16), "b".repeat(8));
        table.insert("c".repeat(16), "d".repeat(8));
        assert_eq!(table.len(), 2, "two entries fit in 120 bytes");
        table.insert("e".repeat(16), "f".repeat(8));
        assert_eq!(table.len(), 2, "the third evicts the oldest");
        assert_eq!(table.get(1).expect("newest").0, "e".repeat(16));
        assert_eq!(table.get(2).expect("older").0, "c".repeat(16));
        assert_eq!(table.size(), 112);
    }

    #[test]
    fn an_entry_that_exactly_fits_is_kept() {
        let mut table = DynamicTable::new(56);
        table.insert("a".repeat(16), "b".repeat(8));
        assert_eq!(
            table.len(),
            1,
            "cost == max_size must be stored, not dropped"
        );
        assert_eq!(table.size(), 56);
    }

    #[test]
    fn an_entry_larger_than_the_table_clears_it() {
        let mut table = DynamicTable::new(64);
        table.insert("a".to_owned(), "b".to_owned());
        assert_eq!(table.len(), 1);
        table.insert("x".repeat(100), "y".repeat(100));
        assert!(table.is_empty(), "an oversized entry empties the table");
    }

    #[test]
    fn a_size_update_beyond_the_advertised_cap_is_refused() {
        let mut decoder = HpackDecoder::with_max_table_size(2048);
        let mut block = Vec::new();
        encode_integer(8192, 5, 0x20, &mut block);
        let error = decoder.decode(&block).expect_err("must refuse");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn a_size_update_after_a_field_is_refused() {
        let mut decoder = HpackDecoder::new();
        let mut block = Vec::new();
        encode_integer(2, 7, 0x80, &mut block);
        encode_integer(1024, 5, 0x20, &mut block);
        let error = decoder.decode(&block).expect_err("must refuse");
        assert!(
            error.to_string().contains("after a header field"),
            "{error}"
        );
    }

    #[test]
    fn an_index_beyond_both_tables_is_refused() {
        let mut decoder = HpackDecoder::new();
        let mut block = Vec::new();
        encode_integer(200, 7, 0x80, &mut block);
        let error = decoder.decode(&block).expect_err("must refuse");
        assert!(error.to_string().contains("beyond both tables"), "{error}");
    }

    #[test]
    fn index_zero_is_refused() {
        let mut decoder = HpackDecoder::new();
        let error = decoder.decode(&[0x80u8]).expect_err("must refuse");
        assert!(error.to_string().contains("index 0"), "{error}");
    }

    #[test]
    fn a_truncated_string_is_refused_rather_than_read_past() {
        let mut slice = &[0x05u8, b'a'][..];
        let error = decode_string(&mut slice).expect_err("must refuse");
        assert!(error.to_string().contains("truncated"), "{error}");
    }

    #[test]
    fn huffman_is_skipped_when_it_does_not_shrink() {
        // "ab" Huffman-encodes to the same number of bytes as the raw form, so the encoder
        // must choose the plain literal (high bit clear on the length prefix).
        let mut dst = Vec::new();
        encode_string("ab", true, &mut dst);
        assert_eq!(dst[0] & 0x80, 0, "fell back to a plain literal");
    }

    #[test]
    fn huffman_is_used_when_it_shrinks() {
        // A repeated character compresses well, so the Huffman form must be chosen.
        let mut dst = Vec::new();
        encode_string(&"a".repeat(64), true, &mut dst);
        assert_eq!(
            dst[0] & 0x80,
            0x80,
            "a long repeated value must be Huffman-coded"
        );
    }
}
