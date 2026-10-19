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
        encode_integer(encoded.len(), 7, 0x80, dst);
        dst.extend_from_slice(&encoded);
    } else {
        encode_integer(s.len(), 7, 0x00, dst);
        dst.extend_from_slice(s.as_bytes());
    }
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
    let mut out = Vec::new();
    let mut current = 0u64;
    let mut bits = 0;

    for &b in raw {
        current = (current << 8) | (b as u64);
        bits += 8;

        'match_symbol: loop {
            for (sym, &(code, len)) in huffman::HUFFMAN_CODES.iter().enumerate() {
                if len as usize <= bits {
                    let shift = bits - len as usize;
                    let candidate = (current >> shift) & ((1 << len) - 1);
                    if candidate == code as u64 {
                        if sym == 256 {
                            return Err(H2Error::Hpack("unexpected EOS symbol".into()));
                        }
                        out.push(sym as u8);
                        bits -= len as usize;
                        continue 'match_symbol;
                    }
                }
            }
            break;
        }
    }
    String::from_utf8(out).map_err(|e| H2Error::Hpack(format!("invalid utf-8 in huffman: {e}")))
}

/// An HPACK header compressor.
#[derive(Debug, Default)]
pub struct HpackEncoder {
    pub use_huffman: bool,
}

impl HpackEncoder {
    pub fn new() -> Self {
        Self { use_huffman: true }
    }

    /// Encode a list of headers in the exact provided order.
    pub fn encode<'a, I>(&self, headers: I) -> Bytes
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut out = Vec::new();

        for (name, value) in headers {
            // Find in static table
            let mut match_full = None;
            let mut match_name = None;

            for (idx, &(s_name, s_val)) in STATIC_TABLE.iter().enumerate() {
                let static_idx = idx + 1;
                if s_name.eq_ignore_ascii_case(name) {
                    if s_val == value {
                        match_full = Some(static_idx);
                        break;
                    } else if match_name.is_none() {
                        match_name = Some(static_idx);
                    }
                }
            }

            if let Some(idx) = match_full {
                // Indexed Header Field: 1xxxxxxx
                encode_integer(idx, 7, 0x80, &mut out);
            } else if let Some(idx) = match_name {
                // Literal with indexing / without indexing: 0000xxxx with indexed name
                encode_integer(idx, 4, 0x00, &mut out);
                encode_string(value, self.use_huffman, &mut out);
            } else {
                // Literal Header Field with Literal Name: 00000000
                out.push(0x00);
                encode_string(name, self.use_huffman, &mut out);
                encode_string(value, self.use_huffman, &mut out);
            }
        }

        Bytes::from(out)
    }
}

/// An HPACK header decompressor.
#[derive(Debug, Default)]
pub struct HpackDecoder;

impl HpackDecoder {
    pub fn new() -> Self {
        Self
    }

    /// Decode an HPACK header block into header key-value pairs.
    pub fn decode(&self, mut payload: &[u8]) -> Result<Vec<(String, String)>, H2Error> {
        let mut headers = Vec::new();

        while !payload.is_empty() {
            let first = payload[0];

            if (first & 0x80) != 0 {
                // Indexed Header Field (1xxxxxxx)
                let idx = decode_integer(7, &mut payload)?;
                if idx >= 1 && idx <= STATIC_TABLE.len() {
                    let (k, v) = STATIC_TABLE[idx - 1];
                    headers.push((k.to_string(), v.to_string()));
                } else {
                    return Err(H2Error::Hpack(format!("unsupported dynamic index {idx}")));
                }
            } else if (first & 0x40) != 0 {
                // Literal with incremental indexing (01xxxxxx)
                let idx = decode_integer(6, &mut payload)?;
                let name = if idx > 0 && idx <= STATIC_TABLE.len() {
                    STATIC_TABLE[idx - 1].0.to_string()
                } else if idx == 0 {
                    decode_string(&mut payload)?
                } else {
                    return Err(H2Error::Hpack(format!("index out of bounds: {idx}")));
                };
                let value = decode_string(&mut payload)?;
                headers.push((name, value));
            } else if (first & 0x20) != 0 {
                // Dynamic table size update (001xxxxx)
                let _new_size = decode_integer(5, &mut payload)?;
            } else {
                // Literal without indexing (0000xxxx or 0001xxxx)
                let idx = decode_integer(4, &mut payload)?;
                let name = if idx > 0 && idx <= STATIC_TABLE.len() {
                    STATIC_TABLE[idx - 1].0.to_string()
                } else if idx == 0 {
                    decode_string(&mut payload)?
                } else {
                    return Err(H2Error::Hpack(format!("index out of bounds: {idx}")));
                };
                let value = decode_string(&mut payload)?;
                headers.push((name, value));
            }
        }

        Ok(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_encoding_and_decoding_round_trip() {
        for val in [0, 1, 10, 127, 128, 255, 1337, 65535, 1_000_000] {
            let mut buf = Vec::new();
            encode_integer(val, 5, 0x20, &mut buf);
            let mut slice = &buf[..];
            let decoded = decode_integer(5, &mut slice).expect("decode integer");
            assert_eq!(val, decoded);
            assert!(slice.is_empty());
        }
    }

    #[test]
    fn hpack_header_block_round_trip() {
        let encoder = HpackEncoder::new();
        let decoder = HpackDecoder::new();

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
        for ((k1, v1), (k2, v2)) in original.iter().zip(decoded.iter()) {
            assert_eq!(*k1, k2.as_str());
            assert_eq!(*v1, v2.as_str());
        }
    }
}
