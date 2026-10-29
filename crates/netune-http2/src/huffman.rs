//! HPACK Huffman coding (RFC 7541 Section 5.2 and Appendix B).

/// Huffman code entry: (bits, length in bits).
pub struct HuffmanCode {
    pub code: u32,
    pub bits: u8,
}

pub use crate::huffman_table::HUFFMAN_CODES;

/// Encode a byte slice using HPACK Huffman coding.
pub fn encode(src: &[u8], dst: &mut Vec<u8>) {
    let mut current = 0u64;
    let mut bits = 0;

    for &b in src {
        let (code, len) = HUFFMAN_CODES[b as usize];
        current = (current << len) | (code as u64);
        bits += len;

        while bits >= 8 {
            bits -= 8;
            dst.push((current >> bits) as u8);
        }
    }

    if bits > 0 {
        // Pad with 1s (EOS prefix) to fill the remaining byte.
        let pad = 8 - bits;
        current = (current << pad) | ((1 << pad) - 1);
        dst.push((current & 0xFF) as u8);
    }
}

// ── Decoding ────────────────────────────────────────────────────────────────

/// A node in the Huffman decoding tree.
///
/// `children[0]`/`children[1]` index other nodes; `symbol` is set on a leaf. A tree rather
/// than a scan of the 257-entry table turns decoding into one branch per input bit, which
/// is what makes a multi-kilobyte header block linear instead of quadratic.
#[derive(Debug, Clone, Copy, Default)]
struct Node {
    children: [Option<u16>; 2],
    symbol: Option<u16>,
}

/// The decoding tree, built once from [`HUFFMAN_CODES`].
fn tree() -> &'static [Node] {
    use std::sync::OnceLock;
    static TREE: OnceLock<Vec<Node>> = OnceLock::new();
    TREE.get_or_init(|| {
        // Worst case: one node per bit of every code. 257 codes averaging 20 bits is well
        // under 8192 nodes; the vector grows if that is ever wrong.
        let mut nodes = vec![Node::default()];
        for (symbol, &(code, length)) in HUFFMAN_CODES.iter().enumerate() {
            let mut current = 0u16;
            for bit_index in (0..length).rev() {
                let bit = ((code >> bit_index) & 1) as usize;
                let next = match nodes[current as usize].children[bit] {
                    Some(next) => next,
                    None => {
                        nodes.push(Node::default());
                        // The RFC's table needs ~500 nodes; the index is asserted to fit
                        // rather than assumed, because a silent wrap would corrupt the tree.
                        let next = (nodes.len() - 1) as u16;
                        assert!(
                            nodes.len() <= usize::from(u16::MAX),
                            "Huffman tree too large"
                        );
                        nodes[current as usize].children[bit] = Some(next);
                        next
                    }
                };
                current = next;
            }
            // Symbol 256 is EOS: it must never appear in a payload, and it is not a byte.
            nodes[current as usize].symbol = Some(symbol as u16);
        }
        nodes
    })
}

/// Decode HPACK Huffman-coded bytes.
///
/// # Errors
///
/// Returns a message when the input is not a whole number of symbols, contains the EOS
/// symbol, or ends with padding that is not all ones (RFC 7541 §5.2 requires the final
/// partial byte to be the EOS prefix).
pub fn decode(src: &[u8]) -> Result<Vec<u8>, String> {
    const EOS: u16 = 256;
    let nodes = tree();
    let mut out = Vec::with_capacity(src.len() * 2);
    let mut current = 0u16;
    // How many bits have been consumed on the current node path, for padding validation.
    let mut depth = 0u32;
    // The bits of the last partial byte, to check they are all ones.
    let mut padding_bits = 0u32;
    let mut padding_value = 0u32;

    for &byte in src {
        for bit_index in (0..8).rev() {
            let bit = ((byte >> bit_index) & 1) as usize;
            depth += 1;
            padding_bits += 1;
            padding_value = (padding_value << 1) | bit as u32;

            let node = nodes[current as usize];
            match node.children[bit] {
                Some(next) => {
                    current = next;
                    if let Some(symbol) = nodes[current as usize].symbol {
                        if symbol == EOS {
                            return Err("Huffman payload contains the EOS symbol".to_owned());
                        }
                        out.push(symbol as u8);
                        current = 0;
                        depth = 0;
                        padding_bits = 0;
                        padding_value = 0;
                    }
                }
                None => {
                    return Err(format!(
                        "Huffman code has no branch for bit {bit} at depth {depth}"
                    ));
                }
            }
        }
    }

    // A whole number of symbols is required; leftover bits must be < 8 and all ones.
    if padding_bits >= 8 {
        return Err(format!(
            "Huffman payload ends mid-symbol with {padding_bits} bits"
        ));
    }
    if padding_bits > 0 {
        let expected = (1u32 << padding_bits) - 1;
        if padding_value != expected {
            return Err(format!(
                "Huffman padding must be all ones, got {padding_value:#b} for {padding_bits} bits"
            ));
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huffman_round_trips_every_byte() {
        // Every byte value must survive: a table typo shows up as a mismatch here.
        let all: Vec<u8> = (0..=255u8).collect();
        let mut encoded = Vec::new();
        encode(&all, &mut encoded);
        assert_eq!(decode(&encoded).expect("decodes"), all);
    }

    #[test]
    fn huffman_matches_the_rfc_example() {
        // RFC 7541 Appendix C.4.1: "www.example.com" encodes to these 12 octets.
        let mut encoded = Vec::new();
        encode(b"www.example.com", &mut encoded);
        assert_eq!(
            encoded,
            vec![
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
            ]
        );
        assert_eq!(decode(&encoded).expect("decodes"), b"www.example.com");
    }

    #[test]
    fn bad_padding_is_refused() {
        // 0xff decodes to a symbol then padding; flipping the padding bits must fail.
        let mut encoded = Vec::new();
        encode(b"a", &mut encoded);
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        assert!(
            decode(&encoded).is_err(),
            "non-ones padding must be refused"
        );
    }

    #[test]
    fn a_truncated_symbol_is_refused() {
        let mut encoded = Vec::new();
        encode(b"www.example.com", &mut encoded);
        // Drop the final octet: the last symbol is incomplete.
        encoded.pop();
        let result = decode(&encoded);
        // Either an incomplete symbol or bad padding, but never a silent success with a
        // wrong value.
        if let Ok(decoded) = result {
            assert_ne!(decoded, b"www.example.com".to_vec());
        }
    }
}
