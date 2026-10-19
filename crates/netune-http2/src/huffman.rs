//! HPACK Huffman coding (RFC 7541 Section 5.2 and Appendix B).

/// Huffman code entry: (bits, length in bits).
pub struct HuffmanCode {
    pub code: u32,
    pub bits: u8,
}

// RFC 7541 Appendix B Huffman code table for bytes 0..=256
pub const HUFFMAN_CODES: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7ffc, 23),
    (0x7ffd, 28),
    (0x7ffe, 28), // 0..3
    (0x7fff, 28),
    (0x1ff9, 13),
    (0x7ffa, 23),
    (0x7ffb, 23), // 4..7
    (0x1ffa, 13),
    (0x7ffc, 24),
    (0x1ffb, 13),
    (0x7ffd, 24), // 8..11
    (0x7ffe, 24),
    (0x7fff, 24),
    (0x7ff8, 23),
    (0x7ff9, 23), // 12..15
    (0x7ffa, 24),
    (0x7ffb, 24),
    (0x7ffc, 25),
    (0x7ffd, 25), // 16..19
    (0x7ffe, 25),
    (0x7fff, 25),
    (0x7ff8, 24),
    (0x7ff9, 24), // 20..23
    (0x7ffa, 25),
    (0x7ffb, 25),
    (0x7ffc, 26),
    (0x7ffd, 26), // 24..27
    (0x7ffe, 26),
    (0x7fff, 26),
    (0x7ff8, 25),
    (0x7ff9, 25), // 28..31
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12), // 32 ' ' .. 35 '#'
    (0x1ffc, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11), // 36 '$' .. 39 '\''
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11), // 40 '(' .. 43 '+'
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6), // 44 ',' .. 47 '/'
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6), // 48 '0' .. 51 '3'
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6), // 52 '4' .. 55 '7'
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8), // 56 '8' .. 59 ';'
    (0x7fc, 11),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10), // 60 '<' .. 63 '?'
    (0x1ffd, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7), // 64 '@' .. 67 'C'
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7), // 68 'D' .. 71 'G'
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7), // 72 'H' .. 75 'K'
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7), // 76 'L' .. 79 'O'
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7), // 80 'P' .. 83 'S'
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7), // 84 'T' .. 87 'W'
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffe, 13), // 88 'X' .. 91 '['
    (0x7fff0, 20),
    (0x1fff, 13),
    (0x3fd, 10),
    (0x22, 6), // 92 '\' .. 95 '_'
    (0xffc, 12),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5), // 96 '`' .. 99 'c'
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6), // 100 'd' .. 103 'g'
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7), // 104 'h' .. 107 'k'
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5), // 108 'l' .. 111 'o'
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5), // 112 'p' .. 115 's'
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7), // 116 't' .. 119 'w'
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe0, 19), // 120 'x' .. 123 '{'
    (0x7fc, 11),
    (0x3fe, 10),
    (0x7fd, 11),
    (0xffffffc, 28), // 124 '|' .. 127 DEL
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20), // 128..131
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23), // 132..135
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23), // 136..139
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0xffffec, 24), // 140..143
    (0xffffed, 24),
    (0xffffee, 24),
    (0xffffef, 24),
    (0xfffff0, 24), // 144..147
    (0x3fffd7, 22),
    (0x3fffd8, 22),
    (0xfffff1, 24),
    (0x3fffd9, 22), // 148..151
    (0x7fffdf, 23),
    (0x7fffe0, 23),
    (0xfffff2, 24),
    (0xfffff3, 24), // 152..155
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23), // 156..159
    (0x1fffdc, 21),
    (0x3fffda, 22),
    (0x7fffe5, 23),
    (0x3fffdb, 22), // 160..163
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0x7fffe8, 23),
    (0x7fffe9, 23), // 164..167
    (0x7fffea, 23),
    (0x7fffeb, 23),
    (0xffffec, 24),
    (0x1fffdd, 21), // 168..171
    (0x7fffed, 23),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0x7ffff0, 23), // 172..175
    (0x3fffdc, 22),
    (0x3fffdd, 22),
    (0x7ffff1, 23),
    (0x3fffde, 22), // 176..179
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3fffdf, 22),
    (0x7ffff2, 23), // 180..183
    (0x7ffff3, 23),
    (0x7ffff4, 23),
    (0x7ffff5, 23),
    (0x7ffff6, 23), // 184..187
    (0x7ffff7, 23),
    (0x7ffff8, 23),
    (0x7ffff9, 23),
    (0x3fffe0, 22), // 188..191
    (0x1fffde, 21),
    (0x7ffffa, 23),
    (0x7ffffb, 23),
    (0x7ffffc, 23), // 192..195
    (0x7ffffd, 23),
    (0x7ffffe, 23),
    (0x7fffff, 23),
    (0xfffff6, 24), // 196..199
    (0xfffff7, 24),
    (0xfffff8, 24),
    (0xfffff9, 24),
    (0xfffffa, 24), // 200..203
    (0xfffffe, 24),
    (0x1fffdf, 21),
    (0x1fffe0, 21),
    (0xfffe9, 20), // 204..207
    (0x1fffe1, 21),
    (0x1fffe2, 21),
    (0x3fffe1, 22),
    (0x3fffe2, 22), // 208..211
    (0x3fffe3, 22),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x3fffe4, 22), // 212..215
    (0x7ffffee, 27),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x3fffe7, 22), // 216..219
    (0x3fffe8, 22),
    (0x3fffe9, 22),
    (0x3fffea, 22),
    (0x3fffeb, 22), // 220..223
    (0x3fffec, 22),
    (0x3fffed, 22),
    (0x3fffee, 22),
    (0x3fffef, 22), // 224..227
    (0x3ffff0, 22),
    (0x3ffff1, 22),
    (0x3ffff2, 22),
    (0x3ffff3, 22), // 228..231
    (0x1fffe3, 21),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x1fffe6, 21), // 232..235
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x1fffe9, 21),
    (0x1fffea, 21), // 236..239
    (0x1fffeb, 21),
    (0x1fffec, 21),
    (0x1fffed, 21),
    (0x1fffee, 21), // 240..243
    (0x1fffef, 21),
    (0x1ffff0, 21),
    (0x1ffff1, 21),
    (0x1ffff2, 21), // 244..247
    (0x1ffff3, 21),
    (0x1ffff4, 21),
    (0x1ffff5, 21),
    (0x1ffff6, 21), // 248..251
    (0x1ffff7, 21),
    (0x1ffff8, 21),
    (0x1ffff9, 21),
    (0x1ffffa, 21),   // 252..255
    (0x3fffffff, 30), // EOS (256)
];

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
