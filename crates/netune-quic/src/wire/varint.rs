// SPDX-License-Identifier: MIT

//! QUIC variable-length integers (RFC 9000 Section 16).

use bytes::{Buf, BufMut};

use super::error::WireError;

/// The largest value representable by a QUIC varint.
pub const MAX: u64 = (1u64 << 62) - 1;

/// Number of bytes `value` occupies.
pub fn encoded_len(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// Append `value` in QUIC varint form.
pub fn encode<B: BufMut>(buf: &mut B, value: u64) -> Result<(), WireError> {
    if value > MAX {
        return Err(WireError::IntegerOverflow);
    }
    match encoded_len(value) {
        1 => buf.put_u8(value as u8),
        2 => {
            buf.put_u8(0x40 | ((value >> 8) as u8));
            buf.put_u8(value as u8);
        }
        4 => {
            buf.put_u8(0x80 | ((value >> 24) as u8));
            buf.put_u8((value >> 16) as u8);
            buf.put_u8((value >> 8) as u8);
            buf.put_u8(value as u8);
        }
        _ => {
            buf.put_u8(0xc0 | ((value >> 56) as u8));
            buf.put_u8((value >> 48) as u8);
            buf.put_u8((value >> 40) as u8);
            buf.put_u8((value >> 32) as u8);
            buf.put_u8((value >> 24) as u8);
            buf.put_u8((value >> 16) as u8);
            buf.put_u8((value >> 8) as u8);
            buf.put_u8(value as u8);
        }
    }
    Ok(())
}

/// Read one QUIC varint.
pub fn decode<B: Buf>(buf: &mut B) -> Result<u64, WireError> {
    let first = buf.try_get_u8().map_err(|_| WireError::UnexpectedEnd)?;
    let length = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..length {
        let byte = buf.try_get_u8().map_err(|_| WireError::UnexpectedEnd)?;
        value = (value << 8) | u64::from(byte);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn rfc9000_examples() {
        let cases = [
            (37u64, vec![0x25]),
            (15293, vec![0x7b, 0xbd]),
            (494_878_333, vec![0x9d, 0x7f, 0x3e, 0x7d]),
            (
                151_288_809_941_952_652,
                vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
        ];
        for (value, wire) in cases {
            let mut out = BytesMut::new();
            encode(&mut out, value).expect("encode");
            assert_eq!(&out[..], &wire);
            let mut read = out.freeze();
            assert_eq!(decode(&mut read).expect("decode"), value);
        }
    }

    #[test]
    fn boundaries_round_trip() {
        for value in [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, MAX] {
            let mut out = BytesMut::new();
            encode(&mut out, value).expect("encode");
            assert_eq!(out.len(), encoded_len(value));
            let mut read = out.freeze();
            assert_eq!(decode(&mut read).expect("decode"), value);
        }
    }

    #[test]
    fn truncation_and_overflow_are_errors() {
        let mut empty: &[u8] = &[];
        assert!(matches!(decode(&mut empty), Err(WireError::UnexpectedEnd)));
        let mut short: &[u8] = &[0x40];
        assert!(matches!(decode(&mut short), Err(WireError::UnexpectedEnd)));
        let mut out = BytesMut::new();
        assert!(matches!(
            encode(&mut out, MAX + 1),
            Err(WireError::IntegerOverflow)
        ));
    }
}
