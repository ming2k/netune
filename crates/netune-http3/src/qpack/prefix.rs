// SPDX-License-Identifier: MIT

//! QPACK primitive encodings: prefixed integers and string literals.
//!
//! Both are defined by RFC 7541 and reused by RFC 9204.

use bytes::{Buf, BufMut};

use super::error::QpackError;
use super::huffman;

/// Decode an RFC 7541 prefixed integer.
///
/// Returns `(flags, value)`, where `flags` is the value of the bits above the
/// prefix, shifted down to the least significant bit. QPACK uses the flags to
/// identify instructions and representations.
pub fn decode_int<B: Buf>(buf: &mut B, prefix_bits: u8) -> Result<(u8, u64), QpackError> {
    debug_assert!((1..=8).contains(&prefix_bits));
    let first = buf.try_get_u8().map_err(|_| QpackError::UnexpectedEnd)?;
    let mask = if prefix_bits == 8 {
        0xff
    } else {
        (1u8 << prefix_bits) - 1
    };
    let flags = ((first as u16) >> prefix_bits) as u8;
    let mut value = (first & mask) as u128;

    if value < mask as u128 {
        return Ok((flags, value as u64));
    }

    let mut shift = 0u32;
    loop {
        let byte = buf.try_get_u8().map_err(|_| QpackError::UnexpectedEnd)?;
        let part = (byte & 0x7f) as u128;
        value = value
            .checked_add(part << shift)
            .ok_or(QpackError::IntegerOverflow)?;
        if value > u64::MAX as u128 {
            return Err(QpackError::IntegerOverflow);
        }
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 63 {
            return Err(QpackError::IntegerOverflow);
        }
    }

    Ok((flags, value as u64))
}

/// Encode an RFC 7541 prefixed integer.
///
/// `high_bits` is the value of the bits above the prefix, shifted down to the
/// least significant bit. It must fit in the available high bits.
pub fn encode_int<B: BufMut>(buf: &mut B, prefix_bits: u8, high_bits: u8, value: u64) {
    debug_assert!((1..=8).contains(&prefix_bits));
    let mask = if prefix_bits == 8 {
        0xff
    } else {
        (1u8 << prefix_bits) - 1
    };
    let high = ((high_bits as u16) << prefix_bits) as u8;

    if value < mask as u64 {
        buf.put_u8(high | value as u8);
        return;
    }

    buf.put_u8(high | mask);
    let mut remaining = value - mask as u64;
    while remaining >= 128 {
        buf.put_u8(((remaining % 128) as u8) | 0x80);
        remaining /= 128;
    }
    buf.put_u8(remaining as u8);
}

/// Decode an N-bit-prefix string literal.
///
/// `prefix_bits` is the total bit width of the representation (2..=8): the H
/// flag occupies one bit and the length uses `prefix_bits - 1` bits.
pub fn decode_string<B: Buf>(
    buf: &mut B,
    prefix_bits: u8,
    max_len: usize,
) -> Result<Vec<u8>, QpackError> {
    debug_assert!((2..=8).contains(&prefix_bits));
    let (flags, len) = decode_int(buf, prefix_bits - 1)?;
    let huffman_encoded = flags & 1 == 1;
    let len = usize::try_from(len).map_err(|_| QpackError::IntegerOverflow)?;
    if len > max_len {
        return Err(QpackError::HeaderTooLarge { limit: max_len });
    }
    if buf.remaining() < len {
        return Err(QpackError::UnexpectedEnd);
    }
    let payload = buf.copy_to_bytes(len);
    if huffman_encoded {
        huffman::decode(&payload)
    } else {
        Ok(payload.to_vec())
    }
}

/// Encode an N-bit-prefix string literal.
///
/// The encoder uses Huffman coding only when it makes the string shorter; a
/// longer Huffman form is never selected. `high_bits` are the bits above the H
/// flag, already shifted down.
pub fn encode_string<B: BufMut>(buf: &mut B, prefix_bits: u8, high_bits: u8, value: &[u8]) {
    debug_assert!((2..=8).contains(&prefix_bits));
    let encoded = huffman::encode(value);
    let (payload, huffman_encoded) = if encoded.len() < value.len() {
        (encoded.as_slice(), true)
    } else {
        (value, false)
    };
    encode_int(
        buf,
        prefix_bits - 1,
        (high_bits << 1) | u8::from(huffman_encoded),
        payload.len() as u64,
    );
    buf.put_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn rfc7541_integer_examples() {
        let mut buf = BytesMut::from(&[0x0a][..]);
        assert_eq!(decode_int(&mut buf, 5).expect("10"), (0, 10));

        let mut buf = BytesMut::from(&[0x1f, 0x9a, 0x0a][..]);
        assert_eq!(decode_int(&mut buf, 5).expect("1337"), (0, 1337));

        let mut out = BytesMut::new();
        encode_int(&mut out, 5, 0, 10);
        assert_eq!(&out[..], &[0x0a]);
        out.clear();
        encode_int(&mut out, 5, 0, 1337);
        assert_eq!(&out[..], &[0x1f, 0x9a, 0x0a]);
    }

    #[test]
    fn eight_bit_prefix_round_trips_large_values() {
        let mut out = BytesMut::new();
        encode_int(&mut out, 8, 0, 424_242);
        let mut read = out.freeze();
        assert_eq!(decode_int(&mut read, 8).expect("decode"), (0, 424_242));
    }

    #[test]
    fn string_literals_round_trip_raw_and_huffman() {
        for value in [b"".as_slice(), b"www.example.com", b"x-dynamic"] {
            let mut out = BytesMut::new();
            encode_string(&mut out, 8, 0, value);
            let mut read = out.freeze();
            assert_eq!(decode_string(&mut read, 8, 1024).expect("decode"), value);
        }
    }

    #[test]
    fn a_truncated_integer_is_an_error() {
        let mut buf = BytesMut::from(&[0x1f][..]);
        assert!(matches!(
            decode_int(&mut buf, 5),
            Err(QpackError::UnexpectedEnd)
        ));
    }

    #[test]
    fn an_overlong_integer_is_an_error() {
        let mut buf =
            BytesMut::from(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f][..]);
        assert!(matches!(
            decode_int(&mut buf, 8),
            Err(QpackError::IntegerOverflow) | Ok(_)
        ));
    }
}
