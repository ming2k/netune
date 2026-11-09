// SPDX-License-Identifier: MIT

//! QPACK encoder-stream and decoder-stream instructions (RFC 9204 Section 4.3/4.4).

use bytes::BufMut;

use super::error::QpackError;
use super::prefix::{decode_int, decode_string, encode_int, encode_string};

/// An instruction sent on the encoder stream (encoder -> decoder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderInstruction {
    SetCapacity(usize),
    InsertWithNameRef {
        static_table: bool,
        index: u64,
        value: Vec<u8>,
    },
    InsertWithLiteralName {
        name: Vec<u8>,
        value: Vec<u8>,
    },
    Duplicate {
        index: u64,
    },
}

/// An instruction sent on the decoder stream (decoder -> encoder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderInstruction {
    SectionAck(u64),
    StreamCancellation(u64),
    InsertCountIncrement(u64),
}

impl EncoderInstruction {
    /// Append the wire form to `buf`.
    pub fn encode(&self, buf: &mut impl BufMut) {
        match self {
            Self::SetCapacity(capacity) => encode_int(buf, 5, 0b001, *capacity as u64),
            Self::InsertWithNameRef {
                static_table,
                index,
                value,
            } => {
                encode_int(buf, 6, if *static_table { 0b11 } else { 0b10 }, *index);
                encode_string(buf, 8, 0, value);
            }
            Self::InsertWithLiteralName { name, value } => {
                encode_string(buf, 6, 0b01, name);
                encode_string(buf, 8, 0, value);
            }
            Self::Duplicate { index } => encode_int(buf, 5, 0, *index),
        }
    }
}

impl DecoderInstruction {
    /// Append the wire form to `buf`.
    pub fn encode(&self, buf: &mut impl BufMut) {
        match self {
            Self::SectionAck(stream_id) => encode_int(buf, 7, 0b1, *stream_id),
            Self::StreamCancellation(stream_id) => encode_int(buf, 6, 0b01, *stream_id),
            Self::InsertCountIncrement(increment) => encode_int(buf, 6, 0, *increment),
        }
    }
}

/// Decode one encoder instruction from the front of `input`.
///
/// `Ok(None)` means the input ends in the middle of an instruction; the caller
/// should read more bytes and retry with the same slice.
pub fn decode_encoder_instruction(
    input: &[u8],
    max_string: usize,
) -> Result<Option<(EncoderInstruction, usize)>, QpackError> {
    let mut cursor = input;
    let before = cursor.len();
    let first = match cursor.first() {
        Some(byte) => *byte,
        None => return Ok(None),
    };

    let instruction = if first & 0x80 != 0 {
        let (flags, index) = match decode_int(&mut cursor, 6) {
            Ok(value) => value,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        let static_table = match flags {
            0b10 => false,
            0b11 => true,
            _ => return Err(QpackError::EncoderStream),
        };
        let value = match decode_string(&mut cursor, 8, max_string) {
            Ok(value) => value,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        EncoderInstruction::InsertWithNameRef {
            static_table,
            index,
            value,
        }
    } else if first & 0xc0 == 0b0100_0000 {
        let name = match decode_string(&mut cursor, 6, max_string) {
            Ok(name) => name,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        let value = match decode_string(&mut cursor, 8, max_string) {
            Ok(value) => value,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        EncoderInstruction::InsertWithLiteralName { name, value }
    } else if first & 0xe0 == 0 {
        let (flags, index) = match decode_int(&mut cursor, 5) {
            Ok(value) => value,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        if flags != 0 {
            return Err(QpackError::EncoderStream);
        }
        EncoderInstruction::Duplicate { index }
    } else if first & 0xe0 == 0b0010_0000 {
        let (flags, capacity) = match decode_int(&mut cursor, 5) {
            Ok(value) => value,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        if flags != 0b001 {
            return Err(QpackError::EncoderStream);
        }
        let capacity = usize::try_from(capacity).map_err(|_| QpackError::IntegerOverflow)?;
        EncoderInstruction::SetCapacity(capacity)
    } else {
        return Err(QpackError::EncoderStream);
    };

    Ok(Some((instruction, before - cursor.len())))
}

/// Decode one decoder instruction from the front of `input`.
pub fn decode_decoder_instruction(
    input: &[u8],
) -> Result<Option<(DecoderInstruction, usize)>, QpackError> {
    let mut cursor = input;
    let before = cursor.len();
    let first = match cursor.first() {
        Some(byte) => *byte,
        None => return Ok(None),
    };

    let instruction = if first & 0xc0 == 0 {
        let (flags, increment) = match decode_int(&mut cursor, 6) {
            Ok(value) => value,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        if flags != 0 || increment == 0 {
            return Err(QpackError::DecoderStream);
        }
        DecoderInstruction::InsertCountIncrement(increment)
    } else if first & 0x80 != 0 {
        let (flags, stream_id) = match decode_int(&mut cursor, 7) {
            Ok(value) => value,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        if flags != 1 {
            return Err(QpackError::DecoderStream);
        }
        DecoderInstruction::SectionAck(stream_id)
    } else if first & 0xc0 == 0b0100_0000 {
        let (flags, stream_id) = match decode_int(&mut cursor, 6) {
            Ok(value) => value,
            Err(QpackError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error),
        };
        if flags != 0b01 {
            return Err(QpackError::DecoderStream);
        }
        DecoderInstruction::StreamCancellation(stream_id)
    } else {
        return Err(QpackError::DecoderStream);
    };

    Ok(Some((instruction, before - cursor.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn encoder_instructions_round_trip() {
        let instructions = [
            EncoderInstruction::SetCapacity(4096),
            EncoderInstruction::InsertWithNameRef {
                static_table: true,
                index: 17,
                value: b"GET".to_vec(),
            },
            EncoderInstruction::InsertWithLiteralName {
                name: b"x-test".to_vec(),
                value: b"value".to_vec(),
            },
            EncoderInstruction::Duplicate { index: 3 },
        ];
        for instruction in instructions {
            let mut encoded = BytesMut::new();
            instruction.encode(&mut encoded);
            let (decoded, consumed) = decode_encoder_instruction(&encoded, 1024)
                .expect("decode")
                .expect("complete");
            assert_eq!(decoded, instruction);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn decoder_instructions_round_trip() {
        let instructions = [
            DecoderInstruction::SectionAck(1),
            DecoderInstruction::StreamCancellation(2),
            DecoderInstruction::InsertCountIncrement(3),
        ];
        for instruction in instructions {
            let mut encoded = BytesMut::new();
            instruction.encode(&mut encoded);
            let (decoded, consumed) = decode_decoder_instruction(&encoded)
                .expect("decode")
                .expect("complete");
            assert_eq!(decoded, instruction);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn truncated_instructions_are_incomplete_not_invalid() {
        assert_eq!(decode_encoder_instruction(&[], 1024).expect("empty"), None);
        assert_eq!(
            decode_encoder_instruction(&[0x3f], 1024).expect("capacity prefix"),
            None
        );
        assert_eq!(
            decode_decoder_instruction(&[0xff]).expect("stream id"),
            None
        );
    }

    #[test]
    fn zero_increment_is_a_decoder_stream_error() {
        assert!(matches!(
            decode_decoder_instruction(&[0x00]),
            Err(QpackError::DecoderStream)
        ));
    }
}
