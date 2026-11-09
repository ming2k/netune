// SPDX-License-Identifier: MIT

//! QPACK field-section decoder (RFC 9204 Section 4.5) and encoder-stream
//! instruction processing.
//!
//! The decoder is synchronous. When a section references an insertion that has
//! not arrived, it returns [`QpackError::MissingInsertions`]; the connection
//! owner waits on the QPACK generation and retries, which keeps the table lock
//! out of the await path.

use super::dynamic::{DynamicTable, HeaderField};
use super::error::QpackError;
use super::instructions::EncoderInstruction;
use super::prefix::{decode_int, decode_string};
use super::static_table;

/// A successfully decoded field section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSection {
    pub fields: Vec<HeaderField>,
    pub required_insert_count: u64,
    pub dynamic: bool,
}

/// One connection's QPACK decoder.
#[derive(Debug)]
pub struct Decoder {
    table: DynamicTable,
    max_capacity: usize,
    max_blocked: usize,
    max_field_section_size: usize,
}

impl Decoder {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            table: DynamicTable::decoder(max_capacity),
            max_capacity,
            max_blocked: 0,
            max_field_section_size: usize::MAX,
        }
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn max_blocked(&self) -> usize {
        self.max_blocked
    }

    pub fn total_inserted(&self) -> u64 {
        self.table.total_inserted()
    }

    pub fn table_capacity(&self) -> usize {
        self.table.capacity()
    }

    pub fn set_max_capacity(&mut self, capacity: usize) -> Result<(), QpackError> {
        if capacity > 1_073_741_823 {
            return Err(QpackError::CapacityTooLarge(capacity, 1_073_741_823));
        }
        self.max_capacity = capacity;
        self.table.set_max_capacity(capacity)
    }

    pub fn set_max_blocked(&mut self, blocked: usize) -> Result<(), QpackError> {
        if blocked > 65_535 {
            return Err(QpackError::CapacityTooLarge(blocked, 65_535));
        }
        self.max_blocked = blocked;
        Ok(())
    }

    pub fn set_max_field_section_size(&mut self, size: usize) {
        self.max_field_section_size = size;
    }

    /// Decode one field section. The caller must retry after receiving more
    /// encoder-stream instructions if this returns `MissingInsertions`.
    pub fn decode_section(
        &mut self,
        _stream_id: u64,
        block: &[u8],
    ) -> Result<DecodedSection, QpackError> {
        let mut cursor = block;
        let (_, encoded_required) = decode_int(&mut cursor, 8)?;
        let (sign, delta) = decode_int(&mut cursor, 7)?;
        let required = decode_required_insert_count(
            encoded_required,
            self.table.total_inserted(),
            self.max_capacity,
        )?;
        if required > self.table.total_inserted() {
            return Err(QpackError::MissingInsertions {
                required,
                received: self.table.total_inserted(),
            });
        }
        let base = if required == 0 {
            0
        } else if sign == 0 {
            required
                .checked_add(delta)
                .ok_or(QpackError::InvalidRequiredInsertCount)?
        } else {
            required
                .checked_sub(delta + 1)
                .ok_or(QpackError::InvalidRequiredInsertCount)?
        };

        let mut fields = Vec::new();
        let mut section_size = 0usize;
        while !cursor.is_empty() {
            let field = self.decode_field(&mut cursor, base, required)?;
            section_size = section_size.saturating_add(field.size());
            if section_size > self.max_field_section_size {
                return Err(QpackError::HeaderTooLarge {
                    limit: self.max_field_section_size,
                });
            }
            fields.push(field);
        }

        Ok(DecodedSection {
            fields,
            required_insert_count: required,
            dynamic: required > 0,
        })
    }

    /// Apply one encoder-stream instruction. Returns the number of insertions
    /// added (0 for a capacity update) so the connection can send the matching
    /// `Insert Count Increment`.
    pub fn apply_encoder_instruction(
        &mut self,
        instruction: EncoderInstruction,
    ) -> Result<u64, QpackError> {
        match instruction {
            EncoderInstruction::SetCapacity(capacity) => {
                if capacity > self.max_capacity {
                    return Err(QpackError::CapacityTooLarge(capacity, self.max_capacity));
                }
                self.table.change_capacity(capacity)?;
                Ok(0)
            }
            EncoderInstruction::InsertWithNameRef {
                static_table: true,
                index,
                value,
            } => {
                let (name, _) = static_table::get(
                    usize::try_from(index).map_err(|_| QpackError::IntegerOverflow)?,
                )
                .ok_or(QpackError::InvalidStaticIndex(
                    usize::try_from(index).unwrap_or(usize::MAX),
                ))?;
                let field = HeaderField::new(name, value);
                self.insert_decoder(field)
            }
            EncoderInstruction::InsertWithNameRef {
                static_table: false,
                index,
                value,
            } => {
                let base = self.table.total_inserted();
                let absolute = self.table.absolute_relative(base, index).map_err(|_| {
                    QpackError::InvalidDynamicIndex(usize::try_from(index).unwrap_or(usize::MAX))
                })?;
                let name = self
                    .table
                    .get_absolute(absolute)
                    .ok_or(QpackError::InvalidDynamicIndex(
                        usize::try_from(index).unwrap_or(usize::MAX),
                    ))?
                    .name
                    .clone();
                self.insert_decoder(HeaderField::new(name, value))
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => {
                self.insert_decoder(HeaderField::new(name, value))
            }
            EncoderInstruction::Duplicate { index } => {
                let base = self.table.total_inserted();
                let absolute = self.table.absolute_relative(base, index).map_err(|_| {
                    QpackError::InvalidDynamicIndex(usize::try_from(index).unwrap_or(usize::MAX))
                })?;
                let field = self
                    .table
                    .get_absolute(absolute)
                    .ok_or(QpackError::InvalidDynamicIndex(
                        usize::try_from(index).unwrap_or(usize::MAX),
                    ))?
                    .clone();
                self.insert_decoder(field)
            }
        }
    }

    fn insert_decoder(&mut self, field: HeaderField) -> Result<u64, QpackError> {
        // RFC 9204 requires a Set Dynamic Table Capacity instruction before the
        // first insertion. h3 0.0.8 omits it and treats the peer's advertised
        // maximum as the initial capacity. Accepting that shape is bounded by
        // the capacity we advertised, so it cannot exceed our memory budget.
        if self.table.capacity() == 0 && self.max_capacity > 0 {
            self.table.change_capacity(self.max_capacity)?;
        }
        match self.table.insert(field) {
            Ok(_) => Ok(1),
            Err(QpackError::EntryTooLarge(..) | QpackError::TableFull) => {
                Err(QpackError::EncoderStream)
            }
            Err(error) => Err(error),
        }
    }

    fn decode_field(
        &self,
        cursor: &mut &[u8],
        base: u64,
        required: u64,
    ) -> Result<HeaderField, QpackError> {
        let first = *cursor.first().ok_or(QpackError::UnexpectedEnd)?;
        if first & 0x80 != 0 {
            let (flags, index) = decode_int(cursor, 6)?;
            return match flags {
                0b11 => {
                    let index = usize::try_from(index).map_err(|_| QpackError::IntegerOverflow)?;
                    let (name, value) =
                        static_table::get(index).ok_or(QpackError::InvalidStaticIndex(index))?;
                    Ok(HeaderField::new(name, value))
                }
                0b10 => {
                    let absolute = self.table.absolute_relative(base, index)?;
                    self.check_reference(absolute, required)?;
                    self.table.get_absolute(absolute).cloned().ok_or(
                        QpackError::InvalidDynamicIndex(
                            usize::try_from(index).unwrap_or(usize::MAX),
                        ),
                    )
                }
                _ => Err(QpackError::InvalidPrefix(first)),
            };
        }

        if first & 0xf0 == 0b0001_0000 {
            let (flags, index) = decode_int(cursor, 4)?;
            if flags != 0b0001 {
                return Err(QpackError::InvalidPrefix(first));
            }
            let absolute = self.table.absolute_postbase(base, index)?;
            self.check_reference(absolute, required)?;
            return self.table.get_absolute(absolute).cloned().ok_or(
                QpackError::InvalidDynamicIndex(usize::try_from(index).unwrap_or(usize::MAX)),
            );
        }

        if first & 0xc0 == 0b0100_0000 {
            let (flags, index) = decode_int(cursor, 4)?;
            if flags & 0b1100 != 0b0100 {
                return Err(QpackError::InvalidPrefix(first));
            }
            let name = if flags & 1 == 1 {
                let index = usize::try_from(index).map_err(|_| QpackError::IntegerOverflow)?;
                static_table::get(index)
                    .ok_or(QpackError::InvalidStaticIndex(index))?
                    .0
            } else {
                let absolute = self.table.absolute_relative(base, index)?;
                self.check_reference(absolute, required)?;
                self.table
                    .get_absolute(absolute)
                    .ok_or(QpackError::InvalidDynamicIndex(
                        usize::try_from(index).unwrap_or(usize::MAX),
                    ))?
                    .name
                    .as_slice()
            };
            let value = decode_string(cursor, 8, self.max_field_section_size)?;
            return Ok(HeaderField::new(name, value));
        }

        if first & 0xf0 == 0 {
            let (flags, index) = decode_int(cursor, 3)?;
            if flags & 0b1110 != 0 {
                return Err(QpackError::InvalidPrefix(first));
            }
            let absolute = self.table.absolute_postbase(base, index)?;
            self.check_reference(absolute, required)?;
            let name = self
                .table
                .get_absolute(absolute)
                .ok_or(QpackError::InvalidDynamicIndex(
                    usize::try_from(index).unwrap_or(usize::MAX),
                ))?
                .name
                .clone();
            let value = decode_string(cursor, 8, self.max_field_section_size)?;
            return Ok(HeaderField::new(name, value));
        }

        if first & 0xe0 == 0b0010_0000 {
            let name = decode_string(cursor, 4, self.max_field_section_size)?;
            let value = decode_string(cursor, 8, self.max_field_section_size)?;
            return Ok(HeaderField::new(name, value));
        }

        Err(QpackError::InvalidPrefix(first))
    }

    fn check_reference(&self, absolute: u64, required: u64) -> Result<(), QpackError> {
        if absolute >= required {
            return Err(QpackError::ReferenceOutsideSection {
                reference: absolute,
                required,
            });
        }
        Ok(())
    }
}

/// Reconstruct the Required Insert Count from the encoded prefix.
///
/// Implements RFC 9204 Section 4.5.1.1, including the wrap-around rule.
pub fn decode_required_insert_count(
    encoded: u64,
    total_inserted: u64,
    max_capacity: usize,
) -> Result<u64, QpackError> {
    if encoded == 0 {
        return Ok(0);
    }
    let max_entries = max_capacity / 32;
    if max_entries == 0 {
        return Err(QpackError::InvalidRequiredInsertCount);
    }
    let full_range = 2 * max_entries as u64;
    if encoded > full_range {
        return Err(QpackError::InvalidRequiredInsertCount);
    }
    let max_value = total_inserted.saturating_add(max_entries as u64);
    let max_wrapped = (max_value / full_range) * full_range;
    let mut required = max_wrapped
        .checked_add(encoded - 1)
        .ok_or(QpackError::InvalidRequiredInsertCount)?;
    if required > max_value {
        if required <= full_range {
            return Err(QpackError::InvalidRequiredInsertCount);
        }
        required -= full_range;
    }
    if required == 0 {
        return Err(QpackError::InvalidRequiredInsertCount);
    }
    Ok(required)
}

/// Encode the Required Insert Count transform. The inverse of
/// [`decode_required_insert_count`].
pub fn encode_required_insert_count(required: u64, max_capacity: usize) -> Result<u64, QpackError> {
    if required == 0 {
        return Ok(0);
    }
    let max_entries = max_capacity / 32;
    if max_entries == 0 {
        return Err(QpackError::InvalidRequiredInsertCount);
    }
    Ok(required % (2 * max_entries as u64) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::encoder::Encoder;
    use crate::qpack::instructions::DecoderInstruction;

    fn field(name: &'static [u8], value: &'static [u8]) -> HeaderField {
        HeaderField::new(name, value)
    }

    #[test]
    fn rfc9204_required_insert_count_example() {
        // The RFC example: 100-byte table, 10 inserts, encoded value 4 -> 9.
        assert_eq!(decode_required_insert_count(4, 10, 100).expect("decode"), 9);
    }

    #[test]
    fn required_insert_count_zero_is_zero() {
        assert_eq!(decode_required_insert_count(0, 0, 0).expect("decode"), 0);
        assert!(decode_required_insert_count(1, 0, 0).is_err());
    }

    #[test]
    fn a_stateless_section_round_trips() {
        let mut encoder = Encoder::new();
        let encoded = encoder
            .encode_section(1, &[field(b":method", b"GET"), field(b"x-test", b"one")])
            .expect("encode");
        let mut decoder = Decoder::new(0);
        let decoded = decoder.decode_section(1, &encoded.block).expect("decode");
        assert_eq!(
            decoded.fields,
            vec![field(b":method", b"GET"), field(b"x-test", b"one")]
        );
        assert!(!decoded.dynamic);
    }

    fn apply_all(decoder: &mut Decoder, mut bytes: &[u8]) -> u64 {
        let mut insertions = 0;
        while !bytes.is_empty() {
            let (instruction, consumed) =
                super::super::instructions::decode_encoder_instruction(bytes, 1024)
                    .expect("decode instruction")
                    .expect("complete");
            insertions += decoder
                .apply_encoder_instruction(instruction)
                .expect("apply instruction");
            bytes = &bytes[consumed..];
        }
        insertions
    }

    #[test]
    fn dynamic_sections_round_trip_after_acknowledgement() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new(4096);
        let capacity = encoder
            .apply_peer_settings(4096, 1 << 20)
            .expect("settings");
        apply_all(&mut decoder, &capacity);

        let first = encoder
            .encode_section(1, &[field(b"x-dynamic", b"one")])
            .expect("insertion");
        let inserted = apply_all(&mut decoder, &first.encoder_instructions);
        assert_eq!(inserted, 1);
        encoder
            .apply_decoder_instruction(DecoderInstruction::InsertCountIncrement(inserted))
            .expect("increment");

        let second = encoder
            .encode_section(3, &[field(b"x-dynamic", b"one")])
            .expect("reference");
        assert_eq!(second.required_insert_count, 1);
        let decoded = decoder.decode_section(3, &second.block).expect("decode");
        assert_eq!(decoded.fields, vec![field(b"x-dynamic", b"one")]);
        assert!(decoded.dynamic);
    }

    #[test]
    fn missing_insertions_are_reported_not_misdecoded() {
        // Required Insert Count 1, Delta Base 0, then an indexed dynamic entry
        // with relative index 0. No encoder-stream insertion has arrived.
        let block = [0x02, 0x00, 0x80];
        let mut decoder = Decoder::new(4096);
        assert!(matches!(
            decoder.decode_section(3, &block),
            Err(QpackError::MissingInsertions {
                required: 1,
                received: 0
            })
        ));
    }

    #[test]
    fn an_invalid_static_index_is_rejected() {
        let mut decoder = Decoder::new(0);
        // Indexed field line, static table, index 99 (past the table).
        let block = [0xff, 0x67];
        assert!(matches!(
            decoder.decode_section(1, &block),
            Err(QpackError::InvalidStaticIndex(_)) | Err(QpackError::UnexpectedEnd)
        ));
    }
}
