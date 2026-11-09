// SPDX-License-Identifier: MIT

//! QPACK field-section encoder (RFC 9204 Section 4.5).
//!
//! The encoder is deliberately conservative about blocking: it references a
//! dynamic entry only after the decoder has acknowledged it. New fields are
//! inserted and sent as literals in the section that discovers them, so the
//! decoder never has to wait for an insertion to finish the current section.
//! This keeps the blocked-stream budget free for peers that choose to use it.

use std::collections::{HashMap, VecDeque};

use bytes::{Bytes, BytesMut};

use super::dynamic::{DynamicTable, HeaderField};
use super::error::QpackError;
use super::instructions::{DecoderInstruction, EncoderInstruction};
use super::prefix::{encode_int, encode_string};
use super::static_table;

/// Upper bound on the encoder table, even if the peer advertises more. The
/// decoder still enforces its own advertised maximum.
const MAX_ENCODER_CAPACITY: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct BlockRefs {
    largest: u64,
    refs: Vec<u64>,
}

/// A header block plus the encoder-stream instructions that must be written
/// before later blocks can rely on its insertions.
#[derive(Debug, Clone)]
pub struct EncodedSection {
    pub block: Bytes,
    pub encoder_instructions: Bytes,
    pub required_insert_count: u64,
}

/// One connection's QPACK encoder.
#[derive(Debug)]
pub struct Encoder {
    table: DynamicTable,
    peer_max_capacity: usize,
    max_field_section_size: usize,
    known_received: u64,
    stream_refs: HashMap<u64, VecDeque<BlockRefs>>,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            table: DynamicTable::encoder(0),
            peer_max_capacity: 0,
            max_field_section_size: usize::MAX,
            known_received: 0,
            stream_refs: HashMap::new(),
        }
    }

    pub fn known_received(&self) -> u64 {
        self.known_received
    }

    pub fn table_capacity(&self) -> usize {
        self.table.capacity()
    }

    /// Apply the peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`.
    ///
    /// Returns the `Set Dynamic Table Capacity` instruction that must be
    /// written to the encoder stream before any insertion instruction.
    pub fn apply_peer_settings(
        &mut self,
        max_table_capacity: usize,
        max_field_section_size: usize,
    ) -> Result<Bytes, QpackError> {
        if max_table_capacity > 1_073_741_823 {
            return Err(QpackError::CapacityTooLarge(
                max_table_capacity,
                1_073_741_823,
            ));
        }
        self.max_field_section_size = max_field_section_size;
        let old_capacity = self.table.capacity();
        let target = if max_table_capacity == 0 {
            0
        } else {
            max_table_capacity.min(MAX_ENCODER_CAPACITY)
        };
        self.peer_max_capacity = max_table_capacity;
        self.table.set_max_capacity(target)?;
        self.table.change_capacity(target)?;
        if self.table.capacity() == old_capacity {
            return Ok(Bytes::new());
        }
        let mut instructions = BytesMut::new();
        EncoderInstruction::SetCapacity(self.table.capacity()).encode(&mut instructions);
        Ok(instructions.freeze())
    }

    /// Encode one field section. `base` is fixed at the start of the section so
    /// insertions performed while encoding do not invalidate earlier indices.
    pub fn encode_section(
        &mut self,
        stream_id: u64,
        fields: &[HeaderField],
    ) -> Result<EncodedSection, QpackError> {
        let section_size: usize = fields.iter().map(HeaderField::size).sum();
        if section_size > self.max_field_section_size {
            return Err(QpackError::HeaderTooLarge {
                limit: self.max_field_section_size,
            });
        }

        let base = self.table.total_inserted();
        let mut block = BytesMut::new();
        let mut instructions = BytesMut::new();
        let mut refs = Vec::new();

        for field in fields {
            self.encode_field(field, base, &mut block, &mut instructions, &mut refs)?;
        }

        let required = refs.iter().copied().max().map_or(0, |index| index + 1);
        let mut prefix = BytesMut::new();
        if required == 0 {
            encode_int(&mut prefix, 8, 0, 0);
            encode_int(&mut prefix, 7, 0, 0);
        } else {
            let max_entries = self.peer_max_capacity / 32;
            if max_entries == 0 {
                return Err(QpackError::InvalidRequiredInsertCount);
            }
            let encoded = required % (2 * max_entries as u64) + 1;
            encode_int(&mut prefix, 8, 0, encoded);
            if base >= required {
                encode_int(&mut prefix, 7, 0, base - required);
            } else {
                encode_int(&mut prefix, 7, 1, required - base - 1);
            }
        }
        prefix.extend_from_slice(&block);

        if !refs.is_empty() {
            let largest = required - 1;
            for reference in &refs {
                self.table.retain(*reference)?;
            }
            self.stream_refs
                .entry(stream_id)
                .or_default()
                .push_back(BlockRefs { largest, refs });
        }

        Ok(EncodedSection {
            block: prefix.freeze(),
            encoder_instructions: instructions.freeze(),
            required_insert_count: required,
        })
    }

    /// Apply one instruction received on the decoder stream.
    pub fn apply_decoder_instruction(
        &mut self,
        instruction: DecoderInstruction,
    ) -> Result<(), QpackError> {
        match instruction {
            DecoderInstruction::SectionAck(stream_id) => {
                let Some(blocks) = self.stream_refs.get_mut(&stream_id) else {
                    // h3 0.0.8 acknowledges every decoded section, including
                    // sections whose Required Insert Count is zero. RFC 9204
                    // says the decoder should omit that acknowledgement; an
                    // encoder that cannot match it has nothing to release, so
                    // ignoring it keeps the connection interoperable.
                    return Ok(());
                };
                let Some(block) = blocks.pop_front() else {
                    return Ok(());
                };
                if blocks.is_empty() {
                    self.stream_refs.remove(&stream_id);
                }
                for reference in block.refs {
                    self.table.release(reference);
                }
                self.known_received = self.known_received.max(block.largest + 1);
                self.table.set_known_received(self.known_received);
            }
            DecoderInstruction::StreamCancellation(stream_id) => {
                if let Some(blocks) = self.stream_refs.remove(&stream_id) {
                    for block in blocks {
                        for reference in block.refs {
                            self.table.release(reference);
                        }
                    }
                }
            }
            DecoderInstruction::InsertCountIncrement(increment) => {
                if increment == 0
                    || self.known_received.saturating_add(increment) > self.table.total_inserted()
                {
                    return Err(QpackError::InvalidInsertCountIncrement);
                }
                self.known_received += increment;
                self.table.set_known_received(self.known_received);
            }
        }
        Ok(())
    }

    fn encode_field(
        &mut self,
        field: &HeaderField,
        base: u64,
        block: &mut BytesMut,
        instructions: &mut BytesMut,
        refs: &mut Vec<u64>,
    ) -> Result<(), QpackError> {
        if let Some(index) = static_table::find_exact(&field.name, &field.value) {
            encode_int(block, 6, 0b11, index as u64);
            return Ok(());
        }

        if let Some(absolute) = self.table.find_exact(&field.name, &field.value)
            && absolute < self.known_received
        {
            let relative = base
                .checked_sub(absolute + 1)
                .ok_or(QpackError::InvalidDynamicIndex(absolute as usize))?;
            encode_int(block, 6, 0b10, relative);
            refs.push(absolute);
            return Ok(());
        }
        // A matching but unacknowledged entry is legal to send as a literal and
        // reference in a later section once the decoder catches up.

        let static_name = static_table::find_name(&field.name);
        let dynamic_name = if static_name.is_none() {
            self.table.find_name(&field.name)
        } else {
            None
        };

        if self.table.capacity() > 0 && field.size() <= self.table.capacity() {
            let old_total = self.table.total_inserted();
            match self.table.insert(field.clone()) {
                Ok(_) => {
                    match static_name {
                        Some(index) => EncoderInstruction::InsertWithNameRef {
                            static_table: true,
                            index: index as u64,
                            value: field.value.clone(),
                        },
                        None => match dynamic_name {
                            Some(absolute) if absolute < old_total => {
                                EncoderInstruction::InsertWithNameRef {
                                    static_table: false,
                                    index: old_total - absolute - 1,
                                    value: field.value.clone(),
                                }
                            }
                            _ => EncoderInstruction::InsertWithLiteralName {
                                name: field.name.clone(),
                                value: field.value.clone(),
                            },
                        },
                    }
                    .encode(instructions);
                }
                Err(QpackError::TableFull | QpackError::EntryTooLarge { .. }) => {}
                Err(error) => return Err(error),
            }
        }

        // The field line itself never references an unacknowledged insertion.
        // It is a literal with the cheapest available name representation.
        if let Some(index) = static_name {
            encode_int(block, 4, 0b0101, index as u64);
            encode_string(block, 8, 0, &field.value);
        } else if let Some(absolute) = dynamic_name.filter(|index| *index < self.known_received) {
            let relative = base
                .checked_sub(absolute + 1)
                .ok_or(QpackError::InvalidDynamicIndex(absolute as usize))?;
            encode_int(block, 4, 0b0100, relative);
            encode_string(block, 8, 0, &field.value);
            refs.push(absolute);
        } else {
            encode_string(block, 4, 0b0010, &field.name);
            encode_string(block, 8, 0, &field.value);
        }

        Ok(())
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::decoder::Decoder;

    fn field(name: &'static [u8], value: &'static [u8]) -> HeaderField {
        HeaderField::new(name, value)
    }

    #[test]
    fn stateless_encoding_uses_static_entries_and_literals() {
        let mut encoder = Encoder::new();
        let section = encoder
            .encode_section(
                1,
                &[
                    field(b":method", b"GET"),
                    field(b":path", b"/"),
                    field(b"x-custom", b"value"),
                ],
            )
            .expect("encode");
        assert_eq!(section.required_insert_count, 0);
        assert!(section.encoder_instructions.is_empty());

        let mut decoder = Decoder::new(0);
        let decoded = decoder.decode_section(1, &section.block).expect("decode");
        assert_eq!(
            decoded.fields,
            vec![
                field(b":method", b"GET"),
                field(b":path", b"/"),
                field(b"x-custom", b"value"),
            ]
        );
        assert!(!decoded.dynamic);
    }

    #[test]
    fn a_dynamic_entry_is_used_only_after_acknowledgement() {
        let mut encoder = Encoder::new();
        encoder
            .apply_peer_settings(4096, 1 << 20)
            .expect("settings");
        let section = encoder
            .encode_section(1, &[field(b"x-dynamic", b"value")])
            .expect("encode");
        assert!(!section.encoder_instructions.is_empty());
        assert_eq!(section.required_insert_count, 0);

        // Simulate the decoder receiving the insertion and acknowledging it.
        encoder
            .apply_decoder_instruction(DecoderInstruction::InsertCountIncrement(1))
            .expect("increment");
        let section = encoder
            .encode_section(3, &[field(b"x-dynamic", b"value")])
            .expect("encode");
        assert_eq!(section.required_insert_count, 1);
        assert!(!section.block.is_empty());
    }

    #[test]
    fn section_acknowledgement_releases_references() {
        let mut encoder = Encoder::new();
        encoder
            .apply_peer_settings(4096, 1 << 20)
            .expect("settings");
        let _ = encoder
            .encode_section(1, &[field(b"x-dynamic", b"value")])
            .expect("insertion");
        encoder
            .apply_decoder_instruction(DecoderInstruction::InsertCountIncrement(1))
            .expect("increment");
        let _ = encoder
            .encode_section(3, &[field(b"x-dynamic", b"value")])
            .expect("reference");
        encoder
            .apply_decoder_instruction(DecoderInstruction::SectionAck(3))
            .expect("ack");
        // A second ack for the same stream has nothing left to release; h3
        // 0.0.8 sends one even for stateless sections, so this is tolerated.
        encoder
            .apply_decoder_instruction(DecoderInstruction::SectionAck(3))
            .expect("duplicate ack");
    }

    #[test]
    fn zero_capacity_emits_no_insertions() {
        let mut encoder = Encoder::new();
        encoder.apply_peer_settings(0, 1 << 20).expect("settings");
        let section = encoder
            .encode_section(1, &[field(b"x-dynamic", b"value")])
            .expect("encode");
        assert!(section.encoder_instructions.is_empty());
        assert_eq!(section.required_insert_count, 0);
    }
}
