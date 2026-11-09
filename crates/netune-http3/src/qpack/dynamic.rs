// SPDX-License-Identifier: MIT

//! The QPACK dynamic table (RFC 9204 Section 3.2).
//!
//! Encoding and decoding each own an independent table. The encoder table
//! refuses to evict an entry that is unacknowledged or still referenced by an
//! outstanding field section; the decoder table applies instructions exactly as
//! received and is therefore allowed to evict any entry.

use std::collections::VecDeque;

use super::error::QpackError;

/// A QPACK field line. Names are lower-case on the wire; validation happens in
/// the H3 layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl HeaderField {
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// RFC 9204 Section 3.2.1: name length + value length + 32 octets.
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

#[derive(Debug)]
struct Entry {
    field: HeaderField,
    size: usize,
    references: u32,
}

/// A dynamic table shared by one QPACK direction.
#[derive(Debug)]
pub struct DynamicTable {
    /// Front is the newest entry, back is the oldest.
    entries: VecDeque<Entry>,
    insert_count: u64,
    size: usize,
    capacity: usize,
    max_capacity: usize,
    known_received: u64,
    decoder_side: bool,
}

impl DynamicTable {
    /// Create an encoder-side table. The peer's SETTINGS set the maximum.
    pub fn encoder(peer_max_capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            insert_count: 0,
            size: 0,
            capacity: 0,
            max_capacity: peer_max_capacity,
            known_received: 0,
            decoder_side: false,
        }
    }

    /// Create a decoder-side table. Our SETTINGS set the maximum.
    pub fn decoder(max_capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            insert_count: 0,
            size: 0,
            capacity: 0,
            max_capacity,
            known_received: 0,
            decoder_side: true,
        }
    }

    pub fn total_inserted(&self) -> u64 {
        self.insert_count
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn known_received(&self) -> u64 {
        self.known_received
    }

    pub fn set_known_received(&mut self, count: u64) {
        self.known_received = self.known_received.max(count);
    }

    /// The lowest absolute index still present.
    pub fn first_absolute(&self) -> u64 {
        self.insert_count - self.entries.len() as u64
    }

    /// Update the peer-advertised maximum. The active capacity is reduced if it
    /// now exceeds the maximum.
    pub fn set_max_capacity(&mut self, capacity: usize) -> Result<(), QpackError> {
        if capacity > 1_073_741_823 {
            return Err(QpackError::CapacityTooLarge(capacity, 1_073_741_823));
        }
        let previous = self.max_capacity;
        self.max_capacity = capacity;
        if self.capacity > capacity
            && let Err(error) = self.change_capacity(capacity)
        {
            self.max_capacity = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Set the active capacity, evicting entries as required.
    pub fn change_capacity(&mut self, capacity: usize) -> Result<(), QpackError> {
        if capacity > self.max_capacity {
            return Err(QpackError::CapacityTooLarge(capacity, self.max_capacity));
        }
        let evicted = self.eviction_plan(capacity)?;
        self.apply_evictions(&evicted);
        self.capacity = capacity;
        Ok(())
    }

    /// Insert a field. The caller decides which capacity and mode apply.
    pub fn insert(&mut self, field: HeaderField) -> Result<u64, QpackError> {
        let size = field.size();
        if size > self.capacity {
            return Err(QpackError::EntryTooLarge(size, self.capacity));
        }

        let target = self.capacity.saturating_sub(size);
        let evicted = self.eviction_plan(target)?;
        self.apply_evictions(&evicted);

        let absolute = self.insert_count;
        self.insert_count = self.insert_count.saturating_add(1);
        self.size += size;
        self.entries.push_front(Entry {
            field,
            size,
            references: 0,
        });
        Ok(absolute)
    }

    /// Mark an entry as referenced by an outstanding field section.
    pub fn retain(&mut self, absolute: u64) -> Result<(), QpackError> {
        let index = self
            .index_of(absolute)
            .ok_or(QpackError::InvalidDynamicIndex(
                usize::try_from(absolute).unwrap_or(usize::MAX),
            ))?;
        self.entries[index].references = self.entries[index].references.saturating_add(1);
        Ok(())
    }

    /// Release one reference taken by [`Self::retain`].
    pub fn release(&mut self, absolute: u64) {
        if let Some(index) = self.index_of(absolute) {
            let entry = &mut self.entries[index];
            entry.references = entry.references.saturating_sub(1);
        }
    }

    /// Borrow a live entry by absolute index.
    pub fn get_absolute(&self, absolute: u64) -> Option<&HeaderField> {
        self.index_of(absolute)
            .and_then(|index| self.entries.get(index))
            .map(|entry| &entry.field)
    }

    /// Resolve a field-section relative index against `base` to an absolute
    /// index. The caller validates the Required Insert Count bound.
    pub fn absolute_relative(&self, base: u64, relative: u64) -> Result<u64, QpackError> {
        let absolute = base
            .checked_sub(relative + 1)
            .ok_or(QpackError::InvalidDynamicIndex(
                usize::try_from(relative).unwrap_or(usize::MAX),
            ))?;
        self.get_absolute(absolute)
            .ok_or(QpackError::InvalidDynamicIndex(
                usize::try_from(relative).unwrap_or(usize::MAX),
            ))
            .map(|_| absolute)
    }

    /// Resolve a field-section post-Base index against `base` to an absolute
    /// index. The caller validates the Required Insert Count bound.
    pub fn absolute_postbase(&self, base: u64, index: u64) -> Result<u64, QpackError> {
        let absolute = base
            .checked_add(index)
            .ok_or(QpackError::InvalidDynamicIndex(
                usize::try_from(index).unwrap_or(usize::MAX),
            ))?;
        self.get_absolute(absolute)
            .ok_or(QpackError::InvalidDynamicIndex(
                usize::try_from(index).unwrap_or(usize::MAX),
            ))
            .map(|_| absolute)
    }

    /// Resolve a field-section relative index against `base`.
    pub fn get_relative(&self, base: u64, relative: u64) -> Result<&HeaderField, QpackError> {
        let absolute = self.absolute_relative(base, relative)?;
        self.get_absolute(absolute)
            .ok_or(QpackError::InvalidDynamicIndex(
                usize::try_from(relative).unwrap_or(usize::MAX),
            ))
    }

    /// Resolve a field-section post-Base index against `base`.
    pub fn get_postbase(&self, base: u64, index: u64) -> Result<&HeaderField, QpackError> {
        let absolute = self.absolute_postbase(base, index)?;
        self.get_absolute(absolute)
            .ok_or(QpackError::InvalidDynamicIndex(
                usize::try_from(index).unwrap_or(usize::MAX),
            ))
    }

    /// The relative index used by encoder-stream instructions (0 is newest).
    pub fn relative_index(&self, absolute: u64) -> Option<u64> {
        if absolute >= self.insert_count {
            return None;
        }
        Some(self.insert_count - absolute - 1)
    }

    /// Find an exact field, returning its absolute index.
    pub fn find_exact(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        self.entries.iter().enumerate().find_map(|(index, entry)| {
            (entry.field.name == name && entry.field.value == value)
                .then_some(self.insert_count - 1 - index as u64)
        })
    }

    /// Find the newest entry with a matching name.
    pub fn find_name(&self, name: &[u8]) -> Option<u64> {
        self.entries.iter().enumerate().find_map(|(index, entry)| {
            (entry.field.name == name).then_some(self.insert_count - 1 - index as u64)
        })
    }

    /// Compute which entries would have to leave the table to reach
    /// `target_size`, without mutating it. A failed plan therefore leaves the
    /// encoder table byte-for-byte identical to the decoder's expectation.
    fn eviction_plan(&self, target_size: usize) -> Result<Vec<u64>, QpackError> {
        if self.size <= target_size {
            return Ok(Vec::new());
        }
        let first = self.first_absolute();
        let mut remaining = self.size;
        let mut evicted = Vec::new();
        for offset in 0..self.entries.len() {
            if remaining <= target_size {
                break;
            }
            let absolute = first + offset as u64;
            if !self.evictable(absolute) {
                return Err(QpackError::TableFull);
            }
            let entry = &self.entries[self.entries.len() - 1 - offset];
            remaining -= entry.size;
            evicted.push(absolute);
        }
        if remaining > target_size {
            return Err(QpackError::TableFull);
        }
        Ok(evicted)
    }

    fn apply_evictions(&mut self, evicted: &[u64]) {
        for _ in evicted {
            let Some(entry) = self.entries.pop_back() else {
                break;
            };
            self.size -= entry.size;
        }
    }

    fn evictable(&self, absolute: u64) -> bool {
        if self.decoder_side {
            return true;
        }
        if absolute >= self.known_received {
            return false;
        }
        self.index_of(absolute)
            .and_then(|index| self.entries.get(index))
            .is_some_and(|entry| entry.references == 0)
    }

    fn index_of(&self, absolute: u64) -> Option<usize> {
        if absolute >= self.insert_count {
            return None;
        }
        let first = self.first_absolute();
        if absolute < first {
            return None;
        }
        let offset = usize::try_from(absolute - first).ok()?;
        let len = self.entries.len();
        (offset < len).then_some(len - 1 - offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_and_relative_indices_match_the_rfc() {
        let mut table = DynamicTable::encoder(4096);
        table.change_capacity(4096).expect("capacity");
        let first = table
            .insert(HeaderField::new(b"x-a".as_slice(), b"1".as_slice()))
            .expect("insert");
        let second = table
            .insert(HeaderField::new(b"x-b".as_slice(), b"2".as_slice()))
            .expect("insert");
        assert_eq!((first, second), (0, 1));
        assert_eq!(
            table.get_absolute(0).map(|f| f.name.as_slice()),
            Some(b"x-a".as_slice())
        );
        assert_eq!(
            table
                .get_relative(2, 0)
                .expect("relative 0")
                .name
                .as_slice(),
            b"x-b".as_slice()
        );
        assert_eq!(
            table
                .get_relative(2, 1)
                .expect("relative 1")
                .name
                .as_slice(),
            b"x-a".as_slice()
        );
        assert_eq!(
            table.get_postbase(1, 0).expect("post-base").name.as_slice(),
            b"x-b".as_slice()
        );
        assert_eq!(table.relative_index(0), Some(1));
        assert_eq!(table.relative_index(1), Some(0));
    }

    #[test]
    fn encoder_does_not_evict_unacknowledged_entries() {
        let mut table = DynamicTable::encoder(64);
        table.change_capacity(64).expect("capacity");
        table
            .insert(HeaderField::new(b"a".as_slice(), b"1".as_slice()))
            .expect("first");
        // A second entry would require evicting the first, which is not acknowledged.
        assert!(matches!(
            table.insert(HeaderField::new(b"b".as_slice(), b"2".as_slice())),
            Err(QpackError::TableFull)
        ));
    }

    #[test]
    fn decoder_can_evict_immediately() {
        let mut table = DynamicTable::decoder(64);
        table.change_capacity(64).expect("capacity");
        table
            .insert(HeaderField::new(b"a".as_slice(), b"1".as_slice()))
            .expect("first");
        table
            .insert(HeaderField::new(b"b".as_slice(), b"2".as_slice()))
            .expect("second");
        assert_eq!(table.total_inserted(), 2);
        assert_eq!(table.size(), 34);
    }

    #[test]
    fn an_entry_larger_than_capacity_is_rejected() {
        let mut table = DynamicTable::decoder(64);
        table.change_capacity(64).expect("capacity");
        assert!(matches!(
            table.insert(HeaderField::new(vec![b'a'; 64], Vec::new())),
            Err(QpackError::EntryTooLarge(..))
        ));
    }
}
