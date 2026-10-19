//! The delta-encoded, bounded event ring.
//!
//! Storage is `(dt_ns, kind, a, b)` per event, where `dt_ns` is the gap from the
//! *previous stored event*. Gaps longer than [`MAX_DELTA_NS`] (4.29 s — a
//! reasoning model can be silent far longer) are carried losslessly by a
//! synthetic [`EventKind::TimeJump`] record holding the high 32 bits, followed
//! by the real event carrying the low 32 bits. No event is ever clamped.
//!
//! The ring is bounded. When it is full the *oldest* event is evicted, its
//! contribution is folded into `base_ns`, and `dropped` is incremented —
//! the loss is always counted and surfaced, never silent.

use serde::{Deserialize, Serialize};

use crate::event::{Event, EventKind};

/// Largest gap one stored event can carry directly: `u32` nanoseconds (4.29 s).
pub const MAX_DELTA_NS: u64 = u32::MAX as u64;

/// One stored event, delta-encoded against its predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedEvent {
    /// Nanoseconds since the previous stored event (`0` for a `TimeJump`).
    pub dt_ns: u32,
    pub kind: EventKind,
    pub a: u32,
    pub b: u32,
}

/// A bounded, delta-encoded event log.
///
/// The log is pure data: it holds no clock and no `Instant`, so it round-trips
/// through serde unchanged and can be replayed anywhere. Producers hand it
/// absolute nanosecond offsets ([`Self::push_at`]) or go through
/// [`crate::Recorder`], which reads the clock once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventLog {
    /// Maximum number of events retained.
    capacity: usize,
    /// Absolute offset (ns from origin) immediately *before* the oldest retained
    /// event: the accumulator base [`Self::iter`] starts from. It advances only
    /// when the ring evicts, so retained offsets stay absolute.
    base_ns: u64,
    /// Absolute offset of the newest stored event.
    last_ns: u64,
    /// Ring storage, grown lazily to `capacity` and then wrapped in place.
    buf: Vec<EncodedEvent>,
    /// Index of the oldest live event in `buf`.
    head: usize,
    /// Number of live events (`<= capacity`).
    len: usize,
    /// Events evicted because the ring was full.
    dropped: u32,
}

impl EventLog {
    /// An empty log that keeps at most `capacity` events.
    ///
    /// A capacity of 0 is raised to 1: a log that can store nothing would make
    /// every derived timing indistinguishable from "no trace". Storage grows
    /// lazily, so a short request never pays for the worst-case ring.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            base_ns: 0,
            last_ns: 0,
            buf: Vec::new(),
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    /// Record an event at an absolute offset from the trace origin.
    ///
    /// Offsets must be non-decreasing; a smaller offset is clamped to the
    /// previous one (a monotonic clock cannot go backwards, so this only ever
    /// absorbs a caller bug without corrupting the encoding).
    pub fn push_at(&mut self, at_ns: u64, kind: EventKind, a: u32, b: u32) {
        debug_assert!(
            !kind.is_synthetic(),
            "TimeJump is an encoding aid; producers must not emit it"
        );
        let at_ns = at_ns.max(self.last_ns);
        let delta = at_ns - self.last_ns;
        self.last_ns = at_ns;

        if delta > MAX_DELTA_NS {
            // Carry the high bits in a synthetic record, the low bits in the
            // real event. Lossless for any u64 gap.
            self.store(EncodedEvent {
                dt_ns: 0,
                kind: EventKind::TimeJump,
                a: (delta >> 32) as u32,
                b: 0,
            });
            self.store(EncodedEvent {
                dt_ns: (delta & u64::from(u32::MAX)) as u32,
                kind,
                a,
                b,
            });
        } else {
            self.store(EncodedEvent {
                dt_ns: delta as u32,
                kind,
                a,
                b,
            });
        }
    }

    fn store(&mut self, event: EncodedEvent) {
        if self.len == self.capacity {
            // Evict the oldest: fold its time contribution into the window base
            // so retained offsets stay absolute.
            let evicted = self.buf[self.head];
            self.base_ns = self
                .base_ns
                .saturating_add(evicted.dt_ns as u64)
                .saturating_add(if evicted.kind.is_synthetic() {
                    (evicted.a as u64) << 32
                } else {
                    0
                });
            self.buf[self.head] = event;
            self.head = (self.head + 1) % self.capacity;
            self.dropped = self.dropped.saturating_add(1);
        } else {
            let index = (self.head + self.len) % self.capacity;
            if index == self.buf.len() {
                self.buf.push(event);
            } else {
                self.buf[index] = event;
            }
            self.len += 1;
        }
    }

    /// Iterate the live window in order, decoding offsets.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        let mut acc = self.base_ns;
        self.raw_iter().filter_map(move |encoded| {
            if encoded.kind.is_synthetic() {
                acc = acc.saturating_add((encoded.a as u64) << 32);
                return None;
            }
            acc = acc.saturating_add(encoded.dt_ns as u64);
            Some(Event {
                at_ns: acc,
                kind: encoded.kind,
                a: encoded.a,
                b: encoded.b,
            })
        })
    }

    fn raw_iter(&self) -> impl Iterator<Item = EncodedEvent> + '_ {
        let modulus = self.capacity;
        (0..self.len).map(move |i| self.buf[(self.head + i) % modulus])
    }

    /// Number of live events.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Events evicted by the ring.
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Absolute offset of the oldest retained event.
    pub fn base_ns(&self) -> u64 {
        self.base_ns
    }

    /// Absolute offset of the newest event.
    pub fn last_ns(&self) -> u64 {
        self.last_ns
    }

    /// First event of a kind, in offset order.
    pub fn first_of(&self, kind: EventKind) -> Option<Event> {
        self.iter().find(|event| event.kind == kind)
    }

    /// Last event of a kind, in offset order.
    pub fn last_of(&self, kind: EventKind) -> Option<Event> {
        self.iter()
            .filter(|event| event.kind == kind)
            .fold(None, |_last, event| Some(event))
    }

    /// Total payload bytes read, across [`EventKind::Read`] events.
    pub fn bytes_read(&self) -> u64 {
        self.iter()
            .filter_map(|event| match event.kind {
                EventKind::Read => Some(u64::from(event.a)),
                _ => None,
            })
            .sum()
    }

    /// Total payload bytes written, across write syscalls.
    pub fn bytes_written(&self) -> u64 {
        self.iter()
            .filter_map(|event| match event.kind {
                EventKind::Write => Some(u64::from(event.a)),
                _ => None,
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(log: &EventLog) -> Vec<(u64, EventKind)> {
        log.iter().map(|e| (e.at_ns, e.kind)).collect()
    }

    #[test]
    fn empty_log_has_no_events() {
        let log = EventLog::with_capacity(0);
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.dropped(), 0);
        assert_eq!(log.iter().count(), 0);
        assert_eq!(log.first_of(EventKind::Read), None);
    }

    #[test]
    fn deltas_round_trip_including_long_gaps() {
        let mut log = EventLog::with_capacity(64);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        log.push_at(1_500, EventKind::Read, 1448, 0);
        // 9.5 s of silence: exceeds one u32 nanosecond field (4.29 s).
        log.push_at(9_500_000_000, EventKind::Read, 100, 0);
        // 200 s: needs two high words.
        log.push_at(209_500_000_000, EventKind::OutputToken, 4, 0);

        let got = kinds(&log);
        assert_eq!(
            got,
            vec![
                (0, EventKind::Dispatch),
                (1_500, EventKind::Read),
                (9_500_000_000, EventKind::Read),
                (209_500_000_000, EventKind::OutputToken),
            ]
        );
        assert_eq!(log.last_ns(), 209_500_000_000);
        assert_eq!(log.bytes_read(), 1548);
    }

    #[test]
    fn non_monotonic_offsets_are_clamped_not_corrupted() {
        let mut log = EventLog::with_capacity(8);
        log.push_at(1_000, EventKind::Read, 10, 0);
        log.push_at(500, EventKind::Read, 10, 0); // caller bug
        assert_eq!(
            kinds(&log),
            vec![(1_000, EventKind::Read), (1_000, EventKind::Read)]
        );
    }

    #[test]
    fn ring_evicts_oldest_and_counts_drops() {
        let mut log = EventLog::with_capacity(3);
        for i in 0..5u64 {
            log.push_at(i * 1_000_000, EventKind::Read, 10, 0);
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.dropped(), 2);
        assert_eq!(
            kinds(&log),
            vec![
                (2_000_000, EventKind::Read),
                (3_000_000, EventKind::Read),
                (4_000_000, EventKind::Read),
            ]
        );
        // The window base moved with the evictions, so offsets stay absolute.
        assert_eq!(log.base_ns(), 1_000_000);
        assert_eq!(log.last_ns(), 4_000_000);
    }

    #[test]
    fn eviction_of_a_time_jump_keeps_offsets_absolute() {
        let mut log = EventLog::with_capacity(3);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        log.push_at(10_000_000_000, EventKind::Read, 1, 0); // TimeJump + Read
        log.push_at(10_000_001_000, EventKind::Read, 2, 0);
        log.push_at(10_000_002_000, EventKind::Read, 3, 0); // evicts Dispatch
        log.push_at(10_000_003_000, EventKind::Read, 4, 0); // evicts the jump

        assert_eq!(
            kinds(&log),
            vec![
                (10_000_001_000, EventKind::Read),
                (10_000_002_000, EventKind::Read),
                (10_000_003_000, EventKind::Read),
            ]
        );
        assert_eq!(log.base_ns(), 10_000_000_000);
    }

    #[test]
    fn serde_round_trip_preserves_offsets_and_drops() {
        let mut log = EventLog::with_capacity(2);
        for i in 0..4u64 {
            log.push_at(i * 1_000, EventKind::Read, 7, 1);
        }
        let json = serde_json::to_string(&log).expect("serialize");
        let back: EventLog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, log);
        assert_eq!(kinds(&back), kinds(&log));
        assert_eq!(back.dropped(), 2);
    }

    #[test]
    fn first_and_last_of_a_kind_are_order_correct() {
        let mut log = EventLog::with_capacity(16);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        log.push_at(100, EventKind::ProtocolFrame, 1, 0);
        log.push_at(200, EventKind::OutputToken, 2, 0);
        log.push_at(300, EventKind::ProtocolFrame, 3, 0);
        log.push_at(400, EventKind::OutputToken, 5, 0);
        assert_eq!(
            log.first_of(EventKind::ProtocolFrame).map(|e| e.at_ns),
            Some(100)
        );
        assert_eq!(
            log.last_of(EventKind::ProtocolFrame).map(|e| e.at_ns),
            Some(300)
        );
        assert_eq!(log.last_of(EventKind::OutputToken).map(|e| e.a), Some(5));
    }
}
