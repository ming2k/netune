//! Byte-path observation strategies.
//!
//! A [`Tap`] is owned by the transport wrapper (`TimedIo`), not shared through
//! an `Arc<Mutex<...>>`. The type parameter is the cost switch: `NoTap` is a
//! zero-sized type whose methods inline to nothing, `Counters` is allocation-free
//! and reads no clock, and `Ring` owns the bounded event ring and the attempt's
//! clock origin.
//!
//! The hot path must never see `Box<dyn Tap>`: a boxed tap reintroduces the
//! allocation, vtable and indirect call that this module exists to remove.

use std::sync::Arc;
use std::time::Instant;

use crate::event::{Event, EventKind, TimeSource};
use crate::log::EventLog;
use crate::record::TraceSink;
use crate::trace::{Fidelity, TraceMeta};

/// A strategy for observing bytes crossing one transport stream.
///
/// Implementations are consumed when the stream ends: [`Tap::finish`] returns
/// the artifact the orchestrator merges into the attempt's trace. `NoTap` and
/// `Counters` deliberately never read a clock; only `Ring` does.
pub trait Tap: Send + Unpin + 'static {
    /// The artifact produced when the stream is consumed.
    type Output: Send + 'static;

    /// What this tap can truthfully report in a trace envelope.
    const FIDELITY: Fidelity;

    /// Record one successful read of `bytes` from the transport.
    #[inline(always)]
    fn read(&mut self, _bytes: usize, _source: TimeSource) {}

    /// Record one successful write of `bytes` to the transport.
    #[inline(always)]
    fn wrote(&mut self, _bytes: usize) {}

    /// Consume the tap and hand its artifact to the cold path.
    fn finish(self) -> Self::Output;
}

/// The zero-cost tap: no clock, no allocation, no event.
///
/// The wrapper compiles to the inner stream. This is the type a caller selects
/// when it can prove it needs no observation at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoTap;

impl Tap for NoTap {
    type Output = ();
    const FIDELITY: Fidelity = Fidelity::none();

    #[inline(always)]
    fn finish(self) {}
}

/// Constant-time byte and call counters.
///
/// This is the default L0 observation: it answers "how many bytes and calls"
/// without a clock, an allocation, or a lock. It is deliberately not a
/// substitute for an event timeline; a consumer that needs ordering selects
/// [`Ring`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub reads: u64,
    pub writes: u64,
}

impl Tap for Counters {
    type Output = Self;
    const FIDELITY: Fidelity = Fidelity::l0();

    #[inline(always)]
    fn read(&mut self, bytes: usize, _source: TimeSource) {
        self.reads = self.reads.saturating_add(1);
        self.read_bytes = self.read_bytes.saturating_add(bytes as u64);
    }

    #[inline(always)]
    fn wrote(&mut self, bytes: usize) {
        self.writes = self.writes.saturating_add(1);
        self.write_bytes = self.write_bytes.saturating_add(bytes as u64);
    }

    #[inline(always)]
    fn finish(self) -> Self {
        self
    }
}

/// The artifact a byte-path tap hands to the cold path.
///
/// The inner [`EventLog`] is readable but cannot be constructed outside this
/// crate, so a caller cannot manufacture `Read`/`Write` events and inject them
/// through [`crate::TraceCollector::merge`]. Only a [`Tap`] produces a `TapLog`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapLog(EventLog);

impl TapLog {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn dropped(&self) -> u32 {
        self.0.dropped()
    }

    pub(crate) fn into_event_log(self) -> EventLog {
        self.0
    }
}

impl std::ops::Deref for TapLog {
    type Target = EventLog;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An owned, bounded event ring for one byte path.
///
/// The ring shares the attempt's origin with the cold-path [`crate::TraceCollector`],
/// so its absolute offsets can be merged with control events without a second
/// clock domain. A sink, when present, receives each event as it is recorded and
/// must not block (`TraceSink`'s contract).
#[derive(Debug)]
pub struct Ring {
    origin: Instant,
    log: EventLog,
    meta: TraceMeta,
    sink: Option<Arc<dyn TraceSink>>,
}

impl Ring {
    /// Create a ring tap against `origin` with a bounded capacity.
    ///
    /// The generated identity is used only when a sink is installed through
    /// [`Ring::new`]; a caller that already owns a collector should use
    /// [`Ring::new_with_meta`] so the byte events carry the same identity.
    pub fn new(origin: Instant, capacity: usize, sink: Option<Arc<dyn TraceSink>>) -> Self {
        Self::new_with_meta(origin, capacity, TraceMeta::egress(), sink)
    }

    /// Create a ring tap bound to an existing trace identity.
    pub fn new_with_meta(
        origin: Instant,
        capacity: usize,
        meta: TraceMeta,
        sink: Option<Arc<dyn TraceSink>>,
    ) -> Self {
        Self {
            origin,
            log: EventLog::with_capacity(capacity),
            meta,
            sink,
        }
    }

    /// The origin shared with the attempt's control recorder.
    pub fn origin(&self) -> Instant {
        self.origin
    }

    fn now_ns(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn emit(&self, event: Event) {
        if let Some(sink) = &self.sink {
            let _ = sink.event(&self.meta, event);
        }
    }
}

impl Tap for Ring {
    type Output = TapLog;
    const FIDELITY: Fidelity = Fidelity::l1();

    fn read(&mut self, bytes: usize, source: TimeSource) {
        let at_ns = self.now_ns();
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        let b = u32::from(source.code());
        self.log.push_at(at_ns, EventKind::Read, bytes, b);
        self.emit(Event {
            at_ns,
            stream: 0,
            kind: EventKind::Read,
            a: bytes,
            b,
        });
    }

    fn wrote(&mut self, bytes: usize) {
        let at_ns = self.now_ns();
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.log.push_at(at_ns, EventKind::Write, bytes, 0);
        self.emit(Event {
            at_ns,
            stream: 0,
            kind: EventKind::Write,
            a: bytes,
            b: 0,
        });
    }

    fn finish(self) -> Self::Output {
        TapLog(self.log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tap_is_zero_sized_and_keeps_its_fidelity_honest() {
        assert_eq!(std::mem::size_of::<NoTap>(), 0);
        assert_eq!(std::mem::size_of::<Counters>(), 32);
        assert_eq!(NoTap::FIDELITY, Fidelity::none());
    }

    #[test]
    fn counters_do_not_read_a_clock() {
        // The type has no clock field; this is a compile-time property, and the
        // arithmetic is the only observable behaviour.
        let mut counters = Counters::default();
        counters.read(10, TimeSource::Syscall);
        counters.wrote(5);
        let counters = counters.finish();
        assert_eq!(counters.reads, 1);
        assert_eq!(counters.read_bytes, 10);
        assert_eq!(counters.writes, 1);
        assert_eq!(counters.write_bytes, 5);
    }

    #[test]
    fn ring_records_at_absolute_offsets_against_its_origin() {
        let origin = Instant::now();
        let mut ring = Ring::new(origin, 8, None);
        ring.read(3, TimeSource::Syscall);
        ring.wrote(4);
        let log = ring.finish();
        let events: Vec<_> = log.iter().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, EventKind::Read);
        assert_eq!(events[0].a, 3);
        assert_eq!(events[1].kind, EventKind::Write);
        assert_eq!(events[1].a, 4);
        assert!(events[1].at_ns >= events[0].at_ns);
    }
}
