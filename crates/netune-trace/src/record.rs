//! The recorder: the one place a clock is read.
//!
//! `netune` owns the socket; this type owns the conversion from "now" to an
//! offset from the trace origin. Everything else in the crate is pure data and
//! pure functions, so a trace can be replayed, diffed and recomputed without a
//! running clock.
//!
//! The recorder is deliberately synchronous, allocation-free after construction
//! and lock-free: a transport read path calls [`Recorder::read`] inline. The
//! `AsyncRead`/`AsyncWrite` wrapper that calls it lives in `netune` (P1); the
//! logic worth testing — batching-agnostic recording, overflow accounting, the
//! origin conversion — is here.

use std::sync::Arc;
use std::time::Instant;

use crate::event::{Event, EventKind, FrameClass, TimeSource};
use crate::log::EventLog;

/// A destination for events as they are recorded (ADR-0010).
///
/// # Why the ring buffer is not enough
///
/// [`EventLog`] is a bounded window: it keeps the last `capacity` events of one attempt,
/// which is exactly right for a request/response client (ADR-0001's `INV-TRACE-01`) and
/// exactly wrong for a transparent proxy relay, where a single connection lives for minutes
/// and moves gigabytes. A relay needs a *stream*, and a consumer that wants one installs a
/// sink.
///
/// # What a sink must and must not do
///
/// * **Must not block.** `Recorder::push` is on the transport read/write path, and the
///   recorder is already behind a mutex. A sink that waits for a slow consumer turns a
///   network read into a queue wait.
/// * **Must not panic.** A panicking sink would take down a flow from inside its own
///   instrumentation.
/// * **May drop.** A sink that cannot keep up is expected to drop; the ring buffer remains the
///   record of truth for the attempt.
pub trait TraceSink: Send + Sync + std::fmt::Debug {
    /// Receives one event. `at_ns` is relative to the recorder's origin.
    fn event(&self, event: Event);
}

/// Records one request attempt's events against a monotonic origin.
#[derive(Debug)]
pub struct Recorder {
    origin: Instant,
    log: EventLog,
    /// Where events go besides the ring, when a consumer asked for a stream.
    sink: Option<Arc<dyn TraceSink>>,
}

impl Recorder {
    /// Begin a trace at "now", emitting [`EventKind::Dispatch`] at offset 0.
    pub fn start(capacity: usize) -> Self {
        Self::start_at(Instant::now(), capacity)
    }

    /// Begin a trace at an explicit origin (tests, and the L2 probe, which
    /// timestamps against its own capture clock).
    pub fn start_at(origin: Instant, capacity: usize) -> Self {
        let mut log = EventLog::with_capacity(capacity);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        Self {
            origin,
            log,
            sink: None,
        }
    }

    /// Streams every event of this trace to `sink` as well as to the ring.
    ///
    /// Consumes and returns `self` so a sink cannot be installed halfway through a trace by
    /// accident: the events before the call would be missing from the stream, and a consumer
    /// reading the stream as the whole record would be wrong.
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn TraceSink>) -> Self {
        // The dispatch event was recorded before the sink existed; replay it so the stream is
        // complete from offset 0.
        if let Some(event) = self.log.first_of(EventKind::Dispatch) {
            sink.event(event);
        }
        self.sink = Some(sink);
        self
    }

    /// Records one event, to the ring and to the sink when there is one.
    fn push(&mut self, at_ns: u64, kind: EventKind, a: u32, b: u32) {
        self.log.push_at(at_ns, kind, a, b);
        if let Some(sink) = &self.sink {
            sink.event(Event { at_ns, kind, a, b });
        }
    }

    /// The monotonic origin this recorder measures against.
    pub fn origin(&self) -> Instant {
        self.origin
    }

    /// Nanoseconds since origin.
    pub fn now_ns(&self) -> u64 {
        let elapsed = self.origin.elapsed().as_nanos();
        u64::try_from(elapsed).unwrap_or(u64::MAX)
    }

    /// Record one successful socket read of `bytes`, timestamped by `source`.
    pub fn read(&mut self, bytes: usize, source: TimeSource) {
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.push(
            self.now_ns(),
            EventKind::Read,
            bytes,
            u32::from(source.code()),
        );
    }

    /// Record one socket write syscall boundary (`poll_write` returned `bytes`).
    pub fn wrote(&mut self, bytes: usize) {
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.push(self.now_ns(), EventKind::Write, bytes, 0);
    }

    /// Record one origin protocol frame of `class` carrying `tokens` output
    /// tokens (0 for a preamble, usage or keep-alive frame).
    pub fn frame(&mut self, class: FrameClass, tokens: u32) {
        let now = self.now_ns();
        self.push(now, EventKind::ProtocolFrame, u32::from(class.code()), 0);
        if tokens > 0 {
            self.push(now, EventKind::OutputToken, tokens, 0);
        }
    }

    /// Record an arbitrary event at "now".
    pub fn mark(&mut self, kind: EventKind, a: u32, b: u32) {
        self.push(self.now_ns(), kind, a, b);
    }

    /// Record that the attempt used a pooled connection: no DNS/TCP/TLS phases
    /// happened, which is what makes those scopes `NotApplicable` rather than
    /// zero.
    ///
    /// This is a zero-payload shorthand. A caller that also knows *how long* the
    /// socket sat idle should use [`Recorder::mark`] with
    /// [`EventKind::ConnectReused`] directly and pass the age in `a`; calling
    /// both would push two reuse events, and a reader taking the first
    /// (`EventLog::first_of`) would find the one without the age.
    pub fn reused_connection(&mut self) {
        self.mark(EventKind::ConnectReused, 0, 0);
    }

    /// Record a `TCP_INFO` sample.
    pub fn tcp_info(&mut self, rtt_us: u32, retransmits: u32) {
        self.mark(EventKind::TcpInfo, rtt_us, retransmits);
    }

    /// Finish recording and hand over the log.
    pub fn into_log(self) -> EventLog {
        self.log
    }

    /// Borrow the log so far (tests, live inspection).
    pub fn log(&self) -> &EventLog {
        &self.log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_emits_dispatch_at_zero() {
        let recorder = Recorder::start(16);
        let log = recorder.log();
        assert_eq!(log.len(), 1);
        assert_eq!(log.first_of(EventKind::Dispatch).map(|e| e.at_ns), Some(0));
    }

    #[test]
    fn offsets_are_monotonic_and_relative_to_origin() {
        let recorder = Recorder::start(16);
        let origin = recorder.origin();
        let mut recorder = recorder;
        recorder.read(100, TimeSource::Syscall);
        recorder.wrote(50);
        recorder.frame(FrameClass::Open, 0);
        recorder.frame(FrameClass::Text, 3);
        let log = recorder.into_log();
        assert!(origin.elapsed().as_nanos() > 0);

        let mut previous = 0;
        for event in log.iter() {
            assert!(event.at_ns >= previous, "monotonic");
            previous = event.at_ns;
        }
        assert_eq!(log.iter().count(), 6);
        assert_eq!(log.bytes_read(), 100);
        assert_eq!(log.bytes_written(), 50);
    }

    #[test]
    fn frame_records_output_tokens_only_when_present() {
        let mut recorder = Recorder::start(16);
        recorder.frame(FrameClass::Open, 0);
        recorder.frame(FrameClass::Usage, 0);
        recorder.frame(FrameClass::Reasoning, 7);
        let log = recorder.into_log();
        let frames = log
            .iter()
            .filter(|e| e.kind == EventKind::ProtocolFrame)
            .count();
        let tokens: u32 = log.iter().filter_map(|e| e.tokens()).sum();
        assert_eq!(frames, 3);
        assert_eq!(tokens, 7);
    }

    #[test]
    fn reused_connection_is_an_explicit_fact() {
        let mut recorder = Recorder::start(8);
        recorder.reused_connection();
        let log = recorder.into_log();
        assert!(log.first_of(EventKind::ConnectReused).is_some());
        assert!(log.first_of(EventKind::DnsStart).is_none());
    }

    /// A sink that keeps everything it is given, for a test that needs the stream.
    #[derive(Debug, Default)]
    struct CollectingSink(std::sync::Mutex<Vec<Event>>);

    impl TraceSink for CollectingSink {
        fn event(&self, event: Event) {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(event);
        }
    }

    #[test]
    fn a_sink_streams_every_event_from_offset_zero() {
        // The property a relay depends on: a stream, not a window. The ring keeps the last
        // `capacity` events, so with a capacity of 2 it would lose everything but the tail;
        // the sink must still have all of them, starting with `Dispatch` at offset 0 — which
        // was recorded *before* the sink existed and is replayed by `with_sink`.
        let sink = Arc::new(CollectingSink::default());
        let mut recorder = Recorder::start(2).with_sink(Arc::clone(&sink) as Arc<dyn TraceSink>);
        recorder.read(10, TimeSource::Syscall);
        recorder.wrote(20);
        recorder.read(30, TimeSource::Syscall);

        let streamed = sink.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(streamed.len(), 4, "dispatch plus three events");
        assert_eq!(streamed[0].kind, EventKind::Dispatch);
        assert_eq!(streamed[0].at_ns, 0);
        assert_eq!(
            streamed
                .iter()
                .filter(|e| e.kind == EventKind::Read)
                .count(),
            2,
            "both reads reached the sink"
        );

        // The ring is still the record of truth for the attempt, and still bounded.
        let log = recorder.into_log();
        assert_eq!(log.len(), 2, "the ring kept only its capacity");
        assert_eq!(log.dropped(), 2, "and counted what it dropped");
    }

    #[test]
    fn a_recorder_without_a_sink_pays_nothing() {
        let mut recorder = Recorder::start(8);
        recorder.read(1, TimeSource::Syscall);
        recorder.wrote(1);
        assert_eq!(recorder.log().len(), 3);
    }
}
