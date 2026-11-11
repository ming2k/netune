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

use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::diagnostic::{DEFAULT_DIAGNOSTIC_CAPACITY, DiagnosticRecord, DiagnosticTable};
#[cfg(test)]
use crate::event::TimeSource;
use crate::event::{Event, EventKind, FrameClass};
use crate::log::EventLog;
use crate::trace::{Fidelity, TraceMeta, TraceSnapshot};

/// A destination for events as they are recorded (ADR-0010, ADR-0042).
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
    /// Called once when the attempt is bound to this sink.
    ///
    /// The default is deliberately empty so a sink that only wants events does
    /// not have to implement lifecycle noise.
    fn trace_started(&self, _meta: &TraceMeta) {}

    /// Receives one event with the envelope that produced it.
    ///
    /// Returning [`Flow::Drop`] is advisory: the sink may have discarded the
    /// event, but the ring remains the record of truth and the recorder does not
    /// stop delivering later events. The drop is counted in [`TraceSummary`].
    fn event(&self, meta: &TraceMeta, event: Event) -> Flow;

    /// Called once when the attempt is finished and its record is complete.
    fn trace_finished(&self, _meta: &TraceMeta, _summary: &TraceSummary) {}
}

/// What a sink saw when an attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceSummary {
    pub events: usize,
    pub dropped_events: u32,
    pub diagnostics: usize,
    pub dropped_diagnostics: u32,
    pub sink_dropped: u32,
}

/// What a sink wants done with an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep delivering.
    Continue,
    /// This event was dropped by the sink; later events may still be delivered.
    Drop,
}

/// Records one request attempt's events against a monotonic origin.
///
/// Internal since ADR-0018: callers receive a [`TraceCollector`]. The recorder
/// owns the ring and the clock; the collector owns the public contract.
#[derive(Debug)]
pub(crate) struct Recorder {
    origin: Instant,
    meta: TraceMeta,
    log: EventLog,
    /// Bounded failure narration. It is recorded even when `enabled` is false:
    /// a failure must remain explainable under `Observation::Off`.
    diagnostics: DiagnosticTable,
    /// Where events go besides the ring, when a consumer asked for a stream.
    sink: Option<Arc<dyn TraceSink>>,
    /// Events the sink asked us to drop. Reported in the summary; never silent.
    sink_dropped: u32,
    /// A disabled recorder keeps the origin and diagnostics but records no
    /// event timeline. It is the cold-path handle for `Observation::Off` and
    /// `Observation::Counters`, whose byte evidence lives in a tap, not in this
    /// ring.
    enabled: bool,
    /// The sink is told the attempt finished exactly once, no matter how many
    /// times a caller asks for a snapshot.
    finished: bool,
}

impl Recorder {
    /// Begin an egress trace at "now", emitting [`EventKind::Dispatch`] at offset 0.
    #[cfg(test)]
    pub(crate) fn start(capacity: usize) -> Self {
        Self::start_with_meta_at(TraceMeta::egress(), Instant::now(), capacity)
    }

    /// Begin an egress trace with an explicit identity.
    pub(crate) fn start_with_meta(meta: TraceMeta, capacity: usize) -> Self {
        Self::start_with_meta_at(meta, Instant::now(), capacity)
    }

    /// Begin an ingress trace with an explicit identity.
    pub(crate) fn start_ingress_with_meta(meta: TraceMeta, capacity: usize) -> Self {
        Self::start_ingress_with_meta_at(meta, Instant::now(), capacity)
    }

    /// Begin an ingress trace at an explicit origin (tests, and a capture with its
    /// own clock).
    pub(crate) fn start_ingress_with_meta_at(
        meta: TraceMeta,
        origin: Instant,
        capacity: usize,
    ) -> Self {
        let mut log = EventLog::with_capacity(capacity);
        log.push_at(0, EventKind::IngressDispatch, 0, 0);
        Self {
            origin,
            meta,
            log,
            diagnostics: DiagnosticTable::default(),
            sink: None,
            sink_dropped: 0,
            enabled: true,
            finished: false,
        }
    }

    /// Begin an egress trace at an explicit origin (tests, and the L2 probe, which
    /// timestamps against its own capture clock).
    pub(crate) fn start_with_meta_at(meta: TraceMeta, origin: Instant, capacity: usize) -> Self {
        let mut log = EventLog::with_capacity(capacity);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        Self {
            origin,
            meta,
            log,
            diagnostics: DiagnosticTable::default(),
            sink: None,
            sink_dropped: 0,
            enabled: true,
            finished: false,
        }
    }

    /// A recorder that keeps the origin and diagnostics but records no event
    /// timeline.
    ///
    /// The origin is still available so a caller can create a tap in the same
    /// time domain; the ring and the sink are not touched. This is how `Off`
    /// and `Counters` attempts avoid allocating an event ring without becoming
    /// undebuggable. Failure diagnostics are recorded on the cold path.
    pub(crate) fn disabled_with_meta(meta: TraceMeta) -> Self {
        Self {
            origin: Instant::now(),
            meta,
            log: EventLog::with_capacity(1),
            diagnostics: DiagnosticTable::new(DEFAULT_DIAGNOSTIC_CAPACITY),
            sink: None,
            sink_dropped: 0,
            enabled: false,
            finished: false,
        }
    }

    /// Streams every event of this trace to `sink` as well as to the ring.
    ///
    /// Consumes and returns `self` so a sink cannot be installed halfway through a trace by
    /// accident: the events before the call would be missing from the stream, and a consumer
    /// reading the stream as the whole record would be wrong.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_sink(mut self, sink: Arc<dyn TraceSink>) -> Self {
        self.install_sink(sink);
        self
    }

    /// Install a sink in place, replaying the origin event.
    ///
    /// The public [`TraceCollector`] uses this so installing a sink does not
    /// require consuming the collector's shared inner value.
    pub(crate) fn install_sink(&mut self, sink: Arc<dyn TraceSink>) {
        if !self.enabled {
            return;
        }
        sink.trace_started(&self.meta);
        if let Some(event) = self.log.first()
            && sink.event(&self.meta, event) == Flow::Drop
        {
            self.sink_dropped = self.sink_dropped.saturating_add(1);
        }
        self.sink = Some(sink);
    }

    /// Records one event, to the ring and to the sink when there is one.
    fn push(&mut self, at_ns: u64, kind: EventKind, a: u32, b: u32) {
        self.push_stream(at_ns, 0, kind, a, b);
    }

    /// Records one event belonging to a specific exchange on the connection.
    ///
    /// See [`Event::stream`]: a multiplexed transport interleaves exchanges on one
    /// connection, so the exchange identity has to travel with the event.
    fn push_stream(&mut self, at_ns: u64, stream: u32, kind: EventKind, a: u32, b: u32) {
        if !self.enabled {
            return;
        }
        self.log.push_at_stream(at_ns, stream, kind, a, b);
        if let Some(sink) = &self.sink {
            let event = Event {
                at_ns,
                stream,
                kind,
                a,
                b,
            };
            if sink.event(&self.meta, event) == Flow::Drop {
                self.sink_dropped = self.sink_dropped.saturating_add(1);
            }
        }
    }

    /// Record a terminal diagnostic and, when the event timeline is enabled, the
    /// corresponding `Error` event.
    fn error(&mut self, record: DiagnosticRecord) -> u32 {
        self.error_stream(0, record)
    }

    /// Record a terminal diagnostic for one multiplexed exchange.
    fn error_stream(&mut self, stream: u32, record: DiagnosticRecord) -> u32 {
        let code = record.code;
        let before = self.diagnostics.dropped();
        let sequence = self.diagnostics.push(record);
        self.after_diagnostic_push(before);
        if self.enabled {
            self.push_stream(
                self.now_ns(),
                stream,
                EventKind::Error,
                code.raw(),
                sequence,
            );
        }
        sequence
    }

    /// Record a non-terminal diagnostic and, when the event timeline is enabled,
    /// the corresponding `Note` event.
    fn note(&mut self, record: DiagnosticRecord) -> u32 {
        self.note_stream(0, record)
    }

    /// Record a non-terminal diagnostic for one multiplexed exchange.
    fn note_stream(&mut self, stream: u32, record: DiagnosticRecord) -> u32 {
        let code = record.code;
        let before = self.diagnostics.dropped();
        let sequence = self.diagnostics.push(record);
        self.after_diagnostic_push(before);
        if self.enabled {
            self.push_stream(self.now_ns(), stream, EventKind::Note, code.raw(), sequence);
        }
        sequence
    }

    fn after_diagnostic_push(&mut self, before: u32) {
        let after = self.diagnostics.dropped();
        if after > before && self.enabled {
            self.push(self.now_ns(), EventKind::DiagnosticDropped, after, 0);
        }
    }

    fn summary(&self) -> TraceSummary {
        TraceSummary {
            events: self.log.len(),
            dropped_events: self.log.dropped(),
            diagnostics: self.diagnostics.len(),
            dropped_diagnostics: self.diagnostics.dropped(),
            sink_dropped: self.sink_dropped,
        }
    }

    /// The monotonic origin this recorder measures against.
    pub fn origin(&self) -> Instant {
        self.origin
    }

    /// The ring capacity this recorder was created with.
    pub fn capacity(&self) -> usize {
        self.log.capacity()
    }

    /// The sink installed on this recorder, if any.
    ///
    /// A byte-path `Ring` tap can forward the same stream, so a consumer that
    /// installed one sink for control events does not silently lose `Read` and
    /// `Write` events.
    pub fn sink(&self) -> Option<Arc<dyn TraceSink>> {
        self.sink.clone()
    }

    /// The identity and provenance of this trace.
    pub fn meta(&self) -> &TraceMeta {
        &self.meta
    }

    pub(crate) fn set_trace_id(&mut self, id: crate::TraceId) {
        self.meta.id = id;
    }

    /// The bounded diagnostic side table.
    pub fn diagnostics(&self) -> &DiagnosticTable {
        &self.diagnostics
    }

    /// Finish the attempt and notify the sink once, when one is installed.
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(sink) = &self.sink {
            sink.trace_finished(&self.meta, &self.summary());
        }
    }

    /// Merge a byte-path tap log produced against the same origin.
    ///
    /// Cold path only. A disabled recorder ignores the merge: its caller selected
    /// `Off` or `Counters`, and the tap artifact is reported through its own
    /// channel rather than through an event ring.
    pub fn merge(&mut self, log: EventLog) {
        if !self.enabled {
            return;
        }
        self.log.merge(log);
    }

    /// Nanoseconds since origin.
    pub fn now_ns(&self) -> u64 {
        let elapsed = self.origin.elapsed().as_nanos();
        u64::try_from(elapsed).unwrap_or(u64::MAX)
    }

    /// Record one successful socket read of `bytes`, timestamped by `source`.
    #[cfg(test)]
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
    #[cfg(test)]
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

    /// Record an arbitrary event at "now", belonging to exchange `0`.
    pub fn mark(&mut self, kind: EventKind, a: u32, b: u32) {
        self.push(self.now_ns(), kind, a, b);
    }

    /// Record an arbitrary event at "now", belonging to the exchange `stream`.
    ///
    /// The ingress HTTP/2 path uses this for every fact it records, because a log with two
    /// concurrent streams in it cannot be split by position.
    pub fn mark_stream(&mut self, stream: u32, kind: EventKind, a: u32, b: u32) {
        self.push_stream(self.now_ns(), stream, kind, a, b);
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

    /// Record that a request head was completely parsed (`a` = head bytes).
    pub fn request_head(&mut self, bytes: usize) {
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.mark(EventKind::RequestHeadComplete, bytes, 0);
    }

    /// Record that the request body was fully consumed (`a` = body bytes).
    pub fn request_body_end(&mut self, bytes: usize) {
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.mark(EventKind::RequestBodyEnd, bytes, 0);
    }

    /// Record that the handler returned, carrying the status it produced.
    pub fn handler_end(&mut self, status: u16) {
        self.mark(EventKind::HandlerEnd, u32::from(status), 0);
    }

    /// Record that the response was fully written (`a` = body bytes written).
    pub fn response_end(&mut self, bytes: usize) {
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.mark(EventKind::ResponseEnd, bytes, 0);
    }

    /// Finish recording and hand over the log.
    #[cfg(test)]
    pub fn into_log(self) -> EventLog {
        self.log
    }

    /// Borrow the log so far (tests, live inspection).
    pub fn log(&self) -> &EventLog {
        &self.log
    }
}

/// The only public handle for an attempt's cold-path trace.
///
/// A collector is cheap to clone for the sampler or a second task that emits
/// phase events. It never exposes `read`/`wrote`: byte events can only come from
/// a [`crate::Tap`] and arrive through [`TraceCollector::merge`].
#[derive(Debug, Clone)]
pub struct TraceCollector {
    inner: Arc<Mutex<Recorder>>,
    /// A copy of the recorder's enabled bit so the disabled path can return
    /// without touching the mutex.
    enabled: bool,
}

impl TraceCollector {
    pub fn start(capacity: usize) -> Self {
        Self::start_with_meta(TraceMeta::egress(), capacity)
    }

    /// Begin an egress trace with an explicit identity.
    pub fn start_with_meta(meta: TraceMeta, capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Recorder::start_with_meta(meta, capacity))),
            enabled: true,
        }
    }

    pub fn start_ingress(capacity: usize) -> Self {
        Self::start_ingress_with_meta(TraceMeta::ingress(), capacity)
    }

    /// Begin an ingress trace with an explicit identity.
    pub fn start_ingress_with_meta(meta: TraceMeta, capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Recorder::start_ingress_with_meta(
                meta, capacity,
            ))),
            enabled: true,
        }
    }

    pub fn disabled() -> Self {
        Self::disabled_with_meta(TraceMeta::egress())
    }

    /// A disabled timeline that still records failure diagnostics.
    pub fn disabled_with_meta(meta: TraceMeta) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Recorder::disabled_with_meta(meta))),
            enabled: false,
        }
    }

    #[must_use]
    pub fn with_sink(self, sink: Arc<dyn TraceSink>) -> Self {
        if self.enabled {
            self.inner
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .install_sink(sink);
        }
        self
    }

    pub fn origin(&self) -> Instant {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .origin()
    }

    pub fn capacity(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .capacity()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn sink(&self) -> Option<Arc<dyn TraceSink>> {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .sink()
    }

    pub fn now_ns(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .now_ns()
    }

    /// The identity and provenance of this trace.
    pub fn meta(&self) -> TraceMeta {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .meta()
            .clone()
    }

    /// Adopt a trace id received from a peer.
    ///
    /// The ingress recorder starts at accept with a generated id; a propagated
    /// request header lets it join an egress attempt. The sink is not installed
    /// on an ingress recorder until the connection finishes, so there is no
    /// already-emitted `trace_started` to contradict.
    pub fn set_trace_id(&self, id: crate::TraceId) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .set_trace_id(id);
    }

    /// Record one terminal diagnostic.
    ///
    /// This is the only supported way to create an `Error` event. It works even
    /// when the collector is disabled: failure evidence survives
    /// `Observation::Off`.
    pub fn record_error(&self, record: DiagnosticRecord) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .error(record)
    }

    /// Record one terminal diagnostic for a multiplexed exchange.
    pub fn record_error_stream(&self, stream: u32, record: DiagnosticRecord) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .error_stream(stream, record)
    }

    /// Record one non-terminal diagnostic.
    pub fn record_note(&self, record: DiagnosticRecord) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .note(record)
    }

    /// Record one non-terminal diagnostic for a multiplexed exchange.
    pub fn record_note_stream(&self, stream: u32, record: DiagnosticRecord) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .note_stream(stream, record)
    }

    /// The diagnostic side table recorded so far.
    pub fn diagnostics(&self) -> DiagnosticTable {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .diagnostics()
            .clone()
    }

    /// A snapshot of the envelope, event log and diagnostic table.
    pub fn snapshot(&self, fidelity: Fidelity) -> TraceSnapshot {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.finish();
        TraceSnapshot::new(
            inner.meta().clone(),
            fidelity,
            inner.log().clone(),
            inner.diagnostics().clone(),
        )
    }

    /// The summary a sink receives when the attempt ends.
    pub fn summary(&self) -> TraceSummary {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .summary()
    }

    /// Record a control/protocol mark at "now".
    ///
    /// # Panics
    ///
    /// In debug builds, `Read`, `Write` or `Segment` panic: those kinds are
    /// byte-path facts and must come from a [`crate::Tap`]. `Error` and `Note`
    /// also panic: a diagnostic must travel through
    /// [`TraceCollector::record_error`] or [`TraceCollector::record_note`] so it
    /// cannot be contentless. Release builds drop such a mark rather than
    /// manufacturing a timeline or an unexplained failure.
    pub fn mark(&self, kind: EventKind, a: u32, b: u32) {
        debug_assert!(
            !kind.is_byte_path(),
            "byte events must come from a Tap, not TraceCollector::mark"
        );
        debug_assert!(
            !kind.is_diagnostic(),
            "diagnostics must use record_error/record_note, not TraceCollector::mark"
        );
        if !self.enabled || kind.is_byte_path() || kind.is_diagnostic() {
            return;
        }
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .mark(kind, a, b);
    }

    /// Record a control/protocol mark for a multiplexed exchange.
    ///
    /// Byte-path and diagnostic kinds are rejected exactly as in
    /// [`TraceCollector::mark`].
    pub fn mark_stream(&self, stream: u32, kind: EventKind, a: u32, b: u32) {
        debug_assert!(
            !kind.is_byte_path(),
            "byte events must come from a Tap, not TraceCollector::mark_stream"
        );
        debug_assert!(
            !kind.is_diagnostic(),
            "diagnostics must use record_error/record_note, not TraceCollector::mark_stream"
        );
        if !self.enabled || kind.is_byte_path() || kind.is_diagnostic() {
            return;
        }
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .mark_stream(stream, kind, a, b);
    }

    pub fn frame(&self, class: FrameClass, tokens: u32) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .frame(class, tokens);
    }

    pub fn reused_connection(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .reused_connection();
    }

    pub fn tcp_info(&self, rtt_us: u32, retransmits: u32) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .tcp_info(rtt_us, retransmits);
    }

    pub fn request_head(&self, bytes: usize) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .request_head(bytes);
    }

    pub fn request_body_end(&self, bytes: usize) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .request_body_end(bytes);
    }

    pub fn handler_end(&self, status: u16) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .handler_end(status);
    }

    pub fn response_end(&self, bytes: usize) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .response_end(bytes);
    }

    /// Merge a byte-path tap log produced against the same origin.
    ///
    /// Only [`crate::TapLog`] is accepted; the collector has no public way to
    /// inject a raw, caller-built `EventLog`.
    pub fn merge(&self, log: crate::TapLog) {
        if !self.enabled {
            return;
        }
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .merge(log.into_event_log());
    }

    /// A snapshot of the log. The collector remains usable.
    pub fn log(&self) -> EventLog {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .log()
            .clone()
    }

    pub fn dropped(&self) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .log()
            .dropped()
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
        fn event(&self, _meta: &TraceMeta, event: Event) -> Flow {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(event);
            Flow::Continue
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
    fn a_collector_merges_the_byte_tap_log_without_exposing_the_recorder() {
        use crate::{Ring, Tap};

        let collector = TraceCollector::start(8);
        let mut ring = Ring::new(collector.origin(), 8, None);
        ring.read(10, TimeSource::Syscall);
        ring.wrote(20);
        collector.merge(ring.finish());

        let kinds: Vec<_> = collector.log().iter().map(|event| event.kind).collect();
        assert_eq!(
            kinds,
            vec![EventKind::Dispatch, EventKind::Read, EventKind::Write]
        );
        assert_eq!(collector.log().bytes_read(), 10);
        assert_eq!(collector.log().bytes_written(), 20);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "byte events must come from a Tap")]
    fn a_collector_rejects_a_byte_event_from_the_control_api() {
        let collector = TraceCollector::start(8);
        collector.mark(EventKind::Read, 1, 0);
    }

    #[test]
    fn a_recorder_without_a_sink_pays_nothing() {
        let mut recorder = Recorder::start(8);
        recorder.read(1, TimeSource::Syscall);
        recorder.wrote(1);
        assert_eq!(recorder.log().len(), 3);
    }

    #[test]
    fn a_disabled_collector_still_records_failure_evidence() {
        let collector = TraceCollector::disabled();
        collector.record_error(
            DiagnosticRecord::new(crate::DiagnosticCode::EGRESS_TLS_FAILED)
                .with_message("verify failed"),
        );
        let snapshot = collector.snapshot(Fidelity::none());
        assert!(snapshot.log.is_empty());
        assert_eq!(snapshot.diagnostics.len(), 1);
        assert_eq!(
            snapshot.diagnostic_code(),
            Some(crate::DiagnosticCode::EGRESS_TLS_FAILED)
        );
    }

    #[test]
    fn a_sink_receives_the_envelope_and_stream_identity() {
        #[derive(Debug, Default)]
        struct EnvelopeSink(std::sync::Mutex<Vec<(TraceMeta, Event)>>);

        impl TraceSink for EnvelopeSink {
            fn event(&self, meta: &TraceMeta, event: Event) -> Flow {
                self.0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push((meta.clone(), event));
                Flow::Continue
            }
        }

        let sink = Arc::new(EnvelopeSink::default());
        let collector = TraceCollector::start(8).with_sink(Arc::clone(&sink) as Arc<dyn TraceSink>);
        collector.mark_stream(7, EventKind::HeadComplete, 0, 0);
        let seen = sink.0.lock().unwrap_or_else(|error| error.into_inner());
        assert!(seen.iter().all(|(meta, _)| meta.id == collector.meta().id));
        assert!(seen.iter().any(|(_, event)| event.stream == 7));
    }

    #[test]
    fn a_sink_drop_is_counted_in_the_summary() {
        #[derive(Debug)]
        struct DroppingSink;
        impl TraceSink for DroppingSink {
            fn event(&self, _meta: &TraceMeta, _event: Event) -> Flow {
                Flow::Drop
            }
        }

        let collector = TraceCollector::start(8).with_sink(Arc::new(DroppingSink));
        collector.mark(EventKind::HeadComplete, 0, 0);
        assert!(collector.summary().sink_dropped >= 2);
    }
}
