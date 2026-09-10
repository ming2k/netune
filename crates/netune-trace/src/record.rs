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

use std::time::Instant;

use crate::event::{EventKind, FrameClass, TimeSource};
use crate::log::EventLog;

/// Records one request attempt's events against a monotonic origin.
#[derive(Debug)]
pub struct Recorder {
    origin: Instant,
    log: EventLog,
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
        Self { origin, log }
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
        self.log.push_at(
            self.now_ns(),
            EventKind::Read,
            bytes,
            u32::from(source.code()),
        );
    }

    /// Record one socket write syscall boundary (`poll_write` returned `bytes`).
    pub fn wrote(&mut self, bytes: usize) {
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.log.push_at(self.now_ns(), EventKind::Write, bytes, 0);
    }

    /// Record one origin protocol frame of `class` carrying `tokens` output
    /// tokens (0 for a preamble, usage or keep-alive frame).
    pub fn frame(&mut self, class: FrameClass, tokens: u32) {
        let now = self.now_ns();
        self.log
            .push_at(now, EventKind::ProtocolFrame, u32::from(class.code()), 0);
        if tokens > 0 {
            self.log.push_at(now, EventKind::OutputToken, tokens, 0);
        }
    }

    /// Record an arbitrary event at "now".
    pub fn mark(&mut self, kind: EventKind, a: u32, b: u32) {
        self.log.push_at(self.now_ns(), kind, a, b);
    }

    /// Record that the attempt used a pooled connection: no DNS/TCP/TLS phases
    /// happened, which is what makes those scopes `NotApplicable` rather than
    /// zero.
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
}
