use super::*;
use crate::event::{FrameClass, TimeSource};
use crate::log::EventLog;
use crate::record::Recorder;
use crate::trace::{ConnectionInfo, Fidelity, TraceId};

fn trace(log: EventLog) -> RequestTrace {
    RequestTrace {
        meta: crate::trace::TraceMeta::new(TraceId::new("test"), crate::trace::Direction::Egress),
        authority: "example.invalid:443".into(),
        connection: ConnectionInfo::default(),
        identity: crate::ConnectionIdentity::default(),
        schema_version: crate::TRACE_SCHEMA_VERSION,
        fidelity: Fidelity::l2(),
        log,
        diagnostics: crate::DiagnosticTable::default(),
    }
}

const MS: u64 = 1_000_000;

#[test]
fn a_cold_streaming_attempt_derives_every_scope() {
    let mut log = EventLog::with_capacity(256);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(20 * MS, EventKind::DnsStart, 0, 0);
    log.push_at(50 * MS, EventKind::DnsEnd, 0, 0);
    log.push_at(50 * MS, EventKind::TcpStart, 0, 0);
    log.push_at(80 * MS, EventKind::TcpEnd, 0, 0);
    log.push_at(80 * MS, EventKind::TlsStart, 0, 0);
    log.push_at(140 * MS, EventKind::TlsEnd, 0, 0);
    log.push_at(150 * MS, EventKind::RequestWriteStart, 0, 0);
    log.push_at(200 * MS, EventKind::RequestWriteEnd, 800_000, 0);
    log.push_at(400 * MS, EventKind::HeadComplete, 200, 0);
    // The origin starts generating 10 ms after the head: the body does not
    // share the head's flush, so the server-side scope is estimable.
    log.push_at(410 * MS, EventKind::BodyStart, 0, 0);
    log.push_at(
        410 * MS,
        EventKind::ProtocolFrame,
        FrameClass::Open.code().into(),
        0,
    );
    for i in 0..50u64 {
        log.push_at(505 * MS + i * 10 * MS, EventKind::Payload, 1, 0);
    }
    log.push_at(1_000 * MS, EventKind::BodyEnd, 0, 0);
    log.push_at(1_002 * MS, EventKind::Validated, 0, 0);

    let derived = derive(&trace(log));
    assert_eq!(derived.dns_us.value(), Some(30_000));
    assert_eq!(derived.tcp_us.value(), Some(30_000));
    assert_eq!(derived.tls_us.value(), Some(60_000));
    assert_eq!(derived.ttfb_us.value(), Some(400_000));
    assert_eq!(derived.first_byte_us.value(), Some(410_000));
    assert_eq!(derived.first_frame_us.value(), Some(410_000));
    assert_eq!(derived.first_payload_us.value(), Some(505_000));
    // first frame → first token: 95 ms
    assert_eq!(derived.frame_to_payload_us.value(), Some(95_000));
    // 49 gaps of 10 ms
    assert_eq!(derived.payload_span_us.value(), Some(490_000));
    assert_eq!(derived.tail_us.value(), Some(5_000));
    assert_eq!(derived.e2e_us.value(), Some(1_002_000));
    // Request fully written at 200 ms; the new TTFT anchors there.
    assert_eq!(derived.request_sent_us.value(), Some(200_000));
    assert_eq!(derived.first_payload_after_sent_us.value(), Some(305_000));
    // The rate is the caller's division now: 50 tokens over a 490 ms span.
    let span_us = derived.payload_span_us.value().expect("stream span");
    assert_eq!(span_us, 490_000);
    let tps = 50.0 * 1_000_000.0 / span_us as f64;
    assert!((tps - 102.0).abs() < 1.0, "got {tps}");
}

#[test]
fn a_reused_connection_makes_connect_scopes_not_applicable() {
    let mut log = EventLog::with_capacity(64);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(MS, EventKind::ConnectReused, 0, 0);
    log.push_at(5 * MS, EventKind::HeadComplete, 0, 0);
    log.push_at(6 * MS, EventKind::BodyStart, 0, 0);
    log.push_at(
        7 * MS,
        EventKind::ProtocolFrame,
        FrameClass::Open.code().into(),
        0,
    );
    log.push_at(50 * MS, EventKind::Payload, 10, 0);
    log.push_at(60 * MS, EventKind::BodyEnd, 0, 0);
    log.push_at(61 * MS, EventKind::Validated, 0, 0);

    let derived = derive(&trace(log));
    for reading in [derived.dns_us, derived.tcp_us, derived.tls_us] {
        assert_eq!(
            reading.validity(),
            crate::Validity::NotApplicable(Reason::ConnectionReused)
        );
        assert_eq!(reading.value(), None);
    }
    assert!(derived.ttfb_us.is_measured());
}

#[test]
fn a_batched_transport_refuses_the_server_scope() {
    let mut log = EventLog::with_capacity(64);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(10 * MS, EventKind::ConnectReused, 0, 0);
    // Head and first body byte in the same flush.
    log.push_at(500 * MS, EventKind::HeadComplete, 0, 0);
    log.push_at(500 * MS + 1_000, EventKind::BodyStart, 0, 0);
    log.push_at(
        500 * MS + 2_000,
        EventKind::ProtocolFrame,
        FrameClass::Open.code().into(),
        0,
    );
    log.push_at(900 * MS, EventKind::Payload, 10, 0);
    log.push_at(950 * MS, EventKind::BodyEnd, 0, 0);
    log.push_at(951 * MS, EventKind::Validated, 0, 0);

    let derived = derive(&trace(log));
    assert_eq!(
        derived.frame_to_payload_us.validity(),
        crate::Validity::NotEstimable(Reason::TransportBatched)
    );
    assert_eq!(derived.frame_to_payload_us.value(), None);
    // The perceived scope is still measured: the wait was real.
    assert_eq!(derived.first_payload_us.value(), Some(900_000));
}

#[test]
fn a_short_response_has_no_stream_span() {
    let mut log = EventLog::with_capacity(32);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(MS, EventKind::ConnectReused, 0, 0);
    log.push_at(2 * MS, EventKind::HeadComplete, 0, 0);
    log.push_at(3 * MS, EventKind::BodyStart, 0, 0);
    log.push_at(
        4 * MS,
        EventKind::ProtocolFrame,
        FrameClass::Text.code().into(),
        0,
    );
    log.push_at(5 * MS, EventKind::Payload, 3, 0);
    log.push_at(6 * MS, EventKind::BodyEnd, 0, 0);
    log.push_at(7 * MS, EventKind::Validated, 0, 0);

    let derived = derive(&trace(log));
    assert_eq!(
        derived.payload_span_us.validity(),
        crate::Validity::NotApplicable(Reason::FewerThanTwoPayloadEvents)
    );
    assert!(derived.payload_span_us.value().is_none());
}

#[test]
fn an_unvalidated_attempt_reports_no_e2e() {
    let mut log = EventLog::with_capacity(32);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(MS, EventKind::ConnectReused, 0, 0);
    log.push_at(5 * MS, EventKind::Error, 1, 0);

    let derived = derive(&trace(log));
    assert_eq!(
        derived.e2e_us.validity(),
        crate::Validity::NotApplicable(Reason::ResponseNotValidated)
    );
    assert_eq!(derived.e2e_us.value(), None);
}

#[test]
fn tcp_info_yields_min_rtt_and_max_retransmits() {
    let mut log = EventLog::with_capacity(32);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(MS, EventKind::ConnectReused, 0, 0);
    log.push_at(2 * MS, EventKind::TcpInfo, 42_000, 0);
    log.push_at(3 * MS, EventKind::TcpInfo, 31_000, 2);
    log.push_at(4 * MS, EventKind::TcpInfo, 58_000, 1);

    let derived = derive(&trace(log));
    assert_eq!(derived.rtt_us.value(), Some(31_000));
    assert_eq!(derived.retransmits.value(), Some(2));
}

#[test]
fn a_trace_without_tcp_info_says_so() {
    let mut log = EventLog::with_capacity(8);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    let derived = derive(&trace(log));
    assert_eq!(
        derived.rtt_us.validity(),
        crate::Validity::NotEstimable(Reason::TcpInfoUnavailable)
    );
}

#[test]
fn a_recorder_produced_trace_derives_without_panicking() {
    let mut recorder = Recorder::start(64);
    recorder.reused_connection();
    recorder.mark(EventKind::HeadComplete, 0, 0);
    recorder.mark(EventKind::BodyStart, 0, 0);
    recorder.frame(FrameClass::Open, 0);
    for _ in 0..20 {
        recorder.frame(FrameClass::Text, 1);
    }
    recorder.mark(EventKind::BodyEnd, 0, 0);
    recorder.mark(EventKind::Validated, 0, 0);
    recorder.read(64, TimeSource::Syscall);
    let derived = derive(&trace(recorder.into_log()));
    assert!(derived.first_payload_us.is_measured());
    // The recorder runs at wall-clock speed, so every frame lands in one
    // flush and the span is tiny. The rate guard lives in the ledger, which
    // refuses to divide by a sub-20 ms span.
    let span = derived.payload_span_us.value().expect("span measured");
    assert!(span < 1_000, "a burst lands in one flush: {span} µs");
}
