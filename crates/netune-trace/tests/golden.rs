//! Golden-trace contract tests, exercised through the public API only.
//!
//! These are the tests ADR-0200's acceptance criterion 1 refers to: a displayed
//! number must be a pure function of a recorded trace, so a trace that survives
//! a JSON round trip must derive byte-identical timings, and a scope the
//! transport hid must come back as a verdict rather than a plausible-looking
//! number.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use netune_trace::{
    AttemptRef, ConnectionInfo, EndpointRef, EventKind, EventLog, Fidelity, FrameClass, Reason,
    RequestTrace, TraceId, Validity, derive,
};

const MS: u64 = 1_000_000;

fn trace_with(log: EventLog) -> RequestTrace {
    RequestTrace {
        id: TraceId::new("01924f4e-0000-7000-8000-000000000001"),
        attempt: AttemptRef {
            round: 7,
            turn: 2,
            attempt: 1,
        },
        endpoint: EndpointRef {
            provider: "example".into(),
            model: "example-model".into(),
            authority: "api.example.invalid:443".into(),
        },
        connection: ConnectionInfo {
            reused: false,
            local_port: Some(51_234),
            age_ns: None,
        },
        fidelity: Fidelity::l2(),
        log,
    }
}

/// A cold connection, a normal streaming answer.
fn cold_streaming_trace() -> RequestTrace {
    let mut log = EventLog::with_capacity(4096);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(5 * MS, EventKind::DnsStart, 0, 0);
    log.push_at(25 * MS, EventKind::DnsEnd, 0, 0);
    log.push_at(25 * MS, EventKind::TcpStart, 0, 0);
    log.push_at(60 * MS, EventKind::TcpEnd, 0, 0);
    log.push_at(60 * MS, EventKind::TlsStart, 0, 0);
    log.push_at(130 * MS, EventKind::TlsEnd, 1, 0);
    log.push_at(131 * MS, EventKind::RequestWriteStart, 0, 0);
    log.push_at(180 * MS, EventKind::RequestWriteEnd, 640_000, 0);
    log.push_at(520 * MS, EventKind::HeadComplete, 0, 0);
    log.push_at(530 * MS, EventKind::BodyStart, 0, 0);
    log.push_at(
        530 * MS,
        EventKind::ProtocolFrame,
        u32::from(FrameClass::Open.code()),
        0,
    );
    log.push_at(
        540 * MS,
        EventKind::ProtocolFrame,
        u32::from(FrameClass::Usage.code()),
        0,
    );
    for i in 0..100u64 {
        log.push_at(700 * MS + i * 8 * MS, EventKind::OutputToken, 1, 0);
    }
    log.push_at(1_600 * MS, EventKind::BodyEnd, 0, 0);
    log.push_at(1_603 * MS, EventKind::Validated, 0, 0);
    trace_with(log)
}

#[test]
fn a_recorded_trace_derives_every_scope() {
    let trace = cold_streaming_trace();
    let derived = derive(&trace);

    assert_eq!(derived.dns_us.value(), Some(20_000));
    assert_eq!(derived.tcp_us.value(), Some(35_000));
    assert_eq!(derived.tls_us.value(), Some(70_000));
    assert_eq!(derived.ttfb_us.value(), Some(520_000));
    assert_eq!(derived.first_byte_us.value(), Some(530_000));
    assert_eq!(derived.first_frame_us.value(), Some(530_000));
    assert_eq!(derived.ttft_us.value(), Some(700_000));
    // The origin said "open" at 530 ms and produced its first token at 700 ms.
    assert_eq!(derived.server_ttft_us.value(), Some(170_000));
    assert_eq!(derived.stream_us.value(), Some(792_000));
    assert_eq!(derived.tail_us.value(), Some(108_000));
    assert_eq!(derived.e2e_us.value(), Some(1_603_000));

    // 99 gaps of 8 ms → a 792 ms span; the rate is the caller's division.
    let span_us = derived.stream_us.value().expect("stream span");
    assert_eq!(span_us, 792_000);
    let tps = 100.0 * 1_000_000.0 / span_us as f64;
    assert!((tps - 126.3).abs() < 1.0, "got {tps}");
    // The request was fully written before the head arrived: the new TTFT
    // anchor is measurable and earlier than the perceived wait.
    assert_eq!(derived.request_sent_us.value(), Some(180_000));
    assert_eq!(derived.first_token_after_sent_us.value(), Some(520_000));
}

#[test]
fn the_trace_is_the_single_source_after_a_round_trip() {
    let trace = cold_streaming_trace();
    let before = derive(&trace);

    let json = serde_json::to_string(&trace).expect("serialize trace");
    let restored: RequestTrace = serde_json::from_str(&json).expect("deserialize trace");
    let after = derive(&restored);

    assert_eq!(before, after, "derivation must survive persistence");
    assert_eq!(restored.dropped_events(), 0);
}

#[test]
fn a_batched_transport_is_reported_as_a_verdict_not_a_number() {
    let mut log = EventLog::with_capacity(64);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(MS, EventKind::ConnectReused, 0, 0);
    log.push_at(2_000 * MS, EventKind::HeadComplete, 0, 0);
    log.push_at(2_000 * MS + 500, EventKind::BodyStart, 0, 0);
    log.push_at(
        2_000 * MS + 1_000,
        EventKind::ProtocolFrame,
        u32::from(FrameClass::Open.code()),
        0,
    );
    for i in 0..40u64 {
        log.push_at(2_100 * MS + i * 10 * MS, EventKind::OutputToken, 1, 0);
    }
    log.push_at(2_600 * MS, EventKind::BodyEnd, 0, 0);
    log.push_at(2_601 * MS, EventKind::Validated, 0, 0);

    let derived = derive(&trace_with(log));
    assert_eq!(
        derived.server_ttft_us.validity(),
        Validity::NotEstimable(Reason::TransportBatched)
    );
    assert_eq!(derived.server_ttft_us.value(), None);
    // Perceived latency is still a fact, and the decode rate is unaffected by
    // the flush: the two scopes stay independent.
    assert_eq!(derived.ttft_us.value(), Some(2_100_000));
    assert!(derived.stream_us.value().is_some());
}

#[test]
fn a_ring_overflow_is_surfaced_rather_than_hidden() {
    let mut log = EventLog::with_capacity(4);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    for i in 1..10u64 {
        log.push_at(i * MS, EventKind::Read, 1_000, 0);
    }
    let trace = trace_with(log);
    assert_eq!(trace.dropped_events(), 6);
    let derived = derive(&trace);
    // The dispatch origin was evicted with the oldest events, so every
    // dispatch-relative scope must refuse rather than measure against a base it
    // no longer has.
    assert_eq!(
        derived.ttft_us.validity(),
        Validity::NotEstimable(Reason::NoOrigin)
    );
    assert_eq!(derived.ttft_us.value(), None);
}
