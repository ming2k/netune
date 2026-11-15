use super::*;
use crate::log::EventLog;
use crate::trace::{AttemptRef, ConnectionInfo, EndpointRef, Fidelity, TraceId};

const MS: u64 = 1_000_000;

fn trace(log: EventLog) -> RequestTrace {
    RequestTrace {
        meta: crate::trace::TraceMeta::new(
            TraceId::new("ingress"),
            crate::trace::Direction::Ingress,
        ),
        attempt: AttemptRef {
            round: 0,
            turn: 0,
            attempt: 0,
        },
        endpoint: EndpointRef {
            provider: String::new(),
            model: String::new(),
            authority: "0.0.0.0:8080".into(),
        },
        connection: ConnectionInfo::default(),
        identity: crate::ConnectionIdentity::default(),
        schema_version: crate::TRACE_SCHEMA_VERSION,
        fidelity: Fidelity::l1(),
        log,
        diagnostics: crate::DiagnosticTable::default(),
    }
}

#[test]
fn every_phase_is_measured_when_every_event_is_present() {
    let mut log = EventLog::with_capacity(32);
    log.push_at(0, EventKind::IngressDispatch, 0, 0);
    log.push_at(2 * MS, EventKind::RequestHeadComplete, 120, 0);
    log.push_at(3 * MS, EventKind::RequestBodyEnd, 5, 0);
    log.push_at(4 * MS, EventKind::HandlerStart, 0, 0);
    log.push_at(9 * MS, EventKind::HandlerEnd, 200, 0);
    log.push_at(10 * MS, EventKind::ResponseHeadSent, 0, 0);
    log.push_at(12 * MS, EventKind::ResponseEnd, 11, 0);

    let derived = derive_ingress(&trace(log));
    assert_eq!(derived.request_read_us.value(), Some(2_000));
    assert_eq!(derived.queue_us.value(), Some(2_000));
    assert_eq!(derived.handler_us.value(), Some(5_000));
    assert_eq!(derived.write_start_us.value(), Some(1_000));
    assert_eq!(derived.write_us.value(), Some(2_000));
    assert_eq!(derived.response_write_us.value(), Some(3_000));
    assert_eq!(derived.ingress_e2e_us.value(), Some(12_000));
    assert_eq!(derived.status.value(), Some(200));
    assert_eq!(derived.response_bytes.value(), Some(11));
    assert_eq!(derived.request_bytes.value(), Some(5));
}

#[test]
fn a_slow_peer_is_distinguishable_from_a_slow_handler() {
    // Same end-to-end time, opposite causes.
    let mut slow_peer = EventLog::with_capacity(16);
    slow_peer.push_at(0, EventKind::IngressDispatch, 0, 0);
    slow_peer.push_at(10 * MS, EventKind::RequestHeadComplete, 10, 0);
    slow_peer.push_at(11 * MS, EventKind::HandlerStart, 0, 0);
    slow_peer.push_at(12 * MS, EventKind::HandlerEnd, 200, 0);
    slow_peer.push_at(12 * MS, EventKind::ResponseEnd, 0, 0);

    let mut slow_handler = EventLog::with_capacity(16);
    slow_handler.push_at(0, EventKind::IngressDispatch, 0, 0);
    slow_handler.push_at(MS, EventKind::RequestHeadComplete, 10, 0);
    slow_handler.push_at(2 * MS, EventKind::HandlerStart, 0, 0);
    slow_handler.push_at(10 * MS, EventKind::HandlerEnd, 200, 0);
    slow_handler.push_at(12 * MS, EventKind::ResponseEnd, 0, 0);

    let peer = derive_ingress(&trace(slow_peer));
    let handler = derive_ingress(&trace(slow_handler));

    assert_eq!(
        peer.request_read_us.value(),
        Some(10_000),
        "the peer took 10 ms to send a head"
    );
    assert_eq!(peer.handler_us.value(), Some(1_000));
    assert_eq!(
        handler.request_read_us.value(),
        Some(1_000),
        "the peer was fast"
    );
    assert_eq!(
        handler.handler_us.value(),
        Some(8_000),
        "the handler took 8 ms"
    );
}

#[test]
fn a_tls_handshake_is_not_charged_to_the_request_read() {
    let mut log = EventLog::with_capacity(16);
    log.push_at(0, EventKind::IngressDispatch, 0, 0);
    log.push_at(5 * MS, EventKind::IngressTlsEnd, 0, 0);
    log.push_at(7 * MS, EventKind::RequestHeadComplete, 10, 0);
    let derived = derive_ingress(&trace(log));
    assert_eq!(
        derived.request_read_us.value(),
        Some(2_000),
        "only the post-handshake read is the request's cost"
    );
    assert_eq!(derived.ingress_e2e_us.value(), None, "no response yet");
}

#[test]
fn absent_phases_are_verdicts_not_zeros() {
    let mut log = EventLog::with_capacity(16);
    log.push_at(0, EventKind::IngressDispatch, 0, 0);
    log.push_at(MS, EventKind::RequestHeadComplete, 10, 0);
    let derived = derive_ingress(&trace(log));
    assert_eq!(derived.handler_us.value(), None);
    assert_eq!(
        derived.handler_us.validity().reason(),
        Some(Reason::PhaseAbsent)
    );
    assert_eq!(derived.status.value(), None);
}

#[test]
fn an_egress_trace_has_no_ingress_origin_and_says_so() {
    let mut log = EventLog::with_capacity(8);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(MS, EventKind::HeadComplete, 0, 0);
    let derived = derive_ingress(&trace(log));
    assert_eq!(
        derived.ingress_e2e_us.validity().reason(),
        Some(Reason::NoOrigin),
        "an egress trace must not be presented as an ingress one"
    );
}

#[test]
fn a_keep_alive_connection_with_two_requests_is_refused_not_truncated() {
    // The regression: this log served a 100 ms request and then a 500 ms one. Reading
    // one `handler_us` off it reported 100 ms and said nothing about the second,
    // which is the shape of a lie rather than a gap.
    let mut log = EventLog::with_capacity(32);
    log.push_at(0, EventKind::IngressDispatch, 0, 0);
    log.push_at(MS, EventKind::RequestHeadComplete, 10, 0);
    log.push_at(2 * MS, EventKind::HandlerStart, 0, 0);
    log.push_at(102 * MS, EventKind::HandlerEnd, 200, 0);
    log.push_at(103 * MS, EventKind::ResponseEnd, 2, 0);
    log.push_at(104 * MS, EventKind::RequestHeadComplete, 10, 0);
    log.push_at(105 * MS, EventKind::HandlerStart, 0, 0);
    log.push_at(605 * MS, EventKind::HandlerEnd, 200, 0);
    log.push_at(606 * MS, EventKind::ResponseEnd, 2, 0);

    let trace = trace(log);
    assert_eq!(exchange_count(&trace.log), 2);

    let refused = derive_ingress(&trace);
    assert_eq!(refused.handler_us.value(), None);
    assert_eq!(
        refused.handler_us.validity().reason(),
        Some(Reason::MultipleExchanges),
        "a single set of spans must not describe only the first request"
    );
    assert_eq!(refused.ingress_e2e_us.value(), None);
}

#[test]
fn per_exchange_derivation_gives_each_request_its_own_spans() {
    let mut log = EventLog::with_capacity(32);
    log.push_at(0, EventKind::IngressDispatch, 0, 0);
    log.push_at(MS, EventKind::RequestHeadComplete, 10, 0);
    log.push_at(2 * MS, EventKind::HandlerStart, 0, 0);
    log.push_at(102 * MS, EventKind::HandlerEnd, 200, 0);
    log.push_at(103 * MS, EventKind::ResponseEnd, 2, 0);
    log.push_at(104 * MS, EventKind::RequestHeadComplete, 10, 0);
    log.push_at(105 * MS, EventKind::HandlerStart, 0, 0);
    log.push_at(605 * MS, EventKind::HandlerEnd, 201, 0);
    log.push_at(606 * MS, EventKind::ResponseEnd, 3, 0);

    let exchanges = derive_ingress_exchanges(&trace(log));
    assert_eq!(exchanges.len(), 2, "one derivation per request");

    assert_eq!(
        exchanges[0].handler_us.value(),
        Some(100_000),
        "the first request's handler took 100 ms"
    );
    assert_eq!(exchanges[0].status.value(), Some(200));

    assert_eq!(
        exchanges[1].handler_us.value(),
        Some(500_000),
        "the second request's handler took 500 ms"
    );
    assert_eq!(exchanges[1].status.value(), Some(201));
    assert_eq!(exchanges[1].response_bytes.value(), Some(3));

    // The second request's read must be its own, not inherited from the first.
    assert_eq!(
        exchanges[1].request_read_us.value(),
        Some(1_000),
        "its read began at 104 ms and the head arrived at 105 ms"
    );
}

#[test]
fn a_single_exchange_log_still_derives_directly() {
    let mut log = EventLog::with_capacity(16);
    log.push_at(0, EventKind::IngressDispatch, 0, 0);
    log.push_at(2 * MS, EventKind::RequestHeadComplete, 10, 0);
    log.push_at(3 * MS, EventKind::HandlerStart, 0, 0);
    log.push_at(5 * MS, EventKind::HandlerEnd, 200, 0);
    log.push_at(6 * MS, EventKind::ResponseEnd, 0, 0);

    let trace = trace(log);
    assert_eq!(exchange_count(&trace.log), 1);
    assert_eq!(derive_ingress(&trace).handler_us.value(), Some(2_000));
    assert_eq!(derive_ingress_exchanges(&trace).len(), 1);
}

#[test]
fn a_connection_that_never_completed_a_request_yields_no_exchanges() {
    let mut log = EventLog::with_capacity(8);
    log.push_at(0, EventKind::IngressDispatch, 0, 0);
    log.push_at(MS, EventKind::Error, 5, 0);
    let trace = trace(log);
    assert_eq!(exchange_count(&trace.log), 0);
    assert!(derive_ingress_exchanges(&trace).is_empty());
}

#[test]
fn queue_is_never_a_wrapped_around_number() {
    // `EventLog::push_at` clamps a non-monotonic offset to its predecessor, so a
    // producer that records backwards is absorbed at the log rather than
    // producing a negative span here. This pins the property at the derivation
    // boundary: the value is 0 (the events coincide), never a wrapped u64.
    let mut log = EventLog::with_capacity(16);
    log.push_at(0, EventKind::IngressDispatch, 0, 0);
    log.push_at(5 * MS, EventKind::RequestHeadComplete, 10, 0);
    log.push_at(2 * MS, EventKind::HandlerStart, 0, 0);
    let derived = derive_ingress(&trace(log));
    assert_eq!(
        derived.queue_us.value(),
        Some(0),
        "the backwards stamp is clamped to the head's, so the span is zero"
    );
}
