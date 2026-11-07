//! Pure derivations for an *ingress* trace: every number a server may show.
//!
//! The egress module answers "how long did the origin take". This one answers the
//! questions a listener actually asks, and they are different questions with
//! different anchors:
//!
//! ```text
//! accept ──► head ──► body end ──► handler start ──► handler end ──► head sent ──► response end
//!    │         │          │             │                 │              │              │
//!    │    request_read_us │      queue_us │          handler_us     write_start_us      │
//!    │                    │               │                                              │
//!    │              request_body_us       └──────────── pre_handler_us ───────────────────┤
//!    │                                                                                  │
//!    └──────────────────────────── ingress_e2e_us ────────────────────────────────────────┘
//! ```
//!
//! # Why these spans and not others
//!
//! - **`request_read_us`** (accept → head parsed) is the number that exposes a slow
//!   or hostile peer. It is where slow-loris lives, and it is invisible to any
//!   handler-level instrumentation.
//! - **`queue_us`** (head parsed → handler entered) is time the *server* spent
//!   before doing any work: admission control, body draining, scheduler delay. If
//!   it is large, the server is the problem and the handler has not been called
//!   yet.
//! - **`handler_us`** is the only span that is application time, and it is
//!   deliberately the only one derived from `HandlerStart`/`HandlerEnd` rather than
//!   from socket events.
//! - **`write_us`** (handler end → response end) separates "the handler was slow"
//!   from "the peer would not read". Those two failures look identical in a
//!   handler-duration metric and demand opposite responses.
//!
//! Every field is a [`Reading`], so a span that was not recorded is a verdict
//! rather than a zero. That is `[INV-SERVER-02]`: the same contract the egress
//! derivation obeys, applied to the other direction of travel.

use serde::{Deserialize, Serialize};

use crate::event::EventKind;
use crate::trace::RequestTrace;
use crate::verdict::{Reading, Reason};

/// Everything derivable from an ingress trace.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DerivedIngress {
    /// Accept → request head parsed. The slow-peer span.
    pub request_read_us: Reading<u64>,
    /// Head parsed → request body fully consumed.
    pub request_body_us: Reading<u64>,
    /// Accept → request body fully consumed.
    pub request_us: Reading<u64>,
    /// Head parsed → handler entered. Server-side delay before any work.
    pub queue_us: Reading<u64>,
    /// Handler entered → handler returned. Application time.
    pub handler_us: Reading<u64>,
    /// Handler returned → response head flushed to the kernel.
    pub write_start_us: Reading<u64>,
    /// Response head flushed → response fully written.
    pub write_us: Reading<u64>,
    /// Handler returned → response fully written.
    pub response_write_us: Reading<u64>,
    /// Accept → response fully written.
    pub ingress_e2e_us: Reading<u64>,
    /// Request body bytes read, when a body was read.
    pub request_bytes: Reading<u64>,
    /// Response body bytes written, when a body was written.
    pub response_bytes: Reading<u64>,
    /// The status the handler produced, when it produced one.
    pub status: Reading<u16>,
}

const NANOS_PER_MICRO: u64 = 1_000;

fn us(ns: u64) -> u64 {
    ns / NANOS_PER_MICRO
}

fn span(start: Option<u64>, end: Option<u64>) -> Reading<u64> {
    match (start, end) {
        (Some(start), Some(end)) if end >= start => Reading::measured(us(end - start)),
        _ => Reading::not_applicable(Reason::PhaseAbsent),
    }
}

fn count(value: Option<u32>) -> Reading<u64> {
    match value {
        Some(value) => Reading::measured(u64::from(value)),
        None => Reading::not_applicable(Reason::PhaseAbsent),
    }
}

/// How many exchanges the trace's log holds.
///
/// One per request head: a connection may serve several requests, and each has exactly one
/// head. Zero means the connection never produced a complete request.
pub fn exchange_count(log: &crate::log::EventLog) -> usize {
    log.iter()
        .filter(|event| event.kind == EventKind::RequestHeadComplete)
        .count()
}

/// What every span reads when the log holds more than one exchange.
fn refused_multiple_exchanges() -> DerivedIngress {
    DerivedIngress {
        request_read_us: Reading::not_estimable(Reason::MultipleExchanges),
        request_body_us: Reading::not_estimable(Reason::MultipleExchanges),
        request_us: Reading::not_estimable(Reason::MultipleExchanges),
        queue_us: Reading::not_estimable(Reason::MultipleExchanges),
        handler_us: Reading::not_estimable(Reason::MultipleExchanges),
        write_start_us: Reading::not_estimable(Reason::MultipleExchanges),
        write_us: Reading::not_estimable(Reason::MultipleExchanges),
        response_write_us: Reading::not_estimable(Reason::MultipleExchanges),
        ingress_e2e_us: Reading::not_estimable(Reason::MultipleExchanges),
        request_bytes: Reading::not_estimable(Reason::MultipleExchanges),
        response_bytes: Reading::not_estimable(Reason::MultipleExchanges),
        status: Reading::not_estimable(Reason::MultipleExchanges),
    }
}

/// Per-exchange derivations for a connection that served more than one request.
///
/// Each returned [`DerivedIngress`] describes exactly one exchange, with its own origin at
/// the point its read began — so `request_read_us` for the second request measures the
/// second request's read, not the first's. The returned vec is empty for a log with no
/// complete request.
///
/// This is the honest answer to "what did this connection do": a single set of spans for a
/// keep-alive connection would describe only its first request and silently omit the rest,
/// which is why [`derive_ingress`] refuses in that case.
pub fn derive_ingress_exchanges(trace: &RequestTrace) -> Vec<DerivedIngress> {
    split_exchanges(&trace.log)
        .iter()
        .map(|log| {
            let mut single = trace.clone();
            single.log = log.clone();
            derive_ingress(&single)
        })
        .collect()
}

/// Split a connection's log into one log per exchange.
///
/// Two shapes are possible, and they are split differently because they *are* different:
///
/// - **A serial connection** (all of HTTP/1.1): one request is served at a time, so an
///   exchange begins where the previous one's response ended — the moment the connection
///   became free. The boundary is taken from the `ResponseEnd`, not from the next recorded
///   event, because seeding at the next event would erase the idle gap between a response and
///   the peer's next request, undercounting exactly the interval a slow peer occupies.
/// - **A multiplexed connection** (HTTP/2): several exchanges are in flight at once and their
///   events *interleave*, so position carries no grouping at all. Each exchange is selected by
///   its `stream` identity, together with the connection-level facts that are true for it
///   (`IngressDispatch`, `IngressTlsEnd`, `Error`) — which is the whole reason
///   [`crate::Event::stream`] exists.
///
/// Each sub-log is seeded with a synthetic [`EventKind::IngressDispatch`] at its own start
/// offset when it does not already carry one, so the same derivation works unchanged and no
/// exchange is charged for time before it existed.
fn split_exchanges(log: &crate::log::EventLog) -> Vec<crate::log::EventLog> {
    let events: Vec<_> = log.iter().collect();
    if events.is_empty() {
        return Vec::new();
    }

    if events.iter().any(|event| event.stream != 0) {
        return split_multiplexed(&events);
    }

    let mut starts: Vec<(usize, u64)> = vec![(0, events[0].at_ns)];
    for (index, event) in events.iter().enumerate() {
        if event.kind == EventKind::ResponseEnd && index + 1 < events.len() {
            starts.push((index + 1, event.at_ns));
        }
    }

    let mut out = Vec::with_capacity(starts.len());
    for (position, &(start, origin_at)) in starts.iter().enumerate() {
        let end = starts
            .get(position + 1)
            .map_or(events.len(), |(next, _)| *next);
        let slice = &events[start..end];
        // An exchange exists only once its request head parsed. A connection that failed
        // before producing one has no exchanges — its failure is visible in the log's
        // `Error` event, not as a phantom request.
        if !slice
            .iter()
            .any(|event| event.kind == EventKind::RequestHeadComplete)
        {
            continue;
        }
        let mut sub = crate::log::EventLog::with_capacity(slice.len() + 1);
        // The exchange's own origin: when the connection became free for it.
        sub.push_at(origin_at, EventKind::IngressDispatch, 0, 0);
        for event in slice {
            sub.push_at_stream(event.at_ns, event.stream, event.kind, event.a, event.b);
        }
        out.push(sub);
    }
    out
}

/// Split a log whose exchanges ran concurrently, by stream identity.
///
/// The connection-level facts a per-stream derivation needs — the accept origin and a TLS
/// handshake, if one happened — are copied into every sub-log, because they are true for
/// every exchange on the connection. An `Error` is copied too: a connection-level failure
/// ended *every* stream on it, and a derivation that omitted it would report a stream as
/// merely unfinished.
fn split_multiplexed(events: &[crate::Event]) -> Vec<crate::log::EventLog> {
    let mut streams: Vec<u32> = Vec::new();
    for event in events {
        if event.stream != 0 && !streams.contains(&event.stream) {
            streams.push(event.stream);
        }
    }

    let shared = |event: &crate::Event| {
        event.stream == 0
            && matches!(
                event.kind,
                EventKind::IngressDispatch | EventKind::IngressTlsEnd | EventKind::Error
            )
    };

    let mut out = Vec::with_capacity(streams.len());
    for stream in streams {
        let mut sub = crate::log::EventLog::with_capacity(events.len());
        let mut seeded = false;
        for event in events {
            if shared(event) || event.stream == stream {
                if event.kind == EventKind::IngressDispatch {
                    seeded = true;
                }
                sub.push_at_stream(event.at_ns, stream, event.kind, event.a, event.b);
            }
        }
        if !seeded && let Some(first) = events.first() {
            let mut with_origin = crate::log::EventLog::with_capacity(sub.len() + 1);
            with_origin.push_at_stream(first.at_ns, stream, EventKind::IngressDispatch, 0, 0);
            for event in sub.iter() {
                with_origin.push_at_stream(event.at_ns, stream, event.kind, event.a, event.b);
            }
            sub = with_origin;
        }
        out.push(sub);
    }
    out
}

/// Derive every ingress timing from `trace`.
///
/// Reads no clock: the whole result is a function of the recorded events, which is what lets
/// a served request be re-analysed, diffed, or replayed offline.
///
/// # One exchange at a time
///
/// A keep-alive connection serves several requests, and `trace` is the whole connection. When
/// the log holds more than one exchange this returns every span as
/// [`Reason::MultipleExchanges`] rather than a set of numbers that describes only the first
/// request — a reader who saw one `handler_us` for a connection would conclude the handler is
/// fast while its fifth request took half a second. Use [`derive_ingress_exchanges`] to get
/// the per-exchange view.
pub fn derive_ingress(trace: &RequestTrace) -> DerivedIngress {
    let log = &trace.log;

    if exchange_count(log) > 1 {
        return refused_multiple_exchanges();
    }

    derive_single(log)
}

/// The single-exchange derivation, on a log that holds at most one request.
fn derive_single(log: &crate::log::EventLog) -> DerivedIngress {
    let mut origin = None;
    let mut tls_end = None;
    let mut head = None;
    let mut body_start = None;
    let mut body_end = None;
    let mut handler_start = None;
    let mut handler_end = None;
    let mut response_head_sent = None;
    let mut response_end = None;
    let mut request_bytes = None;
    let mut response_bytes = None;
    let mut status = None;

    for event in log.iter() {
        let at = event.at_ns;
        match event.kind {
            EventKind::IngressDispatch => origin = origin.or(Some(at)),
            EventKind::IngressTlsEnd => tls_end = tls_end.or(Some(at)),
            EventKind::RequestHeadComplete => {
                head = head.or(Some(at));
                request_bytes = Some(event.a);
            }
            EventKind::RequestBodyStart => body_start = body_start.or(Some(at)),
            EventKind::RequestBodyEnd => {
                body_end = body_end.or(Some(at));
                // The body-end event carries the total body bytes; a request with
                // no body may still record it as zero, which is a measurement.
                request_bytes = Some(event.a);
            }
            EventKind::HandlerStart => handler_start = handler_start.or(Some(at)),
            EventKind::HandlerEnd => {
                handler_end = handler_end.or(Some(at));
                status = Some(event.a as u16);
            }
            EventKind::ResponseHeadSent => response_head_sent = response_head_sent.or(Some(at)),
            EventKind::ResponseEnd => {
                response_end = response_end.or(Some(at));
                response_bytes = Some(event.a);
            }
            _ => {}
        }
    }

    let Some(origin) = origin else {
        // Without an ingress origin, no ingress span can be measured. This is the
        // one case worth a distinct verdict: the trace exists but is the wrong
        // direction, which is a caller bug rather than a gap in the data.
        return DerivedIngress {
            request_read_us: Reading::not_estimable(Reason::NoOrigin),
            request_body_us: Reading::not_estimable(Reason::NoOrigin),
            request_us: Reading::not_estimable(Reason::NoOrigin),
            queue_us: Reading::not_estimable(Reason::NoOrigin),
            handler_us: Reading::not_estimable(Reason::NoOrigin),
            write_start_us: Reading::not_estimable(Reason::NoOrigin),
            write_us: Reading::not_estimable(Reason::NoOrigin),
            response_write_us: Reading::not_estimable(Reason::NoOrigin),
            ingress_e2e_us: Reading::not_estimable(Reason::NoOrigin),
            request_bytes: count(request_bytes),
            response_bytes: count(response_bytes),
            status: status.map_or_else(
                || Reading::not_applicable(Reason::PhaseAbsent),
                Reading::measured,
            ),
        };
    };

    // The read phase starts after a TLS handshake when there was one: charging the
    // handshake to `request_read_us` would blame the peer's first request for a
    // cost the operator's TLS configuration may own.
    let read_start = tls_end.or(Some(origin));

    let queue_us = match (head, handler_start) {
        (Some(head), Some(handler)) if handler >= head => Reading::measured(us(handler - head)),
        (None, _) => Reading::not_applicable(Reason::PhaseAbsent),
        // A handler that was entered before the head was parsed cannot happen; if a
        // producer recorded it that way, the honest answer is "not a span" rather
        // than a wrapped-around number.
        _ => Reading::not_applicable(Reason::PhaseAbsent),
    };

    DerivedIngress {
        request_read_us: span(read_start, head),
        request_body_us: span(head, body_end),
        request_us: span(read_start, body_end),
        queue_us,
        handler_us: span(handler_start, handler_end),
        write_start_us: span(handler_end, response_head_sent),
        write_us: span(response_head_sent, response_end),
        response_write_us: span(handler_end, response_end),
        ingress_e2e_us: span(Some(origin), response_end),
        request_bytes: count(request_bytes),
        response_bytes: count(response_bytes),
        status: status.map_or_else(
            || Reading::not_applicable(Reason::PhaseAbsent),
            Reading::measured,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::EventLog;
    use crate::trace::{AttemptRef, ConnectionInfo, EndpointRef, Fidelity, TraceId};

    const MS: u64 = 1_000_000;

    fn trace(log: EventLog) -> RequestTrace {
        RequestTrace {
            id: TraceId::new("ingress"),
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
            fidelity: Fidelity::l1(),
            log,
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
}
