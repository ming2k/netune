//! Pure derivations for QUIC and HTTP/3 traces.
//!
//! A QUIC or HTTP/3 exchange has no [`EventKind::Dispatch`](crate::EventKind::Dispatch)
//! origin — that anchor belongs to the egress request orchestrator — so the model-facing
//! [`derive`](crate::derive) cannot describe it. These functions do the same job against
//! the transport's own boundaries: the handshake (`QuicStart` → `QuicEnd`) and the
//! request stream (`H3StreamStart` → `H3HeadComplete` → `H3Finished`).
//!
//! Congestion-window and packet-loss counters are deliberately not derived: they are
//! transport *state*, sampled from [`quinn::Connection::stats`](https://docs.rs/quinn) on
//! demand, not ordered boundaries. Recording them as events would mean inventing a
//! sampling clock and would put non-reproducible numbers inside a trace whose value is
//! that it is reproducible.

use serde::{Deserialize, Serialize};

use crate::derive::span;
use crate::event::EventKind;
use crate::trace::RequestTrace;
use crate::verdict::{Reading, Reason};

/// Everything derivable from a QUIC handshake trace.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DerivedQuic {
    /// `QuicStart` → `QuicEnd`, present only when the handshake succeeded.
    pub handshake_us: Reading<u64>,
}

/// Everything derivable from an HTTP/3 request trace.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DerivedH3 {
    /// Request stream start → response head.
    pub ttfb_us: Reading<u64>,
    /// Response head → last body byte.
    pub body_us: Reading<u64>,
    /// Request stream start → last body byte.
    pub e2e_us: Reading<u64>,
}

/// Derive the handshake span from a QUIC trace.
pub fn derive_quic(trace: &RequestTrace) -> DerivedQuic {
    let Some(start) = trace
        .log
        .first_of(EventKind::QuicStart)
        .map(|event| event.at_ns)
    else {
        return DerivedQuic {
            handshake_us: Reading::not_estimable(Reason::NoOrigin),
        };
    };

    let handshake_us = match trace.log.first_of(EventKind::QuicEnd) {
        Some(end) if end.a == 1 => span(Some(start), Some(end.at_ns)),
        // A failed handshake still has a measurable interval, but it is not a
        // handshake duration; reporting it as one would flatter a dead endpoint.
        Some(_) => Reading::not_estimable(Reason::HandshakeFailed),
        None => Reading::not_applicable(Reason::PhaseAbsent),
    };

    DerivedQuic { handshake_us }
}

/// Derive the request spans from an HTTP/3 trace.
pub fn derive_h3(trace: &RequestTrace) -> DerivedH3 {
    let Some(start) = trace
        .log
        .first_of(EventKind::H3StreamStart)
        .map(|event| event.at_ns)
    else {
        let absent = Reading::not_estimable(Reason::NoOrigin);
        return DerivedH3 {
            ttfb_us: absent,
            body_us: absent,
            e2e_us: absent,
        };
    };

    let head = trace
        .log
        .first_of(EventKind::H3HeadComplete)
        .map(|event| event.at_ns);
    let finished = trace
        .log
        .first_of(EventKind::H3Finished)
        .map(|event| event.at_ns);

    DerivedH3 {
        ttfb_us: span(Some(start), head),
        body_us: span(head, finished),
        e2e_us: span(Some(start), finished),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::EventLog;
    use crate::trace::{AttemptRef, ConnectionInfo, EndpointRef, Fidelity, TraceId};

    fn trace(log: EventLog) -> RequestTrace {
        RequestTrace {
            id: TraceId::new("test"),
            attempt: AttemptRef {
                round: 1,
                turn: 1,
                attempt: 1,
            },
            endpoint: EndpointRef {
                provider: "test".into(),
                model: "test".into(),
                authority: "example.invalid:443".into(),
            },
            connection: ConnectionInfo::default(),
            fidelity: Fidelity::l0(),
            log,
        }
    }

    const MS: u64 = 1_000_000;

    #[test]
    fn a_completed_handshake_derives_its_span() {
        let mut log = EventLog::with_capacity(16);
        log.push_at(0, EventKind::QuicStart, 0, 0);
        log.push_at(120 * MS, EventKind::QuicEnd, 1, 0);

        let derived = derive_quic(&trace(log));
        assert_eq!(derived.handshake_us.value(), Some(120_000));
    }

    #[test]
    fn a_failed_handshake_is_not_a_duration() {
        let mut log = EventLog::with_capacity(16);
        log.push_at(0, EventKind::QuicStart, 0, 0);
        log.push_at(120 * MS, EventKind::QuicEnd, 0, 0);

        let derived = derive_quic(&trace(log));
        assert_eq!(derived.handshake_us.value(), None);
        assert_eq!(
            derived.handshake_us.validity().reason(),
            Some(Reason::HandshakeFailed)
        );
    }

    #[test]
    fn a_quic_trace_without_a_start_has_no_origin() {
        let log = EventLog::with_capacity(16);
        let derived = derive_quic(&trace(log));
        assert_eq!(
            derived.handshake_us.validity().reason(),
            Some(Reason::NoOrigin)
        );
    }

    #[test]
    fn an_http3_exchange_derives_ttfb_body_and_e2e() {
        let mut log = EventLog::with_capacity(16);
        log.push_at(0, EventKind::H3StreamStart, 0, 0);
        log.push_at(80 * MS, EventKind::H3HeadComplete, 200, 0);
        log.push_at(200 * MS, EventKind::H3Finished, 4096, 0);

        let derived = derive_h3(&trace(log));
        assert_eq!(derived.ttfb_us.value(), Some(80_000));
        assert_eq!(derived.body_us.value(), Some(120_000));
        assert_eq!(derived.e2e_us.value(), Some(200_000));
    }

    #[test]
    fn an_incomplete_http3_exchange_keeps_only_the_spans_it_has() {
        let mut log = EventLog::with_capacity(16);
        log.push_at(0, EventKind::H3StreamStart, 0, 0);
        log.push_at(80 * MS, EventKind::H3HeadComplete, 200, 0);

        let derived = derive_h3(&trace(log));
        assert_eq!(derived.ttfb_us.value(), Some(80_000));
        assert_eq!(derived.body_us.value(), None);
        assert_eq!(derived.e2e_us.value(), None);
        assert_eq!(
            derived.e2e_us.validity().reason(),
            Some(Reason::PhaseAbsent)
        );
    }
}
