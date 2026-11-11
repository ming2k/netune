//! Pure derivations for QUIC and HTTP/3 traces.
//!
//! A QUIC or HTTP/3 exchange has no [`EventKind::Dispatch`](crate::EventKind::Dispatch)
//! origin — that anchor belongs to the egress request orchestrator — so the model-facing
//! [`derive`](crate::derive) cannot describe it. These functions do the same job against
//! the transport's own boundaries: the handshake (`QuicStart` → `QuicEnd`) and each
//! request stream (`H3StreamStart` → `H3HeadComplete` → `H3Finished`).
//!
//! An `H3Client` serves many requests over one connection and one recorder, so HTTP/3
//! events carry an exchange id in [`Event::stream`](crate::Event::stream). A reader that
//! took the first event of each kind would silently attribute every later request to the
//! first; [`derive_h3`] therefore refuses a multi-exchange log, and
//! [`derive_h3_exchanges`] returns the per-exchange view — the same split the ingress
//! model uses.
//!
//! Congestion-window and packet-loss counters are deliberately not derived: they are
//! transport *state*, sampled from the owned connection on demand, not ordered
//! boundaries. Recording them as events would mean inventing a sampling clock and
//! would put non-reproducible numbers inside a trace whose value is that it is
//! reproducible.

use std::collections::BTreeMap;

use crate::derive::span;
use crate::event::EventKind;
use crate::trace::RequestTrace;
use crate::verdict::{Reading, Reason};

/// Everything derivable from a QUIC handshake trace.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DerivedQuic {
    /// `QuicStart` → `QuicEnd`, present only when the handshake succeeded.
    pub handshake_us: Reading<u64>,
}

/// Everything derivable from one HTTP/3 request exchange.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DerivedH3 {
    /// Request stream start → response head.
    pub ttfb_us: Reading<u64>,
    /// Response head → last body byte.
    pub body_us: Reading<u64>,
    /// Request stream start → last body byte.
    pub e2e_us: Reading<u64>,
}

/// The boundaries recorded for one HTTP/3 exchange.
#[derive(Debug, Clone, Copy, Default)]
struct H3Exchange {
    start: Option<u64>,
    head: Option<u64>,
    finished: Option<u64>,
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

/// Derive the request spans from a single-exchange HTTP/3 trace.
///
/// A log that carries more than one exchange has no single TTFB, body or end-to-end span:
/// every reading is [`NotEstimable(MultipleExchanges)`](Reason::MultipleExchanges). Use
/// [`derive_h3_exchanges`] for the per-request view.
pub fn derive_h3(trace: &RequestTrace) -> DerivedH3 {
    let exchanges = h3_exchanges(trace);
    match exchanges.len() {
        0 => absent_h3(Reason::NoOrigin),
        1 => derive_one(exchanges.into_values().next().unwrap_or_default()),
        _ => absent_h3(Reason::MultipleExchanges),
    }
}

/// Derive every HTTP/3 exchange in the trace, in exchange-id order.
pub fn derive_h3_exchanges(trace: &RequestTrace) -> Vec<DerivedH3> {
    h3_exchanges(trace).into_values().map(derive_one).collect()
}

/// Group the HTTP/3 boundaries by their exchange id.
///
/// Only H3 event kinds participate. Connection-level facts (`QuicStart`/`QuicEnd`) use
/// stream `0`, and `H3Client` numbers its exchanges from `1`, so the two cannot be
/// confused by an absent or default id.
fn h3_exchanges(trace: &RequestTrace) -> BTreeMap<u32, H3Exchange> {
    let mut exchanges: BTreeMap<u32, H3Exchange> = BTreeMap::new();
    for event in trace.log.iter() {
        match event.kind {
            EventKind::H3StreamStart => {
                exchanges
                    .entry(event.stream)
                    .or_default()
                    .start
                    .get_or_insert(event.at_ns);
            }
            EventKind::H3HeadComplete => {
                exchanges
                    .entry(event.stream)
                    .or_default()
                    .head
                    .get_or_insert(event.at_ns);
            }
            EventKind::H3Finished => {
                exchanges
                    .entry(event.stream)
                    .or_default()
                    .finished
                    .get_or_insert(event.at_ns);
            }
            _ => {}
        }
    }
    exchanges
}

fn absent_h3(reason: Reason) -> DerivedH3 {
    let absent = Reading::not_estimable(reason);
    DerivedH3 {
        ttfb_us: absent,
        body_us: absent,
        e2e_us: absent,
    }
}

fn derive_one(exchange: H3Exchange) -> DerivedH3 {
    let Some(start) = exchange.start else {
        return absent_h3(Reason::NoOrigin);
    };

    DerivedH3 {
        ttfb_us: span(Some(start), exchange.head),
        body_us: span(exchange.head, exchange.finished),
        e2e_us: span(Some(start), exchange.finished),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::EventLog;
    use crate::trace::{AttemptRef, ConnectionInfo, EndpointRef, Fidelity, TraceId};

    fn trace(log: EventLog) -> RequestTrace {
        RequestTrace {
            meta: crate::trace::TraceMeta::new(
                TraceId::new("test"),
                crate::trace::Direction::Egress,
            ),
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
            identity: crate::ConnectionIdentity::default(),
            schema_version: crate::TRACE_SCHEMA_VERSION,
            fidelity: Fidelity::l0(),
            log,
            diagnostics: crate::DiagnosticTable::default(),
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
        log.push_at_stream(0, 1, EventKind::H3StreamStart, 0, 0);
        log.push_at_stream(80 * MS, 1, EventKind::H3HeadComplete, 200, 0);
        log.push_at_stream(200 * MS, 1, EventKind::H3Finished, 4096, 0);

        let derived = derive_h3(&trace(log));
        assert_eq!(derived.ttfb_us.value(), Some(80_000));
        assert_eq!(derived.body_us.value(), Some(120_000));
        assert_eq!(derived.e2e_us.value(), Some(200_000));
    }

    #[test]
    fn an_incomplete_http3_exchange_keeps_only_the_spans_it_has() {
        let mut log = EventLog::with_capacity(16);
        log.push_at_stream(0, 1, EventKind::H3StreamStart, 0, 0);
        log.push_at_stream(80 * MS, 1, EventKind::H3HeadComplete, 200, 0);

        let derived = derive_h3(&trace(log));
        assert_eq!(derived.ttfb_us.value(), Some(80_000));
        assert_eq!(derived.body_us.value(), None);
        assert_eq!(derived.e2e_us.value(), None);
        assert_eq!(
            derived.e2e_us.validity().reason(),
            Some(Reason::PhaseAbsent)
        );
    }

    #[test]
    fn a_multi_exchange_log_refuses_a_single_attribution() {
        let mut log = EventLog::with_capacity(32);
        for (exchange, offset) in [(1u32, 0u64), (2, 400 * MS)] {
            log.push_at_stream(offset, exchange, EventKind::H3StreamStart, 0, 0);
            log.push_at_stream(
                offset + 80 * MS,
                exchange,
                EventKind::H3HeadComplete,
                200,
                0,
            );
            log.push_at_stream(offset + 200 * MS, exchange, EventKind::H3Finished, 4096, 0);
        }

        let trace = trace(log);
        let single = derive_h3(&trace);
        assert_eq!(
            single.ttfb_us.validity().reason(),
            Some(Reason::MultipleExchanges)
        );

        let exchanges = derive_h3_exchanges(&trace);
        assert_eq!(exchanges.len(), 2);
        assert_eq!(exchanges[0].ttfb_us.value(), Some(80_000));
        assert_eq!(exchanges[1].ttfb_us.value(), Some(80_000));
        assert_eq!(exchanges[0].e2e_us.value(), Some(200_000));
        assert_eq!(exchanges[1].e2e_us.value(), Some(200_000));
    }
}
