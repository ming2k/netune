//! Pure derivations: every number a surface may show.
//!
//! `derive` is a pure function of a recorded trace. It reads no clock, consults
//! no envelope state that is not itself recorded as an event, and never
//! substitutes one scope for another. Each field is a [`Reading`], so the
//! verdict travels with the number.
//!
//! Anchors, all offsets from dispatch:
//!
//! ```text
//! dispatch ──► head ──► first body byte ──► first frame ──► first payload ──► last payload ──► body end ──► validated
//!    │           │            │                  │              │
//!    │        ttfb_us     first_byte_us    first_frame_us    first_payload_us
//!    │                          └────── frame_to_payload_us ──────┘
//!    │                                     (first frame → first payload)
//!    └───────────────────────────── e2e_us ──────────────────────────────────────────────────┘
//! ```
//!
//! `frame_to_payload_us` is the scope that answers "how fast does the origin
//! produce content once it has committed to responding". It is refused when the response head
//! and the first body byte arrived in one flush, because then the frame anchor
//! was compressed by the transport and the number would flatter the origin.

use crate::event::EventKind;
use crate::trace::RequestTrace;
use crate::verdict::{Reading, Reason};

/// Everything derivable from a trace.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DerivedTimings {
    /// Name resolution, on a connection that needed one.
    pub dns_us: Reading<u64>,
    /// TCP connect.
    pub tcp_us: Reading<u64>,
    /// TLS handshake.
    pub tls_us: Reading<u64>,
    /// Dispatch → response head.
    pub ttfb_us: Reading<u64>,
    /// Dispatch → first body byte.
    pub first_byte_us: Reading<u64>,
    /// Dispatch → first application frame of any class.
    pub first_frame_us: Reading<u64>,
    /// Dispatch → the request's last byte handed to the kernel.
    pub request_sent_us: Reading<u64>,
    /// Dispatch → first payload (the total wait).
    pub first_payload_us: Reading<u64>,
    /// Request sent → first payload.
    ///
    /// This is the latency the origin and the network after the request add up
    /// to. It excludes connection setup and the upload, so it is the number to
    /// compare across networks — at the cost of being a lower bound on what the
    /// user actually waited.
    pub first_payload_after_sent_us: Reading<u64>,
    /// First application frame → first payload.
    pub frame_to_payload_us: Reading<u64>,
    /// First → last payload. The denominator of a streaming rate.
    pub payload_span_us: Reading<u64>,
    /// Last payload → body end.
    pub tail_us: Reading<u64>,
    /// Dispatch → validated response.
    pub e2e_us: Reading<u64>,
    /// Smallest smoothed RTT observed via `TCP_INFO`.
    pub rtt_us: Reading<u64>,
    /// Largest retransmit counter observed via `TCP_INFO`.
    pub retransmits: Reading<u32>,
}

const NANOS_PER_MICRO: u64 = 1_000;

/// Truncating nanoseconds → microseconds. A sub-microsecond span measures 0 µs,
/// which is honest for the resolution the field claims.
pub(crate) fn us(ns: u64) -> u64 {
    ns / NANOS_PER_MICRO
}

pub(crate) fn span(start: Option<u64>, end: Option<u64>) -> Reading<u64> {
    match (start, end) {
        (Some(start), Some(end)) if end >= start => Reading::measured(us(end - start)),
        _ => Reading::not_applicable(Reason::PhaseAbsent),
    }
}

/// Derive every timing and rate from `trace`.
pub fn derive(trace: &RequestTrace) -> DerivedTimings {
    let log = &trace.log;

    let mut reused = false;
    let mut dns = (None, None);
    let mut tcp = (None, None);
    let mut tls = (None, None);
    let mut head = None;
    let mut body_start = None;
    let mut body_end = None;
    let mut first_frame = None;
    let mut validated = None;
    let mut tcp_info = false;
    let mut rtt_min: Option<u64> = None;
    let mut retrans_max: u32 = 0;
    let mut request_sent = None;
    let mut last_write = None;

    let mut output: Vec<(u64, u32)> = Vec::new();

    for event in log.iter() {
        let at = event.at_ns;
        match event.kind {
            EventKind::ConnectReused => reused = true,
            // The reuse claim is revocable: if the socket turned out to be dead
            // and the attempt reconnected, its phases were really paid. Leaving
            // `reused` set would report a handshake this attempt did pay as
            // `ConnectionReused` — the same class of fabrication as claiming a
            // handshake that never happened.
            EventKind::ConnectStaleDiscarded => reused = false,
            EventKind::DnsStart => dns.0 = dns.0.or(Some(at)),
            EventKind::DnsEnd => dns.1 = dns.1.or(Some(at)),
            EventKind::TcpStart => tcp.0 = tcp.0.or(Some(at)),
            EventKind::TcpEnd => tcp.1 = tcp.1.or(Some(at)),
            EventKind::TlsStart => tls.0 = tls.0.or(Some(at)),
            EventKind::TlsEnd => tls.1 = tls.1.or(Some(at)),
            EventKind::HeadComplete => head = head.or(Some(at)),
            EventKind::BodyStart => body_start = body_start.or(Some(at)),
            EventKind::BodyEnd => body_end = body_end.or(Some(at)),
            EventKind::ProtocolFrame => first_frame = first_frame.or(Some(at)),
            EventKind::Payload => output.push((at, event.a)),
            EventKind::Validated => validated = validated.or(Some(at)),
            EventKind::RequestWriteEnd => request_sent = request_sent.or(Some(at)),
            EventKind::Write => last_write = Some(at),
            EventKind::TcpInfo => {
                tcp_info = true;
                rtt_min = Some(rtt_min.map_or(u64::from(event.a), |m| m.min(u64::from(event.a))));
                retrans_max = retrans_max.max(event.b);
            }
            _ => {}
        }
    }

    let dispatch = log.first_of(EventKind::Dispatch).map(|event| event.at_ns);
    if dispatch.is_none() {
        // Without an origin nothing is measurable against anything.
        return DerivedTimings {
            dns_us: Reading::not_estimable(Reason::NoOrigin),
            tcp_us: Reading::not_estimable(Reason::NoOrigin),
            tls_us: Reading::not_estimable(Reason::NoOrigin),
            ttfb_us: Reading::not_estimable(Reason::NoOrigin),
            first_byte_us: Reading::not_estimable(Reason::NoOrigin),
            first_frame_us: Reading::not_estimable(Reason::NoOrigin),
            request_sent_us: Reading::not_estimable(Reason::NoOrigin),
            first_payload_us: Reading::not_estimable(Reason::NoOrigin),
            first_payload_after_sent_us: Reading::not_estimable(Reason::NoOrigin),
            frame_to_payload_us: Reading::not_estimable(Reason::NoOrigin),
            payload_span_us: Reading::not_estimable(Reason::NoOrigin),
            tail_us: Reading::not_estimable(Reason::NoOrigin),
            e2e_us: Reading::not_estimable(Reason::NoOrigin),
            rtt_us: Reading::not_estimable(Reason::NoOrigin),
            retransmits: Reading::not_estimable(Reason::NoOrigin),
        };
    }
    let origin = dispatch.unwrap_or(0);

    let connect_phase = |pair: (Option<u64>, Option<u64>)| {
        if reused {
            Reading::not_applicable(Reason::ConnectionReused)
        } else {
            span(pair.0, pair.1)
        }
    };

    let head_at = head;
    let first_payload_at = output.first().map(|(at, _)| *at);
    let last_payload_at = output.last().map(|(at, _)| *at);

    let frame_to_payload_us = match (first_frame, first_payload_at) {
        (Some(frame), Some(payload)) if payload >= frame => {
            let head_to_body = match (head_at, body_start) {
                (Some(head), Some(body)) => body.saturating_sub(head),
                // Without a body-start anchor the batched test cannot be run;
                // refusing is the honest response.
                _ => u64::MAX,
            };
            if head_to_body < crate::BATCH_GAP_NS {
                Reading::not_estimable(Reason::TransportBatched)
            } else {
                Reading::measured(us(payload - frame))
            }
        }
        _ => Reading::not_applicable(Reason::PhaseAbsent),
    };

    let payload_span_us = match (first_payload_at, last_payload_at) {
        (Some(first), Some(last)) if output.len() >= 2 && last >= first => {
            Reading::measured(us(last - first))
        }
        (Some(_), Some(_)) => Reading::not_applicable(Reason::FewerThanTwoPayloadEvents),
        _ => Reading::not_applicable(Reason::PhaseAbsent),
    };

    let tail_us = match (last_payload_at, body_end) {
        (Some(payload), Some(end)) if end >= payload => Reading::measured(us(end - payload)),
        _ => Reading::not_applicable(Reason::PhaseAbsent),
    };

    let e2e_us = match validated {
        Some(at) if at >= origin => Reading::measured(us(at - origin)),
        Some(_) => Reading::not_applicable(Reason::PhaseAbsent),
        None => Reading::not_applicable(Reason::ResponseNotValidated),
    };

    let tcp_info_validity = if tcp_info {
        None
    } else {
        Some(Reason::TcpInfoUnavailable)
    };

    DerivedTimings {
        dns_us: connect_phase(dns),
        tcp_us: connect_phase(tcp),
        tls_us: connect_phase(tls),
        ttfb_us: head.map_or(Reading::not_applicable(Reason::PhaseAbsent), |at| {
            Reading::measured(us(at.saturating_sub(origin)))
        }),
        first_byte_us: body_start.map_or(Reading::not_applicable(Reason::PhaseAbsent), |at| {
            Reading::measured(us(at.saturating_sub(origin)))
        }),
        first_frame_us: first_frame.map_or(Reading::not_applicable(Reason::PhaseAbsent), |at| {
            Reading::measured(us(at.saturating_sub(origin)))
        }),
        request_sent_us: request_sent
            .or(last_write)
            .map_or(Reading::not_applicable(Reason::PhaseAbsent), |at| {
                Reading::measured(us(at.saturating_sub(origin)))
            }),
        first_payload_us: first_payload_at
            .map_or(Reading::not_applicable(Reason::PhaseAbsent), |at| {
                Reading::measured(us(at.saturating_sub(origin)))
            }),
        first_payload_after_sent_us: match (request_sent.or(last_write), first_payload_at) {
            (Some(sent), Some(payload)) if payload >= sent => Reading::measured(us(payload - sent)),
            _ => Reading::not_applicable(Reason::PhaseAbsent),
        },
        frame_to_payload_us,
        payload_span_us,
        tail_us,
        e2e_us,
        rtt_us: match tcp_info_validity {
            Some(reason) => Reading::not_estimable(reason),
            None => rtt_min.map_or(
                Reading::not_estimable(Reason::TcpInfoUnavailable),
                Reading::measured,
            ),
        },
        retransmits: match tcp_info_validity {
            Some(reason) => Reading::not_estimable(reason),
            None => Reading::measured(retrans_max),
        },
    }
}

#[cfg(test)]
mod tests;
