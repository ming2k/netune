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
//! dispatch ──► head ──► first body byte ──► first frame ──► first token ──► last token ──► body end ──► validated
//!    │           │            │                  │              │
//!    │        ttfb_us     first_byte_us    first_frame_us    ttft_us
//!    │                          └──────── server_ttft_us ─────┘
//!    │                                       (first frame → first token)
//!    └───────────────────────────── e2e_us ──────────────────────────────────────────────────┘
//! ```
//!
//! `server_ttft_us` is the scope that answers "how fast does the model start
//! once it has committed to responding". It is refused when the response head
//! and the first body byte arrived in one flush, because then the frame anchor
//! was compressed by the transport and the number would flatter the origin.

use serde::{Deserialize, Serialize};

use crate::event::EventKind;
use crate::trace::RequestTrace;
use crate::verdict::{Reading, Reason};

/// Everything derivable from a trace.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
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
    /// Dispatch → first origin protocol frame of any class.
    pub first_frame_us: Reading<u64>,
    /// Dispatch → the request's last byte handed to the kernel.
    pub request_sent_us: Reading<u64>,
    /// Dispatch → first output-bearing token (the total wait).
    pub ttft_us: Reading<u64>,
    /// Request sent → first output token.
    ///
    /// This is the latency the model and the network after the request add up
    /// to. It excludes connection setup and the upload, so it is the number to
    /// compare across networks — at the cost of being a lower bound on what the
    /// user actually waited.
    pub first_token_after_sent_us: Reading<u64>,
    /// First origin frame → first output token.
    pub server_ttft_us: Reading<u64>,
    /// First → last output token. The denominator of the streaming rate.
    pub stream_us: Reading<u64>,
    /// Last output token → body end.
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
fn us(ns: u64) -> u64 {
    ns / NANOS_PER_MICRO
}

fn span(start: Option<u64>, end: Option<u64>) -> Reading<u64> {
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
            EventKind::OutputToken => output.push((at, event.a)),
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
            ttft_us: Reading::not_estimable(Reason::NoOrigin),
            first_token_after_sent_us: Reading::not_estimable(Reason::NoOrigin),
            server_ttft_us: Reading::not_estimable(Reason::NoOrigin),
            stream_us: Reading::not_estimable(Reason::NoOrigin),
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
    let first_token_at = output.first().map(|(at, _)| *at);
    let last_token_at = output.last().map(|(at, _)| *at);

    let server_ttft_us = match (first_frame, first_token_at) {
        (Some(frame), Some(token)) if token >= frame => {
            let head_to_body = match (head_at, body_start) {
                (Some(head), Some(body)) => body.saturating_sub(head),
                // Without a body-start anchor the batched test cannot be run;
                // refusing is the honest response.
                _ => u64::MAX,
            };
            if head_to_body < crate::BATCH_GAP_NS {
                Reading::not_estimable(Reason::TransportBatched)
            } else {
                Reading::measured(us(token - frame))
            }
        }
        _ => Reading::not_applicable(Reason::PhaseAbsent),
    };

    let stream_us = match (first_token_at, last_token_at) {
        (Some(first), Some(last)) if output.len() >= 2 && last >= first => {
            Reading::measured(us(last - first))
        }
        (Some(_), Some(_)) => Reading::not_applicable(Reason::FewerThanTwoOutputEvents),
        _ => Reading::not_applicable(Reason::PhaseAbsent),
    };

    let tail_us = match (last_token_at, body_end) {
        (Some(token), Some(end)) if end >= token => Reading::measured(us(end - token)),
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
        ttft_us: first_token_at.map_or(Reading::not_applicable(Reason::PhaseAbsent), |at| {
            Reading::measured(us(at.saturating_sub(origin)))
        }),
        first_token_after_sent_us: match (request_sent.or(last_write), first_token_at) {
            (Some(sent), Some(token)) if token >= sent => Reading::measured(us(token - sent)),
            _ => Reading::not_applicable(Reason::PhaseAbsent),
        },
        server_ttft_us,
        stream_us,
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
mod tests {
    use super::*;
    use crate::event::{FrameClass, TimeSource};
    use crate::log::EventLog;
    use crate::record::Recorder;
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
            fidelity: Fidelity::l2(),
            log,
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
            log.push_at(505 * MS + i * 10 * MS, EventKind::OutputToken, 1, 0);
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
        assert_eq!(derived.ttft_us.value(), Some(505_000));
        // first frame → first token: 95 ms
        assert_eq!(derived.server_ttft_us.value(), Some(95_000));
        // 49 gaps of 10 ms
        assert_eq!(derived.stream_us.value(), Some(490_000));
        assert_eq!(derived.tail_us.value(), Some(5_000));
        assert_eq!(derived.e2e_us.value(), Some(1_002_000));
        // Request fully written at 200 ms; the new TTFT anchors there.
        assert_eq!(derived.request_sent_us.value(), Some(200_000));
        assert_eq!(derived.first_token_after_sent_us.value(), Some(305_000));
        // The rate is the caller's division now: 50 tokens over a 490 ms span.
        let span_us = derived.stream_us.value().expect("stream span");
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
        log.push_at(50 * MS, EventKind::OutputToken, 10, 0);
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
        log.push_at(900 * MS, EventKind::OutputToken, 10, 0);
        log.push_at(950 * MS, EventKind::BodyEnd, 0, 0);
        log.push_at(951 * MS, EventKind::Validated, 0, 0);

        let derived = derive(&trace(log));
        assert_eq!(
            derived.server_ttft_us.validity(),
            crate::Validity::NotEstimable(Reason::TransportBatched)
        );
        assert_eq!(derived.server_ttft_us.value(), None);
        // The perceived scope is still measured: the wait was real.
        assert_eq!(derived.ttft_us.value(), Some(900_000));
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
        log.push_at(5 * MS, EventKind::OutputToken, 3, 0);
        log.push_at(6 * MS, EventKind::BodyEnd, 0, 0);
        log.push_at(7 * MS, EventKind::Validated, 0, 0);

        let derived = derive(&trace(log));
        assert_eq!(
            derived.stream_us.validity(),
            crate::Validity::NotApplicable(Reason::FewerThanTwoOutputEvents)
        );
        assert!(derived.stream_us.value().is_none());
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
        assert!(derived.ttft_us.is_measured());
        // The recorder runs at wall-clock speed, so every frame lands in one
        // flush and the span is tiny. The rate guard lives in the ledger, which
        // refuses to divide by a sub-20 ms span.
        let span = derived.stream_us.value().expect("span measured");
        assert!(span < 1_000, "a burst lands in one flush: {span} µs");
    }
}
