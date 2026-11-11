//! Pure failure diagnosis over a recorded trace.
//!
//! `diagnose` reads no clock and performs no I/O. It answers the review
//! questions a raw event log makes a human reconstruct: what failed, in which
//! phase, was the last phase reached, is retry safe, and how much of the record
//! is actually present.

use std::fmt;

use crate::diagnostic::{
    DiagnosticCode, DiagnosticLevel, DiagnosticPhase, DiagnosticRecord, DiagnosticTable,
    RetryVerdict,
};
use crate::event::EventKind;
use crate::log::EventLog;
use crate::trace::{Fidelity, TraceMeta};

/// How an attempt ended, as far as the record can prove.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Outcome {
    /// A completion marker is present and no terminal error was recorded.
    Succeeded,
    /// A terminal error was recorded.
    Failed,
    /// The record ends without a completion or an error.
    Incomplete,
}

/// A pure root-cause summary of one trace.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Diagnosis {
    pub trace_id: String,
    pub outcome: Outcome,
    pub terminal: Option<DiagnosticRecord>,
    pub last_phase: DiagnosticPhase,
    pub retry: RetryVerdict,
    pub event_count: usize,
    pub dropped_events: u32,
    pub dropped_diagnostics: u32,
    pub fidelity: Fidelity,
    pub next_checks: Vec<String>,
}

impl Diagnosis {
    /// Render a concise human-readable report for a runbook or an issue.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "trace {}: {:?} after {} event(s), last phase {:?}\n",
            self.trace_id, self.outcome, self.event_count, self.last_phase
        ));
        if let Some(terminal) = &self.terminal {
            out.push_str(&format!(
                "  code: {} ({:?}, {:?})\n",
                terminal.code, terminal.level, terminal.retry
            ));
            if !terminal.message.is_empty() {
                out.push_str(&format!("  message: {}\n", terminal.message));
            }
            for field in &terminal.fields {
                if field.sensitivity != crate::diagnostic::Sensitivity::Secret {
                    out.push_str(&format!("  {}: {}\n", field.key, field.value));
                }
            }
            if let Some(cause) = &terminal.cause {
                out.push_str(&format!("  cause: {cause}\n"));
            }
        } else {
            out.push_str("  code: none recorded\n");
        }
        out.push_str(&format!(
            "  retry: {:?}, fidelity: {:?}, dropped events: {}, dropped diagnostics: {}\n",
            self.retry, self.fidelity, self.dropped_events, self.dropped_diagnostics
        ));
        for check in &self.next_checks {
            out.push_str(&format!("  next: {check}\n"));
        }
        out
    }
}

impl fmt::Display for Diagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render_text())
    }
}

/// Diagnose one attempt from its recorded envelope, log and diagnostics.
pub fn diagnose(
    meta: &TraceMeta,
    fidelity: Fidelity,
    log: &EventLog,
    diagnostics: &DiagnosticTable,
) -> Diagnosis {
    let mut last_phase = DiagnosticPhase::Dispatch;
    let mut last_error: Option<(DiagnosticCode, u32)> = None;
    let mut completed = false;

    for event in log.iter() {
        last_phase = phase_of(event.kind).unwrap_or(last_phase);
        match event.kind {
            EventKind::Error => {
                last_error = Some((DiagnosticCode::from_raw(event.a), event.b));
            }
            EventKind::Validated | EventKind::ResponseEnd | EventKind::H3Finished => {
                completed = true;
            }
            _ => {}
        }
    }

    let terminal = last_error
        .map(|(code, sequence)| {
            diagnostics
                .get(sequence)
                .cloned()
                .unwrap_or_else(|| DiagnosticRecord::new(code).with_message(code.symbol()))
        })
        // A disabled timeline has no `Error` event, but its diagnostic table is
        // still the record of the failure. Evidence is not a function of the
        // observation tier.
        .or_else(|| diagnostics.last_error().cloned());

    let outcome = if terminal.is_some() {
        Outcome::Failed
    } else if completed {
        Outcome::Succeeded
    } else {
        Outcome::Incomplete
    };

    let retry = terminal
        .as_ref()
        .map_or(RetryVerdict::Conditional, |record| record.retry);

    // When the record ends at the origin event itself, the diagnostic's phase
    // is the only phase fact available. A transport event always wins when one
    // exists, because it is evidence rather than classification.
    let last_phase = if matches!(
        last_phase,
        DiagnosticPhase::Dispatch | DiagnosticPhase::Unknown
    ) {
        terminal.as_ref().map_or(last_phase, |record| record.phase)
    } else {
        last_phase
    };

    let next_checks = next_checks(terminal.as_ref().map(|record| record.code), last_phase);

    Diagnosis {
        trace_id: meta.id.to_string(),
        outcome,
        terminal,
        last_phase,
        retry,
        event_count: log.len(),
        dropped_events: log.dropped(),
        dropped_diagnostics: diagnostics.dropped(),
        fidelity,
        next_checks,
    }
}

fn phase_of(kind: EventKind) -> Option<DiagnosticPhase> {
    // A diagnostic does not name the phase it happened in; the last transport
    // event before it does. Reporting `Unknown` here would erase that fact.
    if kind == EventKind::Error || kind == EventKind::Note {
        return None;
    }
    Some(match kind {
        EventKind::Dispatch | EventKind::Retry => DiagnosticPhase::Dispatch,
        EventKind::DnsStart | EventKind::DnsEnd => DiagnosticPhase::Dns,
        EventKind::TcpStart | EventKind::TcpEnd => DiagnosticPhase::Tcp,
        EventKind::TlsStart | EventKind::TlsEnd | EventKind::TlsInfo => DiagnosticPhase::Tls,
        EventKind::ProxyTunnel => DiagnosticPhase::Proxy,
        EventKind::ConnectReused | EventKind::ConnectStaleDiscarded => DiagnosticPhase::Pool,
        EventKind::RequestWriteStart | EventKind::RequestWriteEnd => DiagnosticPhase::Request,
        EventKind::HeadComplete
        | EventKind::BodyStart
        | EventKind::ChunkBoundary
        | EventKind::Trailers
        | EventKind::BodyEnd
        | EventKind::Read
        | EventKind::Write
        | EventKind::Segment
        | EventKind::ProtocolFrame
        | EventKind::OutputToken
        | EventKind::Validated
        | EventKind::TcpInfo
        | EventKind::Redirect
        | EventKind::UdpOpen
        | EventKind::UdpDatagram => DiagnosticPhase::Response,
        EventKind::WsFrame => DiagnosticPhase::WebSocket,
        EventKind::QuicStart | EventKind::QuicEnd | EventKind::QuicStreamOpen => {
            DiagnosticPhase::Quic
        }
        EventKind::H3StreamStart | EventKind::H3HeadComplete | EventKind::H3Finished => {
            DiagnosticPhase::Http3
        }
        EventKind::IngressDispatch => DiagnosticPhase::Listener,
        EventKind::IngressTlsEnd => DiagnosticPhase::Tls,
        EventKind::RequestHeadComplete
        | EventKind::RequestBodyStart
        | EventKind::RequestBodyEnd => DiagnosticPhase::Request,
        EventKind::HandlerStart | EventKind::HandlerEnd => DiagnosticPhase::Server,
        EventKind::ResponseHeadSent | EventKind::ResponseChunkSent | EventKind::ResponseEnd => {
            DiagnosticPhase::Response
        }
        EventKind::TimeJump | EventKind::DiagnosticDropped => DiagnosticPhase::Trace,
        EventKind::Error | EventKind::Note => DiagnosticPhase::Unknown,
    })
}

fn next_checks(code: Option<DiagnosticCode>, phase: DiagnosticPhase) -> Vec<String> {
    let mut checks = Vec::new();
    match phase {
        DiagnosticPhase::Dns => {
            checks.push("check the resolver, the resolved addresses and egress confinement".into())
        }
        DiagnosticPhase::Tcp => {
            checks.push("check the route, socket options and the configured connect bound".into())
        }
        DiagnosticPhase::Tls => {
            checks.push("check the TLS profile, SNI, trust store and TLS alert".into())
        }
        DiagnosticPhase::Proxy => {
            checks.push("check the proxy scheme, CONNECT/SOCKS5 reply and auth outcome".into())
        }
        DiagnosticPhase::Pool => {
            checks.push("check pool age, identity and the stale-socket discard event".into())
        }
        DiagnosticPhase::Http1 => checks
            .push("check the HTTP/1 grammar rule, declared framing and configured limit".into()),
        DiagnosticPhase::Http2 => {
            checks.push("check SETTINGS, GOAWAY, RST_STREAM and the stream id".into())
        }
        DiagnosticPhase::Quic => {
            checks.push("check the QUIC handshake, transport close code and path MTU".into())
        }
        DiagnosticPhase::Http3 => {
            checks.push("check the H3 control stream, QPACK state and SETTINGS".into())
        }
        DiagnosticPhase::WebSocket => {
            checks.push("check the upgrade response, subprotocol and close code".into())
        }
        DiagnosticPhase::Server => {
            checks.push("check the handler outcome, panic record and configured timeout".into())
        }
        DiagnosticPhase::Listener => {
            checks.push("check listener admission, shed and accept events".into())
        }
        DiagnosticPhase::Drain => {
            checks.push("check the drain deadline and in-flight connection count".into())
        }
        DiagnosticPhase::Sink => checks.push("check sink lag and drop counters".into()),
        DiagnosticPhase::Trace => checks.push("check ring and diagnostic-table drop counts".into()),
        DiagnosticPhase::Dispatch
        | DiagnosticPhase::Request
        | DiagnosticPhase::Response
        | DiagnosticPhase::Unknown => {
            checks.push("inspect the last successful phase and the terminal diagnostic".into())
        }
    }
    if let Some(code) = code {
        checks.push(format!(
            "look up {} in docs/reference/diagnostics.md",
            code.symbol()
        ));
        if code.level() == DiagnosticLevel::Error {
            checks
                .push("attach the trace bundle to the failure report before changing code".into());
        }
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::DiagnosticCode;
    use crate::trace::{Direction, TraceId};

    fn meta() -> TraceMeta {
        TraceMeta::new(
            TraceId::new("01924f4e-0000-7000-8000-000000000001"),
            Direction::Egress,
        )
    }

    #[test]
    fn a_terminal_error_is_reported_with_its_detail() {
        let mut log = EventLog::with_capacity(16);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        let mut diagnostics = DiagnosticTable::default();
        let sequence = diagnostics.push(
            DiagnosticRecord::new(DiagnosticCode::EGRESS_TLS_FAILED)
                .with_message("certificate verify failed")
                .with_field("authority", "api.example.invalid:443"),
        );
        log.push_at(
            5_000_000,
            EventKind::Error,
            DiagnosticCode::EGRESS_TLS_FAILED.raw(),
            sequence,
        );

        let diagnosis = diagnose(&meta(), Fidelity::l1(), &log, &diagnostics);
        assert_eq!(diagnosis.outcome, Outcome::Failed);
        assert_eq!(
            diagnosis.terminal.as_ref().map(|record| record.code),
            Some(DiagnosticCode::EGRESS_TLS_FAILED)
        );
        assert_eq!(diagnosis.last_phase, DiagnosticPhase::Tls);
        assert!(
            diagnosis
                .render_text()
                .contains("certificate verify failed")
        );
    }

    #[test]
    fn a_trace_without_a_terminal_error_is_incomplete_not_failed() {
        let mut log = EventLog::with_capacity(8);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        let diagnosis = diagnose(&meta(), Fidelity::l0(), &log, &DiagnosticTable::default());
        assert_eq!(diagnosis.outcome, Outcome::Incomplete);
        assert!(diagnosis.terminal.is_none());
    }

    #[test]
    fn a_completed_attempt_is_successful() {
        let mut log = EventLog::with_capacity(8);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        log.push_at(1, EventKind::Validated, 0, 0);
        let diagnosis = diagnose(&meta(), Fidelity::l1(), &log, &DiagnosticTable::default());
        assert_eq!(diagnosis.outcome, Outcome::Succeeded);
    }
}
