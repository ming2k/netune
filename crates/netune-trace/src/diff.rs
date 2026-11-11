//! Pure diff between two recorded attempts.
//!
//! A diff is for regression review, not for grading one request against
//! another: it reports where the records diverge and how the outcome changed,
//! and it never invents a timing that one side did not measure.

use crate::diagnose::{Diagnosis, Outcome};
use crate::event::{Event, EventKind};
use crate::trace::TraceSnapshot;

/// One side of a divergence, with only the fields that are stable across runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EventView {
    pub at_ns: u64,
    pub stream: u32,
    pub kind: EventKind,
}

impl From<Event> for EventView {
    fn from(event: Event) -> Self {
        Self {
            at_ns: event.at_ns,
            stream: event.stream,
            kind: event.kind,
        }
    }
}

/// The first event where two logs disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Divergence {
    pub index: usize,
    pub left: Option<EventView>,
    pub right: Option<EventView>,
}

/// What changed between two attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceDiff {
    pub left_id: String,
    pub right_id: String,
    pub left_outcome: Outcome,
    pub right_outcome: Outcome,
    pub left_terminal: Option<String>,
    pub right_terminal: Option<String>,
    pub left_events: usize,
    pub right_events: usize,
    pub left_dropped_events: u32,
    pub right_dropped_events: u32,
    pub left_diagnostics: usize,
    pub right_diagnostics: usize,
    pub left_dropped_diagnostics: u32,
    pub right_dropped_diagnostics: u32,
    pub first_divergence: Option<Divergence>,
}

impl TraceDiff {
    /// Render a reviewable text diff.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "trace diff {} -> {}\n",
            self.left_id, self.right_id
        ));
        out.push_str(&format!(
            "  outcome: {:?} -> {:?}\n  terminal: {:?} -> {:?}\n",
            self.left_outcome, self.right_outcome, self.left_terminal, self.right_terminal
        ));
        out.push_str(&format!(
            "  events: {} -> {} (dropped {} -> {})\n",
            self.left_events,
            self.right_events,
            self.left_dropped_events,
            self.right_dropped_events
        ));
        out.push_str(&format!(
            "  diagnostics: {} -> {} (dropped {} -> {})\n",
            self.left_diagnostics,
            self.right_diagnostics,
            self.left_dropped_diagnostics,
            self.right_dropped_diagnostics
        ));
        match &self.first_divergence {
            Some(divergence) => out.push_str(&format!(
                "  first divergence at event {}: {:?} -> {:?}\n",
                divergence.index, divergence.left, divergence.right
            )),
            None => out.push_str("  first divergence: none (event kinds and streams match)\n"),
        }
        out
    }
}

impl std::fmt::Display for TraceDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render_text())
    }
}

/// Diff two snapshots without reading a clock or performing I/O.
pub fn diff(left: &TraceSnapshot, right: &TraceSnapshot) -> TraceDiff {
    let left_diagnosis = left.diagnose();
    let right_diagnosis = right.diagnose();
    let left_events: Vec<EventView> = left.log.iter().map(EventView::from).collect();
    let right_events: Vec<EventView> = right.log.iter().map(EventView::from).collect();
    let first_divergence = (0..left_events.len().max(right_events.len())).find_map(|index| {
        let left_event = left_events.get(index).copied();
        let right_event = right_events.get(index).copied();
        let same = match (left_event, right_event) {
            (Some(left_event), Some(right_event)) => {
                left_event.kind == right_event.kind && left_event.stream == right_event.stream
            }
            (None, None) => true,
            _ => false,
        };
        (!same).then_some(Divergence {
            index,
            left: left_event,
            right: right_event,
        })
    });

    TraceDiff {
        left_id: left.meta.id.to_string(),
        right_id: right.meta.id.to_string(),
        left_outcome: left_diagnosis.outcome,
        right_outcome: right_diagnosis.outcome,
        left_terminal: terminal_symbol(&left_diagnosis),
        right_terminal: terminal_symbol(&right_diagnosis),
        left_events: left.log.len(),
        right_events: right.log.len(),
        left_dropped_events: left.log.dropped(),
        right_dropped_events: right.log.dropped(),
        left_diagnostics: left.diagnostics.len(),
        right_diagnostics: right.diagnostics.len(),
        left_dropped_diagnostics: left.diagnostics.dropped(),
        right_dropped_diagnostics: right.diagnostics.dropped(),
        first_divergence,
    }
}

fn terminal_symbol(diagnosis: &Diagnosis) -> Option<String> {
    diagnosis
        .terminal
        .as_ref()
        .map(|record| record.code.symbol().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{DiagnosticCode, DiagnosticRecord, DiagnosticTable};
    use crate::event::EventKind;
    use crate::trace::{Fidelity, TraceId, TraceMeta};

    fn snapshot(id: &str, log: crate::EventLog) -> TraceSnapshot {
        TraceSnapshot::new(
            TraceMeta::new(TraceId::new(id), crate::Direction::Egress),
            Fidelity::l0(),
            log,
            DiagnosticTable::default(),
        )
    }

    #[test]
    fn a_kind_change_is_the_first_divergence() {
        let mut left = crate::EventLog::with_capacity(8);
        left.push_at(0, EventKind::Dispatch, 0, 0);
        left.push_at(1, EventKind::TcpStart, 0, 0);
        let mut right = crate::EventLog::with_capacity(8);
        right.push_at(0, EventKind::Dispatch, 0, 0);
        right.push_at(1, EventKind::TlsStart, 0, 0);

        let diff = diff(&snapshot("left", left), &snapshot("right", right));
        assert_eq!(diff.first_divergence.expect("divergence").index, 1);
        assert_eq!(diff.left_terminal, None);
    }

    #[test]
    fn a_different_terminal_code_is_reported() {
        let mut log = crate::EventLog::with_capacity(8);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        let mut diagnostics = DiagnosticTable::default();
        let sequence = diagnostics
            .push(DiagnosticRecord::new(DiagnosticCode::EGRESS_TLS_FAILED).with_message("left"));
        log.push_at(
            1,
            EventKind::Error,
            DiagnosticCode::EGRESS_TLS_FAILED.raw(),
            sequence,
        );
        let left = TraceSnapshot::new(
            TraceMeta::new(TraceId::new("left"), crate::Direction::Egress),
            Fidelity::l0(),
            log.clone(),
            diagnostics,
        );
        let mut right_log = crate::EventLog::with_capacity(8);
        right_log.push_at(0, EventKind::Dispatch, 0, 0);
        right_log.push_at(
            1,
            EventKind::Error,
            DiagnosticCode::EGRESS_QUIC_FAILED.raw(),
            0,
        );
        let right = snapshot("right", right_log);
        let diff = diff(&left, &right);
        assert_eq!(diff.left_terminal.as_deref(), Some("NET-E-TLS-FAILED"));
        assert_eq!(diff.right_terminal.as_deref(), Some("NET-E-QUIC-FAILED"));
        assert_eq!(diff.left_outcome, Outcome::Failed);
        assert_eq!(diff.right_outcome, Outcome::Failed);
    }
}
