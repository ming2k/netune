//! The offline tool must read exactly what the bundle writer produced.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use netune_diagnostics::{RedactionPolicy, TraceBundle};
use netune_trace::{
    DiagnosticCode, DiagnosticRecord, DiagnosticTable, EventKind, EventLog, Fidelity, TraceMeta,
    TraceSnapshot,
};

fn snapshot(id: &str, terminal: Option<DiagnosticCode>) -> TraceSnapshot {
    let mut log = EventLog::with_capacity(8);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    let mut diagnostics = DiagnosticTable::default();
    if let Some(code) = terminal {
        let sequence = diagnostics.push(DiagnosticRecord::new(code).with_message("fixture"));
        log.push_at(5, EventKind::Error, code.raw(), sequence);
    } else {
        log.push_at(5, EventKind::Validated, 0, 0);
    }
    TraceSnapshot::new(
        TraceMeta::new(
            netune_trace::TraceId::new(id),
            netune_trace::Direction::Egress,
        ),
        Fidelity::l0(),
        log,
        diagnostics,
    )
}

fn temp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "netune-cli-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ))
}

#[test]
fn inspect_prints_the_bundle_diagnosis() {
    let snapshot = snapshot(
        "01924f4e-0000-7000-8000-000000000010",
        Some(DiagnosticCode::EGRESS_TLS_FAILED),
    );
    let diagnosis = snapshot.diagnose();
    let directory = temp_dir("inspect");
    let bundle = TraceBundle::write(
        &directory,
        &snapshot,
        &diagnosis,
        None,
        RedactionPolicy::default(),
    )
    .expect("bundle");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_netune-diagnose"))
        .arg("inspect")
        .arg(&bundle.directory)
        .output()
        .expect("run netune-diagnose");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NET-E-TLS-FAILED"), "{stdout}");
    std::fs::remove_dir_all(bundle.directory).ok();
}

#[test]
fn diff_reports_the_terminal_code_change() {
    let left = snapshot(
        "01924f4e-0000-7000-8000-000000000011",
        Some(DiagnosticCode::EGRESS_TLS_FAILED),
    );
    let right = snapshot(
        "01924f4e-0000-7000-8000-000000000012",
        Some(DiagnosticCode::EGRESS_QUIC_FAILED),
    );
    let left_directory = temp_dir("diff-left");
    let right_directory = temp_dir("diff-right");
    let left_bundle = TraceBundle::write(
        &left_directory,
        &left,
        &left.diagnose(),
        None,
        RedactionPolicy::default(),
    )
    .expect("left bundle");
    let right_bundle = TraceBundle::write(
        &right_directory,
        &right,
        &right.diagnose(),
        None,
        RedactionPolicy::default(),
    )
    .expect("right bundle");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_netune-diagnose"))
        .arg("diff")
        .arg(&left_bundle.directory)
        .arg(&right_bundle.directory)
        .output()
        .expect("run netune-diagnose");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NET-E-TLS-FAILED"), "{stdout}");
    assert!(stdout.contains("NET-E-QUIC-FAILED"), "{stdout}");
    std::fs::remove_dir_all(left_bundle.directory).ok();
    std::fs::remove_dir_all(right_bundle.directory).ok();
}
