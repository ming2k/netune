//! Native diagnostic sinks and review bundles.
//!
//! `netune-trace` owns the record and deliberately owns no presentation or file
//! I/O. This crate is the optional leaf that turns a trace into a development
//! log line, a JSONL stream, or a reviewable bundle. It never opens a socket and
//! never depends on an orchestrator.
//!
//! The sinks are not a logging facade: they receive the same [`TraceMeta`] and
//! [`Event`] the transport recorded, so a sink cannot invent a second timeline.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use netune_trace::{
    Diagnosis, DiagnosticField, DiagnosticRecord, DiagnosticTable, Event, Flow, Sensitivity,
    TraceMeta, TraceSink, TraceSnapshot, TraceSummary,
};

/// Which diagnostic fields a sink or bundle may render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionPolicy {
    /// Keep `Internal` fields. `Secret` fields are always removed.
    pub include_internal: bool,
    /// Keep `Internal` message and cause text. `Secret` text is always removed.
    pub include_messages: bool,
}

impl Default for RedactionPolicy {
    /// The production-safe default: only `Public` fields and text survive.
    fn default() -> Self {
        Self::public_only()
    }
}

impl RedactionPolicy {
    /// The strict policy: only `Public` fields and text survive.
    pub const fn public_only() -> Self {
        Self {
            include_internal: false,
            include_messages: false,
        }
    }

    /// Full local diagnosis: internal fields and messages survive; secret text
    /// is still removed.
    pub const fn internal() -> Self {
        Self {
            include_internal: true,
            include_messages: true,
        }
    }

    pub(crate) fn allows(self, sensitivity: Sensitivity) -> bool {
        match sensitivity {
            Sensitivity::Public => true,
            Sensitivity::Internal => self.include_internal,
            Sensitivity::Secret => false,
        }
    }

    pub(crate) fn allows_text(self, sensitivity: Sensitivity) -> bool {
        match sensitivity {
            Sensitivity::Public => true,
            Sensitivity::Internal => self.include_messages,
            Sensitivity::Secret => false,
        }
    }
}

/// A sink that writes one JSON object per line.
pub struct JsonLinesSink {
    writer: Mutex<Box<dyn Write + Send>>,
    policy: RedactionPolicy,
}

impl fmt::Debug for JsonLinesSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLinesSink")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl JsonLinesSink {
    pub fn new(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Mutex::new(Box::new(writer)),
            policy: RedactionPolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn stderr() -> Self {
        Self::new(io::stderr())
    }

    fn write_event(&self, meta: &TraceMeta, event: Event) -> Flow {
        #[derive(serde::Serialize)]
        struct Line<'a> {
            trace: &'a TraceMeta,
            event: Event,
        }
        let line = serde_json::to_vec(&Line { trace: meta, event });
        match line {
            Ok(bytes) => {
                let mut writer = self
                    .writer
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if writer.write_all(&bytes).is_ok() && writer.write_all(b"\n").is_ok() {
                    Flow::Continue
                } else {
                    Flow::Drop
                }
            }
            Err(_) => Flow::Drop,
        }
    }
}

impl TraceSink for JsonLinesSink {
    fn event(&self, meta: &TraceMeta, event: Event) -> Flow {
        self.write_event(meta, event)
    }
}

/// A sink that writes a compact human-readable line to stderr.
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrSink;

impl TraceSink for StderrSink {
    fn trace_started(&self, meta: &TraceMeta) {
        eprintln!(
            "{} {:?} started (build {})",
            meta.id, meta.direction, meta.build_version
        );
    }

    fn event(&self, meta: &TraceMeta, event: Event) -> Flow {
        eprintln!(
            "{} {:?} +{}ns {:?} stream={} a={} b={}",
            meta.id, meta.direction, event.at_ns, event.kind, event.stream, event.a, event.b
        );
        Flow::Continue
    }

    fn trace_finished(&self, meta: &TraceMeta, summary: &TraceSummary) {
        eprintln!(
            "{} finished: {} events, {} diagnostics, {} dropped, sink dropped {}",
            meta.id,
            summary.events,
            summary.diagnostics,
            summary.dropped_events + summary.dropped_diagnostics,
            summary.sink_dropped
        );
    }
}

/// A sink that forwards to several sinks.
#[derive(Debug, Default)]
pub struct FanoutSink {
    sinks: Vec<Arc<dyn TraceSink>>,
}

impl FanoutSink {
    pub fn new(sinks: Vec<Arc<dyn TraceSink>>) -> Self {
        Self { sinks }
    }

    pub fn push(mut self, sink: Arc<dyn TraceSink>) -> Self {
        self.sinks.push(sink);
        self
    }
}

impl TraceSink for FanoutSink {
    fn trace_started(&self, meta: &TraceMeta) {
        for sink in &self.sinks {
            sink.trace_started(meta);
        }
    }

    fn event(&self, meta: &TraceMeta, event: Event) -> Flow {
        let mut flow = Flow::Continue;
        for sink in &self.sinks {
            if sink.event(meta, event) == Flow::Drop {
                flow = Flow::Drop;
            }
        }
        flow
    }

    fn trace_finished(&self, meta: &TraceMeta, summary: &TraceSummary) {
        for sink in &self.sinks {
            sink.trace_finished(meta, summary);
        }
    }
}

/// A written review bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceBundle {
    pub directory: std::path::PathBuf,
}

impl TraceBundle {
    /// Write a manifest, the trace, and the diagnosis to `directory`.
    ///
    /// The operation is deliberately explicit: the default transport never
    /// writes a file. A caller chooses `OnFailure` or `Always` at its boundary.
    pub fn write(
        directory: impl Into<std::path::PathBuf>,
        snapshot: &TraceSnapshot,
        diagnosis: &Diagnosis,
        notes: Option<&str>,
        policy: RedactionPolicy,
    ) -> io::Result<Self> {
        let directory = directory.into();
        std::fs::create_dir_all(&directory)?;
        secure_dir(&directory)?;

        let mut trace = snapshot.clone();
        trace.diagnostics = redact_table(&trace.diagnostics, policy);
        let diagnosis = redact_diagnosis(diagnosis, policy);

        #[derive(serde::Serialize)]
        struct Manifest<'a> {
            bundle_schema: u32,
            trace_id: &'a str,
            created_unix_ns: u64,
            build_version: &'a str,
            direction: netune_trace::Direction,
            include_internal_fields: bool,
            files: &'a [&'a str],
        }
        let manifest = Manifest {
            bundle_schema: 1,
            trace_id: snapshot.meta.id.as_str(),
            created_unix_ns: snapshot.meta.started_unix_ns,
            build_version: &snapshot.meta.build_version,
            direction: snapshot.meta.direction,
            include_internal_fields: policy.include_internal,
            files: &["trace.json", "diagnosis.json", "diagnosis.txt"],
        };
        write_json(&directory.join("manifest.json"), &manifest)?;
        write_json(&directory.join("trace.json"), &trace)?;
        write_json(&directory.join("diagnosis.json"), &diagnosis)?;
        let diagnosis_path = directory.join("diagnosis.txt");
        std::fs::write(&diagnosis_path, diagnosis.render_text())?;
        secure_file(&diagnosis_path)?;
        if let Some(notes) = notes {
            let notes_path = directory.join("notes.md");
            std::fs::write(&notes_path, notes)?;
            secure_file(&notes_path)?;
        }

        Ok(Self { directory })
    }

    pub fn manifest_path(&self) -> std::path::PathBuf {
        self.directory.join("manifest.json")
    }
}

fn write_json(path: &std::path::Path, value: &impl serde::Serialize) -> io::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut writer = io::BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    drop(writer);
    secure_file(path)
}

#[cfg(unix)]
fn secure_dir(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn secure_dir(_path: &std::path::Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn secure_file(_path: &std::path::Path) -> io::Result<()> {
    Ok(())
}

fn redact_table(table: &DiagnosticTable, policy: RedactionPolicy) -> DiagnosticTable {
    let mut out = DiagnosticTable::new(table.capacity());
    for record in table.iter() {
        out.push(redact_record(record, policy));
    }
    out
}

fn redact_record(record: &DiagnosticRecord, policy: RedactionPolicy) -> DiagnosticRecord {
    let mut record = record.clone();
    record
        .fields
        .retain(|field| policy.allows(field.sensitivity));
    if !policy.allows_text(record.message_sensitivity) {
        record.message.clear();
    }
    if !policy.allows_text(record.cause_sensitivity) {
        record.cause = None;
    }
    record
}

fn redact_diagnosis(diagnosis: &Diagnosis, policy: RedactionPolicy) -> Diagnosis {
    let mut diagnosis = diagnosis.clone();
    if let Some(terminal) = &diagnosis.terminal {
        let mut terminal = terminal.clone();
        terminal
            .fields
            .retain(|field| policy.allows(field.sensitivity));
        if !policy.allows_text(terminal.message_sensitivity) {
            terminal.message.clear();
        }
        if !policy.allows_text(terminal.cause_sensitivity) {
            terminal.cause = None;
        }
        diagnosis.terminal = Some(terminal);
    }
    diagnosis
}

/// A field that is safe to show, for a caller building its own renderer.
pub fn visible_fields(
    record: &DiagnosticRecord,
    policy: RedactionPolicy,
) -> impl Iterator<Item = &DiagnosticField> {
    record
        .fields
        .iter()
        .filter(move |field| policy.allows(field.sensitivity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netune_trace::{
        DiagnosticCode, DiagnosticRecord, DiagnosticTable, EventKind, Fidelity, TraceMeta,
        TraceSnapshot,
    };

    fn snapshot() -> TraceSnapshot {
        let mut diagnostics = DiagnosticTable::default();
        diagnostics.push(
            DiagnosticRecord::new(DiagnosticCode::EGRESS_TLS_FAILED)
                .with_message("verify failed")
                .with_public_field("authority", "api.example.invalid:443")
                .with_secret_field("authorization", "Bearer secret"),
        );
        let mut log = netune_trace::EventLog::with_capacity(8);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        log.push_at(
            5,
            EventKind::Error,
            DiagnosticCode::EGRESS_TLS_FAILED.raw(),
            1,
        );
        TraceSnapshot::new(TraceMeta::egress(), Fidelity::l1(), log, diagnostics)
    }

    #[test]
    fn a_bundle_redacts_secret_fields() {
        let snapshot = snapshot();
        let diagnosis = snapshot.diagnose();
        let directory = std::env::temp_dir().join(format!(
            "netune-bundle-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let bundle = TraceBundle::write(
            &directory,
            &snapshot,
            &diagnosis,
            Some("reproducer"),
            RedactionPolicy::default(),
        )
        .expect("write bundle");
        let trace = std::fs::read_to_string(bundle.directory.join("trace.json")).expect("trace");
        assert!(trace.contains("api.example.invalid"));
        assert!(!trace.contains("Bearer secret"));
        assert!(!trace.contains("verify failed"));
        assert!(bundle.manifest_path().exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(&bundle.directory)
                .expect("dir metadata")
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(bundle.directory.join("trace.json"))
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
        std::fs::remove_dir_all(bundle.directory).ok();
    }

    #[test]
    fn jsonl_sink_writes_the_envelope_with_every_event() {
        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let sink = JsonLinesSink::new(Shared(Arc::clone(&buffer)));
        let meta = TraceMeta::egress();
        assert_eq!(
            sink.event(
                &meta,
                Event {
                    at_ns: 1,
                    stream: 7,
                    kind: EventKind::Read,
                    a: 10,
                    b: 0,
                }
            ),
            Flow::Continue
        );
        let text = String::from_utf8(buffer.lock().unwrap().clone()).expect("utf8");
        assert!(text.contains(meta.id.as_str()));
        assert!(text.contains("\"stream\":7"));
    }
}
