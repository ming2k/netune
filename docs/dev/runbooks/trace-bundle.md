# Trace Bundle Playbook

## Target Subsystem & Reference Environment

- `netune-diagnostics` with the `json` feature.
- A `TraceSnapshot` from `AttemptError::trace()` or an `IngressTrace`.
- A writable directory chosen by the operator; the transport never writes files by default.

## Core Protocol Rules & Invariants

- The ring and diagnostic table are the record of truth; a sink or bundle is a view (`[INV-TRACE-03]`).
- Bundle serialization removes `Secret` fields and can remove `Internal` fields (`[INV-DIAG-05]`).
- A bundle carries a manifest with the trace id, build, direction, and redaction policy.

## Diagnostic Playbook

1. Capture on failure at the call site:

   ```rust,no_run
   use netune_diagnostics::{RedactionPolicy, TraceBundle};

   # fn capture(error: &netune::AttemptError) -> std::io::Result<()> {
   let bundle = TraceBundle::write(
       "/tmp/netune-review",
       error.trace(),
       &error.diagnosis(),
       Some("reproducer notes"),
       RedactionPolicy::default(),
   )?;
   println!("{}", bundle.directory.display());
   # Ok(())
   # }
   ```

2. Read `manifest.json` first: trace id, build, direction, redaction policy.
3. Read `diagnosis.txt` for the phase and terminal code.
4. Read `trace.json` only when the diagnosis points at an event sequence; `Event` is fixed-size and has no payload strings.
5. Attach the directory to the issue or postmortem. The default policy is production-safe (`Public` fields/text only); `RedactionPolicy::internal()` keeps internal context for a local investigation. `Secret` fields/text are removed under both policies. If a secret was needed for diagnosis, capture it separately under the deployment's secret-handling policy; do not weaken the default redaction.
6. For a regression comparison, run:

   ```bash
   netune-diagnose inspect /tmp/netune-review
   netune-diagnose diff /tmp/netune-baseline /tmp/netune-regression
   ```

   The diff reports outcome, terminal code, event/diagnostic drop counts, and the first event where the logs diverge.

## Do-Not-Regress Checklist

- [ ] `manifest.json`, `trace.json`, `diagnosis.json`, and `diagnosis.txt` exist.
- [ ] No `Secret` field appears in the bundle.
- [ ] The trace id in the manifest matches the diagnosis.
- [ ] The bundle is attached to the failure record.
