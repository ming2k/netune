# First Response: A Failed Attempt

## Target Subsystem & Reference Environment

- `netune` egress or `netune-server` ingress.
- A captured `AttemptError` or `IngressTrace`, or a `TraceBundle` produced by `netune-diagnostics`.
- The build version and workspace tag the record names in `TraceMeta`.

## Core Protocol Rules & Invariants

- A failure is classified by a stable `DiagnosticCode`, not by its `Display` string (`[INV-DIAG-01]`).
- Evidence survives `Observation::Off`; an empty event log is not an empty diagnosis (`[INV-DIAG-02]`).
- A missing phase is a `Reading` verdict, never a fabricated zero (`[INV-TRACE-01]`).
- The record is bounded. Check `dropped_events`, `dropped_diagnostics`, and `fidelity` before trusting a gap.

## Diagnostic Playbook

1. Read `diagnosis.txt` or call `AttemptError::diagnosis()`.
2. Start with `terminal.code`; look it up in `docs/reference/diagnostics.md`.
3. Check `last_phase` and the event immediately before the terminal diagnostic.
4. If the code is retryable, verify the caller actually retried and that the retry did not duplicate a side effect (`[INV-TRANSPORT-01]`).
5. If the record is L0 or dropped events, say so in the report; do not infer a syscall timeline that was never recorded.
6. Reproduce with `FaultIo` where possible; attach the bundle to the issue.
7. If the failure reveals a systemic gap, open a postmortem and name the detection layer that should have caught it.

## Do-Not-Regress Checklist

- [ ] The terminal diagnostic is registered and documented.
- [ ] The reproduction is a test named `diag_<code>_<symptom>`.
- [ ] The bundle redacts secret fields.
- [ ] The postmortem action item names a test, gate, or invariant.
