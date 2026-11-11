# Incident Postmortem Standards

This document establishes the blameless postmortem standard, timeline
reconstruction methodology, and systemic defense analysis for incidents in
`netune`.

In network transport systems, incidents include process crashes, silent data
corruption, connection pool desynchronization, replay of non-idempotent
requests, stream framing deadlocks, or privilege boundary leaks. The structure
below applies to all of them.

---

## 1. Blameless Culture & Intent

Incidents are opportunities to identify systemic fragility, missing automation,
and verification gaps.

- **Strictly Blameless**: Postmortems must NEVER assign personal blame or
  attribute root causes to "human error" or "developer negligence".
- **Focus on Systemic Safeguards**: The central question is always: *Why did the
  type system, state machine, verification ladder, or architecture permit an
  unsafe state to manifest?*

---

## 2. Postmortem Structure

Every postmortem recorded under `docs/dev/postmortems/` must follow this structure:

1. **Executive Summary**: High-level impact (affected protocol or endpoint,
   duration, whether request replay safety, data integrity, or credentials were
   compromised).
2. **Timeline of Events (UTC)**:
   - $T_0$: Introduction of the defect (commit, dependency bump, feature release).
   - $T_{\text{impact}}$: First manifestation in a session, test, or deployment.
   - $T_{\text{detect}}$: Detection by an automated test, error alert, or user report.
   - $T_{\text{mitigate}}$: Mitigation or rollback applied.
   - $T_{\text{resolve}}$: Permanent fix verified.
3. **Evidence**: The `TraceId`, terminal `DiagnosticCode`, trace bundle (or a
   link to it), fidelity level, and ring/diagnostic drop counts. If the evidence
   is incomplete, say which part is missing rather than reconstructing it.
4. **Detection Gaps**: Why did unit tests, differential oracle parity, `FaultIo`
   chaos injection, loopback e2e, or CI fail to detect this before release? Name the
   verification layer that should have caught it (see [Testing Standards](../testing.md)).
5. **Trigger & Underlying Root Cause**: Detailed technical analysis of the
   state-machine failure, framing desynchronization, missing timeout, or boundary leak.
6. **Action Items & Defense-in-Depth**:
   - Preventative actions (add a type-level invariant, tighten an egress policy).
   - Detection actions (add a specific regression test, expand a differential test suite).
   - Each action item must name a verifiable completion criterion: a test name,
     a documentation/architecture gate, or an invariant tag.

### Frontmatter

Every postmortem carries the schema in
[`TEMPLATE.md`](../postmortems/TEMPLATE.md): `id`, `severity`, `status`,
`detected_by`, `affected_versions`, `invariants`, `adrs`, and `trace_ids`.
`status` is `open` or `closed`. A `closed` record must have at least one action
item whose verification references a test, gate, or invariant. The docs gate
enforces the structure; the release checklist enforces closure.

---

## 3. Severity Guidance

| Severity | Examples | Response |
| :--- | :--- | :--- |
| **Sev 1** | Privilege boundary breach, data corruption across pooled sockets, credential leakage | Postmortem mandatory; hotfix before next release |
| **Sev 2** | Silent framing desynchronization, non-idempotent request replay, connection leak | Postmortem mandatory; regression test required |
| **Sev 3** | Contained protocol error with clear workaround, minor telemetry drift | Postmortem optional; regression test still required |

A Sev 1 or Sev 2 incident without a postmortem blocks the next release.

---

## 4. Relationship to ADRs

If the fix establishes a durable boundary or modifies an existing architectural
contract, it must be ratified as an ADR and registered in
[`docs/dev/invariants.md`](../invariants.md). The postmortem cites the governing
ADR; the ADR remains the single source of truth for the invariant's normative
definition.
