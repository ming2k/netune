---
id: PM-NNNN
severity: 2
status: open
detected_by: user-report
affected_versions: []
invariants: []
adrs: []
trace_ids: []
---

# PM-NNNN: <incident title>

## Executive Summary

What broke, which protocol or endpoint was affected, for how long, and whether replay safety, data integrity, or credentials were involved.

## Timeline of Events (UTC)

- `T0` — introduction (commit, dependency bump, release).
- `T_impact` — first manifestation.
- `T_detect` — detection by test, alert, trace bundle, or user report.
- `T_mitigate` — mitigation or rollback.
- `T_resolve` — permanent fix verified.

## Evidence

- Trace bundle(s): `<trace-id>` / link.
- Terminal diagnostic code(s): `NET-E-...`.
- Fidelity and drop counts: state whether the record is complete.
- Reproduction: command or `FaultIo` scenario.

## Detection Gaps

Why did the unit, differential, integration, chaos, fuzz, or release layer miss this? Name the layer that should have caught it.

## Trigger & Underlying Root Cause

The state-machine, framing, timeout, boundary, or policy failure. Do not name a person or “human error” as the cause.

## Action Items & Defense-in-Depth

Each item names an owner and a verifiable completion criterion.

| ID | Action | Owner | Verification |
| :--- | :--- | :--- | :--- |
| PM-NNNN-A1 | Add the regression test | — | `test: diag_...` |
| PM-NNNN-A2 | Tighten the invariant | — | `invariant: INV-...` or `gate: ...` |

## Do-Not-Regress Checklist

- [ ] The reproducing test fails before the fix and passes after it.
- [ ] The terminal diagnostic code is registered and documented.
- [ ] The trace bundle is attached or linked.
- [ ] Any durable boundary change is ratified in an ADR and indexed in `docs/dev/invariants.md`.
