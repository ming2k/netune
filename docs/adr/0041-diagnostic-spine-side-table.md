---
id: ADR-0041
title: "Failure Narration Is a Diagnostic Side Table on the Trace"
status: accepted
date: 2026-11-11
scope: [trace/model, trace/diagnostics, transport/egress, transport/ingress, process/postmortems]
superseded_by: null
---

# 0041. Failure Narration Is a Diagnostic Side Table on the Trace

- Status: Accepted
- Date: 2026-11-11
- Deciders: Ming Li
- Amends: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0010](0010-quic-ownership-and-trace-sink.md), [ADR-0017](0017-tiered-observation-and-connection-identity.md), [ADR-0018](0018-one-trace-collector-per-attempt.md)

---

## Context and Problem Statement

The trace model answers *when* with unusual precision, but it answers *why* almost nowhere. A terminal
failure is recorded as `EventKind::Error` with two `u32` payload words. On the egress path those words
are literally `(0, 0)`; on ingress they are one of ten numeric constants declared inside
`netune-server`'s HTTP/1 module. A trace therefore cannot distinguish a DNS failure from a TLS alert
from a body decode failure, and it cannot carry the phase, the configured bound, the observed limit,
the peer, the retry verdict, or the cause chain.

Worse, the record is discarded at the moment it matters. `Client::send` creates the recorder
internally and returns `Result<Response, NetError>`; on `Err`, the recorder is dropped. The normal API
can describe a successful attempt but not a failed one.

The project already rejected a logging facade for good reasons (ADR-0010): a second record would
drift from the trace, and a logging dependency would leak into leaves. The missing capability is not
"logging". It is **failure narration attached to the same record**.

## Decision Drivers

- `[INV-TRACE-01]` must remain true: every timing is a pure derivation of the recorded events.
- The hot byte path must stay allocation-free; diagnostic strings belong on the cold path only.
- A failed attempt must return evidence, including when observation is `Off`.
- Error codes must be stable, greppable, documented, and impossible to invent at a call site.
- The same model must serve egress and ingress without either orchestrator depending on the other.
- Post-bug review must consume a real artifact, not a narrative reconstructed from memory.

## Decision

### 1. Diagnostics are a bounded side table on the trace

`Event` stays 24 bytes. Strings do not enter it. `RequestTrace` and `IngressTrace` gain a
`DiagnosticTable`.

- `EventKind::Error` carries `a = DiagnosticCode` and `b = diagnostic sequence`.
- `EventKind::Note` carries a non-terminal diagnostic with the same two-word shape.
- The sequence is a producer sequence, never a ring index, so ring eviction cannot re-key a record.
- The table is bounded and counts its own drops. Overflow emits `EventKind::DiagnosticDropped`.
- `TRACE_SCHEMA_VERSION` becomes `2`. This is a clean break: v1 traces are not claimed to be
  interpretable as v2.

`DiagnosticRecord` contains only cold-path data: code, level, phase, retry verdict, a bounded
message, bounded fields, and an optional cause/backtrace reference.

### 2. One stable code registry

`DiagnosticCode(u32)` lives in `netune-trace`, with stable ranges per subsystem. Each code names its
symbol (`NET-E-TLS-HANDSHAKE-TIMEOUT`), phase, level, retry verdict, documentation anchor, and
operator next checks. The numeric value is the persisted contract; a code is never renumbered or
reused. `0` is reserved for `Unclassified` and is forbidden for new producers.

The `ERROR_*` constants in `netune-server` and the ad hoc `class()` strings are replaced by registry
entries. A test asserts uniqueness, stability, and documentation coverage.

### 3. Diagnostics are independent of observation tier

`Observation` selects byte-path measurement cost. It does not select whether a failure can be
explained.

- `Observation::Off` records no byte timeline.
- It still records a terminal `DiagnosticRecord`, because that path only runs on failure.
- The default policy is "capture on failure, no file I/O". A successful request pays nothing.

This separation is the core reason `Off` no longer means "undebuggable".

### 4. A failed attempt returns its evidence

The public egress boundary returns an error type carrying the original error plus a `TraceSnapshot`
(meta, diagnostics, and the event log when one exists). `request_traced` finalizes the recorder on
both success and failure. A failure without a registered diagnostic is a test failure.

Internal helpers may still return the narrow error vocabulary; the orchestrator attaches evidence
once, at the boundary where the attempt is owned.

### 5. Diagnosis is a pure derivation

`diagnose(meta, fidelity, log, diagnostics) -> Diagnosis` reads no clock and performs no I/O. It
reports the terminal diagnostic, the last successful phase, the phase timeline, retry verdict,
fidelity caveats, drop counts, and code-specific next checks.

`Diagnosis` can be rendered as text or serialized. It is golden-tested like `derive`.

### 6. Review artifacts are first-class

A `TraceBundle` contains a manifest, the trace envelope with its diagnostic table, the diagnosis,
and optional operator notes. Redaction is part of serialization: no body bytes, no header values, no
credentials, bounded strings, explicit sensitivity classes. Capture policy is explicit
(`Off`/`OnFailure`/`Always`/`Sampled`).

A postmortem is closed only when its action items name a test, gate, or invariant that verifies the
fix. The documents gate and the release checklist enforce that closure.

## Invariants & Behavioral Boundaries

- **`[INV-DIAG-01]` No Unclassified Terminal Failure**: every terminal failure emitted by a public
  attempt carries exactly one registered `DiagnosticCode` with a phase and retry verdict. No
  production path may emit `EventKind::Error` with code `0`. *Enforced by*: a workspace test that
  scans recorded traces and a gate that rejects literal `Error(0, 0)` call sites.

- **`[INV-DIAG-02]` Evidence Survives Failure**: a failed public attempt exposes a `TraceSnapshot`
  with its diagnostics, even when `Observation::Off` was selected. *Enforced by*: a `FaultIo`/mock
  egress test that fails with `Off` and asserts a non-empty diagnostic table.

- **`[INV-DIAG-05]` Bounded, Redacted Diagnosis**: diagnostic strings and fields are cold-path,
  bounded, and carry a sensitivity class. No credentials, bodies, or unbounded peer strings are
  recorded by default. *Enforced by*: the bundle redaction test and the registry's field schema.

- **`[INV-DIAG-06]` Review Closure Is Mechanical**: every Sev 1/Sev 2 postmortem action item names a
  verifiable test, gate, or invariant, and an open postmortem with unverified items blocks release.
  *Enforced by*: the postmortem gate and the release checklist.

## Consequences

- **Positive**:
  - A failed request can be explained from the same record that measures it.
  - Error codes become a stable API instead of per-module constants.
  - The hot path stays fixed-size; only failures allocate.
  - Postmortems cite a bundle and a code, not a recollection.
- **Negative & Trade-offs**:
  - Schema v2 is a breaking change; v1 traces are not silently reinterpreted.
  - Diagnostic capture adds a small cold-path allocation on failure.
  - A code registry is a maintenance surface; it is deliberately small and reviewed like an enum.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Add a `String` to `Event`

It would make every event allocation-bearing, break the 24-byte size assertion, and put unbounded
peer-controlled text on the hot path. ADR-0017 already decided that strings travel in a side table.

### Option 2 (Rejected): Adopt `tracing` or `log`

ADR-0010's reasoning still holds. A logging facade would create a second record, add a dependency to
leaves, and make the event vocabulary a function of the facade's data model. The native sink contract
is the replacement.

### Option 3 (Rejected): Keep `Error(0,0)` and reconstruct from the error string

The string is not recorded, is not stable, is not bounded, and is not available when the trace is
read offline. A review cannot join a postmortem to a string that was never persisted.

### Option 4 (Rejected): Make the sink the source of truth

A sink is fire-and-forget and may drop. The ring and the diagnostic table remain the record of truth;
the sink is a view.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0010](0010-quic-ownership-and-trace-sink.md),
  [ADR-0017](0017-tiered-observation-and-connection-identity.md),
  [ADR-0018](0018-one-trace-collector-per-attempt.md),
  [ADR-0042](0042-trace-identity-and-sink-context.md)
