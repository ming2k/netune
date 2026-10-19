# Invariant & Constraint Governance

This document codifies the definition, categorization, and lifecycle of invariants in `netune`. It exists to keep `INV-*` tags rare, load-bearing, and verifiable.

---

## 1. Core Principle: Mechanisms Over Exhortations

An invariant is a condition that must hold in every valid state of the system. A rule that is only asserted in prose is not an invariant — it is a comment.

> **If a rule has neither a compiler-level proof nor an automated test, it is not an invariant.**

---

## 2. Constraint Admissibility Matrix

| Category | Definition & scope | Identifier policy | Enforcement mechanism |
| :--- | :--- | :--- | :--- |
| **System invariant** | Non-negotiable structural red-line with cross-boundary blast radius: dependency firewalls, privilege boundaries, replay safety, protocol direction. | Ratified in an ADR as `[INV-FAMILY-NN]`. | 1. Crate/feature boundaries<br>2. Dedicated integration test (`tests/*_integration.rs`)<br>3. Type-level constraints |
| **Domain contract** | State-machine behaviour inside one crate: decoder phases, stream states, close handshakes. | No global `INV-` tag. Expressed as named types and `enum` variants. | Private fields, typestates, unit tests |
| **Design constant** | Sizes, timeouts, buffer limits, preset values, default heads. | No `INV-` tag. A named `const`. | The constant itself; a test where it is load-bearing |
| **Implementation note** | Localized edge-case guard or workaround. | No `INV-` tag. Ordinary code comment. | Direct regression test |

---

## 3. The 3-Condition Gate

A rule may be elevated to a system invariant only if **all three** hold:

1. **High blast radius** — a violation corrupts data, inverts an architectural boundary, leaks privilege, or makes retries unsafe.
2. **Durable** — it survives ordinary feature work; it is not a snapshot of current defaults.
3. **Mechanically enforced** — it names the test, feature gate, or type that fails when the rule is broken.

---

## 4. Current Invariant Families

| Family | Scope | Ratified in |
| :--- | :--- | :--- |
| `[INV-TRACE-01..02]` | Timings are pure derivations of recorded events; no synthetic measurement bias. | ADR-0001 |
| `[INV-TRANSPORT-00..04]` | Replay safety: a pooled socket that drops before any response-head byte is replaced; after that point it is never retried. Idle bound, distinct `Incomplete`. | ADR-0001 (`00`), ADR-0005 (`01..04`) |
| `[INV-EGRESS-01..03]` | Confinement is checked before connect; private, loopback, link-local and metadata ranges are refused. | ADR-0002 |
| `[INV-TLS-01..03]` | TLS identity is explicit data (`TlsProfile`); presets keep a stable wire identity across dependency updates. | ADR-0004 |
| `[INV-CUSTOM-01..03]` | Wire determinism: configured-or-documented socket/DNS/segmentation behaviour; no lowercasing of raw headers. | ADR-0006 |
| `[INV-WS-01..08]` | Client-role exclusivity, masking direction, bounded reassembly, frame-level observability, no pooling, proven liveness, incremental UTF-8, differential parity. | ADR-0007 |
| `[INV-HTTP2-01]` | HTTP/2 framing and HPACK live in `netune-http2`, never behind a feature flag of `netune-http1`. | ADR-0003 |
| `[INV-PROBE-01..02]` | Zero transmission in default builds; transmission requires `CAP_NET_RAW`. | ADR-0003 |

The authoritative wording of each invariant lives in its ADR. This table is an index, not a second source of truth; if the two disagree, the ADR wins and this table is corrected.

---

## 5. Retirement Policy

1. **True invariants** retire in place through an ADR: set `status: superseded` and `superseded_by: ADR-NNNN`, and keep the original wording and failure mode for forensic use.
2. **Pseudo-invariants** (styling, layout, local state, convenience defaults) are not renamed or tombstoned. They are deleted from annotations and, where useful, replaced by a named constant or a test name that says what is actually guaranteed.
3. **Never renumber an invariant.** A retired family's numbers are not reused for a different rule; that would silently change what existing references mean.
