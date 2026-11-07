# Documentation Taxonomy & Layout

This document defines how documentation is organized in `netune`, which audiences each surface serves, and what may live at the repository root.

---

## 1. The Four-Quadrant System (Diátaxis)

User-facing documentation in `docs/` follows the Diátaxis split:

```text
               PRACTICAL                   THEORETICAL
          ┌─────────────────────────┬─────────────────────────┐
          │  Tutorials              │  How-To Guides          │
LEARNING  │  (Learning-Oriented)    │  (Task-Oriented)        │
          │  `docs/tutorials/`      │  `docs/how-to/`         │
          ├─────────────────────────┼─────────────────────────┤
          │  Reference              │  Explanation            │
WORKING   │  (Information-Oriented) │  (Understanding)        │
          │  `docs/reference/`      │  `docs/explanation/`    │
          └─────────────────────────┴─────────────────────────┘
```

| Surface | Purpose | Examples |
| :--- | :--- | :--- |
| `docs/tutorials/` | Guided first success, in order. | Getting started: build, send a request, read a trace. |
| `docs/how-to/` | Task recipes for a competent user. | Configure a proxy, select a TLS profile, inject faults, use the WebSocket client, serve HTTP. |
| `docs/reference/` | Factual description of what exists. | Crate responsibilities, architecture reference. |
| `docs/explanation/` | Why the system is shaped this way. | Structural privilege boundaries, two orchestrators model. |

Each quadrant has an `index.md` that lists its contents. Adding a document means adding it to its index in the same change.

---

## 2. Scope Boundary (Public vs. Internal)

```text
┌─────────────────────────────────────────────────────────────┐
│ Public surface (users, integrators)                         │
│ docs/tutorials/  docs/how-to/  docs/reference/  docs/explanation/ │
└──────────────────────────────┬──────────────────────────────┘
                               │ public docs must never link down
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Internal surface (maintainers, contributors, agents)        │
│ docs/dev/ (setup, testing, standards, release, postmortems) │
│ docs/adr/ (binding decisions)                               │
└─────────────────────────────────────────────────────────────┘
```

1. **Firewall**: a document in `docs/{tutorials,how-to,reference,explanation}/` must never contain a relative link into `docs/dev/**` or `docs/adr/**` … with one exception: a public document may link to a specific ADR when the decision is genuinely part of the public explanation. Links into `docs/dev/**` are never permitted.
2. **Reverse links are free**: internal documents may link outward to public guides.
3. **Root documents are neither**: `README.md` and `CONTRIBUTING.md` are entry points and may point to either surface.

The firewall is enforced mechanically by `DOC-001`–`DOC-004` in `.github/scripts/check-docs.py`; a rule stated only in this document is a comment.

---

## 3. Repository Root Whitelist

To keep the root readable, only these Markdown files may be documentation and
live there:

- `README.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `LICENSE` / `LICENSE.md`
- `SECURITY.md`

Documentation that belongs to none of these lives under `docs/`. Enforced by
`DOC-006`.

### Files this system does not govern

A repository root also holds files that tooling consumes and the operator
maintains: agent directive files, editor configuration, CI entry points. They
are **not documentation**, and this taxonomy has no authority over them. It
does not whitelist them, index them, link-check their contents, or prescribe
their structure — and no document under `docs/` may cite them (`DOC-005`).

The distinction is one of authority, not importance:

- A tool-owned file may point into `docs/` like any consumer can. The
  repository's link check covers it as ordinary Markdown (`DOC-001`), because a
  dead link is a defect wherever it appears.
- Its *content* is owned by whoever operates the tool that reads it. If a
  maintainer rewrites it, no rule in this directory is violated and no
  documentation change is owed.

The list of such files is maintained in exactly one place — the `TOOL_OWNED_ROOT_FILES`
table in `.github/scripts/check-docs.py` — precisely so that this document never
has to name one. Naming a file here would make this taxonomy the authority over
it, which is the coupling the rule exists to prevent.

---

## 4. Where a New Document Goes

| The document is about… | Put it in… |
| :--- | :--- |
| A first run, end to end | `docs/tutorials/` |
| One task a user wants to complete | `docs/how-to/` |
| A fact: crate, API, type, limit, option | `docs/reference/` |
| A rationale or design boundary | `docs/explanation/` |
| Why a decision was ratified | `docs/adr/` |
| How contributors build, test, or release | `docs/dev/` |
| A meta-standard contributors must obey | `docs/dev/standards/` |
| Operational runbooks and wire diagnostic playbooks | `docs/dev/runbooks/` |
| What went wrong and why it was not caught | `docs/dev/postmortems/` |

---

## 5. Knowledge Lifecycle

| Temperature | Content | Cadence |
| :--- | :--- | :--- |
| **HOT** | Living ground truth: `README.md`, `docs/{tutorials,how-to,reference,explanation}/`, `docs/dev/`. | Updated in the same change as the code it describes. |
| **WARM** | Active decision contracts: `docs/adr/` (draft, accepted). | Created or amended upon architectural review. |
| **COLD** | Historical rationale: superseded and rejected ADRs, post-mortems. | Retained in place; retrieved during forensics and refactoring. |

Superseded and rejected records are never deleted and never moved; their status
is recorded in frontmatter. See [ADR Standards](adr.md) for the in-place
lifecycle.

---

## 6. Experience Crystallization Pipeline

Ad-hoc engineering trial-and-error, wire discoveries, and transport bring-up
lessons must never linger as unorganized notes. Engineering experience must flow
through a four-stage pipeline:

```text
                  Transport Bring-up & Wire Lessons
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼                         ▼
  Stage 1: Code            Stage 2: ADRs             Stage 3: Explanation      Stage 4: Runbooks
(Mechanisms & Tests)    (Architectural Choice)     (Conceptual Understanding)   (Operational Manual)
─────────────────────   ────────────────────────   ──────────────────────────   ────────────────────
• Typestate invariants  • Why path A over B        • System architecture        • Baseline environment
• Regression tests      • Rejected alternatives    • Protocol state machines    • Wire quirks log
• Differential suites   • Irreversible boundaries  • Performance/timing models  • Diagnostic playbook
```

1. **Stage 1 — Mechanisms Over Documentation (Highest Priority)**:
   Any constraint that can be verified by the Rust compiler (typestates, private
   visibility) or caught by automated tests must be committed to code. Do not
   document what a test or type system can enforce.
2. **Stage 2 — Architectural Decisions (`docs/adr/`)**:
   Lessons that reveal trade-offs, dead-ends, or boundary rules belong in the
   governing ADR's context and rejected alternatives.
3. **Stage 3 — System Architecture (`docs/explanation/`)**:
   General protocol dynamics, framing mechanics, and component topologies belong
   in Diátaxis Explanation documents.
4. **Stage 4 — Subsystem Runbooks (`docs/dev/runbooks/`)**:
   Residual operational knowledge that requires manual intervention, raw packet
   inspection, or middlebox troubleshooting belongs in a dedicated runbook
   following [Runbook Standards](runbooks.md).
