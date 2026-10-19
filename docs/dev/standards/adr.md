# Architectural Decision Records (ADR) Standards

This document establishes the qualification criteria, lifecycle, frontmatter schema, and template for Architectural Decision Records in `netune`.

---

## 1. Qualification (The 3-Question Test)

To keep the log high-signal, author an ADR only if a proposal meets **at least two** criteria:

1. **High reversal cost** — undoing it would require multi-week refactoring or a breaking migration.
2. **Cross-boundary blast radius** — it changes crate boundaries, public APIs, wire behaviour, data layouts, or a security/latency guarantee.
3. **Generates binding red-lines** — it establishes structural constraints that later work must obey.

### Anti-patterns to reject

- **Triviality smear** — ADRs for routine choices (a serializer, a function rename, a log level).
- **Ephemeral workaround** — recording a temporary bug fix or environment hack.
- **Toothless declaration** — vague prose with no enforceable boundary.
- **Post-hoc justification** — writing an ADR after the code landed with no genuine consideration of alternatives.

---

## 2. In-Place Lifecycle

ADRs evolve in place through frontmatter. Files are never moved to an `archive/` directory; moving them breaks history and every inbound link.

```text
       [ draft ] ───► [ accepted ] ───► [ superseded ]
           │
           └───► [ rejected ]
```

- **draft** — proposal under deliberation.
- **accepted** — ratified and binding on the repository.
- **superseded** — replaced by a later ADR; `superseded_by` is mandatory.
- **rejected** — a discarded alternative kept for its failure mode.

### Frontmatter schema

```yaml
---
id: ADR-NNNN
title: "[Title of the decision]"
status: accepted # draft | accepted | superseded | rejected
date: YYYY-MM-DD
scope: [transport/pool, security/egress] # subsystem tags, shown in the registry index
superseded_by: null # ADR-NNNN when status is superseded
---
```

`id`, `title`, `status`, `date` and `scope` are mandatory. `scope` uses `area/subsystem` tags so the registry stays searchable without opening every file.

### Registry index

`docs/adr/index.md` is the single table of record:

```markdown
| ID | Title | Status | Scope | Decision Summary & Primary Invariant | Date |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [0001](0001-owned-transport-trace-model.md) | Owned Transport Substrate | accepted | transport/owned-stack, trace/model | Zero third-party HTTP runtime; timings are pure functions of recorded events | 2026-09-08 |
```

Every ADR must appear in the index in the same change that adds or amends it.

---

## 3. Authoritative Template

```markdown
---
id: ADR-NNNN
title: "[Title of the decision]"
status: draft
date: YYYY-MM-DD
scope: [area/subsystem]
superseded_by: null
---

# NNNN. [Title of the decision]

- Status: Draft | Accepted | Superseded by [ADR-NNNN](NNNN-slug.md) | Rejected
- Date: YYYY-MM-DD
- Deciders: [Names / GitHub handles]
- Amends: [Optional links to amended ADRs]

---

## Context and Problem Statement

What problem exists, and why must it be decided now?

## Decision Drivers

- Driver 1: e.g. replay safety under a pooled keep-alive socket
- Driver 2: e.g. no third-party HTTP implementation in the production graph

## Considered Options

- Option 1: ...
- Option 2: ...

## Decision Outcome

Chosen option: "Option N", because ...

### Invariants & Behavioral Boundaries

- `[INV-FAMILY-NN]` Name: the constraint and the mechanism that enforces it.

### Consequences

- **Positive**: ...
- **Negative & Trade-offs**: ...

## Rejected Alternatives & Negative Knowledge

### Option N (Rejected)

- **Why considered**: ...
- **Why rejected**: the specific failure mode, not a preference.

## Links

- Related ADRs: [ADR-NNNN](NNNN-slug.md)
```

---

## 4. Writing Rules

1. **Negative knowledge is mandatory.** Every ADR states why the discarded options fail. An ADR without it will be sent back.
2. **Invariants name their enforcement.** `[INV-WS-01]` is backed by a test or a boundary, not by emphasis.
3. **No ghost references.** Cite only ADRs that exist in `docs/adr/`.
4. **One decision per record.** If a change contains two independently reversible decisions, write two ADRs.
