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
| `docs/how-to/` | Task recipes for a competent user. | Configure a proxy, select a TLS profile, inject faults, use the WebSocket client. |
| `docs/reference/` | Factual description of what exists. | Crate responsibilities, architecture reference. |
| `docs/explanation/` | Why the system is shaped this way. | Structural privilege boundaries. |

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
3. **Root documents are neither**: `README.md`, `CONTRIBUTING.md` and `AGENTS.md` are entry points and may point to either surface.

---

## 3. Repository Root Whitelist

To keep the root readable, only these Markdown files may live there:

- `README.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `AGENTS.md`
- `LICENSE` / `LICENSE.md`
- `SECURITY.md`

Everything else belongs under `docs/`.

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
| A rule contributors must obey | `docs/dev/standards/` |
| What went wrong and why it was not caught | `docs/dev/postmortems/` |

---

## 5. Knowledge Lifecycle

- **Living documents** (`README`, tutorials, how-to, reference, explanation) are updated in the same change as the code they describe.
- **Decision records** never move; they transition status in place (see [`adr.md`](adr.md)).
- **Postmortems** are permanent once written; corrections are appended, not rewritten.
- **Superseded designs** stay readable for forensics but are not implementation guidance.
