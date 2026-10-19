# netune Engineering Standards

This directory defines the authoritative engineering, architectural, and documentation standards for the `netune` project.

Standards live flat in `docs/dev/standards/`. Each file addresses one active engineering concern; there are no nested `core/` or `profiles/` trees.

---

## Standards Directory Structure

| Document | Purpose & Authority |
| :--- | :--- |
| [`architecture.md`](architecture.md) | **Workspace topology & system boundaries**: crate layering, dependency direction, and structural red-lines. |
| [`invariants.md`](invariants.md) | **Invariant standard & admissibility**: what qualifies as a system invariant, how it is enforced, and how it retires. |
| [`adr.md`](adr.md) | **Architectural Decision Records**: the 3-question qualification test, in-place lifecycle, frontmatter schema, and template. |
| [`rfc.md`](rfc.md) | **Request for Comments**: deliberation protocol for cross-cutting changes before an ADR is ratified. |
| [`taxonomy.md`](taxonomy.md) | **Documentation taxonomy**: four-quadrant layout, public/internal firewall, and repository-root whitelist. |
| [`style.md`](style.md) | **Documentation & markdown style**: hyperlink routing, formatting, and tone. |
| [`workflow.md`](workflow.md) | **Engineering workflow**: verification gates, code-to-doc synchronization, and release hygiene. |
| [`postmortems.md`](postmortems.md) | **Blameless incident postmortems**: timeline reconstruction and systemic defense analysis. |

For execution-level procedures, see:

- [`docs/dev/setup.md`](../setup.md) — toolchain, build, and local environment.
- [`docs/dev/testing.md`](../testing.md) — test tiers, determinism rules, and commands.
- [`docs/dev/release-and-versioning.md`](../release-and-versioning.md) — versioning, tagging, and distribution.

---

## Core Philosophy

1. **Mechanisms over exhortations.** A boundary is real only when something enforces it: a crate dependency rule, a private field, a feature gate, or a deterministic test. Prose alone is not enforcement.
2. **A sharp line between invariants and notes.** A system invariant is a cross-boundary red-line with an enforcement mechanism. Everything else is a domain contract, a design constant, or a code comment, and does not carry an `INV-*` tag.
3. **Flat and pragmatic.** One directory, one file per concern. Nesting must earn its keep.
4. **Self-contained lineage.** Every decision resolves to an in-repo ADR (`docs/adr/0001`+). References to decision numbers that do not exist in this repository are prohibited.
