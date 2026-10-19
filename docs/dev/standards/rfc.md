# Request for Comments (RFC) Standards

This document defines when and how to author an RFC in `netune`.

---

## 1. When to Author an RFC

An ADR records a decision that has been made. An RFC is the deliberation that happens **before** a decision is made, when at least one of these is true:

- Several competing designs have materially different trade-offs and the cost of choosing wrong is high.
- The change spans multiple crates or alters a wire contract (connection pool semantics, TLS profile selection, codec boundaries).
- Reviewers need a written design before any proof-of-concept code is worth writing.

An RFC that has converged becomes an ADR; the RFC itself is not a source of truth for implementation.

---

## 2. Lifecycle

```text
[ Proposed ] ──► [ Under Review ] ──► [ Approved ] ──► [ Migrated to ADR ]
                       │
                       └──► [ Closed / Withdrawn ]
```

1. **Proposed** — draft circulated for feedback.
2. **Under Review** — active review; open questions are tracked explicitly.
3. **Approved** — consensus reached; implementation may start.
4. **Migrated to ADR** — conclusions are ratified as a record in `docs/adr/`; implementation follows the ADR, not the RFC.
5. **Closed / Withdrawn** — rejected or superseded before implementation.

Unratified RFC designs are speculative and must not be cited as binding patterns.

---

## 3. Required Sections

1. **Motivation and user stories** — what breaks or is impossible today.
2. **Detailed design** — APIs, data structures, state machines, and concurrency semantics.
3. **Failure modes and security** — behaviour under truncation, resets, malformed input, and adversarial peers.
4. **Alternatives considered** — and why each is worse.
5. **Migration and compatibility** — impact on existing users and versioning.
6. **Unresolved questions** — the known unknowns reviewers must answer.

---

## 4. Storage

RFCs live alongside the code they affect until ratified:

- Accepted or in-flight: `docs/rfcs/NNNN-slug.md` (created on first use).
- Ratified: the conclusion moves to `docs/adr/`; the RFC file is kept or removed in the same change that lands the ADR.
