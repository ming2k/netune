# Incident Postmortem Standards

This document defines how `netune` records incidents, so that the systemic gap is fixed rather than the person blamed.

---

## 1. Blameless by Construction

- **No personal attribution.** The root cause is never "human error" or "carelessness". It is a missing mechanism.
- **Ask the systemic question.** *Why did the compiler, test suite, or architecture permit this state to be reached and shipped?*
- **Assume good faith.** The author of the defect had the same information everyone else had at the time; the postmortem explains why that information was insufficient.

---

## 2. Required Structure

Postmortems live in `docs/dev/postmortems/YYYY-MM-DD-slug.md` and contain:

1. **Executive summary** — impact, duration, and whether data or credentials were affected.
2. **Timeline (UTC)** — introduction of the defect, first manifestation, detection, mitigation, permanent fix.
3. **Detection gaps** — which test, check, or review would have caught it, and why it did not run or did not exist.
4. **Root cause** — the concrete mechanism (state machine, boundary leak, missing limit), not a narrative of who did what.
5. **Action items** — each with an owner and a verifiable completion criterion:
   - preventative (a type, a boundary, a lint),
   - detection (a named regression test),
   - documentation (the document that was wrong, if any).

---

## 3. Severity Guidance

| Severity | Examples | Response |
| :--- | :--- | :--- |
| **Sev 1** | Privilege boundary breach, wrong peer data returned, credential leak | Postmortem mandatory; fix before the next release |
| **Sev 2** | Silent protocol error, replay of a non-idempotent request, pool corruption | Postmortem mandatory; regression test required |
| **Sev 3** | Contained bug with a clear workaround | Postmortem optional; test still required |

A Sev 1 or Sev 2 incident without a postmortem blocks the next release.

---

## 4. Relationship to ADRs

If the fix establishes a durable boundary, it is ratified as an ADR and the invariant is registered in that ADR. The postmortem links the ADR; the ADR does not depend on the postmortem for its wording.
