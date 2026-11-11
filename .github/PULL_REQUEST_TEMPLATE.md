## What changed

<!-- One concern per PR. Explain why, not only what. -->

## Failure record (required for any bug fix)

- Symptom:
- Terminal diagnostic code (`NET-E-...` / `NET-W-...`):
- Trace id or review bundle:
- Detection gap (which test or gate should have caught it):
- Regression test name (`diag_<code>_<symptom>`):
- Postmortem (required for Sev 1/Sev 2):

## Verification

- [ ] `cargo check --all-targets --all-features`
- [ ] `cargo nextest run` (and the `inject` suite when relevant)
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo fmt --check`
- [ ] `python3 .github/scripts/check-docs.py`
- [ ] `python3 .github/scripts/check-architecture.py`

## Documentation

- [ ] Public API, diagnostic code, or failure behaviour is documented in the same commit.
- [ ] A new or changed invariant is ratified in an ADR and indexed in `docs/dev/invariants.md`.
- [ ] A new runbook or postmortem is listed in its index.
