# Engineering Workflow & Verification Gates

This document defines what must pass before a change lands, and which
documents move with it. Every gate below is a command that runs in CI; none of
them is a convention that relies on a reviewer remembering it.

---

## 1. Verification Gates

Run these before every commit. They are the same commands CI runs.

```text
┌────────────────────────────────────────────────────────────────────┐
│ 1. Compilation   cargo check --all-targets --all-features          │
│                  cargo check --all-targets --no-default-features   │
├────────────────────────────────────────────────────────────────────┤
│ 2. Tests         cargo nextest run                                 │
│                  cargo nextest run -p netune-probe --features inject│
├────────────────────────────────────────────────────────────────────┤
│ 3. Lints         cargo clippy --all-targets --all-features \       │
│                      -- -D warnings                                │
│                  cargo fmt --check                                 │
├────────────────────────────────────────────────────────────────────┤
│ 4. Documentation cargo doc --no-deps --all-features                │
│                  (RUSTDOCFLAGS="-D warnings")                      │
│                  python3 .github/scripts/check-docs.py             │
│                  cargo test --doc --workspace --all-features       │
├────────────────────────────────────────────────────────────────────┤
│ 5. Architecture  python3 .github/scripts/check-architecture.py     │
│ 6. Supply chain  cargo deny check advisories licenses sources bans │
└────────────────────────────────────────────────────────────────────┘
```

CI sets `RUSTFLAGS="-D warnings"`, so a local warning is a build failure on
`main`. The `--no-default-features` check is not decorative: it is the build
that proves the codecs are genuinely optional, and the `inject` suite is run
separately so both privilege postures are proven rather than assumed.

### Architecture gate

`check-architecture.py` reads the manifests and the source, and fails on:

| Rule | Rejects |
| :--- | :--- |
| `ARCH-001` | A dependency edge the topology table does not allow, or a crate missing from it. |
| `ARCH-002` | `netune` and `netune-server` depending on each other. |
| `ARCH-003` | A leaf crate depending on an orchestrator. |
| `ARCH-004` | `netune-probe` depending on any workspace crate. |
| `ARCH-005` | A WebSocket, HTTP/2 or QUIC runtime in a production graph. |
| `ARCH-006` | A third-party HTTP client in a production graph. |
| `ARCH-007` | A crate that does not inherit `[workspace.package] version`. |
| `ARCH-008` | A transmit path that compiles without `--features inject`. |
| `ARCH-009` | A workspace `path` dependency with no `version`, or the wrong one. |

The allowed edges live in one table inside that script, because the real graph
is not a flat ring: `netune-io` depends on `netune-trace`, since `TimedIo`
writes into a `Recorder` and there is no version of that type which does not. A
rule reading "leaves never depend on each other" would be false, and a false
rule teaches people to ignore the checker.

Two things are deliberately *not* enforced mechanically: "no history surgery"
and "terminating commands" are properties of how a command is run, not of the
repository's contents. The agent directive file states them as review-only
rather than implying a mechanism that does not exist.

---

## 2. Code-to-Doc Synchronization

A change that alters a visible surface updates its documentation in the **same
commit**. "Update the docs later" is how the dead links this file's gate exists
to catch got there in the first place.

| Changed surface | Documentation to update |
| :--- | :--- |
| Public API, type, or error variant in `netune` | `docs/reference/` or the relevant `docs/how-to/` |
| Crate responsibility, dependency direction, or version line | `docs/reference/crates.md`, `docs/reference/architecture.md` |
| Wire behaviour, pool semantics, TLS profiles, WS contract | The owning ADR; a new ADR when the decision changes |
| Testing approach, feature matrix, or CI commands | `docs/dev/testing.md` |
| Build, bootstrap, or toolchain | `docs/dev/setup.md` |
| Versioning, tagging, or distribution | `docs/dev/release-and-versioning.md` |
| A rule reviewers must enforce | `docs/dev/standards/` |
| An incident with a systemic gap | `docs/dev/postmortems/` |

If a change makes a documented statement false and you cannot fix it in the
same commit, the correct action is to stop and split the change — not to leave
the document wrong.

### Deleting a document

Deleting a page is a code change with a compile step. Before the deletion
lands, every inbound link must be re-pointed or removed, or the gate is red.
A deletion that leaves dangling links is not a smaller change; it is an
unfinished one.

---

## 3. Pre-Release Checklist

Before a version bump or tag:

1. `cargo check --all-targets --all-features` — zero warnings.
2. `cargo nextest run` and the `inject` suite — all pass.
3. `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --check`.
4. `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS="-D warnings"`.
5. `python3 .github/scripts/check-docs.py` — clean.
6. `CHANGELOG.md` has an entry for the exact version; the release workflow
   reads it.
7. Version tables in `docs/reference/crates.md` match
   `[workspace.package] version`, and every consumer snippet in `README.md`
   shows the current tag (`DOC-014` enforces both).
8. Working tree is clean; no scratch files or experiments are staged.

Tagging and distribution are defined in
[release-and-versioning.md](release-and-versioning.md).

---

## 4. Commit Discipline

- One concern per commit; a refactor and a behaviour change are separate.
- Commit messages use a `type(scope): summary` subject and explain *why* in the
  body when the change is not self-evident.
- A change that alters a documented fact names the document it updated.
- Never rewrite published history or a pushed tag. Fix forward.

---

## 5. Documentation Integrity Gate

`.github/scripts/check-docs.py` enforces the rules stated in
[taxonomy.md](standards/taxonomy.md), [style.md](standards/style.md), and [adr.md](standards/adr.md). The
standards are indexed in [standards/README.md](standards/README.md).

Two properties make it a gate rather than a suggestion:

1. **It fails.** `DOC-003` is the reason a shortcut bracket like `[INV-WS-01]`
   is *not* a broken link: CommonMark treats an undefined shortcut reference as
   literal text. The gate encodes that, so it reports real defects instead of
   noise nobody reads.
2. **It is tested.** `test-check-docs.py` holds a failing fixture for every
   rule and a passing fixture for every legitimate near-miss. Weakening a rule
   to make a build green breaks the self-test.

When a new documentation rule is worth stating, it is worth a rule ID, a check,
and a fixture. A rule that has none of the three belongs in prose and should
say so.
