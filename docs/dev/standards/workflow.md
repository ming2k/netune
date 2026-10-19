# Engineering Workflow & Verification Gates

This document defines what must pass before a change lands, and which documentation must move with it.

---

## 1. Verification Gates

Every change clears all four gates. They are cheap enough to run before every commit:

```text
┌──────────────────────────────────────────────────────────────┐
│ 1. Compilation:  cargo check --all-targets --all-features    │
├──────────────────────────────────────────────────────────────┤
│ 2. Tests:        cargo nextest run                           │
│                  cargo nextest run -p netune-probe \         │
│                      --features inject                       │
├──────────────────────────────────────────────────────────────┤
│ 3. Lints:        cargo clippy --all-targets --all-features \ │
│                      -- -D warnings                          │
│                  cargo fmt --check                           │
├──────────────────────────────────────────────────────────────┤
│ 4. Documentation: cargo doc --no-deps --all-features         │
│                  (RUSTDOCFLAGS="-D warnings")                │
└──────────────────────────────────────────────────────────────┘
```

CI runs the same commands with `RUSTFLAGS="-D warnings"`, so a local warning is a build failure on `main`.

**Architecture gate.** Beyond the toolchain: no leaf crate may depend on a sibling, `netune-probe` may not depend on the stack, and no third-party HTTP/WebSocket runtime may enter the production graph. These are checked in review against [`architecture.md`](architecture.md).

---

## 2. Code-to-Doc Synchronization

A change that alters a visible surface updates its documentation in the **same commit**:

| Changed surface | Documentation to update |
| :--- | :--- |
| Public API, type, or error variant in `netune` | `docs/reference/` or the relevant `docs/how-to/` |
| Crate responsibility, dependency direction, or version line | `docs/reference/crates.md`, `docs/reference/architecture.md` |
| Wire behaviour, pool semantics, TLS profiles, WS contract | The owning ADR; a new ADR when the decision changes |
| Testing approach, feature matrix, or CI commands | `docs/dev/testing.md` |
| Build/bootstrap/toolchain | `docs/dev/setup.md` |
| Versioning, tagging, or distribution | `docs/dev/release-and-versioning.md` |
| A rule reviewers must enforce | `docs/dev/standards/` |
| An incident with a systemic gap | `docs/dev/postmortems/` |

If a change makes a documented statement false and you cannot fix it in the same commit, the correct action is to stop and split the change — not to leave the document wrong.

---

## 3. Pre-Release Checklist

Before a version bump or tag:

1. `cargo check --all-targets --all-features` — zero warnings.
2. `cargo nextest run` and the `inject` suite — all pass.
3. `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --check`.
4. `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS="-D warnings"`.
5. `CHANGELOG.md` has an entry for the exact version; the release workflow reads it.
6. Version tables in `README.md` and `docs/reference/crates.md` match `[workspace.package] version`.
7. Working tree is clean; no scratch files or experiments are staged.

Tagging and distribution are defined in [`release-and-versioning.md`](../release-and-versioning.md).

---

## 4. Commit Discipline

- One concern per commit; a refactor and a behaviour change are separate commits.
- Commit messages use a `type(scope): summary` subject and explain *why* in the body when the change is not self-evident.
- Never rewrite published history or a pushed tag. Fix forward.
