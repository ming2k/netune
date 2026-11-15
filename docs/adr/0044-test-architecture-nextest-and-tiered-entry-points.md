---
id: ADR-0044
title: "Test Architecture: Nextest Owns Execution, Shared Fixtures, and Tier Entry Points"
status: accepted
date: 2026-11-15
scope: [workspace/topology, testing/runner, testing/infrastructure, ci/verification]
superseded_by: null
---

# 0044. Test Architecture: Nextest Owns Execution, Shared Fixtures, and Tier Entry Points

- Status: Accepted
- Date: 2026-11-15
- Deciders: Ming Li
- Amends: [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md)

---

## Context and Problem Statement

The suite grew one test executable per external file, duplicated the same
scripted I/O, loopback and self-signed-TLS fixtures across crates, and left the
runner split between `cargo test` in prose and `cargo nextest` in CI. The
workspace also had no package that could own a root `tests/` directory: Cargo
does not compile tests for a virtual workspace.

Those are not cosmetic problems. Each external file linked its own binary, so
adding a scenario paid a link cost and a reviewer had to know which crate's
`tests/` happened to own a fixture. A helper copied into two crates drifted at
the next protocol revision. A runner named differently in a document and in CI
is a gate nobody can reproduce locally.

## Decision Drivers

- **One runner.** Discovery, filtering, retries, timeouts and ignored tests
  belong to one tool, configured once, not to a repository wrapper.
- **One compilation unit per external tier.** An external test is a module in
  the integration binary or the end-to-end binary, not a new executable.
- **Shared fixtures are test-only by construction.** A fixture crate must be
  impossible to link into a shipping graph, and a production dependency on it
  must be an architecture violation rather than a review request.
- **Unit tests follow the code.** Small and medium modules keep inline
  `#[cfg(test)]` modules; a module moves its tests out only when the tests — not
  the business logic — are what made the file large.
- **Doctests remain executable.** They are a real gate and `nextest` does not
  run them.

## Considered Options

- **Option 1: Keep `cargo test` and document both runners.** Rejected: the
  local command and the CI command already disagreed, which is how a gate
  becomes optional.
- **Option 2: Add an `xtask test` wrapper.** Rejected: it reimplements
  discovery, filtering and retry policy that `nextest` already owns, and becomes
  a second, weaker runner that hides the real command from contributors.
- **Option 3: Keep every external file as its own test target.** Rejected: it
  multiplies link steps and leaves shared fixtures inside one crate's private
  test directory.
- **Option 4: `nextest` plus one test-only crate and one root test package,
  with one integration and one end-to-end entry point.** Chosen.

## Decision Outcome

Chosen option: "Option 4".

### 1. Nextest is the runner; doctests are the exception

`cargo nextest run --workspace` is the suite. `.config/nextest.toml` owns the
policy: no retries, no fail-fast, a bounded slow-test timeout and a separate
`soak` profile. `cargo test --doc --workspace --all-features` remains because
`nextest` cannot execute doctests; no other `cargo test` command is a gate. An
`xtask test` wrapper is forbidden: test execution is not a build-script
responsibility.

### 2. Shared fixtures live in a dev-only leaf

`crates/test-support` owns scripted byte transports, loopback pairs,
HTTP/1.1 wire constants and generated self-signed TLS identities. It declares
`publish = false`, depends on no workspace crate, and is referenced only under
`[dev-dependencies]`. Its topology entry has an empty allowed edge set, so any
production dependency on it is `ARCH-001`.

### 3. The root is a test-only package

`workspace-tests` exists because a virtual workspace cannot own a
`tests/` directory. It has no library and no binary, only `dev-dependencies`,
and exactly two test targets:

```text
tests/integration/main.rs   one binary for all integration modules
tests/e2e/main.rs           one binary for all end-to-end modules
tests/common/               fixtures included by both entry points
```

`ARCH-012` enforces that shape. Adding a scenario is adding a module under
`tests/integration/` or `tests/e2e/`, not adding a target.

### 4. Unit-test placement is a rule, not a preference

A module keeps its tests inline by default. It moves them to
`src/<module>/tests.rs` (or `src/<module>/tests/` when there are distinct
sub-suites) only when the test code is at least 150 lines **and** at least 30%
of the file. A large state machine with a small test module keeps it inline:
the size is the behaviour it implements, not test bloat.

### Invariants & Behavioral Boundaries

- **`[INV-TEST-01]`** Nextest is the only test runner for executable tests.
  Doctests are the one deliberate `cargo test` command. Enforced by
  `.config/nextest.toml`, CI and the absence of an `xtask` crate.
- **`[INV-TEST-02]`** Test infrastructure is dev-only. `test-support`
  depends on no workspace crate and no production manifest names it. Enforced
  by `ARCH-001`.
- **`[INV-TEST-03]`** The root harness is test-only and has exactly the
  `integration` and `e2e` entry points. Enforced by `ARCH-012`.
- **`[INV-TEST-04]`** External tests compile one binary per tier; a new
  scenario is a module, not a new test target. Enforced by the two explicit
  `[[test]]` targets and `autotests = false` in the root manifest.

### Consequences

- **Positive**: one command reproduces CI, adding an external case does not
  add a linker invocation, and fixtures cannot silently enter a shipping build.
- **Positive**: a moved unit-test module keeps `use super::*`, so no production
  symbol becomes public for testing.
- **Negative & Trade-offs**: `cargo nextest run` without `--workspace` selects
  only the root package, because the workspace root is now a package. Every
  gate passes `--workspace` explicitly; the documentation says so.
- **Negative & Trade-offs**: the root package is a Cargo package with no
  library, which is unusual but is exactly what makes a root `tests/` directory
  legal without adding a product crate.

## Rejected Alternatives & Negative Knowledge

### An `xtask` Test Wrapper (Rejected)

- **Why considered**: one stable command could hide feature combinations.
- **Why rejected**: it duplicates nextest's discovery, filter expressions,
  ignored-test handling and timeouts. A wrapper that drifts from the runner is
  worse than the runner itself, and it violates the separation between build
  automation and test execution.

### Keeping Fixtures in Each Crate's `tests/support` (Rejected)

- **Why considered**: no new crate and no dependency edge.
- **Why rejected**: `netune-http1` and the server suite already carried two
  scripted-I/O implementations and nine QUIC/H3 suites carried the same
  `AcceptAnyCert`. Copies drift; a shared dev-only crate makes the duplication
  a compile error instead of a review catch.

### Moving Every Test `mod` Out of `src/` (Rejected)

- **Why considered**: uniform layout is easier to describe.
- **Why rejected**: most modules are 20–100 lines of tests beside the code they
  exercise. Moving them adds navigation cost and no compilation benefit. The
  150-line / 30% threshold is the enforceable boundary.
