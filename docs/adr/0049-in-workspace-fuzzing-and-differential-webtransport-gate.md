---
id: ADR-0049
title: "In-Workspace Parser Fuzzing and Pure-Rust WebTransport Differential Gate"
status: accepted
date: 2026-11-15
scope: [workspace/topology, testing/runner, testing/infrastructure, protocol/webtransport, ci/verification]
superseded_by: null
---

# 0049. In-Workspace Parser Fuzzing and Pure-Rust WebTransport Differential Gate

- Status: Accepted
- Date: 2026-11-15
- Deciders: Ming Li
- Amends: [ADR-0037](0037-webtransport-draft17-completion-gate.md),
  [ADR-0038](0038-webtransport-external-interoperability.md),
  [ADR-0044](0044-test-architecture-nextest-and-tiered-entry-points.md)

---

## Context and Problem Statement

[ADR-0044](0044-test-architecture-nextest-and-tiered-entry-points.md) unified test execution under `cargo nextest` and a single Cargo workspace, yet two verification islands remained outside the workspace:

1. **Out-of-workspace `fuzz/` (`cargo-fuzz` + `libfuzzer-sys`)**:
   - Declared an empty `[workspace]` with a second `Cargo.lock` so `libfuzzer-sys` would not pollute the main dependency graph.
   - Required a Nightly compiler and an external `cargo-fuzz` binary, so `cargo check --workspace --all-targets` and `cargo clippy` never compiled the six fuzz targets during ordinary development or pull-request checks.
   - Ran only on a weekly cron schedule rather than gating every pull request with a deterministic pass.
2. **Out-of-workspace `interop/webtransport-go` + `scripts/webtransport-go-interop.sh` + `crates/netune-webtransport/examples/interop_server.rs`**:
   - Introduced a second language toolchain (`go.mod` / `go.sum`) and a Bash runner that polled a log file with `sleep 0.1` to discover the bound UDP port, violating `[INV-TEST-01]` (Nextest is the one runner).
   - Polluted `netune-webtransport` with a pseudo-example (`interop_server.rs`) containing a hardcoded 11-day certificate expiration (`2026-11-20`, a latent CI time-bomb), a fixed `/tmp/netune-webtransport-interop-cert.der` path, and a trailing `tokio::time::sleep(Duration::from_secs(2))`.

## Decision Drivers

- **Single Cargo workspace and lockfile.** Every test, differential oracle and fuzz target must resolve against the root `Cargo.toml` / `Cargo.lock` and compile on the pinned stable toolchain under `cargo check --all-targets`.
- **One runner (`[INV-TEST-01]`).** Both pull-request gates and scheduled soak campaigns must execute through `cargo nextest`, with zero shell-script wrappers or log-polling loops.
- **Zero sleep and zero time-bombs.** Certificates come from `test-support::tls::identity`; session teardown synchronizes on stream/capsule completion rather than wall-clock sleeps.
- **Fast PR feedback plus deep scheduled soak.** Parser fuzzing must run deterministically in milliseconds on every PR and scale to deep mutation campaigns under `--profile soak`.

## Considered Options

- **Option 1: Keep `fuzz/` and `interop/webtransport-go` at the repository root.** Rejected: preserves the second `Cargo.lock`, Nightly-only compilation blind spot, Go toolchain requirement, shell polling wrapper and `interop_server` example.
- **Option 2: Keep the Go peer inside `tests/e2e/` and invoke `Command::new("go")` from Rust.** Rejected: removes the shell script but still requires a Go toolchain and network module fetch in a pure-Rust workspace when the wire invariants (`[INV-QUIC-25]`, `[INV-H3-15]`, `[INV-WT-07]`) can be tested directly at the raw HTTP/3 and QUIC framing boundary in Rust.
- **Option 3: Move parser fuzzing into each crate's `tests/fuzz.rs` backed by `test-support::fuzz`, and replace the Go harness with an in-process wire-role differential suite in `crates/netune-webtransport/tests/differential.rs`.** Chosen.

## Decision Outcome

Chosen option: "Option 3".

### 1. In-workspace deterministic and soak parser fuzzing

`crates/test-support/src/fuzz.rs` provides a zero-dependency, deterministic byte-stream fuzzing engine (`run_fuzz` and `run_fuzz_soak`) combining explicit protocol seeds, exhaustive prefix/suffix truncations, boundary-value injection and stacked libFuzzer-style mutations (bit flips, boundary overwrites, arithmetic deltas, slice deletion/duplication, token insertion and cross-seed splicing).

Every wire-facing parser crate owns a first-class `tests/fuzz.rs` target:

- `crates/netune-http1/tests/fuzz.rs`
- `crates/netune-http2/tests/fuzz.rs`
- `crates/netune-http3/tests/fuzz.rs`
- `crates/netune-quic/tests/fuzz.rs`
- `crates/netune-webtransport/tests/fuzz.rs`

Each file defines:

1. A standard `#[test]` that runs on every `cargo nextest run --workspace` (4,096 mutations plus all seed truncations).
2. An `#[ignore]` soak test (`soak_fuzz_*`) that runs 131,072 mutations under `cargo nextest run --workspace --all-features --run-ignored ignored-only --profile soak`.

### 2. Pure-Rust WebTransport wire-role differential suite

`crates/netune-webtransport/tests/differential.rs` replaces `interop/webtransport-go`, `scripts/webtransport-go-interop.sh` and `crates/netune-webtransport/examples/interop_server.rs`. It drives an independent raw-H3 wire peer in both directions:

- **Wire client against `WebTransportServer`**: connects while omitting the server-only `SETTINGS_ENABLE_CONNECT_PROTOCOL` and `SETTINGS_WT_ENABLED` settings (`[INV-H3-15]`, `[INV-WT-07]`), asserts that the server advertises both `0x20b8933b` (draft-17) and `0x2c7cf000` (draft-16), and completes a bidirectional stream (`0x41`), unidirectional streams (`0x54`) in both directions, Quarter-Stream-ID datagrams in both directions, and `WT_CLOSE_SESSION` capsule teardown.
- **Draft-16-only and draft-17-only wire servers against `WebTransportClient`**: verifies that `WebTransportClient` negotiates either `SETTINGS_WT_ENABLED` codepoint and completes the full bidirectional, unidirectional, datagram and close-capsule exchange.

### 3. Top-level workspace hygiene (`ARCH-014`)

`fuzz/`, `interop/`, `scripts/` and `crates/netune-webtransport/examples/interop_server.rs` are removed. `.github/scripts/check-architecture.py` enforces `ARCH-014`, rejecting any reintroduction of top-level `fuzz/`, `interop/` or `scripts/` trees.

### Invariants & Behavioral Boundaries

- **`[INV-TEST-05]` Single Workspace and Lockfile for All Verification Suites**: every unit, differential, integration, end-to-end and parser-fuzz target lives inside the primary Cargo workspace, resolves against the root `Cargo.lock`, compiles on stable Rust under `cargo check --workspace --all-targets`, and runs under `cargo nextest`. No top-level `fuzz/`, `interop/` or `scripts/` tree may exist. Enforced by `ARCH-014`.
- **`[INV-TEST-06]` Dual-Tier In-Workspace Parser Fuzzing**: every wire parser crate (`netune-http1`, `netune-http2`, `netune-http3`, `netune-quic`, `netune-webtransport`) owns a `tests/fuzz.rs` target executing a deterministic corpus/truncation/mutation pass on every PR and a deep `#[ignore]` soak campaign under `--profile soak`. Enforced by `crates/*/tests/fuzz.rs` and `.github/workflows/fuzz.yml`.

### Consequences

- **Positive**: `cargo check --all-targets --all-features` and `cargo nextest run --workspace --all-features` compile and execute every fuzz and WebTransport differential test on stable Rust with no external Go or `cargo-fuzz` toolchain.
- **Positive**: removes the hardcoded `2026-11-20` certificate expiration time-bomb, `/tmp` file side effects, and wall-clock sleeps from the WebTransport interop gate.
- **Negative & Trade-offs**: in-workspace fuzzing uses deterministic PRNG mutation rather than LLVM SanitizerCoverage edge instrumentation; any parser bug found in production or review is added to the crate's `SEEDS` slice so all future PR and soak runs mutate around it.

## Rejected Alternatives & Negative Knowledge

### Keep `cargo-fuzz` in an Out-of-Workspace `fuzz/` Directory (Rejected)

- **Why considered**: `cargo-fuzz` provides coverage-guided instrumentation on Nightly.
- **Why rejected**: it requires a separate `[workspace]`, a second `Cargo.lock`, and a Nightly toolchain, making fuzz targets invisible to `cargo check --workspace --all-targets` and unrunnable in standard PR gates.

### Shell-Orchestrated External Go Harness in `interop/` and `scripts/` (Rejected)

- **Why considered**: `quic-go/webtransport-go` is an external codebase.
- **Why rejected**: it bypasses `cargo nextest` (`[INV-TEST-01]`), requires a Go toolchain in CI and local setups, relies on stdout log polling and wall-clock sleeps, and leaked test-only scaffolding into `crates/netune-webtransport/examples/`.

## Links

- Amends: [ADR-0037](0037-webtransport-draft17-completion-gate.md),
  [ADR-0038](0038-webtransport-external-interoperability.md),
  [ADR-0044](0044-test-architecture-nextest-and-tiered-entry-points.md)
