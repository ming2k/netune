# Contributor Environment & Setup

This document describes how to build `netune` locally. For test strategy and commands, see [`testing.md`](testing.md).

---

## 1. Toolchain

- **Rust**: `1.95.0`, pinned in `rust-toolchain.toml` (the workspace declares `rust-version = "1.95"`).
- **Components**: `rustfmt`, `clippy`.
- **Test runner**: `cargo-nextest`.

If `rustup` is installed, the pinned toolchain is selected automatically when you enter the repository. Verify with:

```bash
rustc --version   # expect 1.95.0
cargo --version
```

Install the test runner once:

```bash
cargo install cargo-nextest --locked
```

---

## 2. Build

```bash
# Whole workspace, every target and feature
cargo check --all-targets --all-features

# Docs, with warnings treated as errors (as CI does)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

---

## 3. Verify Before Sending a Change

```bash
cargo nextest run
cargo nextest run -p netune-probe --features inject
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
python3 .github/scripts/check-docs.py
cargo test --doc --workspace --all-features
```

These are the same gates CI runs; see [`workflow.md`](workflow.md) for the full list, including the documentation integrity gate and the code-to-doc synchronization rules.

---

## 4. Repository Layout

| Path | Contents |
| :--- | :--- |
| `crates/netune` | Transport orchestration and policy (the only crate that composes the stack). |
| `crates/netune-http1`, `netune-http2`, `netune-ws` | Wire codecs; they never open sockets. |
| `crates/netune-trace` | Trace model, pure timing derivations, JA3/JA4. |
| `crates/netune-probe` | L2 frame parse/build; transmit only behind `--features inject`. |
| `docs/adr/` | Ratified decisions. |
| `docs/dev/` | Contributor docs, setup, testing, architecture, invariants, and workflow. |
| `docs/dev/standards/` | Engineering documentation & collaboration meta-standards. |
| `docs/dev/` | Setup, testing, release, postmortems. |
| `.github/scripts/` | The documentation integrity gate and its self-test. |

---

## 5. Local Conventions

- Do not commit `target/`, editor swap files, or machine-specific tool directories (see `.gitignore`).
- Build artifacts and caches are local; a clean clone must always build with `cargo check --workspace` equivalents.
- If a command needs elevated privileges, it belongs to an explicit opt-in path and must never be part of the default test run.
