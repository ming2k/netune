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
```

These are the same gates CI runs; see [`standards/workflow.md`](standards/workflow.md) for the full list and the code-to-doc synchronization rules.

---

## 4. Repository Layout

| Path | Contents |
| :--- | :--- |
| `crates/netune` | Transport orchestration and policy (the only crate that composes the stack). |
| `crates/netune-http1`, `netune-http2`, `netune-ws` | Wire codecs; they never open sockets. |
| `crates/netune-trace` | Trace model, pure timing derivations, JA3/JA4. |
| `crates/netune-probe` | L2 frame parse/build; transmit only behind `--features inject`. |
| `docs/adr/` | Ratified decisions. |
| `docs/dev/standards/` | Engineering standards. |
| `docs/dev/` | Setup, testing, release, postmortems. |

---

## 5. Local Conventions

- Do not commit `target/`, editor swap files, or machine-specific tool directories (see `.gitignore`).
- Build artifacts and caches are local; a clean clone must always build with `cargo check --workspace` equivalents.
- If a command needs elevated privileges, it belongs to an explicit opt-in path and must never be part of the default test run.
