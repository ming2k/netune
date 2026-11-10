# Build & Run Guide

This document is the authoritative developer guide for building, running, and
verifying `netune` — the owned and observable network stack in Rust.

---

## 1. Prerequisites & Toolchain Setup

- **Rust Toolchain**: `rustc` ≥ 1.95 (Rust 2024 edition), per `rust-toolchain.toml`.
- **Kernel & Privileges**: Linux with loopback network interface enabled for integration suites; `CAP_NET_RAW` for `netune-probe`.

---

## 2. Compiling the Crates

```bash
# Build the workspace
cargo build --workspace

# Build specific components
cargo build -p netune
cargo build -p netune-server
cargo build -p netune-probe
```

---

## 3. Running Netune Server & Codecs Locally

The ingress and egress suites use a real loopback client/server pair:

```bash
cargo test -p netune-server --test interop
```

To fetch from an origin you have started yourself, use the typed-error example
(see [Serve HTTP/1.1 and HTTP/2](../how-to/serve-http.md) for a runnable
handler):

```bash
cargo run -p netune --example fetch -- http://127.0.0.1:8080/health
```

---

## 4. Automated Verification & Testing

```bash
# Run all unit tests, differential tests, and loopback E2E suites
cargo test --workspace

# Run differential tests against reference codecs
cargo test -p netune-http1 --test differential

# Check formatting and Clippy warnings
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 5. Runtime Diagnostics

- **Packet Capture Permissions**: `netune-probe` requires `CAP_NET_RAW` when listening to raw Ethernet/IPv4 interfaces.
- **Port Contention**: Integration tests bind ephemeral ports (`:0`) to avoid address collisions.
