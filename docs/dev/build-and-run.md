# Build & Run Guide

This document is the authoritative developer guide for building, running, and
verifying `netune` — the owned and observable network stack in Rust.

---

## 1. Prerequisites & Toolchain Setup

- **Rust Toolchain**: `rustc` ≥ 1.85 (Rust 2021/2024 edition).
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

To launch the HTTP/1.1 and HTTP/2 observable listener over loopback:

```bash
# Run server example on localhost:8080
cargo run -p netune-server --example echo_server
```

In another terminal, test using the netune client:

```bash
cargo run -p netune --example fetch -- https://127.0.0.1:8080/
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
