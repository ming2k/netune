# Contributing to netune

Thank you for contributing to `netune`.

## Getting Started

- [Contributor Setup](docs/dev/setup.md) — toolchain, build, and local environment.
- [Testing Guide](docs/dev/testing.md) — test tiers, determinism rules, and commands.

## Where Things Live

| You are looking for… | Go to |
| :--- | :--- |
| Engineering standards (topology, invariants, style, workflow) | [docs/dev/standards/](docs/dev/standards/README.md) |
| Ratified architectural decisions | [ADR Registry](docs/adr/index.md) |
| User-facing guides | [Tutorials](docs/tutorials/index.md) · [How-To](docs/how-to/index.md) · [Reference](docs/reference/) · [Explanation](docs/explanation/index.md) |
| Versioning, tagging, and distribution | [Release & Versioning](docs/dev/release-and-versioning.md) |

## Before You Send a Change

```bash
cargo check --all-targets --all-features
cargo nextest run
cargo nextest run -p netune-probe --features inject
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

CI runs the same gates with `RUSTFLAGS="-D warnings"`.

## Architectural Changes

A change that alters a crate boundary, a wire contract, a pool/liveness rule, or a security guarantee requires an ADR. Read the [ADR standard](docs/dev/standards/adr.md) first: it defines the qualification test, the lifecycle, and the required "Rejected Alternatives & Negative Knowledge" section.

## Code-to-Doc Synchronization

If your change makes a documented statement false, update that document in the same commit. The mapping from changed surface to required document is in [workflow.md](docs/dev/standards/workflow.md).
