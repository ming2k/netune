# Contributing to netune

Thank you for contributing to `netune`.

## Getting Started

- [Contributor Setup](docs/dev/setup.md) — toolchain, build, and local environment.
- [Testing Guide](docs/dev/testing.md) — test tiers, determinism rules, and commands.

## Where Things Live

| You are looking for… | Go to |
| :--- | :--- |
| Engineering meta-standards (taxonomy, ADR, runbooks, testing, style) | [docs/dev/standards/](docs/dev/standards/README.md) |
| Architecture governance & topology | [docs/dev/architecture.md](docs/dev/architecture.md) |
| System invariants | [docs/dev/invariants.md](docs/dev/invariants.md) |
| Ratified architectural decisions | [ADR Registry](docs/adr/index.md) |
| User-facing guides | [Tutorials](docs/tutorials/index.md) · [How-To](docs/how-to/index.md) · [Reference](docs/reference/index.md) · [Explanation](docs/explanation/index.md) |
| Workflows & review gates | [docs/dev/workflow.md](docs/dev/workflow.md) |
| Versioning, tagging, and distribution | [Release & Versioning](docs/dev/release-and-versioning.md) |

## Before You Send a Change

```bash
cargo check --all-targets --all-features
cargo nextest run
cargo nextest run -p netune-probe --features inject
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
python3 .github/scripts/check-docs.py
cargo test --doc --workspace --all-features
```

CI runs the same gates with `RUSTFLAGS="-D warnings"`.

## Architectural Changes

A change that alters a crate boundary, a wire contract, a pool/liveness rule, or a security guarantee requires an ADR. Read the [ADR standard](docs/dev/standards/adr.md) first: it defines the qualification test, the lifecycle, and the required "Rejected Alternatives & Negative Knowledge" section.

## Code-to-Doc Synchronization

If your change makes a documented statement false, update that document in the same commit. The mapping from changed surface to required document is in [workflow.md](docs/dev/workflow.md).

If you change a documented Rust example, you do not need to remember anything:
the example is compiled as a doctest, so CI fails until the code and the prose
agree again.
