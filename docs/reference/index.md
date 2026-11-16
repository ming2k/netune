# Reference

Factual descriptions of what exists in `netune`: the crates, their
responsibilities, and the system they compose. Read these to look something up,
not to learn a task.

---

## Documents

| Document | Describes |
| :--- | :--- |
| [Crates Reference](crates.md) | Every workspace crate: responsibility, dependencies, key types, and the privilege posture of each. |
| [System Architecture](architecture.md) | The layering model, how the crates fit together, and the invariants that hold across them. |
| [Diagnostic Codes](diagnostics.md) | Stable failure codes, their phases and retry verdicts, and the trace-bundle review workflow. |
| [Stability and Production Boundaries](stability.md) | Support tiers, production defaults, and the gates an owned-TLS, HTTP/3 or WebTransport production claim must pass. |
| [WebTransport Browser Interoperability](webtransport-interop.md) | Pinned browser matrix, executable harness contract, and the evidence required before WebTransport leaves Experimental. |
| [Migrating to 0.1.0 (GA)](migration-0.1.0.md) | Breaking changes from `0.0.x` to `0.1.0`, `#[non_exhaustive]` builders, `Client::builder()`, and post-GA SemVer guarantees. |
| [Migrating to 0.0.26](migration-0.0.26.md) | The breaking trace, sink, error-boundary and configuration changes. |

For the reasoning behind the structure, see
[Explanation](../explanation/index.md). For binding decisions, see the
[ADR Registry](../adr/index.md).
