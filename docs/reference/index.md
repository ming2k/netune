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
| [Migrating to 0.0.26](migration-0.0.26.md) | The breaking trace, sink, error-boundary and configuration changes. |

For the reasoning behind the structure, see
[Explanation](../explanation/index.md). For binding decisions, see the
[ADR Registry](../adr/index.md).
