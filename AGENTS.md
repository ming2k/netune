# Agent Directives

## 1. Operational Guardrails (Hard Constraints)

- **No third-party protocol runtime.** Never add an HTTP client, HTTP/2 implementation, or WebSocket runtime to a production dependency graph. Oracles (`hyper`, `tungstenite`) are `dev-dependencies` only.
- **Privilege boundary.** Never make `netune-probe`'s transmit path reachable in a default build. `Capture::send_frame` stays behind `--features inject` and requires `CAP_NET_RAW`.
- **Client-role WebSocket only.** Never add a listening socket, accept loop, or server session table to production code.
- **Confinement before connect.** Never open a socket before `EgressConfinement` has checked the resolved address.
- **No history surgery.** Never force-push, rewrite a published commit, or move a pushed tag unless the user explicitly asks for it.
- **Terminating commands.** Every command must finish. Do not start background servers or unbounded loops without a timeout.

## 2. Core Mental Model & Subsystem Boundaries

- **One orchestrator, four leaves.** `netune` composes `netune-http1`, `netune-http2`, `netune-ws` and `netune-trace`. The leaves do not depend on each other, and `netune-probe` depends on none of them.
- **Codecs never own a socket.** They operate on caller-provided buffers or `AsyncRead`/`AsyncWrite` handles; DNS, TCP, TLS and policy belong to `netune`.
- **Observability is structural.** Transport steps emit events into the attempt's `Recorder`; timings are pure functions of those events.
- **WebSocket is not pooled.** An upgraded socket belongs to its `WsStream` for its lifetime; heartbeat liveness is explicit and reconnection is not a transport policy.
- **Trace, then trust.** A measurement that is not derived from recorded events is a guess and does not belong in the API.

## 3. Engineering Discipline

- **Mechanisms over exhortations.** Enforce boundaries with crate rules, private fields, feature gates, and deterministic tests — not with comments.
- **Verify before declaring done.** Run `cargo check --all-targets --all-features`, `cargo nextest run`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo fmt --check`.
- **Clean lineage.** Reference only ADRs that exist in `docs/adr/0001`+. Never cite external decision numbers.
- **Documentation has a place.** User-facing docs live in `docs/{tutorials,how-to,reference,explanation}/`; contributor docs in `docs/dev/`; no new Markdown files at the repository root.

## 4. On-Demand Standards Routing

Do not guess repository rules. Consult the authoritative specification when the task touches one of these areas:

- Topology & structural red-lines: [`docs/dev/standards/architecture.md`](docs/dev/standards/architecture.md)
- Invariant policy: [`docs/dev/standards/invariants.md`](docs/dev/standards/invariants.md)
- ADR authoring & lifecycle: [`docs/dev/standards/adr.md`](docs/dev/standards/adr.md)
- RFCs: [`docs/dev/standards/rfc.md`](docs/dev/standards/rfc.md)
- Documentation taxonomy & firewall: [`docs/dev/standards/taxonomy.md`](docs/dev/standards/taxonomy.md)
- Markdown & link style: [`docs/dev/standards/style.md`](docs/dev/standards/style.md)
- Verification gates & code-doc sync: [`docs/dev/standards/workflow.md`](docs/dev/standards/workflow.md)
- Postmortems: [`docs/dev/standards/postmortems.md`](docs/dev/standards/postmortems.md)
- Testing: [`docs/dev/testing.md`](docs/dev/testing.md)
- Release & versioning: [`docs/dev/release-and-versioning.md`](docs/dev/release-and-versioning.md)
