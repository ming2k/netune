# Agent Directives

## 1. Operational Guardrails (Hard Constraints)

- **No third-party protocol runtime in pure crates.** Never add a third-party HTTP client, HTTP/2 implementation (`h2`), HTTP/3 implementation, or WebSocket runtime to an owned codec or orchestrator. The QUIC engine is owned by `netune-quic` (ADR-0028); `quinn`/`quinn-proto` are dev-only differential oracles. HTTP/3 and QPACK are owned by `netune-http3` (ADR-0027). Oracles (`hyper`, `tungstenite`, `h3`) are `dev-dependencies` only.
- **Privilege boundary.** Never make `netune-probe`'s transmit path reachable in a default build. `Capture::send_frame` stays behind `--features inject` and requires `CAP_NET_RAW`.
- **Directional exclusivity.** `netune` opens outbound connections and never listens; `netune-server` accepts inbound connections and never dials (ADR-0011).
- **Confinement before connect.** Never open a socket before `EgressConfinement` has checked the resolved address (ADR-0002).
- **Unified crypto provider.** All TLS and QUIC operations compile exclusively against `aws-lc-rs`; `ring` is forbidden (ADR-0016).
- **No history surgery.** Never force-push, rewrite a published commit, or move a pushed tag unless the user explicitly asks for it.
- **Terminating commands.** Every command must finish. Do not start background servers or unbounded loops without a timeout.

## 2. Core Mental Model & Subsystem Boundaries

- **Two orchestrators, dedicated leaf crates.** `netune` (egress) and `netune-server` (ingress) are peers that never depend on each other. Leaves (`netune-trace`, `netune-io`, `netune-http1`, `netune-http2`, `netune-http3`, `netune-quic`, `netune-ws`) do not depend on orchestrators, and `netune-probe` depends on no workspace crate.
- **Codecs never own a socket.** They operate on caller-provided buffers or `AsyncRead`/`AsyncWrite` handles; DNS, TCP, TLS and policy belong to orchestrators.
- **Observability is structural.** Transport steps emit events into the attempt's `Recorder`; timings are pure derivations of those events (`[INV-TRACE-01]`).
- **WebSocket is not pooled.** An upgraded socket belongs to its `WsStream` for its lifetime; heartbeat liveness is explicit and reconnection is not a transport policy.
- **Trace, then trust.** A measurement that is not derived from recorded events is a guess and does not belong in the API.

## 3. Engineering Discipline

- **Mechanisms over exhortations.** Enforce boundaries with crate rules, private fields, feature gates, and deterministic tests — not with comments.
- **Verify before declaring done.** Run `cargo check --all-targets --all-features`, `cargo test --workspace --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt --check`, and the integrity scripts in `.github/scripts/`.
- **Clean lineage.** Reference only ADRs that exist in `docs/adr/0001`+. Never cite external decision numbers.
- **Documentation has a place.** User-facing docs live in `docs/{tutorials,how-to,reference,explanation}/`; contributor docs in `docs/dev/`; no new Markdown files at the repository root.

## 4. On-Demand Standards Routing

Do not guess repository rules. Consult the authoritative specification when the task touches one of these areas:

- Topology & structural red-lines: [`docs/dev/architecture.md`](docs/dev/architecture.md)
- Invariant policy: [`docs/dev/invariants.md`](docs/dev/invariants.md)
- ADR authoring & lifecycle: [`docs/dev/standards/adr.md`](docs/dev/standards/adr.md)
- Documentation taxonomy & firewall: [`docs/dev/standards/taxonomy.md`](docs/dev/standards/taxonomy.md)
- Markdown & link style: [`docs/dev/standards/style.md`](docs/dev/standards/style.md)
- Verification gates & code-doc sync: [`docs/dev/workflow.md`](docs/dev/workflow.md)
- Postmortems: [`docs/dev/standards/postmortems.md`](docs/dev/standards/postmortems.md)
- Testing: [`docs/dev/testing.md`](docs/dev/testing.md)
- Release & versioning: [`docs/dev/release-and-versioning.md`](docs/dev/release-and-versioning.md)
