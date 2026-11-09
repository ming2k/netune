# Invariant & Constraint Governance

This document codifies the definition, categorization, and lifecycle of invariants in `netune`. It exists to keep `INV-*` tags rare, load-bearing, and verifiable.

---

## 1. Core Principle: Mechanisms Over Exhortations

An invariant is a condition that must hold in every valid state of the system. A rule that is only asserted in prose is not an invariant — it is a comment.

> **If a rule has neither a compiler-level proof nor an automated test, it is not an invariant.**

---

## 2. Constraint Admissibility Matrix

| Category | Definition & scope | Identifier policy | Enforcement mechanism |
| :--- | :--- | :--- | :--- |
| **System invariant** | Non-negotiable structural red-line with cross-boundary blast radius: dependency firewalls, privilege boundaries, replay safety, protocol direction. | Ratified in an ADR as `[INV-FAMILY-NN]`. | 1. Crate/feature boundaries<br>2. Dedicated integration test (`tests/*_integration.rs`)<br>3. Type-level constraints |
| **Domain contract** | State-machine behaviour inside one crate: decoder phases, stream states, close handshakes. | No global `INV-` tag. Expressed as named types and `enum` variants. | Private fields, typestates, unit tests |
| **Design constant** | Sizes, timeouts, buffer limits, preset values, default heads. | No `INV-` tag. A named `const`. | The constant itself; a test where it is load-bearing |
| **Implementation note** | Localized edge-case guard or workaround. | No `INV-` tag. Ordinary code comment. | Direct regression test |

---

## 3. The 3-Condition Gate

A rule may be elevated to a system invariant only if **all three** hold:

1. **High blast radius** — a violation corrupts data, inverts an architectural boundary, leaks privilege, or makes retries unsafe.
2. **Durable** — it survives ordinary feature work; it is not a snapshot of current defaults.
3. **Mechanically enforced** — it names the test, feature gate, or type that fails when the rule is broken.

---

## 4. Current Invariant Families

| Family | Scope | Ratified in |
| :--- | :--- | :--- |
| `[INV-TRACE-01..02]` | Timings are pure derivations of recorded events; no synthetic measurement bias. | ADR-0001 |
| `[INV-TRACE-03]` | An event reaches a configured `TraceSink` before the operation that recorded it returns, and the ring buffer remains an independent bounded record of the attempt (a slow sink may drop; the ring may not lose its window silently). | ADR-0010 |
| `[INV-TRACE-04..06]` | Observation cost is type-level (`NoTap`/`Counters`/`Ring` owned by `TimedIo`); fidelity is produced by the tap, not asserted; a Cargo feature never changes a default observation or identity policy. | ADR-0017 |
| `[INV-TRACE-07..09]` | `TraceCollector` is the only public cold-path handle and `Tap` the only byte-event producer; H2/H3 are connection-level L0; no public `Recorder` and no public `read`/`wrote` on the collector. | ADR-0018 |
| `[INV-CUSTOM-04..06]` | Connection identity is one typed, hashable value in the pool key and trace envelope; redirects preserve it; wire-shape decisions are named policies, never booleans on `Target`. | ADR-0017 |
| `[INV-CUSTOM-07]` | Every protocol client and connector uses the same `TraceCollector`; no protocol owns a parallel recorder abstraction. | ADR-0018 |
| `[INV-CUSTOM-08..11]` | Every profile resolves before connect; connection-fixed identity and request-only wire profiles are separate; built-in and custom profiles share one registry path; explicit raw HTTP/1 bytes win over a profile. | ADR-0019 |
| `[INV-CUSTOM-12..13]` | HTTP/2 connection and request halves have separate types; the pool key contains only the connection half, and a request profile can change without reopening the socket. | ADR-0020 |
| `[INV-CUSTOM-14..15]` | QUIC profiles resolve through one registry, unknown names fail loudly before endpoint creation, and the resolved profile name is available for identity/trace construction. | ADR-0021 |
| `[INV-CUSTOM-16..17]` | HTTP/3 connection identity is the resolved QUIC profile; H3 does not grow a second handshake registry, and no request-order profile is added until the encoder can enforce it. | ADR-0022 |
| `[INV-CUSTOM-18..19]` | H3 request-header order is enforced at the QPACK input boundary by the owned encoder; request order is request-scoped and never changes QUIC connection identity. `[INV-CUSTOM-20]` is retired with the fork it constrained. | ADR-0027 |
| `[INV-H3-01..08]` | H3 request streaming is the primitive; SETTINGS profiles are typed and enforceable; decoded dynamic header sections are acknowledged and blocked streams wait on insertions; header order is independent of QPACK table state; no third-party H3/QPACK runtime ships; critical-stream closure is connection-fatal; QPACK references are bounded. | ADR-0024, ADR-0027 |
| `[INV-SOCKET-01]` | A `SocketConfig` option is either applied or reported; no pre-connect option may be silently skipped by the fast path (`needs_manual_socket`). | ADR-0006, ADR-0010 |
| `[INV-TRANSPORT-00..04]` | Replay safety: a pooled socket that drops before any response-head byte is replaced; after that point it is never retried. Idle bound, distinct `Incomplete`. | ADR-0001 (`00`), ADR-0005 (`01..04`) |
| `[INV-EGRESS-01..03]` | Confinement is checked before connect; private, loopback, link-local and metadata ranges are refused. | ADR-0002 |
| `[INV-TLS-01..03]` | TLS identity is explicit data (`TlsProfile`); presets keep a stable wire identity across dependency updates. | ADR-0004 |
| `[INV-CUSTOM-01..03]` | Wire determinism: configured-or-documented socket/DNS/segmentation behaviour; no lowercasing of raw headers. | ADR-0006 |
| `[INV-WS-01..08]` | Client-role exclusivity of the WebSocket transport surface in `netune` (the workspace-wide prohibition on inbound code was retired by ADR-0011), masking direction, bounded reassembly, frame-level observability, no pooling, proven liveness, incremental UTF-8, differential parity. Directional exclusivity is now enforced per orchestrator by `[INV-SERVER-01]`. | ADR-0007, ADR-0011 |
| `[INV-HTTP2-01]` | HTTP/2 framing and HPACK live in `netune-http2`, never behind a feature flag of `netune-http1`. | ADR-0003 |
| `[INV-PROBE-01..02]` | Zero transmission in default builds; transmission requires `CAP_NET_RAW`. | ADR-0003 |
| `[INV-UDP-01..05]` | Confinement precedes the datagram socket; a session is one peer; a relayed datagram must carry the session's source; fragments are refused; a session records `UdpOpen` and never a handshake. | ADR-0008 |
| `[INV-SERVER-01..07]` | Two orchestrators with no cross-dependency; ingress timings are pure derivations and a multi-request connection is refused rather than described by its first request; a request is bounded before it is served; one framing implementation for both roles; concurrency is capped and shedding is explicit; shutdown drains. | ADR-0011 |
| `[INV-SERVER-08..11]` | HTTP/2 ingress: one connection machine for both ends; one protocol per connection, never upgraded in place; a multiplexed log is split by stream identity rather than by position; both receive windows are enforced and credited on handler consumption, not on frame arrival. | ADR-0012 |
| `[INV-SERVER-12..13]` | A response cannot contradict its head (body under `HEAD`/`1xx`/`204`/`304`/`CONNECT`-2xx, a body past its declared length, a `finish` short of it are all refused), and a streamed body is terminated exactly once by the writer. | ADR-0013 |
| `[INV-SERVER-18..21]` | TLS termination is inside the trace (handshake completion and failure are events); the configuration serves the SNI name the peer asked for, with a required fallback; the handshake is bounded by `head_timeout`; a TLS configuration whose ALPN list cannot serve what `protocols` claims is refused at bind time. | ADR-0015 |
| `[INV-SERVER-17]` | A protocol a build cannot speak is refused, not absorbed: the default `Protocols` is what the feature set can serve, an explicit request for an absent protocol fails at bind time, and neither protocol is served by a listener that does not offer it. | ADR-0012 |
| `[INV-SERVER-14..16]` | A request is grammatical before it is routed (target form, `Host` grammar, CRLF strictness), a body bound is cumulative and a declared length is checked before the body, and every refusal is a status line rather than a reset socket. | ADR-0014 |
| `[INV-SERVER-22..24]` | H3 ingress is a separate QUIC listener; its exchanges use non-zero trace ids; body, handler, write and drain bounds come from the same `ServerConfig`. | ADR-0025 |
| `[INV-QUIC-01..04]` | Crypto unification on `aws-lc-rs` (`ring` forbidden); pre-connect socket options and confinement precede QUIC initial packet; pure trace derivation; predictable datagram sizing failure. | ADR-0016 |
| `[INV-QUIC-05..09]` | QUIC is owned by `netune-quic`: no quinn production path, delegated rustls/aws-lc-rs crypto, validate-before-mutate, timestamp-driven bounded recovery, and flow control before buffering. | ADR-0028 |
| `[INV-QUIC-10..14]` | QUIC lifecycle hardening: Retry precedes server state, stateless reset tokens are keyed by CID, key update retains reordering keys, Version Negotiation never selects an unconfigured version, and migration waits for path validation. | ADR-0029 |

The authoritative wording of each invariant lives in its ADR. This table is an index, not a second source of truth; if the two disagree, the ADR wins and this table is corrected.

---

## 5. Retirement Policy

1. **True invariants** retire in place through an ADR: set `status: superseded` and `superseded_by: ADR-NNNN`, and keep the original wording and failure mode for forensic use.
2. **Pseudo-invariants** (styling, layout, local state, convenience defaults) are not renamed or tombstoned. They are deleted from annotations and, where useful, replaced by a named constant or a test name that says what is actually guaranteed.
3. **Never renumber an invariant.** A retired family's numbers are not reused for a different rule; that would silently change what existing references mean.
