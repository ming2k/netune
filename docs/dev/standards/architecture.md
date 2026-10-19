# System Architecture Governance

This document codifies the workspace topology, dependency direction, and non-negotiable structural red-lines of `netune`.

---

## 1. Workspace Topology

`netune` is a small, deliberately flat workspace. One crate orchestrates; the others are leaves that never depend on each other:

```text
┌──────────────────────────────────────────────────────────────┐
│ netune                                                       │
│  Transport & policy orchestration: DNS, TCP, TLS, pool,      │
│  proxies, redirects, decompression, HTTP/2 execution,        │
│  WebSocket egress, fault injection, egress confinement       │
└───────┬───────────────┬───────────────┬───────────────┬──────┘
        ▼               ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ netune-http1 │ │ netune-http2 │ │  netune-ws   │ │ netune-trace │
│ HTTP/1.1     │ │ RFC 9113 +   │ │ RFC 6455     │ │ trace model, │
│ codec        │ │ HPACK        │ │ codec        │ │ JA3/JA4      │
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘

┌──────────────────────────────────────────────────────────────┐
│ netune-probe (independent leaf)                              │
│  L2 Ethernet/IPv4/TCP parse and build; socket transmission   │
│  only behind --features inject + CAP_NET_RAW                 │
└──────────────────────────────────────────────────────────────┘
```

**Dependency rule**: the four leaf crates depend on no other workspace crate, and `netune-probe` depends on none of them. Only `netune` composes the stack. A leaf importing a sibling, or `netune-probe` importing the transport, is an architectural inversion and is rejected in review.

---

## 2. Structural Red-Lines

### 2.1 No Third-Party HTTP Runtime (ADR-0001)

- **Red-line**: no third-party HTTP client, HTTP/2 implementation, or WebSocket runtime may appear in the production dependency graph of any crate.
- **Permitted exception**: differential-test oracles (`hyper`, `hyper-util`, `tungstenite`) as `dev-dependencies` only, so owned codecs can be compared byte-for-byte against a battle-tested implementation.
- **Enforcement**: review of `Cargo.toml` dependency sections; the differential suites fail if the owned encoder diverges from the oracle.

### 2.2 Structural Privilege Separation (ADR-0003)

- **Red-line**: frame transmission never compiles into a default artifact. `netune-probe`'s `Capture::send_frame` lives behind `--features inject` and requires `CAP_NET_RAW` at runtime.
- **Enforcement**: the symbol does not exist without the feature; CI builds and tests both configurations.

### 2.3 Client-Role WebSocket Exclusivity (ADR-0007)

- **Red-line**: the workspace owns WebSocket **client** egress only. No listening socket, accept loop, or server session table exists in production code. The pure codec understands both wire roles for testability; the transport surface exposes one.
- **Enforcement**: `netune` exposes `connect_ws` and no `listen`; mock origins exist only under `tests/`.

### 2.4 Egress Confinement Before Connect (ADR-0002)

- **Red-line**: resolved destination addresses are checked against `EgressConfinement` before a socket is opened. A URL that resolves to loopback, RFC 1918, link-local, or a cloud-metadata address must not produce a connection.
- **Enforcement**: the connect path calls `is_public_ip` first; `StrictPublic` tests cover decimal/octal/hex encodings, IPv6-mapped forms, and DNS rebinding.

### 2.5 Codecs Never Open Sockets

- **Red-line**: `netune-http1`, `netune-http2` and `netune-ws` operate on caller-provided byte buffers or `AsyncRead`/`AsyncWrite` handles. They never resolve, connect, or own a socket; transport policy belongs to `netune`.
- **Enforcement**: the codec crates have no DNS/TCP entry points and do not depend on `netune`.

### 2.6 Every Attempt Is Recorded (ADR-0001)

- **Red-line**: transport steps write structured events into the attempt's `Recorder`. Derived timings are pure functions of those events — never wall-clock estimates.
- **Enforcement**: timing types are computed from event logs; a step that cannot emit an event is a design error, not an acceptable gap.

### 2.7 WebSocket Connections Are Never Pooled (ADR-0005, ADR-0007)

- **Red-line**: an upgraded socket belongs to its `WsStream` for its lifetime and never enters the keep-alive `Pool`. Heartbeat liveness (`WsSession`) is explicit; automatic reconnection is not a transport policy.
- **Enforcement**: `Pool` accepts only HTTP connection keys; a WS test asserts the pool is untouched after an upgrade.

---

## 3. Crate Addition & Workspace Integrity

1. **Addition threshold**: a new crate is admitted only when its responsibility cannot be modeled as a module of an existing crate and its position in the topology is unambiguous. The structural reason is recorded as an ADR.
2. **No sibling-directory dependencies**: workspace crates are referenced by `path` *and* `version` inside the repository. Depending on a checkout outside it breaks `cargo check --workspace` for every clean clone and CI run.
3. **Workspace-wide version line**: every crate inherits `[workspace.package] version` unless an ADR explicitly ratifies an independent number.
