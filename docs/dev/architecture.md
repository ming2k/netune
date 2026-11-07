# System Architecture Governance

This document codifies the workspace topology, dependency direction, and non-negotiable structural red-lines of `netune`.

---

## 1. Workspace Topology

`netune` is a small, deliberately flat workspace. Two crates orchestrate — one per direction of travel — and the rest are leaves. The leaves are **not** a flat ring: a few sit above others (`netune-io` above `netune-trace`; the QUIC stack above its shared leaves), and encoding that real DAG is the point of the topology table in `.github/scripts/check-architecture.py`. What every leaf shares is a single rule: **no leaf depends on an orchestrator.**

```text
┌────────────────────────────────┐   ┌────────────────────────────────┐
│ netune (egress orchestrator)   │   │ netune-server (ingress)        │
│  DNS, TCP, TLS, pool, proxies, │   │  accept loop, concurrency cap, │
│  redirects, HTTP/2, WS, QUIC/H3,│   │  HTTP/1.1 + HTTP/2 dispatch,   │
│  egress confinement, faults    │   │  slow-peer bounds, drain       │
└──┬─────┬─────┬─────┬─────┬─────┘   └───┬────────┬────────┬─────────┘
   ▼     ▼     ▼     ▼     ▼             ▼        ▼        ▼
┌────────┐┌────────┐┌────────┐┌────────┐┌──────────┐┌──────────┐┌──────────┐
│ http1  ││ http2  ││  ws    ││ trace  ││  http1   ││  http2   ││   io     │
└────────┘└────────┘└────────┘└───┬────┘└──────────┘└──────────┘└────┬─────┘
                                  ▼                                 ▼
              ┌─────────────────────────┐              (io → trace)
              │ http3 ──► quic ──┬───────┘
              └──────────────────┤
                                 ▼
              (quic → io, trace, egress)

┌──────────────────────────────────────────────────────────────┐
│ netune-probe (independent leaf)                              │
│  L2 Ethernet/IPv4/TCP parse and build; socket transmission   │
│  only behind --features inject + CAP_NET_RAW                 │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ netune-egress (pure leaf, no dependencies)                   │
│  is_public_ip + EgressConfinement: the one confinement policy│
│  every outbound transport (TCP, UDP, QUIC) shares            │
└──────────────────────────────────────────────────────────────┘
```

**Dependency rule**: no leaf depends on an orchestrator; `netune` and `netune-server` never depend on each other (`[INV-SERVER-01]`, ADR-0011); `netune-probe` depends on no workspace crate at all. Leaves may depend on other leaves only along the edges the topology table permits (`netune-io → netune-trace`; `netune-quic → netune-egress, netune-io, netune-trace`; `netune-http3 → netune-quic, netune-trace`). Any edge not in that table — a leaf importing an orchestrator, an orchestrator importing the other orchestrator, or a cycle — is an architectural inversion and is rejected by the gate `.github/scripts/check-architecture.py`.

---

## 2. Structural Red-Lines

### 2.1 No Third-Party HTTP Runtime (ADR-0001)

- **Red-line**: no third-party HTTP client, HTTP/2 implementation, or WebSocket runtime may appear in the production dependency graph of any crate.
- **Permitted exception**: differential-test oracles (`hyper`, `hyper-util`, `tungstenite`) as `dev-dependencies` only, so owned codecs can be compared byte-for-byte against a battle-tested implementation.
- **Enforcement**: the architecture gate `.github/scripts/check-architecture.py` reads every `Cargo.toml` and fails on a forbidden runtime in any `[dependencies]` section (`ARCH-005`/`ARCH-006`); the differential suites fail if the owned encoder diverges from the oracle.

### 2.2 Structural Privilege Separation (ADR-0003)

- **Red-line**: frame transmission never compiles into a default artifact. `netune-probe`'s `Capture::send_frame` lives behind `--features inject` and requires `CAP_NET_RAW` at runtime.
- **Enforcement**: the symbol does not exist without the feature; CI builds and tests both configurations.

### 2.3 Directional Role Exclusivity (ADR-0007, ADR-0011)

- **Red-line**: each orchestrator exposes one direction of travel. `netune` opens sockets outward and never listens; `netune-server` accepts inward and never dials a peer on a caller's behalf. No listening socket, accept loop or server session table exists in `netune`; no egress connector, pool or `EgressConfinement` call exists in `netune-server`.
- **Enforcement**: `netune` exposes no `listen` and no `TcpListener`; `netune-server`'s dependency list contains no egress crate, and `cargo tree` proves it (`[INV-SERVER-01]`). Mock origins in `crates/netune/tests/` remain the client suite's own fixtures; `netune-server` is tested by its own suite and by `crates/netune-server/tests/`.

### 2.3.1 Codec Role Symmetry (ADR-0011, ADR-0012)

- **Red-line**: a codec may understand both wire roles (`Role::Client` for `netune-ws`, response/request direction for `netune-http1`, `Role::Client`/`Role::Server` for `netune-http2`), because a one-directional codec cannot be differential-tested against an oracle in the direction it lacks. Symmetry is never exposed as a transport surface: the role a codec supports and the direction an orchestrator permits are independent facts.
- **Enforcement**: `netune-http1`'s two readers share one `StreamState` (`[INV-SERVER-04]`) and `netune-http2`'s two roles share one `H2Connection` (`[INV-SERVER-08]`); `netune` never constructs a server-direction role, and `netune-server` never constructs a client-direction one.

### 2.3.2 One Protocol Per Connection (ADR-0012)

- **Red-line**: a connection is HTTP/1.1 or HTTP/2, decided once from its first bytes or its ALPN result. No in-place upgrade (`h2c`, `Upgrade: websocket`) appears in the accept path, and a listener that does not offer the protocol a peer asked for refuses it rather than downgrading.
- **Enforcement**: `[INV-SERVER-09]`; the accept loop peeks the preface and never re-enters protocol selection, and `http2_is_refused_when_the_listener_does_not_offer_it` pins the refusal.

### 2.4 Egress Confinement Before Connect (ADR-0002)

- **Red-line**: resolved destination addresses are checked against `EgressConfinement` before a socket is opened. A URL that resolves to loopback, RFC 1918, link-local, or a cloud-metadata address must not produce a connection.
- **Enforcement**: the connect path calls `is_public_ip` first; `StrictPublic` tests cover decimal/octal/hex encodings, IPv6-mapped forms, and DNS rebinding.

### 2.5 Codecs Never Open Sockets

- **Red-line**: `netune-http1`, `netune-http2` and `netune-ws` operate on caller-provided byte buffers or `AsyncRead`/`AsyncWrite` handles. They never resolve, connect, listen, or own a socket; transport policy belongs to an orchestrator.
- **Enforcement**: the codec crates have no DNS/TCP/listen entry points and depend on no orchestrator.

### 2.5.1 A Multiplexed Trace Carries Stream Identity (ADR-0012)

- **Red-line**: every event records which exchange it belongs to (`Event::stream`, `0` where the transport cannot multiplex). A derivation over a multiplexed log groups by that field and never by position.
- **Enforcement**: `[INV-SERVER-10]`; `split_multiplexed` is the only splitter, and `derive_ingress` still refuses a multi-exchange log rather than describing one of them.

### 2.6 Every Attempt Is Recorded (ADR-0001)

- **Red-line**: transport steps write structured events into the attempt's `Recorder`. Derived timings are pure functions of those events — never wall-clock estimates — in both directions of travel (`[INV-SERVER-02]` for ingress).
- **Enforcement**: timing types are computed from event logs; a step that cannot emit an event is a design error, not an acceptable gap.

### 2.6.1 A Response Cannot Contradict Its Head (ADR-0013)

- **Red-line**: the bytes written for a response agree with the framing its head declares and with what its request method and status permit. A body under `HEAD`/`1xx`/`204`/`304`/`CONNECT`-2xx, a body past a declared `Content-Length`, and a `finish` short of it are all refusals.
- **Enforcement**: `[INV-SERVER-12]`; `netune_http1::ResponseWriter` is the only writer, and its `start`/`write`/`finish` each have a refusal test.

### 2.7 WebSocket Connections Are Never Pooled (ADR-0005, ADR-0007)

- **Red-line**: an upgraded socket belongs to its `WsStream` for its lifetime and never enters the keep-alive `Pool`. Heartbeat liveness (`WsSession`) is explicit; automatic reconnection is not a transport policy.
- **Enforcement**: `Pool` accepts only HTTP connection keys; a WS test asserts the pool is untouched after an upgrade.

---

## 3. Crate Addition & Workspace Integrity

1. **Addition threshold**: a new crate is admitted only when its responsibility cannot be modeled as a module of an existing crate and its position in the topology is unambiguous — including which direction of travel it serves. The structural reason is recorded as an ADR.
2. **No sibling-directory dependencies**: workspace crates are referenced by `path` *and* `version` inside the repository. Depending on a checkout outside it breaks `cargo check --workspace` for every clean clone and CI run.
3. **Workspace-wide version line**: every crate inherits `[workspace.package] version` unless an ADR explicitly ratifies an independent number.
