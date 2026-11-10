# System Architecture Governance

This document codifies the workspace topology, dependency direction, and non-negotiable structural red-lines of `netune`.

---

## 1. Workspace Topology

`netune` is a small, deliberately flat workspace. Two crates orchestrate — one per direction of travel — and the rest are leaves. The leaves are **not** a flat ring: a few sit above others (`netune-io` above `netune-trace`; the QUIC stack above its shared leaves), and encoding that real DAG is the point of the topology table in `.github/scripts/check-architecture.py`. What every leaf shares is a single rule: **no leaf depends on an orchestrator.**

```text
┌────────────────────────────────┐   ┌────────────────────────────────┐
│ netune (egress orchestrator)   │   │ netune-server (ingress)        │
│  DNS, TCP, TLS, pool, proxies, │   │  accept loop, concurrency cap, │
│  redirects, HTTP/2, WS, QUIC/H3,│   │  HTTP/1.1 + H2 + H3 dispatch, │
│  egress confinement, faults    │   │  QUIC listener, drain          │
└──┬─────┬─────┬─────┬─────┬─────┘   └───┬────────┬────────┬─────────┘
   ▼     ▼     ▼     ▼     ▼             ▼        ▼        ▼
┌────────┐┌────────┐┌────────┐┌────────┐┌──────────┐┌──────────┐┌──────────┐
│ http1  ││ http2  ││  ws    ││ trace  ││  http1   ││  http2   ││ http3/   │
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

**Dependency rule**: no leaf depends on an orchestrator; `netune` and `netune-server` never depend on each other (`[INV-SERVER-01]`, ADR-0011); `netune-probe` depends on no workspace crate at all. Leaves may depend on other leaves only along the edges the topology table permits (`netune-io → netune-trace`; `netune-quic → netune-egress, netune-io, netune-trace`; `netune-http3 → netune-quic, netune-trace`; `netune-webtransport → netune-http3, netune-quic`; `netune-server → netune-http3, netune-quic` for the optional H3 ingress). Any edge not in that table — a leaf importing an orchestrator, an orchestrator importing the other orchestrator, or a cycle — is an architectural inversion and is rejected by the gate `.github/scripts/check-architecture.py`.

---

## 2. Structural Red-Lines

### 2.1 No Third-Party HTTP Runtime (ADR-0001)

- **Red-line**: no third-party HTTP client, HTTP/2 implementation, HTTP/3 implementation, or WebSocket runtime may appear in the production dependency graph of any crate. HTTP/3 and QPACK are owned by `netune-http3` (ADR-0027); QUIC is owned by `netune-quic` (ADR-0028).
- **Permitted exception**: differential-test oracles (`hyper`, `hyper-util`, `tungstenite`, `h3`, `h3-quinn`, `quinn`, `quinn-proto`) as `dev-dependencies` only, so owned codecs can be compared byte-for-byte against a battle-tested implementation.
- **Enforcement**: the architecture gate `.github/scripts/check-architecture.py` reads every `Cargo.toml` and fails on a forbidden runtime in any `[dependencies]` section (`ARCH-005`/`ARCH-006`), and fails if a `vendor/h3` or `vendor/h3-quinn` tree exists (`ARCH-010`); the differential suites fail if the owned encoder diverges from the oracle.

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

### 2.4.1 Profile Resolution Precedes Connect (ADR-0019)

- **Red-line**: every TLS/H1/H2 profile name used by an attempt is resolved by `Client::plan` before a pool lookup or connector call. An unknown name is a hard error, never a fallback.
- **Separation**: connection-fixed identity (TLS, SNI, evasion, socket/route, H2 SETTINGS) keys the pool; request-only wire profiles (HTTP/1 header order/casing, HTTP/2 pseudo-header order) do not.
- **Multiplexed halves**: `H2ConnectionProfile` and `H2RequestProfile` are distinct types; the connection stores both, but only the connection half enters the pool key (`[INV-CUSTOM-12..13]`).
- **H3 identity**: HTTP/3 has no second handshake; its connection identity is the resolved QUIC profile. Typed HTTP/3 SETTINGS (including QPACK capacity and blocked-stream budget) are a separate connection-fixed profile, and request-header order is request-scoped and enforced before QPACK encoding by the owned H3/QPACK implementation (`[INV-CUSTOM-16..19]`, `[INV-H3-03..08]`).
- **Enforcement**: `[INV-CUSTOM-08..19]`, `[INV-H3-03..08]`; `ConnectionPlan` is the only path from `Target` to a request, unknown-profile tests cover H1 and H2, H3/QUIC integration asserts the resolved profile and SETTINGS profile, and the owned ordered-header test asserts wire order.

### 2.4.2 H3 Ingress Is a Peer Transport (ADR-0025)

- **Red-line**: HTTP/3 ingress is an `H3Server` bound to a QUIC endpoint, not a mode of the TCP `Server`. The H3 state machine lives in `netune-http3`; the orchestrator owns admission, handler dispatch, bounds, trace and drain.
- **Exchange identity**: H3 wire stream `0` is a valid request, so ingress traces use non-zero exchange ids and record the wire stream id in the H3 start event (`[INV-SERVER-22..24]`).
- **Enforcement**: `crates/netune-server/src/h3.rs`, `crates/netune-http3/src/server.rs`, and `crates/netune-server/tests/http3_ingress.rs`.

### 2.4.3 Owned QUIC (ADR-0028)

- **Red-line**: `netune-quic` owns the RFC 9000 state machine, RFC 9001 packet-protection wiring and RFC 9002 recovery; `quinn`/`quinn-proto` never appear in the production graph.
- **Engine**: `wire` (varints, packet headers, frames, transport parameters), `crypto` (rustls packet protection and TLS handshake), `owned::core` (spaces, streams, ACK, flow control) and `owned::endpoint` (UDP routing and async handles).
- **Crypto**: Initial/Handshake/1-RTT keys and packet/header protection come from `rustls::quic` backed by `aws-lc-rs`; no owned cipher or HKDF.
- **Lifecycle**: Retry/address validation, keyed stateless reset, 1-RTT key update, fast loss detection, receive-window top-up, QUIC v2 and Version Negotiation are owned by `netune-quic` (ADR-0029).
- **H3 extensions**: RFC 9297 datagrams, RFC 9297 capsules and RFC 9220 extended CONNECT are owned by `netune-http3` (ADR-0030, ADR-0032). WebTransport over HTTP/3 is a separate `netune-webtransport` product layer pinned to draft-17 (ADR-0033); H3/QUIC only expose generic seams and reliable-reset support.
- **0-RTT**: the client caches authenticated QUIC transport parameters; the server enables early data only with stateful single-use tickets; rejected early frames are replayed in 1-RTT (ADR-0031).
- **Consumer seams**: a per-connection `QuicUdpSocketFactory` (invoked after confinement and before the first Initial), a per-connection `CongestionControllerFactory`, `QuicProfile.keep_alive`, RFC 9000 idle timeout and verified `peer_certificates` are the only product extension points. They never grant flow-control credit, change packet sizing or bypass TLS verification (ADR-0034).
- **Handshake failures are values**: `Endpoint::accept` separates `EndpointClosed` from `Handshake`; a failed peer is observable and non-fatal, and `H3Server` publishes it to a bounded observer channel instead of stopping the listener (ADR-0035, `[INV-QUIC-23]`, `[INV-SERVER-25]`).
- **Enforcement**: `crates/netune-quic/src/{wire,crypto,owned}/`, `ARCH-005` with an empty `ALLOWED_RUNTIME_DEPS`, the quinn differential tests, and the consumer-seam tests in `crates/netune-quic/tests/owned_server_e2e.rs`.

### 2.5 Codecs Never Open Sockets

- **Red-line**: `netune-http1`, `netune-http2` and `netune-ws` operate on caller-provided byte buffers or `AsyncRead`/`AsyncWrite` handles. They never resolve, connect, listen, or own a socket; transport policy belongs to an orchestrator.
- **Enforcement**: the codec crates have no DNS/TCP/listen entry points and depend on no orchestrator.

### 2.5.1 A Multiplexed Trace Carries Stream Identity (ADR-0012)

- **Red-line**: every event records which exchange it belongs to (`Event::stream`, `0` where the transport cannot multiplex). A derivation over a multiplexed log groups by that field and never by position.
- **Enforcement**: `[INV-SERVER-10]`; `split_multiplexed` is the only splitter, and `derive_ingress` still refuses a multi-exchange log rather than describing one of them.

### 2.6 Every Traced Attempt Is Recorded; Observation Cost Is Chosen (ADR-0001, ADR-0017)

- **Red-line**: an attempt observed with `Observation::Traced` writes structured events into its `TraceCollector`, and every derived timing is a pure function of those events — never a wall-clock estimate, in both directions of travel (`[INV-SERVER-02]` for ingress).
- **L0 is not L1**: `Observation::Counters` and `Observation::Off` are deliberate observation policies, not attempts pretending to have an event timeline. A trace envelope may not claim fidelity its tap did not produce. H2/H3 are connection-level L0.
- **Hot path**: `TimedIo` owns its `Tap` by value. `NoTap` is zero-sized; `Counters` reads no clock and allocates nothing; `Ring` owns the bounded log. No `Box<dyn Tap>`, `Arc<Mutex<Recorder>>` or per-byte lock is permitted on `poll_read`/`poll_write`.
- **Cold path**: phase marks, redirects, `TCP_INFO` samples and protocol-frame events may share a `TraceCollector`; its internal mutex is never touched by the byte path. `Recorder` is not a public type (`[INV-TRACE-07]`).
- **Enforcement**: timing types are computed from event logs; `TimedIo<I, NoTap>` is size-equal to `I` (`crates/netune-io/src/timed.rs`); the pool key is a typed `PoolKey` and cannot be constructed without the whole `ConnectionIdentity` (`[INV-CUSTOM-04]`).

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
