---
id: ADR-0017
title: "Tiered Observation Cost and Typed Connection Identity"
status: accepted
date: 2026-11-08
scope: [trace/model, trace/cost, transport/pool, transport/customizability]
superseded_by: null
---

# 0017. Tiered Observation Cost and Typed Connection Identity

- Status: Accepted
- Date: 2026-11-08
- Deciders: Ming Li
- Amends: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md), [ADR-0006](0006-transport-customizability-wire-evasion.md), [ADR-0010](0010-quic-ownership-and-trace-sink.md)

---

## Context and Problem Statement

Two of netune's promises are currently structural half-truths.

**Observation is not optional, and it is not cheap by construction.** `Client::request`,
`Client::prewarm` and `Client::connect_ws` each construct a `Recorder::start(1024)` with no
consumer (`crates/netune/src/client.rs`). `TimedIo` holds an `Arc<Mutex<Recorder>>` on every
connection, so every `poll_read`/`poll_write` that moves bytes takes a lock and reads a clock
(`crates/netune-io/src/timed.rs`). `Fidelity` is an envelope label, not an input: the egress
trace hard-codes `Fidelity::l1()` even when no syscall tap was requested
(`crates/netune/src/client.rs`). The `overhead.rs` test is a wall-clock assertion, which
`docs/dev/testing.md` §2 forbids, and its 20 µs budget is far above the measured cost; it
therefore cannot distinguish "cheap but unconditional" from "actually free".

**Customization is not fully accounted for.** `pool_key` is
`authority + "#" + tls_profile` (`crates/netune/src/client.rs`). It does not include the TLS
server name or the SNI-segmentation policy, so a connection can be reused across different
SNI identities or with a wire-shaping policy silently omitted. On an absolute redirect,
`resolve_location` constructs a fresh `Target` and drops the TLS profile, the evasion policy
and `force_h2` (`crates/netune/src/client.rs`). The existing invariant
`[INV-TLS-01]` says pool isolation is absolute; this is a present violation, not a future
design preference.

The two problems are duals. A customization that cannot be observed cannot be audited; an
observation that costs the same whether or not it was requested cannot be trusted in
production. This ADR makes both explicit in the type system and in the connection pool key.

### What this ADR does not change

`[INV-TRACE-01]` remains binding: every timing and rate is a pure derivation over recorded
events. This ADR changes *which* events are produced and *how* the byte path records them; it
does not make ambient-clock measurements legitimate, and it does not make a missing stage a
fabricated number. "Not recorded" remains honest absence, never zero.

`[INV-TRANSPORT-00]` (no third-party HTTP runtime) and `[INV-SERVER-01]` (the two
orchestrators are peers) remain binding. `netune-trace` remains a leaf; `netune` and
`netune-server` each depend on it and never on each other.

---

## Decision Drivers

- A production client must be debuggable without enabling a 1024-event ring or a per-syscall
  mutex.
- "Off" must mean *no clock, no allocation, no synchronization, no push*, not "a cheaper
  branch". A `cfg(feature)` cannot express this: features are additive and silently unified
  by the dependency graph.
- Every property fixed at connection establishment must participate in connection identity,
  or a request can silently receive a socket that does not match its requested identity.
- Observation and customization must meet in the trace envelope: the trace says what
  identity was requested and what fidelity actually produced it.
- The hot path is per syscall; the cold path is per connection or per attempt. They deserve
  different mechanisms.

---

## Decision

### 1. Observation cost is a type on the byte path, selected by a per-attempt policy

`netune-trace` gains a `Tap` trait and three implementations:

- `NoTap`: a zero-sized type. Every method is `#[inline(always)]` and empty; the wrapper
  compiles to the inner stream. It reads no clock and allocates nothing.
- `Counters`: fixed-width counters of bytes and successful read/write calls. It reads no
  clock and allocates nothing.
- `Ring`: an owned `EventLog` plus the attempt's origin and an optional `Arc<dyn TraceSink>`.
  It reads the clock once per byte-moving call and records `Read`/`Write` events. It is
  bounded by its capacity; eviction is counted.

`netune-io::TimedIo<I, T: Tap = NoTap>` owns `T` by value. It does **not** hold
`Arc<Mutex<Recorder>>`, and its `poll_read`/`poll_write` do not allocate, lock or dispatch
through a trait object. The tap's `finish` output is merged into the attempt trace by the
orchestrator on the cold path. `netune-io::RingIo<T>` is the same owned tap for a protocol
that boxes its transport (ingress HTTP/1, WebSocket) and merges the log when the wrapper is
dropped; the byte path is still lock-free.

A per-attempt `Observation` policy selects one of the three concrete tap types:

```rust
pub enum Observation {
    Off,
    Counters,
    Traced(TraceConfig),
}
```

`Client::send` dispatches once at the attempt boundary to a monomorphized
`send_with::<NoTap>`, `send_with::<Counters>` or `send_with::<Ring>`. There is no
`Box<dyn Tap>` and no `if observe` inside the byte path. `Observation::Off` is the explicit
pure mode; `Observation::Counters` is the default for `Client::request`; `Observation::Traced`
is explicit and carries the ring capacity and optional sink.

The cold path (DNS/TCP/TLS phase marks, redirects, `TCP_INFO` samples, protocol frame events)
may continue to use a shared `Recorder` behind `Arc<Mutex<...>>`. That mutex is not touched by
`TimedIo`. A mutex on a per-connection cold path is acceptable; a mutex on every moved byte is
not.

### 2. Fidelity is produced, not asserted

`RequestTrace::fidelity` is derived from the tap that actually produced the byte timeline.
A trace produced by `NoTap` or `Counters` never claims `syscall: true`; a trace produced by
`Ring` may. `BodyStream::trace()` returns `None` when the attempt was not traced rather than
returning an empty L1 envelope.

### 3. Connection identity is one typed value

`netune-trace` owns the protocol-neutral identity vocabulary:

```rust
pub struct ConnectionIdentity {
    pub tls_profile: Option<String>,
    pub tls_server_name: Option<String>,
    pub evasion: EvasionPolicy,
    pub h2_profile: Option<String>,
    pub h3_profile: Option<String>,
    pub socket_shape: Option<String>,
}

pub enum EvasionPolicy {
    None,
    SniSplit { chunk_size: u16, segment_limit: u16, gap_us: u32 },
}
```

The type is `Clone + PartialEq + Eq + Hash + Serialize + Deserialize`. The pool key is a
typed value, not a formatted string:

```rust
pub struct PoolKey {
    pub authority: String,
    pub identity: ConnectionIdentity,
}
```

Every axis fixed at connection establishment participates: TLS profile, TLS server name,
evasion policy applied to the handshake, H2 connection settings, H3 transport parameters and
socket shape. Request-only wire profiles (HTTP/1 header order and casing, HTTP/2
pseudo-header order) do **not** key the pool; they are applied per request and recorded in the
request trace separately.

`Target` carries the identity value. `resolve_location` preserves it across redirects; only
the authority and the TLS server name change when the redirect changes host or scheme.
Boolean wire-shape switches such as `sni_segmentation` are replaced by the named,
hashable `EvasionPolicy`. Unknown profiles fail before connect; there is no silent fallback.

### 4. The trace envelope carries identity and schema version

`RequestTrace` gains `identity: ConnectionIdentity` and `schema_version: u32`. A trace can
now answer "what wire identity was requested?" and "what fidelity actually produced this?"
without reconstructing either from a pool key string or a caller's log.

The event payload stays compact. String payloads do not go into `Event`; if a future event
needs one, it travels in an append-only side table keyed by a stable producer sequence, never
by a ring index. The encoded event size is documented and asserted by a test; the stale
"13 bytes" comment is corrected.

### 5. Delivery is non-blocking; the ring is the record of truth

`TraceSink::event` returns `Flow`; `Flow::Drop` is advisory and never suppresses the ring
push. Sink implementations must not block. A sink may drop; the ring remains the bounded
record of truth and reports its drop count (`[INV-TRACE-03]`). Library-provided bounded and
sampled adapters may be added later, but no sink is allowed to turn a transport read into a
queue wait.

### 6. Features are additive; they never change defaults

`cfg(feature)` may add code (`ja4`, `serde`, `sink`, `registry`). It may not select the default
observation policy, the default identity, or a cheaper/expensive behavior. Defaults are
expressed by types and values at the call site. A consumer enabling a feature must never
silently turn a `NoTap` build into a ring-mutex build.

### 7. Cold path uses `dyn`, hot path uses generics

`dyn Connector`, `dyn DnsResolver`, `dyn Registry<T>` and `dyn TraceSink` are acceptable at
per-connection or per-attempt boundaries: one indirect call is noise there. The byte path
must be generic over `Tap`; `Box<dyn Tap>` is forbidden.

---

## Invariants & Behavioral Boundaries

- **`[INV-TRACE-04]` Type-Level Observation Cost**: `TimedIo<I, NoTap>` has the same size as
  `I` and adds no clock read, allocation, lock or event push per byte-moving call.
  `TimedIo<I, Counters>` adds no clock read or allocation. *Enforced by*: the `size_of`
  assertion in `crates/netune-io/src/timed.rs`, the fixed-width `Counters` assertion in
  `netune-trace`, and `cargo bench -p netune --bench zero_cost` under
  `iai-callgrind` with an `ir=0%` baseline gate in CI; no `Mutex<Recorder>` field in `TimedIo`.

- **`[INV-TRACE-05]` Fidelity Truth**: `RequestTrace::fidelity` equals the fidelity of the
  tap that produced the log. A trace cannot claim `syscall` detail that was not recorded.
  *Enforced by*: `Observation`/`Tap` carries `FIDELITY`; `BodyStream::trace()` returns `None`
  for `Off`/`Counters`.

- **`[INV-CUSTOM-04]` Identity Completeness**: every property fixed at connection
  establishment is part of `ConnectionIdentity`, and `PoolKey` contains the whole identity.
  A request can never receive a pooled connection whose identity differs from the one it
  requested. *Enforced by*: `PoolKey` is the only pool key type; a typed identity equality is
  the reuse predicate; regression tests cover SNI name and evasion policy.

- **`[INV-CUSTOM-05]` Redirect Continuity**: an absolute redirect preserves the selected
  connection identity except for the authority and TLS server name that the new location
  necessarily changes. *Enforced by*: `resolve_location` is the only redirect constructor and
  has identity-preservation tests.

- **`[INV-CUSTOM-06]` No Boolean Wire-Shape Switches**: a configurable wire-shape decision is
  a named, hashable policy, not a `bool` on `Target`. *Enforced by*: `EvasionPolicy` replaces
  `sni_segmentation`; the identity is `Eq + Hash`.

- **`[INV-TRACE-06]` Defaults Are Not Features**: enabling a Cargo feature cannot change the
  observation cost, the default identity, or the pool key. *Enforced by*: the `ja4` and `serde`
  feature matrix in CI; `default-features = false` builds and tests the same behavior.

---

## Consequences

- **Positive**:
  - A default client is debuggable at L0 (counters) without paying a ring, a clock, a mutex or
    an `Arc` on every read/write.
  - A caller that needs L1 chooses `Observation::Traced`; a caller that needs zero overhead
    chooses `Observation::Off`.
  - Pool isolation becomes a type property. SNI name and SNI-segmentation can no longer be
    silently dropped by reuse or redirect.
  - `RequestTrace` can be audited for identity and fidelity without external metadata.
  - The byte path is free of trait objects and shared mutability.

- **Negative & Trade-offs**:
  - Public API break: `Client::send` takes an `Observation`, `TimedIo` takes a tap,
    `Target` carries `ConnectionIdentity`, and `RequestTrace` gains fields. There is no
    compatibility shim; this is a clean break at the 0.0.x line.
  - The control path still uses a shared `Recorder`; removing that is a separate, later
    refactor and is not required by the byte-path invariant.
  - `Observation::Traced` still pays a clock read per byte-moving call, by definition.
  - Ingress HTTP/1 merges its owned tap into the connection recorder when the transport is
    dropped; HTTP/2 ingress still records control/frame events only and therefore reports L0,
    not a synthetic syscall timeline.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): `if observe { recorder.read(...) }`

The branch saves execution but not the `Arc` clone, the mutex, the `Box<dyn Transport>`
indirection or the unconditional ring allocation. The measured cost of the current path is
small in absolute terms, but it is paid on every byte-moving call whether or not the caller
asked for it. A branch cannot make `TimedIo<I>` the same size as `I`.

### Option 2 (Rejected): `cfg(feature = "observe")`

Cargo features are additive and are unified across the dependency graph. A third-party crate
can enable the feature without the application's knowledge, turning a "high-performance
default" into a ring-mutex build. Features may add capabilities; they may not select
behavior.

### Option 3 (Rejected): `Box<dyn Tap>`

A boxed tap restores the allocation, the vtable and the indirect call that this ADR exists to
remove. A generic `T: Tap` is the only shape that lets the compiler erase `NoTap`.

### Option 4 (Rejected): hashing the identity to `u64` for the pool key

A 64-bit hash collision would let two different wire identities share a pooled socket,
violating `[INV-TLS-01]`. The pool key uses typed equality over the full identity; a hash may
be displayed, never used as the isolation predicate.

### Option 5 (Rejected): making `NoTap` the default

A completely blind default is not the industry default: it makes production undebuggable and
pushes operators to `tcpdump` or ad-hoc logging. The default is `Counters`: constant-time,
allocation-free, clock-free L0 evidence. `NoTap` is available where the caller can prove it
needs no observation at all.

### Option 6 (Rejected): replacing `[INV-TRACE-01]`

This ADR changes the producer side, not the derivation model. Timings remain pure functions
of recorded events; a missing event remains honest absence.

---

## Evidence

- Current unconditional construction: `crates/netune/src/client.rs`
  (`Client::request`, `prewarm`, `connect_ws`).
- Current hot-path lock: `crates/netune-io/src/timed.rs`.
- Current wall-clock gate: `crates/netune/tests/overhead.rs`; the measured p99 on the
  development host is 69 ns per recorded event and the data-path tap adds 68 ns per write,
  far below the asserted 5 µs p99. The test is a loose guardrail, not evidence of a 5 µs
  cost.
- Current pool key and redirect loss: `crates/netune/src/client.rs` (`pool_key`,
  `resolve_location`).
- Current fidelity label: `crates/netune/src/client.rs` (`BodyStream::trace`).

---

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md),
  [ADR-0006](0006-transport-customizability-wire-evasion.md),
  [ADR-0010](0010-quic-ownership-and-trace-sink.md),
  [ADR-0011](0011-server-side-ingress-transport.md)
