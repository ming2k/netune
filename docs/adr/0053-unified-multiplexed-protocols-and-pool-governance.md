---
id: ADR-0053
title: "Unified Multiplexed Protocols, Pool Governance, and Owned-TLS Fuzzing"
status: accepted
date: 2026-11-16
scope: [transport/egress, transport/pool, protocol/http2, protocol/http3, testing/fuzzing]
superseded_by: null
---

# 0053. Unified Multiplexed Protocols, Pool Governance, and Owned-TLS Fuzzing

- Status: Accepted
- Date: 2026-11-16
- Deciders: Ming Li
- Amends: [ADR-0020](0020-split-multiplexed-profiles.md),
  [ADR-0022](0022-http3-connection-identity.md),
  [ADR-0040](0040-egress-handshakes-share-a-bound.md),
  [ADR-0049](0049-in-workspace-fuzzing-and-differential-webtransport-gate.md)
- Supersedes: `Target::with_force_h2` ([ADR-0019](0019-connection-plan-and-wire-profile-registry.md)),
  `netune::H2Client`

---

## Context

After `RoundTrip` separated `Client` from concrete wire state
([ADR-0050](0050-request-level-exchange-seam-and-mock-transport.md)), three gaps
remained in the transport and verification layers:

1. **Serial HTTP/2 & separate entrypoints.** Pooled HTTP/2 connections were still
   checked out for exclusive ownership one stream at a time, leaving idle
   sockets deaf to `PING`/`SETTINGS`/`GOAWAY` and blocking concurrent callers onto
   extra handshakes. Meanwhile HTTP/2 still carried a legacy standalone
   `H2Client` alongside `Target::force_h2: bool`, and HTTP/3 existed only on
   `netune_http3::H3Client` rather than flowing through `Client`, `Pool`,
   redirects, streaming uploads, and `Mock`.
2. **Unbounded pool residency.** `PoolConfig` enforced only a per-key idle count
   cleaned lazily on `take()`, with no global idle ceiling across authorities,
   no in-flight concurrency ceiling, and no passive eviction of idle connections
   (so idle multiplexed sessions would linger forever).
3. **`netune-tls` lacked dual-tier fuzz coverage.** Every other wire parser
   owned PR + soak fuzz targets in `crates/*/tests/fuzz.rs`, while `netune-tls`
   (including encrypted flight parsing and RFC 8879 `CompressedCertificate`) did
   not yet run under `test-support::fuzz`.

---

## Decision

1. **Multiplexed `H2ClientSession` and `H3Session` shared inside `Pool`.**
   - `netune-http2` adds `H2ClientSession`: a background connection driver owns
     `H2Connection` exclusively, answers idle `PING`, `SETTINGS`, and `GOAWAY`,
     tracks active streams atomically via `H2StreamPermit` up to peer
     `SETTINGS_MAX_CONCURRENT_STREAMS`, and isolates early stream drops by
     sending `RST_STREAM(CANCEL)` while keeping the connection alive.
   - `netune-http3` adds shareable `&self`/`Arc` `H3Session` (and refactors
     `H3Client` to wrap it) tracking active streams, idle age, and `GOAWAY`
     retryability without pinning a single `TraceCollector` to the connection.
   - `Pool` stores live `H2ClientSession` and `H3Session` handles while keeping
     single-owner idle storage only for HTTP/1.1 keep-alive sockets (`[INV-TRANSPORT-09]`).
   - Cold multiplexed dials coalesce per `PoolKey` through a cancellation-safe
     singleflight barrier so concurrent cold calls open one socket and multiplex
     immediately upon handshake registration.

2. **Pool lifecycle governance.**
   - `PoolConfig` gains `max_idle_total` (default 64) and
     `max_in_flight_per_authority` (default `None`), and removes the legacy
     single-owner `Http2Idle`/`put_http2` API (`[INV-TRANSPORT-10]`).
   - Putting or registering a connection lazily spawns a `Weak<PoolInner>`
     background reaper when inside a Tokio runtime, paired with synchronous
     `Pool::reap()` for deterministic unit testing and non-runtime pools.

3. **One `HttpProtocol` surface and streaming uploads behind `RoundTrip`.**
   - `Target::force_h2` is replaced by `HttpProtocol::{Auto, Http1, Http2, Http3}`;
     `netune::H2Client` is removed cleanly (`[INV-EXCHANGE-03]`).
   - `ConnectionPlan::transport` distinguishes `PlannedTransport::Tcp` from
     `PlannedTransport::Http3`. `Wire<C>` holds a `QuicConnector` (configurable via
     `Wire::with_quic`), inherits `EgressConfinement` from `Connector`, refuses
     bypass over a proxy connector, and drives `wire::h3` through `Pool`.
   - `RequestBody::Stream` (`RequestBodySource`) and `netune_http1::RequestWriter`
     stream uploads incrementally across HTTP/1.1, HTTP/2, and HTTP/3 without
     buffering; unconsumed/consumed stream state gates redirect and replay safety.

4. **Dual-tier in-workspace fuzzing for `netune-tls`.**
   - `crates/netune-tls/tests/fuzz.rs` adds PR + `#[ignore]` soak harnesses for
     record parsing/unprotection (TLS 1.3 GCM/ChaCha20, TLS 1.2 GCM/ChaCha20/CBC),
     SPKI DER extraction, TLS 1.2/1.3 handshakes, and compressed certificates
     (`zlib` and `brotli`), extending `[INV-TEST-06]`.

---

## Options Considered

### Keep Exclusive HTTP/2 Pool Checkout + Standalone `H2Client` (Rejected)
- **Why considered**: avoids spawning a background task per HTTP/2 connection.
- **Why rejected**: violates multiplexed concurrency (`tokio::join!` opens N
  connections), leaves idle sockets unresponsive to `PING`/`GOAWAY`, and keeps
  two parallel HTTP/2 APIs drifting out of sync.

### Separate `H3RoundTrip` Transport Outside `Wire<C>` (Rejected)
- **Why considered**: keeps `netune-quic` decoupled from `Wire<C>`.
- **Why rejected**: breaks transparent `HttpProtocol::Http3` targets on a single
  `Client`, bypasses `Pool` caps and `max_in_flight_per_authority`, and duplicates
  replay and redirect safety rules.

---

## Negative Knowledge & Trade-offs

- Idle HTTP/2 connections now retain one lightweight Tokio driver task until
  `GOAWAY`, socket EOF, or reaper eviction (bounded by `idle_timeout` and
  `max_idle_total`).
- Dropping `Pool` drops all pooled `H2ClientSession` and `H3Session` handles;
  already open exchanges keep the underlying session alive via their `H2StreamReader`
  or `H3ResponseStream` until finished or dropped.
- `ProxyConnector` currently fails closed on `HttpProtocol::Http3` targets
  instead of silently tunneling direct UDP past the configured TCP proxy.

---

## Invariants & Enforcement

| Invariant | Summary | Enforcement Mechanism |
| :--- | :--- | :--- |
| `[INV-EXCHANGE-03]` | All HTTP wire protocols (`HTTP/1.1`, `HTTP/2`, `HTTP/3`) and streaming request bodies sit behind `RoundTrip` | `HttpProtocol`, `PlannedTransport`, `wire::{h1,h2,h3}`, `RequestBody::Stream` |
| `[INV-TRANSPORT-09]` | Multiplexed H2/H3 sessions stay shared in `Pool` up to stream limits with cold-dial singleflight coalescing and isolated cancellation | `H2ClientSession`, `H3Session`, `Pool::begin_or_join_dial`, `client_h2_integration.rs`, `http3_client.rs` |
| `[INV-TRANSPORT-10]` | Pool enforces global idle caps, per-authority in-flight bounds, and weak-referenced idle reaping | `PoolConfig::{max_idle_total,max_in_flight_per_authority}`, `Pool::reap()`, `pool/tests.rs` |
| `[INV-TEST-06]` (amended) | All wire parser crates including `netune-tls` own dual-tier PR + soak fuzz targets | `crates/netune-tls/tests/fuzz.rs`, `test-support::fuzz` |
