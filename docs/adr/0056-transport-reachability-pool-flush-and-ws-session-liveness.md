---
id: ADR-0056
title: "Typed Unreachability, Explicit Pool Flush, and Cancel-Safe WebSocket Session Liveness"
status: accepted
date: 2026-11-19
scope: [transport/egress, transport/pool, transport/websocket]
superseded_by: null
---

# 0056. Typed Unreachability, Explicit Pool Flush, and Cancel-Safe WebSocket Session Liveness

- Status: Accepted
- Date: 2026-11-19
- Deciders: Ming Li
- Amends: [ADR-0007](0007-owned-client-websocket-codec.md),
  [ADR-0052](0052-replay-and-exchange-bounds.md),
  [ADR-0053](0053-unified-multiplexed-protocols-and-pool-governance.md)

---

## Context and Problem Statement

Consumers such as Nuo layer retry budgets, offline fast-fail, and remote WebSocket attach sessions directly above `netune` without duplicating transport machinery. Three concrete gaps existed at that boundary:

1. **Offline unreachability was indistinguishable from upstream jitter.** `NetError::is_retryable()` returned `true` for both DNS/routing unreachability (`ENETUNREACH`, `EHOSTUNREACH`, `ENETDOWN`, resolver failure) and transient remote faults (connection reset, mid-stream stall). A caller with a 30-attempt transient retry budget had no prose-free way to fast-fail when the host had no route to the network.
2. **Stranded pooled connections could not be flushed on demand.** `Pool::reap()` only evicted expired or dead entries. When a caller experienced a transport failure across a Wi-Fi or VPN switch, live-looking half-open sockets remained in the pool until `idle_timeout` elapsed, even though the caller knew the previous route had just failed.
3. **Full-duplex `WsSession` had a liveness defect and lacked cancel-safety.** `WsStream::receive()` cleared `outstanding_ping` *before* returning `Message::Pong`, so `WsSession::next()` saw `outstanding_ping_matches() == false`, never cleared `ping_in_flight`, and killed live sessions on the second poll after `pong_timeout`. In addition, `WsSession` sent empty ping payloads, `WsStream::write_frame()` cleared and re-wrote `write_buf` via `write_all` (non-cancel-safe under `tokio::select!`), `Target::from_url` rejected `ws://`/`wss://`, and callers wanting custom `WsHandshake` headers without a trace collector had no untraced `connect_ws_with` entry point.

## Decision Drivers

- Keep retry loops, offline policy, and OS network-interface watchers out of `netune` (mechanism over policy).
- Expose minimal, orthogonal primitives that eliminate caller-side prose sniffing and duplicated WebSocket runtimes.
- Preserve cancel-safety for single-task full-duplex `tokio::select!` loops over `WsSession`.

## Considered Options

- Option 1: Add OS interface-change watchers and automatic retry/offline state machines inside `netune`.
- Option 2: Leave `netune` unchanged and let callers parse `Display` strings and keep a second third-party WebSocket stack (`tokio-tungstenite`).
- Option 3: Expose typed `is_unreachable()`, explicit `Pool::clear()` / `Client::clear_pool()`, `ws://`/`wss://` URL parsing, `Client::connect_ws_with`, and fix `WsSession`/`WsStream` probe discharge and write cancel-safety.

## Decision Outcome

Chosen option: "Option 3".

1. **Typed unreachability predicate (`[INV-TRANSPORT-14]`).** `ResolveError::is_unreachable()`, `ConnectError::is_unreachable()`, and `NetError::is_unreachable()` classify DNS failures and OS routing unreachability (`NetworkUnreachable`, `HostUnreachable`, `NetworkDown`) as a pure boolean predicate while keeping `is_retryable() == true`. Callers that want to keep retrying still can; callers that enforce a short offline budget branch on the predicate without string matching.
2. **Explicit pool flush (`[INV-TRANSPORT-15]`).** `Pool::clear() -> usize`, `RoundTrip::clear_pool() -> usize`, and `Client::clear_pool() -> usize` synchronously evict all pooled HTTP/1.1, HTTP/2, and HTTP/3 entries without disturbing checked-out in-flight streams. Callers flush on retry backoff instead of maintaining platform-specific OS interface listeners.
3. **First-class WebSocket client ergonomics and cancel-safe liveness (`[INV-WS-09]`).**
   - `Target::from_url` accepts `ws://` (plain, default port 80) and `wss://` (TLS, default port 443).
   - `Client::connect_ws_with` establishes an untraced upgraded stream with explicit `WsHandshake` headers and bounds.
   - `WsSession` stamps each heartbeat ping with a monotonic non-empty 8-byte probe payload, tracks `(Instant, Bytes)` directly, arms `ping_in_flight` before awaiting flush, and discharges only on an exact payload match across unlimited ping/pong cycles.
   - `WsStream` drains `write_buf` incrementally (`advance(n)`) and flushes any residual bytes at the top of both `send()` and `receive()`, making `WsSession::next()` cancel-safe inside `tokio::select!`.

### Invariants & Behavioral Boundaries

- `[INV-TRANSPORT-14]` Typed Unreachability Predicate: DNS resolution failures (excluding `InvalidAuthority`) and OS routing unreachability (`NetworkUnreachable`, `HostUnreachable`, `NetworkDown`) report `NetError::is_unreachable() == true` while remaining `is_retryable() == true`; remote refusals, resets, and mid-exchange timeouts report `false`. *Enforced by*: `error::tests::inv_transport_14_unreachability_is_a_typed_predicate`.
- `[INV-TRANSPORT-15]` Non-Disruptive Pool Flush: `Pool::clear()` and `Client::clear_pool()` synchronously remove every idle and shared pooled connection entry and return the evicted count without disturbing active in-flight streams. *Enforced by*: `pool::tests::inv_transport_15_clear_evicts_all_idle_entries`.
- `[INV-WS-09]` Cancel-Safe Full-Duplex `WsSession` Liveness: `WsSession` issues non-empty monotonic ping probes, discharges `ping_in_flight` on matching pongs across repeated cycles, and preserves frame alignment when `WsSession::next()` is cancelled inside `tokio::select!` beside interleaved `send()` calls. *Enforced by*: `e2e::websocket_session::inv_ws_09_session_survives_multiple_ping_pong_cycles_and_interleaved_sends`.

### Consequences

- **Positive**: Callers drop prose sniffing, avoid OS-specific network watcher threads, discard stranded connections on retry backoff, and can migrate client WebSocket links cleanly onto `netune::WsSession` with real heartbeat liveness.
- **Negative & Trade-offs**: `Pool::clear()` is coarse-grained (whole pool rather than per-authority), which is intentional: a network switch invalidates all authorities equally and keeps the API minimal.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected)

- **Why considered**: Automatically flushing pools on Linux Netlink / macOS SystemConfiguration / Windows IP Helper events and retrying inside `netune` could hide network transitions from callers.
- **Why rejected**: It breaks `[INV-TRANSPORT-01]` (policy stays outside `netune`), introduces three platform-specific native event-loop backends, and duplicates the caller's retry/backoff state machine.

### Option 2 (Rejected)

- **Why considered**: Zero changes to `netune`.
- **Why rejected**: Forces callers to regex-match OS error text for offline detection and leaves a second WebSocket runtime (`tokio-tungstenite`) in downstream clients while `WsSession`'s multi-cycle ping bug remains latent in `netune`.

## Links

- Related ADRs: [ADR-0007](0007-owned-client-websocket-codec.md),
  [ADR-0052](0052-replay-and-exchange-bounds.md),
  [ADR-0053](0053-unified-multiplexed-protocols-and-pool-governance.md)
