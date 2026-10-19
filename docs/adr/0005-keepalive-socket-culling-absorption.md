---
id: ADR-0005
title: "Keep-Alive Socket Culling Absorption and Stale Socket Recovery"
status: accepted
date: 2026-09-30
scope: [transport/pool, resilience/keepalive]
superseded_by: null
---

# 0005. Keep-Alive Socket Culling Absorption and Stale Socket Recovery

- Status: Accepted
- Date: 2026-09-30
- Deciders: Ming Li

---

## Context and Problem Statement

In long-running client sessions with intermittent request cadences, idle TCP connections kept in the connection pool were repeatedly closed by upstream relays, edge proxies, and server load balancers. These intermediate devices routinely cull idle sockets within 30 to 60 seconds without transmitting a TLS `close_notify` or TCP `FIN`.

Because `netune` originally configured a 300 s idle timeout, connections that were dead on the wire remained marked as fresh in the pool. When popped from the pool, attempts failed immediately. Furthermore, callers experienced non-deterministic error classifications: an abrupt TCP reset was treated as retryable, whereas a TLS alert was marked as a terminal protocol failure. Over 300 observed session attempts, 101 requests failed solely due to culled sockets.

## Decision Drivers

- Transparent absorption of dead keep-alive sockets without leaking spurious errors to caller applications.
- Zero request replay hazards: requests that might have reached the origin must never be replayed automatically.
- Accurate telemetry: metrics must distinguish fresh handshakes from reused sockets, revoking reuse claims if reconnecting.
- Alignment of pool idle timeouts with real-world edge gateway eviction thresholds.

## Considered Options

- Option 1: Send periodic TCP keep-alive or HTTP/1.1 ping probes over idle sockets.
- Option 2: Align pool idle timeout to 20 s, absorb stale pooled socket closures before the response head is parsed with a transparent single retry, and distinguish incomplete stream reads from protocol errors.

## Decision Outcome

Chosen option: "Option 2: Align pool idle timeout to 20 s and absorb pre-head stale socket drops".

When `Client::send` extracts a pooled socket and encounters an abrupt EOF/connection drop before receiving any response bytes, it discards the dead connection, establishes a fresh TCP+TLS connection, and executes the request.

### Invariants & Behavioral Boundaries

- **`[INV-TRANSPORT-01]` Pre-Head Replay Safety**: A request may only be transparently re-attempted on a fresh socket if the failure occurred on a pooled connection *before* any response head byte was parsed. Requests that failed after receiving response head bytes must never be replayed.
- **`[INV-TRANSPORT-02]` Phase-Based Classification**: Error classification keys on failure location rather than the specific I/O error type. Abrupt socket closure while waiting for a response head is categorized as `HttpError::Incomplete(0)` (retryable transport event), whereas syntactically malformed headers remain terminal protocol errors.
- **`[INV-TRANSPORT-03]` Telemetry Claim Revocation**: When a pooled connection is found dead and retried, `ConnectStaleDiscarded` is emitted to revoke the reuse claim, ensuring subsequent timing derivations record the actual handshake rather than `NotApplicable(ConnectionReused)`.
- **`[INV-TRANSPORT-04]` Single ConnectReused Emission**: `ConnectReused` is recorded at most once per attempt, carrying the connection's idle age.

### Consequences

- **Positive**:
  - Eliminated spurious keep-alive drops in long-running processes without user-space retry loops.
  - Reduced idle connection pool holding time to 20 s, closely matching intermediate middlebox cull windows.
  - Preserved strict replay safety across non-idempotent and idempotent HTTP methods.
- **Negative & Trade-offs**:
  - A culled pooled connection incurs the latency of detecting the dead socket before initiating the fresh handshake.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Periodic Keep-Alive Probes

- **Why considered**: Keeps connections alive indefinitely by preventing gateway timeouts.
- **Why rejected**: Middleboxes frequently drop connections silently regardless of low-frequency TCP keep-alives. Actively probing idle connections wastes battery/CPU on mobile/edge clients, triggers unsolicited server traffic, and fails to handle races where the server drops the socket simultaneously with the client probe.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md)
