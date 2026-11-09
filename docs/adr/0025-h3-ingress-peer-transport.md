---
id: ADR-0025
title: "H3 Ingress Is a Peer QUIC Transport, Not a TCP Server Mode"
status: accepted
date: 2026-11-09
scope: [transport/ingress, protocol/http3, trace/ingress, workspace/topology]
superseded_by: null
---

# 0025. H3 Ingress Is a Peer QUIC Transport, Not a TCP Server Mode

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0011](0011-server-side-ingress-transport.md),
  [ADR-0012](0012-http2-ingress.md),
  [ADR-0016](0016-quic-and-http3-transport.md)

---

## Context and Problem Statement

`netune-server` serves HTTP/1.1 and HTTP/2 over a TCP listener. HTTP/3 needs a
QUIC endpoint, a TLS handshake inside the transport, per-connection stream
multiplexing, QPACK control streams, a QUIC connection-limit/drain model, and a
response writer over `h3`'s stream API. None of that is a branch in the TCP
accept loop.

The question was whether to refactor the existing server into a generic
multiplexed listener first, or add H3 as a peer transport. A premature generic
listener would put the stable H1/H2 connection model at risk for a transport
whose lifecycle is genuinely different.

## Decision Drivers

- Directional role exclusivity: ingress accepts, it never dials.
- One `Handler`, body reader and response shape across all ingress protocols.
- Per-stream trace identity; H3 stream `0` is a valid request stream, unlike
  HTTP/2 where stream `0` is connection-level.
- Admission, slow-peer bounds and drain must be explicit for QUIC too.
- `netune-server` must not depend on `netune`; H3's protocol state machine
  belongs in the `netune-http3` leaf.

## Decision

### 1. A separate `H3Server` listener

`netune-server` gains an `http3` feature (off by default) with:

```rust
H3Server::bind(
    address,
    ServerConfig,
    Arc<rustls::ServerConfig>,
    H3SettingsProfile,
    Arc<dyn Handler>,
) -> Result<H3Server, BindError>
```

It binds a QUIC endpoint with ALPN forced to `h3`, admission controlled by the
same `max_connections` semaphore, and the same timeout, body-bound and trace
configuration as the TCP listener. `serve` stops accepting on shutdown, sends
GOAWAY through the H3 connection, waits for in-flight request tasks up to
`drain_timeout`, then closes the endpoint.

The existing `Server` is not generalized. There is no `Server::bind_quic` and no
QUIC branch in the TCP protocol selection. Both listeners share the application
boundary, not the connection machine.

### 2. The H3 state machine stays in the leaf

`netune-http3::server` exposes a narrow `H3ServerConnection` / `H3ServerRequest`
/ `H3ServerStream` adapter over the controlled `h3` runtime. `netune-server`
maps that to `Handler` and always uses `netune_http3` types; it does not import
the `h3` crate directly.

The leaf remains egress/ingress neutral: it holds no listener, no handler and
no admission policy.

### 3. H3 exchange identity is an exchange id, not stream 0

An H3 connection has a valid request on wire stream `0`. The ingress trace
therefore allocates a non-zero exchange id starting at `1` for each accepted
request, records the wire stream id in the `H3StreamStart` event, and tags all
request/response events with the exchange id. `derive_ingress_exchanges` groups
by that id exactly as it does for HTTP/2.

This is the same identity convention the H3 client uses and preserves the rule
that stream `0` is connection-level in the trace model.

### 4. Body and response are the shared handler shapes

`RequestBody` is constructed with `new_at_stream`, so body events follow the
H3 exchange. `H3BodySource` enforces `body_timeout` and `max_body_bytes`;
`H3ServerStream` resets an unconsumed body when the handler returns. Response
translation removes HTTP/1.1-only hop-by-hop fields, adds `Date`, sends the
head, writes `ResponseBody::Empty`/`Bytes`/`Stream`, and finishes exactly once.

### 5. Trace is connection-level L0

`ServedProtocol::Http3` reports `Fidelity::l0()`, like H2. The QUIC byte path is
not a syscall tap; claiming L1 would be a lie. The accept origin, handler spans,
per-exchange events and drain behavior are still recorded.

## Invariants & Behavioral Boundaries

- **`[INV-SERVER-22]` H3 Ingress Is a Separate Listener**: an H3 server is an
  `H3Server` bound to a QUIC endpoint, not a mode of the TCP `Server`. *Enforced
  by*: separate type, separate feature, no QUIC branch in `serve_selected`.

- **`[INV-SERVER-23]` H3 Exchange Identity Is Non-Zero**: every H3 ingress
  exchange gets a distinct non-zero trace id; the wire stream id lives in the
  `H3StreamStart` event. *Enforced by*: `next_exchange` in `h3::serve_connection`
  and `http3_ingress` asserting two derived exchanges.

- **`[INV-SERVER-24]` H3 Owns the Same Bounds**: body timeout, handler timeout,
  write timeout, body ceiling and drain apply to H3 through the same
  `ServerConfig`. *Enforced by*: `H3BodySource` and `write_response` consuming
  the config rather than defining protocol-local defaults.

## Consequences

- **Positive**:
  - H3 ingress exists without destabilizing the H1/H2 listener.
  - The same handler serves all three protocols.
  - The trace model gains a truthful H3 L0 connection view.
- **Negative & Trade-offs**:
  - `netune-server`'s production graph grows optional QUIC/H3 leaves when the
    feature is enabled.
  - SNI-based certificate selection is single-config in this slice; a
    `rustls::ServerConfig` is enough for the listener, but per-name selection
    over QUIC requires a lazy server configuration seam that `quinn` does not
    currently expose the way `tokio-rustls` does for TCP.
  - The H3 server advertises its own QPACK/SETTINGS profile; there is no
    protocol-mode switch inside one connection.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): make `Server` generic over TCP and QUIC

The accept, handshake, stream and drain lifecycles are not the same state
machine. A generic abstraction would either be a thin enum with two unrelated
arms or would force H1/H2 into QUIC-shaped per-stream tasks. The stable side
should not pay for the new transport.

### Option 2 (Rejected): put the QUIC listener in `netune-http3`

The leaf may parse and frame H3, but admission, handler dispatch, trace hand-over
and drain are ingress orchestration. Putting them in the leaf would invert the
topology.

## Links

- Related ADRs: [ADR-0011](0011-server-side-ingress-transport.md),
  [ADR-0012](0012-http2-ingress.md),
  [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0023](0023-h3-request-header-order.md),
  [ADR-0026](0026-controlled-dynamic-qpack.md)
