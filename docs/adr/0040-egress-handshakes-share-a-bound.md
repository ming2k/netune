---
id: ADR-0040
title: "Every Egress Connection-Establishment Phase Shares a Configurable Bound"
status: accepted
date: 2026-11-10
scope: [transport/egress, transport/proxy, transport/http2, transport/websocket, transport/datagram, observability]
superseded_by: null
---

# 0040. Every Egress Connection-Establishment Phase Shares a Configurable Bound

- Status: Accepted
- Date: 2026-11-10
- Deciders: Ming Li
- Amends: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0005](0005-keepalive-socket-culling-absorption.md), [ADR-0008](0008-datagram-transport-and-socks5-udp-association.md), [ADR-0017](0017-tiered-observation-and-connection-identity.md)

---

## Context and Problem Statement

A request does not exist until several peer-controlled exchanges have finished:
DNS resolution, TCP establishment, the proxy tunnel, TLS, the HTTP/2 preface
and SETTINGS exchange, and — for an upgrade — the WebSocket response. Each of
those phases can stop after the previous one succeeded. A peer can accept TCP
and never answer the ClientHello, complete TLS and never answer SETTINGS, or
accept `CONNECT` and never answer the tunnel request.

ADR-0001 and ADR-0005 bound the *request* path: a streaming response carries no
overall deadline, and a pooled socket that drops before the response head is
replaced. That is the correct shape for generation, but it leaves establishment
unbounded. When a phase stalls, the failure surfaces at an outer streaming
watchdog as a generation timeout, which misnames the broken phase and spends the
caller's retry budget on a connection that never existed.

The transport already bounded DNS/TCP (`TcpConnector::connect_timeout`) and TLS
(`with_handshake_timeout`), and ingress bounded its own HTTP/2 handshake. The
egress half remained incomplete: `H2ClientConnection::handshake`,
`ProxyConnector`'s tunnel exchange, the SOCKS5 UDP associate, and the WebSocket
upgrade all waited without a bound. The proxy module even documented both
handshakes as "bounded" while no clock was attached to either. A comment is not
a mechanism.

## Decision Drivers

- **Name the stalled phase.** A timeout must be a retryable connect failure that
  identifies the phase and peer, not a generation failure reported by a
  watchdog three layers up.
- **Never bound the stream.** A long model generation is legitimate; only
  connection establishment has a completion point that can be required.
- **One policy, explicit overrides.** Operators should reason about one default
  handshake budget, while a caller with an outer deadline can remove a phase's
  bound deliberately.
- **No clocks in codecs.** `netune-http2` and `netune-ws` own wire framing; the
  orchestrator owns the policy that says how long the peer may take.
- **Observability stays structural.** A bound must not invent a synthetic
  measurement; it turns absence of a recorded completion event into a typed
  failure that the attempt trace can explain.

## Considered Options

- **Option 1: One overall request deadline** on every `Client::send`. Rejected:
  it cuts legitimate long streams and repeats the bug ADR-0005 fixed.
- **Option 2: Put timeouts inside the codecs.** Rejected: it gives protocol
  leaves a clock and a retry policy they do not own, and makes the bound
  impossible to vary at the orchestrator.
- **Option 3: A fixed, non-configurable constant per phase.** Rejected: tests
  need short bounds, an embedding caller may already have a deadline, and a
  future proxy or upgrade protocol would tempt another constant.
- **Option 4: A shared default plus per-phase override, applied by the
  orchestrator/connector that owns the phase.** Chosen.

## Decision Outcome

Chosen option: "Option 4". `netune` owns a single private
`DEFAULT_HANDSHAKE_TIMEOUT` (10 s) and a `handshake::bound` helper that runs a
phase future under an optional limit. Expiry is always
`NetError::Connect`, which `NetError::is_retryable` already classifies as
retryable: the request was never dispatched.

The phases and their override surfaces are:

| Phase | Owner | Override |
| :--- | :--- | :--- |
| DNS + TCP | `TcpConnector` | `with_connect_timeout` |
| Proxy tunnel (HTTP `CONNECT` / SOCKS5 greeting + request) | `ProxyConnector` | `with_handshake_timeout` |
| TLS | `TlsConnector`, `TlsRouterConnector` | `with_handshake_timeout` |
| HTTP/2 preface + SETTINGS + peer ACK | `Client`, `H2Client` | `ClientConfig::h2_handshake_timeout`, `H2Client::with_handshake_timeout` |
| WebSocket upgrade response | `Client::connect_ws*` | `WsHandshake::with_handshake_timeout` |
| SOCKS5 UDP associate | `Socks5DatagramConnector` | `with_handshake_timeout` |

`None` removes a bound. It is valid only when the caller has an outer deadline
that reports the stall as a connection failure; the documentation on each
override says so. A pooled HTTP/2 connection is not re-bound: it already
completed the exchange, and its liveness is the pool's concern.

The bound covers the whole exchange a peer controls, not each read: a peer that
dribbles SETTINGS fragments or proxy bytes cannot reset a per-read timer by
making progress. Write and read both live inside the same future.

### Invariants & Behavioral Boundaries

- **`[INV-TRANSPORT-05]` Establishment Is Bounded**: every egress
  connection-establishment phase after DNS/TCP completes under a configurable
  bound whose default is `DEFAULT_HANDSHAKE_TIMEOUT`; expiry is a retryable
  `NetError::Connect` naming the phase, and no stalled connection enters the
  pool. Enforced by `a_peer_that_never_answers_settings_is_bounded`,
  `a_proxy_that_never_answers_connect_is_bounded`,
  `a_socks5_proxy_that_never_answers_is_bounded`,
  `a_peer_that_never_answers_the_upgrade_is_bounded`, and
  `a_control_connection_that_never_answers_is_bounded`.

### Consequences

- **Positive**: a half-open peer is reported as a connection failure in one
  place, with the phase named, before any streaming watchdog fires. A
  generation retry is not spent on a connection that never became usable. The
  proxy module's documentation is now true by construction.
- **Positive**: one default makes the transport's worst-case establishment
  latency predictable; per-phase overrides keep embedding possible.
- **Negative & Trade-offs**: a proxy or origin slower than 10 s to finish its
  handshake now fails by default. A caller on such a path must opt into a
  longer or absent bound, exactly as it would for `connect_timeout` or TLS.

## Rejected Alternatives & Negative Knowledge

### Overall Request Deadline (Rejected)

- **Why considered**: one field would cover every phase.
- **Why rejected**: it also covers the response body, so a healthy long
  generation is cut. A transport cannot distinguish "slow prefill" from
  "stalled handshake" once the request is dispatched.

### Codec-Owned Timeouts (Rejected)

- **Why considered**: both `H2ClientConnection::handshake` and a WebSocket
  upgrade read are conveniently located in the protocol layer.
- **Why rejected**: codecs would read ambient clocks and need a retry
  classification they do not own. The same codec is used by ingress and tests
  where the policy differs.

### A Bound That Never Expires to Preserve Compatibility (Rejected)

- **Why considered**: an unbounded default changes no existing caller.
- **Why rejected**: that is the failure mode this ADR exists to remove. The
  default must be finite; compatibility is preserved by the explicit `None`
  override, not by leaving production half-open.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0005](0005-keepalive-socket-culling-absorption.md),
  [ADR-0008](0008-datagram-transport-and-socks5-udp-association.md),
  [ADR-0017](0017-tiered-observation-and-connection-identity.md)
- Verification: `docs/dev/testing.md` §1 and the integration tests named in
  `[INV-TRANSPORT-05]`.
