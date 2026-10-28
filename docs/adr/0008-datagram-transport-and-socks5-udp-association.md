---
id: ADR-0008
title: "Datagram Transport and SOCKS5 UDP Association"
status: accepted
date: 2026-10-28
scope: [transport/datagram, proxy/socks5, security/egress]
superseded_by: null
---

# 0008. Datagram Transport and SOCKS5 UDP Association

- Status: Accepted
- Date: 2026-10-28
- Deciders: Ming Li
- Amends: [ADR-0002](0002-egress-confinement-policy.md), [ADR-0006](0006-transport-customizability-wire-evasion.md)

---

## Context and Problem Statement

Until now netune had **no datagram path at all**: `crates/netune/src/` contained zero
references to UDP, and `Proxy` ([proxy.rs](../reference/crates.md)) exposed only `Http`
and `Socks5` over a TCP stream. This blocks every datagram-shaped consumer at once —
QUIC-based proxy protocols, DNS over a tunnel, SOCKS5 UDP associate, voice and game
traffic — and it makes `SocketConfig`'s L3/L4 tuning ([ADR-0006](0006-transport-customizability-wire-evasion.md))
half-applied: a stack that can set `SO_MARK` and buffers for TCP but not for datagrams
cannot answer the one question a transparent proxy always asks, namely *will my own
outbound traffic escape my own capture rules?*

The tempting design is to mirror the TCP surface exactly: a `Connector` that returns a
stream-like object, and a `send_to`/`recv_from` pair so one socket can address many
peers. That design is wrong here, and the reason is architectural rather than cosmetic:

> A per-datagram destination cannot be confinement-checked.

`EgressConfinement` ([ADR-0002](0002-egress-confinement-policy.md)) is checked *before
a socket is opened* (`INV-EGRESS-01..03`). With `send_to(destination, payload)` the peer
is named after the socket exists and changes per datagram, so the invariant would have to
be re-checked on every send, at which point it is a filter on a live socket rather than a
precondition of opening one — and a filter that runs after the socket exists is exactly
the shape the policy was written to forbid.

## Decision Drivers

- Egress confinement must remain a precondition of opening a socket, not a per-datagram
  filter.
- `cargo tree` must show no new third-party runtime: no QUIC, no HTTP, no WS.
- The trace must stay a pure derivation of recorded events (`INV-TRACE-01`), so a
  datagram session needs events or it is invisible.
- A consumer with no datagram traffic (an HTTP-only client) must not pay for this.
- A protocol that multiplexes peers (SOCKS5 associate, QUIC connection IDs, WireGuard)
  must be expressible without reopening the confinement question.

## Considered Options

- **Option 1**: extend `Connector` to return a session that also carries
  `send_to(destination, payload)`, mirroring the TCP traits one-for-one.
- **Option 2**: a parallel `DatagramConnector` / `DatagramTransport` pair whose sessions
  are *connected* to one peer, plus one concrete association connector for the single
  case where the wire protocol itself multiplexes peers.
- **Option 3**: expose only a raw `UdpSocket` wrapper and leave association, framing and
  confinement to each consumer.

## Decision Outcome

Chosen option: **Option 2**, because it is the only one where confinement stays a
precondition and multi-peer protocols remain expressible.

```text
DatagramConnector::connect(authority, recorder)
        └─> EstablishedDatagrams { datagrams: Box<dyn DatagramTransport>, local_port }

DatagramTransport: send(payload) / recv(buffer) / max_datagram_size()
```

The session is **connected to one peer**, decided at `connect`. A protocol that needs a
second peer opens a second session and owns its demultiplexing above this layer. The one
protocol where the peer is chosen by the *proxy* rather than by the caller — SOCKS5 UDP
associate — gets a concrete connector (`Socks5DatagramConnector`) that opens one
association per peer and encapsulates every datagram with that peer's address, so the
multiplexing lives inside the transport where the wire format already requires it.

`DatagramConnector` returns a boxed future instead of being an `async fn`, so the trait is
object-safe: a proxy chain selects a datagram transport at runtime. `DatagramTransport` is
`Send + Sync` so one session can be driven by a send task and a receive task at once.

Direct datagrams use `connect`ed sockets rather than `send_to`. A connected socket keeps
the kernel's ICMP error reporting and reverse-path filter meaningful, and makes `recv`
impossible to confuse with a datagram from an unrelated host.

`UdpConnector` is the datagram twin of `TcpConnector`: same `DnsResolver`, same
`EgressConfinement`, same `SocketConfig`. `SO_MARK` is applied **before** `connect`, for
the same reason it must precede the TCP `SYN` — the mark is consulted when the route is
chosen for the first datagram. `max_datagram_size` is derived from `SO_SNDBUF` (halved on
Linux, where the kernel reports double) and capped at the IP ceiling, so a caller sizing
a buffer from it cannot build a payload that is guaranteed to fail.

### Invariants & Behavioral Boundaries

- `[INV-UDP-01]` **Confinement precedes the socket.** `UdpConnector` resolves, checks
  `EgressConfinement` against every resolved address, and only then opens the socket. A
  refused session records no `UdpOpen`. Enforced by
  `udp::tests::inv_udp_01_confinement_precedes_the_datagram_socket`.
- `[INV-UDP-02]` **A session is one peer.** `DatagramTransport` has no destination
  parameter; the peer is fixed at `connect`. Enforced at the type level: a method that
  could address a second peer does not exist.
- `[INV-UDP-03]` **A relayed datagram must carry the session's source.** A decoded
  SOCKS5 wrapper whose source differs from the destination the caller asked for is
  dropped, never delivered. A hostile or buggy relay cannot deliver a host the caller
  never addressed. Enforced by `tests/udp_socks5.rs::inv_udp_03_a_datagram_claiming_a_foreign_source_is_dropped`.
- `[INV-UDP-04]` **Fragments are refused.** A SOCKS5 UDP request with `FRAG != 0` is
  dropped: netune never emits fragments, and reading a fragment as a whole datagram
  would corrupt the protocol above. Enforced by
  `udp::tests::inv_udp_04_a_fragment_is_refused`.
- `[INV-UDP-05]` **A datagram session records `UdpOpen` and never a handshake.** The
  trace shows `DnsStart`/`UdpOpen` (and `ProxyTunnel` for an association) and may not
  claim `TcpStart`/`TlsStart` for the peer. Enforced by
  `udp::tests::inv_udp_05_a_session_records_open_and_never_a_handshake`.

### Consequences

- **Positive**: one abstraction serves direct UDP, SOCKS5 associate, and (later) QUIC,
  with `INV-EGRESS-01..03` intact. No new dependency: `socket2` and `tokio::net` were
  already present. `SocketConfig` now means the same thing for both transports.
- **Positive**: `EventKind::UdpOpen` / `UdpDatagram` extend the persisted trace codes at
  30/31 without renumbering any existing code, so an older reader degrades to "unknown
  kind" rather than misreading an event.
- **Negative & Trade-offs**: a workload with thousands of peers pays one socket per
  peer. For a `dae`-shaped UDP relay that is bounded and natural (one session per flow);
  for a QUIC server it would not be, but netune is a client stack.
- **Negative & Trade-offs**: SOCKS5 UDP destinations are **literal IP addresses only**.
  A domain destination would require `Target` to carry a second address channel that TLS
  verification and the pool key must both ignore. That is a `Target` redesign with its own
  ADR, so it is refused explicitly (`NetError::UnsupportedEncoding`) rather than closed by
  resolving locally — a local lookup would move the DNS decision away from the caller that
  owns the routing policy. This is the correct shape for a UDP relay, which already knows
  the address its routing decision was made on.
- **Negative & Trade-offs**: an authenticated SOCKS5 association (user/pass) is refused
  rather than attempted: the greeting offered here is the no-auth method, and pretending
  otherwise would send datagrams a proxy silently drops with the payload not arriving.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected)

- **Why considered**: it mirrors the TCP surface exactly, so a reader who knows
  `Connector` knows the datagram side, and one socket serves many peers.
- **Why rejected**: it makes `[INV-EGRESS-02]` unenforceable as a precondition. The
  destination arrives per send, after the socket exists, so confinement degenerates into
  a live filter. It also forces every consumer to implement destination bookkeeping even
  when, as with a UDP relay, each session has exactly one peer.

### Option 3 (Rejected)

- **Why considered**: smallest surface — expose `UdpSocket` and let each consumer frame
  its own datagrams.
- **Why rejected**: it leaves the confinement order to every consumer, and the first one
  to call `connect` before checking an address breaks `[INV-EGRESS-01]`. A boundary is
  enforced by a type or it is not enforced. It also loses `SocketConfig`, which is what
  makes `global.so-mark` meaningful for datagram consumers.
- **What survives**: the plain `UdpSocket` is still reachable (the connected session wraps
  one), so a consumer that genuinely needs `send_to` is not blocked — it just does not get
  to call itself netune's confinement-checked path.

### Also rejected: a QUIC API in this ADR

- **Why considered**: `hysteria2` and `tuic` are the motivating consumers, so an ADR that
  mentions them but ships only UDP could look half-finished.
- **Why rejected**: QUIC is a full protocol implementation (TLS 1.3 handshake integration,
  loss recovery, congestion control, connection IDs), not a socket option. `hysteria2`'s
  Brutal controller additionally needs a pluggable congestion controller that stock
  implementations do not expose. That is a dependency decision worth its own record, and
  bundling it here would make this decision reversible only as a unit. Datagrams stand
  alone and unblock DNS-over-tunnel and SOCKS5 UDP today.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0002](0002-egress-confinement-policy.md),
  [ADR-0006](0006-transport-customizability-wire-evasion.md)
- Public surface: `DatagramConnector`, `DatagramTransport`, `EstablishedDatagrams`,
  `UdpConnector`, `Socks5DatagramConnector` in `crates/netune/src/udp.rs`.
