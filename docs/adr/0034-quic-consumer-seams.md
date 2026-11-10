---
id: ADR-0034
title: "Consumer Seams for the Owned QUIC Transport"
status: accepted
date: 2026-11-10
scope: [transport/quic, api/quic, security/egress, security/tls, recovery/congestion]
superseded_by: null
---

# 0034. Consumer Seams for the Owned QUIC Transport

- Status: Accepted
- Date: 2026-11-10
- Deciders: Ming Li
- Amends: [ADR-0016](0016-quic-and-http3-transport.md)
- Related: [ADR-0002](0002-egress-confinement-policy.md),
  [ADR-0028](0028-owned-quic.md), [ADR-0029](0029-quic-lifecycle-hardening.md),
  [ADR-0031](0031-quic-0rtt-and-session-resumption.md)

---

## Context and Problem Statement

The owned QUIC engine replaced `quinn` as the production transport. A consumer
(`daer`, Hysteria 2 outbound) previously used four capabilities from `quinn`
that do not belong in a generic transport implementation:

1. a datagram stack below QUIC for Salamander/Gecko obfuscation and port
   hopping;
2. a congestion controller pinned to an operator-declared rate (Brutal) rather
   than inferred from loss;
3. connection keep-alive for long-lived NAT bindings; and
4. access to the verified peer certificate chain for `pin-sha256` checks.

Re-implementing any of these inside `netune-quic` would turn a protocol engine
into a product proxy. Forking the engine in the consumer would duplicate the
state machine, lose `netune-trace` boundaries, and drift from confinement and
crypto policy. The first iteration of these seams (`QuicConnector::with_custom_socket`)
also exposed a shared socket on a cloneable connector, which makes concurrent
connections demultiplex datagrams ambiguously. That API is rejected here.

## Decision Drivers

- The production dependency graph must keep one QUIC state machine and one
  trace vocabulary ([INV-TRACE-01], ADR-0028).
- Egress confinement must still precede every socket, including a custom one
  ([INV-EGRESS-01], [INV-QUIC-02]).
- A custom datagram stack must not be able to widen the send path: the engine
  remains the authority for flow control, packet sizing and connection state.
- Product policy must stay outside `QuicProfile`; a profile is resolved data
  used for connection identity, not a bag of callbacks.
- The API must be explicit about ownership: one socket stack belongs to exactly
  one connection.

## Considered Options

### Option 1: Absorb Hysteria 2 behaviour into `netune-quic`

- **Why considered**: one crate, no consumer-side state.
- **Why rejected**: obfuscation keys, port-hopping policy and Brutal's declared
  rate are product wire identity, not QUIC protocol facts. They would make
  `netune-quic` depend on one consumer's deployment model and force every
  consumer to carry code it never executes.

### Option 2: Let the consumer fork or wrap the owned engine

- **Why considered**: preserves a generic core.
- **Why rejected**: the consumer would reimplement packet routing, handshake
  state and recovery, or wrap the engine in a second state machine. Both paths
  recreate the drift ADR-0028 exists to prevent, and neither can produce the
  same trace events or confinement guarantees.

### Option 3: Put callbacks on `QuicProfile`

- **Why considered**: one object configures everything.
- **Why rejected**: `QuicProfile` is resolved through `QuicProfileRegistry` and
  used as connection identity. Closures are not stable identity, do not belong
  in a registry, and would mix connection-fixed policy with per-deployment
  code. It also makes `Clone` and `Debug` on profiles lie.

### Option 4: Narrow ownership seams (chosen)

- **Why considered**: each seam replaces one policy boundary while the engine
  keeps every protocol invariant.
- **Why chosen**: a consumer supplies exactly the capability it owns; the
  engine keeps the state machine, flow control, packet sizing, trace and
  confinement.

## Decision Outcome

Chosen option: **Option 4**.

### 1. Per-connection UDP socket factory

`QuicUdpSocket` is the async datagram interface. `QuicUdpSocketFactory::create`
is called exactly once per connection, after egress confinement has accepted the
target and before the first Initial packet. It receives the target and the
connector's `QuicSocketConfig`, so a transform stack can apply (or explicitly
reject) every pre-connect option. The returned socket belongs to one client
endpoint for one connection; a factory must not return the same socket to
concurrent client calls. A port-hopping wrapper reports its logical peer
address, not each physical hop, so QUIC does not interpret every hop as
connection migration. An ingress endpoint is the one intentional exception:
one bound socket routes many server connections by connection ID, as QUIC
requires.

`Endpoint::client_with_socket` and `Endpoint::server_with_socket` expose the same
interface to callers that own endpoint construction directly. The connector's
`with_custom_socket` is removed; its shared-socket lifetime was ambiguous.

### 2. Per-connection congestion controller

`CongestionControllerFactory::build` is called once per connection. A custom
controller receives ACK, loss and PTO notifications and reports a congestion
window. It does not own packet construction, stream credit, flow control or
datagram sizing; those remain engine responsibilities. Without a factory, the
profile's NewReno/Cubic/BBR selection is unchanged.

### 3. Keep-alive and idle timeout

`QuicProfile.keep_alive` is a client connection policy. When set, the engine
queues a PING after the negotiated receive-inactivity interval, only after the
handshake and only before the idle timeout. A zero interval is a configuration
error.

The engine also enforces the RFC 9000 Section 10.1 idle timeout: the effective
value is the minimum non-zero `max_idle_timeout` advertised by either endpoint,
lifted to at least three times the current PTO. An idle close is silent (no
`CONNECTION_CLOSE`) and discards queued frames. Sending an ack-eliciting packet
restarts the idle timer only when none has been sent since the last
successfully processed peer packet.

### 4. Verified peer identity

`Connection::peer_certificates` returns the chain produced by the rustls
session after the configured verifier accepted it. netune does not implement
pinning, trust-on-first-use, or a CA bypass. A consumer that needs
`pin-sha256` checks performs them before sending sensitive application data;
a failed check is a consumer policy decision and a normal connection close.

### Invariants & Behavioral Boundaries

- **`[INV-QUIC-18]` Confinement Precedes Socket Creation**: a target refused by
  `EgressConfinement` never reaches a socket factory and never opens a socket.
  *Enforced by*: `QuicConnector::connect_early` ordering and
  `a_refused_target_never_invokes_the_socket_factory`.
- **`[INV-QUIC-19]` One Factory Invocation per Client Connection**: a client
  factory is invoked exactly once for each connection, and the endpoint owns
  the returned socket for that connection's lifetime; a factory must not hand
  the same socket to concurrent client calls. An ingress endpoint owns one
  bound socket and routes many connections by connection ID. *Enforced by*:
  `a_factory_is_invoked_once_for_each_connection` and the one-call assertion in
  `a_connector_factory_creates_one_socket_after_confinement`.
- **`[INV-QUIC-20]` Custom Controllers Are Policy, Not Authority**: a custom
  window gates sends but never grants flow-control credit, changes packet
  sizing, or bypasses stream/connection limits. *Enforced by*: the packet budget
  in `Core::poll_transmit` and `many_streams_never_produce_an_oversized_datagram`.
- **`[INV-QUIC-21]` Keep-Alive Is a PING**: keep-alive never carries application
  data, never fires before the handshake, and never outlives the negotiated idle
  timer. *Enforced by*: `keep_alive_queues_a_ping_before_the_idle_timeout`,
  `keep_alive_does_not_fire_before_its_interval` and the idle-timeout test.
- **`[INV-QUIC-22]` Peer Certificates Are Post-Verification**: the exposed chain
  is exactly the one rustls verified; netune adds no pinning or bypass.
  *Enforced by*: `TlsSession::peer_certificates` reads the session result;
  `peer_certificates_are_post_verification` proves a verified chain is exposed
  and `an_untrusted_certificate_never_yields_a_connection` proves a wrong root
  fails before `connect` returns.

### Consequences

- **Positive**: consumers can run obfuscation, port hopping, Brutal, keep-alive
  and certificate pinning without forking the engine. Trace, confinement and
  packet sizing remain structural. The shared-socket ambiguity is gone.
- **Negative & Trade-offs**: a custom factory is responsible for applying
  `QuicSocketConfig` or rejecting it; netune cannot prove a third-party socket
  honours the config. Custom congestion control can still be a bad policy; the
  engine bounds its blast radius, not its quality. Keep-alive is a client
  profile policy on the client and `ServerOptions` on ingress; both feed the
  same bounded PING/idle implementation. The low-level
  `Endpoint::server_with_socket` and the orchestrator's
  `H3Server::bind_with_socket` expose the ingress socket seam; both use one
  bound socket for the listener lifetime and route accepted connections by
  connection ID. `H3Server::bind_with_quic_options` exposes server keep-alive
  and congestion policy without putting callbacks in a wire profile.
- **Breaking**: `QuicConnector::with_custom_socket` is removed. Callers implement
  `QuicUdpSocketFactory` and use `with_socket_factory`. The project is pre-1.0
  and publishes from `0.0.x`, so the break is a normal patch-line change.

## Rejected Alternatives & Negative Knowledge

### Socket object stored on the connector (rejected)

- **Why considered**: smallest API.
- **Why rejected**: a cloned connector could open multiple endpoints over one
  socket; each endpoint driver would race for datagrams. A factory makes the
  per-connection lifetime explicit and lets a port-hopping implementation own
  its shared state behind the factory.

### Socket configuration on the trait object (rejected)

- **Why considered**: the custom stack could configure itself.
- **Why rejected**: configuration belongs to the connector and must be applied
  before the first packet. Passing a `QuicSocketConfig` snapshot to the factory
  keeps one source of truth and makes an unsupported option an explicit error
  rather than a silent skip.

### Congestion controller as a trait object inside `QuicProfile` (rejected)

- **Why considered**: no second registry.
- **Why rejected**: profile identity is resolved before connect and may be
  shared by many connections; a controller is mutable per connection. A factory
  is the only shape that preserves both lifetimes.

### Implementing pinning in `netune-quic` (rejected)

- **Why considered**: one less consumer callback.
- **Why rejected**: certificate pinning is an application trust policy. It
  changes per deployment and must fail before data is sent. Exposing the
  verified chain keeps the transport generic and the policy auditable in the
  consumer.

## Links

- [ADR-0016](0016-quic-and-http3-transport.md) — QUIC/HTTP3 transport
- [ADR-0028](0028-owned-quic.md) — owned QUIC engine
- [ADR-0029](0029-quic-lifecycle-hardening.md) — lifecycle hardening
- [ADR-0031](0031-quic-0rtt-and-session-resumption.md) — 0-RTT and resumption
- [RFC 9000 Section 10.1](https://www.rfc-editor.org/rfc/rfc9000#section-10.1)
