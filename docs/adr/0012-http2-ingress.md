---
id: ADR-0012
title: "HTTP/2 Ingress: One Connection Machine, Two Roles, One Handler"
status: accepted
date: 2026-11-06
scope: [transport/ingress, protocol/rfc9113, workspace/topology]
superseded_by: null
---

# 0012. HTTP/2 Ingress: One Connection Machine, Two Roles, One Handler

- Status: Accepted
- Date: 2026-11-06
- Deciders: Ming Li
- Amends: [ADR-0011](0011-server-side-ingress-transport.md)

---

## Context and Problem Statement

[ADR-0011](0011-server-side-ingress-transport.md) shipped an HTTP/1.1 ingress path and stated the
omission plainly: *"HTTP/2 ingress is deliberately not part of this decision. It needs its own
accept-time SETTINGS exchange, a stream scheduler and flow-control accounting."*

The omission has now become the constraint. Every client that matters — every browser, every gRPC
client, most service meshes — opens with ALPN `h2`. A listener that speaks only HTTP/1.1 is therefore
not a listener an operator can put behind a TLS terminator without either forwarding the protocol
choice to a third-party terminator (which is exactly the observability loss ADR-0011 was written
against) or accepting that the majority of its traffic takes an HTTP/1.1 fallback path that exists
only because of us.

The question is not "should HTTP/2 ingress exist". It is: **where does a multiplexed protocol live in a
workspace built on one-exchange-per-attempt traces, and how do the HTTP/1.1 red-lines survive a
protocol that has no chunked encoding, no `Host` header, and no single request at a time?**

Three facts make this a decision rather than a task:

1. **`[INV-SERVER-07]` says one derivation describes one exchange.** HTTP/2 interleaves exchanges on
   one connection, so an event's *position* is not its exchange. The trace model has no way to describe
   that today.
2. **The connection layer is where Http/2 bugs are expensive.** Frame bounds, `CONTINUATION`
   contiguity, `SETTINGS` application, and flow-control accounting are direction-agnostic, and a
   second implementation of them is a second place a fix can be forgotten — the argument ADR-0011 made
   for the chunked decoder.
3. **Two protocols over one application is the actual product requirement.** An operator must not have
   to write their routing twice because we could not decide where the protocol boundary lives.

## Decision Drivers

- Ingress timings must remain pure derivations of recorded events, in both protocols
  (`[INV-TRACE-01]`, `[INV-SERVER-02]`).
- A multiplexed trace must be derivable per exchange, or the derivation must refuse — never describe
  one exchange with another's numbers (`[INV-SERVER-07]`).
- The codec must stay a leaf: no socket, no clock, no trace model, no policy (`ADR-0003`).
- One protocol per connection, decided once. An in-place upgrade is a request-smuggling surface and a
  second parser on one socket.
- An application writes one handler. Two handler traits would be a framework decision this crate has
  no business making.

## Considered Options

- **Option 1**: HTTP/2 ingress as a second, independent connection loop inside `netune-server`,
  duplicating frame reading, SETTINGS handling and flow control.
- **Option 2**: a third orchestrator `netune-h2-server`, agreeing with `netune-server` by convention.
- **Option 3**: split `netune-http2` into a direction-agnostic connection machine plus two thin role
  modules, add the per-stream identity to the trace model, and dispatch both protocols from the one
  listener through one `Handler`.
- **Option 4**: terminate HTTP/2 in front of the listener (nginx, Envoy) and keep speaking HTTP/1.1
  inward.

## Decision Outcome

Chosen option: **"Option 3"**, for four reasons that each follow from a constraint already in this
repository:

1. **One connection machine, two roles.** `netune-http2::connection::H2Connection` owns frame reading
   with the *local* advertised maximum, `SETTINGS` exchange and acknowledgement, `PING` echo, `GOAWAY`
   bookkeeping, HPACK with its dynamic table, `CONTINUATION` reassembly with contiguity enforced, and
   both flow-control windows. `Role` is a parameter, not a second module. `client` and `server` are the
   thin roles that differ in three things only: who sends the preface, which stream-id parity each may
   originate, and which direction `HEADERS` carries a request in.
2. **The trace learns stream identity.** `Event` and `EncodedEvent` gain a `stream: u32`, `0` for
   everything that cannot multiplex (all of egress, all of HTTP/1.1 ingress) and the protocol's own
   stream id for HTTP/2. `derive_ingress_exchanges` splits a multiplexed log *by stream* instead of by
   position, so two genuinely simultaneous exchanges each derive their own spans. `derive_ingress`
   still refuses a multi-exchange log — the invariant is unchanged, it now has a shape that can
   actually be derived.
3. **A codec may not depend on a trace model.** The HTTP/2 server role reports `StreamEvent`s to a
   `SessionObserver` it defines, and the orchestrator adapts them to `EventKind`. Putting `Recorder` in
   the codec would have inverted `ADR-0003`'s leaf rule for the sake of saving an adapter.
4. **One handler, two protocols.** `netune-server` translates `H2Request` into the same
   `IncomingRequest` an HTTP/1.1 handler already receives — including synthesising `host` from
   `:authority` and dropping `Connection`, which HTTP/2 forbids (§8.2.2) — and translates `Response`
   back, turning a `BodyStream` into a channel of `DATA` frames. An application's routing is written
   once.

### Invariants & Behavioral Boundaries

- **`[INV-SERVER-08]` One Connection Machine**: frame reading, `SETTINGS`, `PING`, `GOAWAY`, HPACK and
  flow-control accounting exist once in `netune-http2::connection` and take `Role` as data; a second
  implementation for either end is prohibited. *Enforced by*: `netune-http2` has one `H2Connection`,
  and `role()` is a field rather than a module boundary; the two roles' tests both drive it.
- **`[INV-SERVER-09]` One Protocol Per Connection**: a connection is HTTP/1.1 or HTTP/2, decided from
  its first bytes or its ALPN result, and never upgraded in place. A listener that does not offer the
  protocol a peer asked for refuses it (`505`) rather than downgrading. *Enforced by*:
  `the first bytes select the protocol` and `http2_is_refused_when_the_listener_does_not_offer_it` in
  `crates/netune-server/tests/production.rs`; there is no upgrade path in the accept loop.
- **`[INV-SERVER-10]` A Multiplexed Log Is Split By Stream**: a trace whose events carry
  `stream != 0` is grouped by that field, never by position, and a connection-level failure is
  copied into every sub-log it ended. *Enforced by*: `split_multiplexed` in
  `netune-trace/src/derive_ingress.rs`, and the multiplexed derivation test.
- **`[INV-SERVER-11]` Both Receive Windows Are Enforced And Credited On Consumption**: inbound `DATA`
  is charged against the connection window *and* the stream window, an overrun is a `FLOW_CONTROL_ERROR`,
  and credit is returned to each when the handler consumes bytes rather than when a frame arrives.
  *Enforced by*: `H2Connection::consume_inbound` and `SessionState::recv_window`;
  `a_body_larger_than_the_window_is_delivered_whole` and
  `a_request_body_larger_than_the_stream_window_is_accepted` drive 256 KiB through a 64 KiB window in
  each direction.
- **`[INV-SERVER-17]` A Protocol A Build Cannot Speak Is Refused, Not Absorbed**: `Protocols` defaults to
  what the compiled feature set can serve, an explicit request for an absent protocol fails at bind
  time, and a listener refuses any protocol it does not offer in *either* direction. *Enforced by*:
  `the_default_protocols_are_ones_this_build_can_serve`, `asking_for_http2_in_a_build_that_omits_it_is_refused_at_bind_time`,
  `http2_is_refused_when_the_listener_does_not_offer_it` and
  `an_http2_only_listener_refuses_http11_instead_of_serving_it`.

### Consequences

- **Positive**:
  - An application serves both protocols behind one handler, so its routing, its body handling and its
    streaming are written once.
  - The trace can now describe a genuinely multiplexed connection per exchange, which is the case
    `[INV-SERVER-07]` existed to refuse.
  - The egress client and the ingress server share the connection machine, so a framing fix lands in
    one file and both ends get it.
  - The `H2Connection` decoder now strips `PADDED` and `PRIORITY`, which the previous client-only
    implementation ignored — a conforming client that pads (as privacy-preserving clients do) would
    have had its pad-length octet decoded as a header block.
- **Negative & Trade-offs**:
  - `Event` grew a field. The delta encoding carries it, so the wire form of a trace changed; there is
    no compatibility shim, by design (this workspace has no published trace format version 1).
  - The HTTP/2 server keeps one writer task and one read loop, so a *handler* cannot write directly to
    the socket. Full-duplex streaming therefore needs the application to buffer or spawn; a transport
    that let a handler own the write half could not enforce flow control or framing.
  - `netune-server`'s production graph now contains `netune-http2`, so `the shared leaves are the only
    shared dependencies` had to be corrected. The `netune-ws` exclusion stands: WebSocket ingress is
    still a later decision.
  - Priority *scheduling* is still not implemented. `PRIORITY` frames are accepted and ignored, which
    RFC 9113 §5.3.1 explicitly permits; a real scheduler is policy and belongs above a transport.
  - The codec is behind a default-on `http2` feature, so an HTTP/1.1-only listener does not link
    HPACK's Huffman tables or the frame decoder. That is the same argument `netune` makes for its own
    codec features: a parser on an externally-controlled byte path that is never executed is attack
    surface, not insurance.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): A Second Connection Loop In `netune-server`

- **Why considered**: no leaf changes; the HTTP/2 code sits next to the HTTP/1.1 code it serves.
- **Why rejected**: frame reading, `SETTINGS` application, `CONTINUATION` contiguity and flow control
  are the whole bug surface of HTTP/2, and a second copy would be exercised by whatever tests were
  written for it rather than by the client suite that has been failing against real servers for
  months. The two copies would diverge exactly where the protocol is subtle: `SETTINGS` retroactivity,
  zero-increment `WINDOW_UPDATE`, `PADDED` stripping.

### Option 2 (Rejected): A Third Orchestrator `netune-h2-server`

- **Why considered**: HTTP/2's concurrency model has nothing in common with HTTP/1.1's, so one crate
  per model looks clean.
- **Why rejected**: the *listener* is shared — admission control, the permit semaphore, the trace
  origin, the drain deadline and the `Handler` trait are identical. Two crates would either duplicate
  the accept loop or need a fourth crate for it, and `[INV-SERVER-01]`'s "two orchestrators" would
  quietly become three with no boundary that justified it. The concurrency difference belongs inside a
  connection, not around a listener.

### Option 4 (Rejected): Terminate HTTP/2 In Front Of The Listener

- **Why considered**: zero new surface; the mature option an operator would pick today.
- **Why rejected**: it is ADR-0011's Option 4 in a different costume. A fronting proxy owns the read
  loop, so the accept-queue dwell time, the upload/handler overlap and the write-side stall cause are
  again unobservable — and with HTTP/2 the loss is worse, because stream concurrency is exactly the
  thing a proxy will not report per stream. It also makes the workspace's own client the only HTTP/2
  implementation here, which is a position that cannot be tested in the direction that matters.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md),
  [ADR-0006](0006-transport-customizability-wire-evasion.md),
  [ADR-0011](0011-server-side-ingress-transport.md)
