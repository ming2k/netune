---
id: ADR-0011
title: "Server-Side Ingress Is a Second Orchestrator, Not a Mode of the Egress Stack"
status: accepted
date: 2026-11-01
scope: [transport/ingress, workspace/topology, trace/ingress, protocol/rfc9112]
superseded_by: null
---

# 0011. Server-Side Ingress Is a Second Orchestrator, Not a Mode of the Egress Stack

- Status: Accepted
- Date: 2026-11-01
- Deciders: Ming Li
- Amends: [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md),
  [ADR-0007](0007-owned-client-websocket-codec.md)

---

## Context and Problem Statement

Every invariant in this workspace was written for one direction of travel: bytes
leaving a harness. `EgressConfinement` is a precondition of `connect`
(`INV-EGRESS-01`), `Pool` culls idle sockets before a gateway does
(`INV-TRANSPORT-01..04`), and `[INV-WS-01]` stated the conclusion of that
worldview outright — *"server-side accept/listen code exists nowhere in the
workspace"*.

That was correct while the stack had one job, and it is now the thing blocking
the next one. The reason is not completeness for its own sake. It is that the
observability contract this project is built on — *every timing a surface shows
is a pure function of a recorded trace* (`INV-TRACE-01`) — has no server-side
counterpart anywhere in the Rust ecosystem that this project would accept. A
deployed service can tell you its handler duration from a `tracing` span and
still cannot tell you how long the request sat in the kernel accept queue, how
much of the client's upload overlapped the handler, or whether the response
stalled because the handler was slow or because the peer's receive window was
closed. Those numbers exist; they are simply never recorded, because a
third-party HTTP server owns the read loop and exposes only what it chose to.

So the question is not "should a server exist". It is: **where does a server
live in a workspace whose entire topology encodes an egress-only worldview, and
what happens to the red-lines that encoded it?**

## Decision Drivers

- Server observability must obey `INV-TRACE-01` exactly as the client does:
  ingress timings are pure derivations of recorded events, never ambient clock
  reads.
- Two products in one crate is the failure `ADR-0007` already rejected once: a
  listening runtime (accept queue, session table, backpressure, graceful drain)
  has no shared state machine with an egress connector (DNS, confinement, TLS
  profiles, pool).
- Cargo features are additive (`ADR-0003`, Option 1's rejection): a `server`
  feature on `netune` would let any transitive dependency compile an accept loop
  into a client-only binary. Unacceptable.
- A codec that cannot be exercised from both ends cannot be differential-tested
  against the oracle it claims parity with. `hyper` can play client *or* server;
  a one-directional codec can only be compared in one direction.
- Chunked framing is a request-smuggling surface. Two copies of it — one client,
  one server — is a bug fixed in one and left armed in the other.

## Considered Options

- **Option 1**: add `--features server` to `netune` and put the accept loop
  beside `Client`.
- **Option 2**: put the accept loop in a new crate `netune-server`, duplicating
  the HTTP/1.1 parser for the request direction inside it.
- **Option 3**: split `netune-http1` into a direction-agnostic framing core plus
  two thin role readers, add a second orchestrator `netune-server` that depends
  only on leaf crates, and move the byte-path instrumentation both orchestrators
  need into its own leaf.
- **Option 4**: keep the workspace client-only and tell consumers to use `hyper`
  for anything that listens.

## Decision Outcome

Chosen option: **"Option 3"**, for four reasons that are each a consequence of a
constraint already in this repository:

1. **One framing core, two roles.** `netune-http1`'s body state machine
   (`BodyState`, chunk-size parsing, trailer draining, the bounded line reader)
   is direction-agnostic; only the start line and the framing *decision* differ.
   It becomes a shared `StreamState` behind `Http1Reader` (response direction,
   client role) and `Http1ServerReader` (request direction, server role). There
   is one implementation of chunked decoding, so a smuggling fix cannot land in
   one role and miss the other.
2. **Two orchestrators, one leaf layer.** `netune` composes egress;
   `netune-server` composes ingress. Neither depends on the other. They share
   `netune-trace`, `netune-http1`, and `netune-io`, all of which remain pure
   (no socket, no policy, no clock).
3. **The instrumentation moves to a leaf.** `TimedIo` and `FaultIo` are
   `AsyncRead`/`AsyncWrite` wrappers over a `Recorder` with no policy and no
   socket. Leaving them in `netune` would force `netune-server` to depend on the
   egress orchestrator — an inversion. They move to `netune-io`, and `netune`
   re-exports them so its surface is unchanged in name and unchanged in
   behaviour.
4. **The ingress trace vocabulary is distinct, and so is its derivation.** A
   server's anchors are not a client's: there is no DNS, no connect, no pool
   reuse, and the interesting span is `handler` rather than `first token`.
   `EventKind` gains an ingress family at offsets 32+ and `derive_ingress`
   anchors on `IngressDispatch`. `derive` (egress) is untouched, so no existing
   consumer's numbers change meaning.

### Invariants & Behavioral Boundaries

- **`[INV-SERVER-01]` Two Orchestrators, No Cross-Dependency**: `netune` and
  `netune-server` must not depend on each other in either direction. Neither may
  be a feature of the other. *Enforced by*: `cargo tree -p netune` shows no
  `netune-server`, and `cargo tree -p netune-server` shows no `netune`; the
  workspace dependency rule in `docs/dev/architecture.md` §1.
- **`[INV-SERVER-02]` Ingress Timings Are Pure Derivations**: every ingress
  timing is a function of the ingress `Recorder`'s events, anchored on
  `EventKind::IngressDispatch`. A surface must not read a clock to produce one.
  *Enforced by*: `derive_ingress` takes only a `&RequestTrace`; every field is a
  `Reading<u64>`.
- **`[INV-SERVER-03]` A Request Is Bounded Before It Is Served**: the head, the
  header count, the body and the time allowed to produce them are all bounded
  before the handler is invoked, so a slow or oversized peer cannot consume
  worker time or memory the operator did not grant. A violation closes the
  connection without invoking the handler. *Enforced by*: `Limits` re-used from
  the codec, `ServerConfig::head_timeout`, and the pre-dispatch tests.
- **`[INV-SERVER-04]` One Framing Implementation**: request- and
  response-direction body decoding share one state machine; chunked decoding
  exists once. *Enforced by*: `netune-http1` has a single `StreamState` and a
  test that runs the same corpus through both roles.
- **`[INV-SERVER-05]` Concurrency Is Capped, and Shedding Is Explicit**: the
  number of simultaneously served connections is bounded by configuration, and
  a connection that cannot be admitted is closed rather than queued without
  limit. *Enforced by*: `ServerConfig::max_connections` gates on a semaphore
  permit acquired before the connection task is spawned.
- **`[INV-SERVER-06]` Shutdown Drains** (amends `[INV-WS-01]`): on shutdown the
  listener stops accepting, in-flight exchanges are allowed to finish up to a
  deadline, and only then are their sockets closed.
- **`[INV-SERVER-07]` One Derivation Describes One Exchange**: a derivation over a
  trace either describes exactly one exchange or refuses. A connection that served
  several requests must not report one set of spans, because a reader would conclude the
  handler is fast while a later request on the same connection took far longer. *Enforced
  by*: `derive_ingress` returns `NotEstimable(MultipleExchanges)` when the log holds more
  than one `RequestHeadComplete`, and `derive_ingress_exchanges` is the per-exchange
  view.

### Consequences

- **Positive**:
  - Ingress timings — `dispatch_us`, `request_read_us`, `handler_us`,
    `response_write_us`, `e2e_us` — are measured, not guessed, and carry the same
    `Validity` verdicts as egress numbers.
  - `netune-http1` is now differential-testable in both directions against one
    oracle (`hyper` as client for our server role, `hyper` as server for our
    client role), which is strictly stronger than the previous single-direction
    corpus.
  - `netune-server` is usable as a reference origin for this workspace's own
    client tests, so the loopback scaffolding in `crates/netune/tests/` can be
    replaced by code under test rather than by ad-hoc byte literals.
- **Negative & Trade-offs**:
  - The workspace now ships something that listens. The privilege argument that
    `netune-probe`'s transmit path is gated no longer implies "nothing in this
    repository can accept a connection"; it now means "the *default build of
    each crate* contains only what that crate is for", which is what
    `[INV-PROBE-01]` actually said.
  - `[INV-WS-01]`'s wording ("server-side accept/listen code exists nowhere in
    the workspace") is retired in place: the WebSocket *transport surface in
    `netune`* remains client-only, and a WS upgrade will be served by
    `netune-server` as a separate ingress path when that lands. The codec's
    `Role::Server` support stops being test-only, which was always the honest
    reading of it.
  - HTTP/2 ingress is deliberately not part of this decision. It needs its own
    accept-time SETTINGS exchange, stream scheduler and flow-control accounting,
    and bundling it here would make the first ingress path un-reviewable.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): `--features server` on `netune`

- **Why considered**: one crate, one mental model, no new topology.
- **Why rejected**: Cargo features are additive across the dependency graph, so
  a single transitive `features = ["server"]` would compile an accept loop and a
  listener into every consumer of `netune` — including the ones whose entire
  security posture rests on being unable to accept inbound connections. This is
  the same failure the monolithic-crate alternative to `ADR-0003` was rejected
  for, and it does not become acceptable because the code is new.

### Option 2 (Rejected): Accept Loop in `netune-server`, Parser Duplicated There

- **Why considered**: fastest route; nothing in the existing codec changes.
- **Why rejected**: HTTP/1.1 request-direction framing is not a small copy — it
  is the chunked decoder, the trailer drain, the line-bounded reader and the
  `Content-Length`/`Transfer-Encoding` conflict rules, i.e. exactly the
  request-smuggling surface. Two copies means the client-side copy is exercised
  by 30 differential cases and the server-side copy by whatever was written for
  it, and a divergence shows up as a smuggling vulnerability rather than a test
  failure.

### Option 4 (Rejected): Stay Client-Only, Point Consumers at `hyper`

- **Why considered**: zero new surface; `hyper` is battle-tested at exactly
  this.
- **Why rejected**: it forfeits the only thing this project sells. A `hyper`
  server hides the read loop, so the kernel-queue dwell time, the upload/handler
  overlap and the write-side stall cause are all unobservable — the same
  argument `ADR-0001` made against `hyper` as a client, and it does not weaken
  in the other direction. It also breaks `INV-TRANSPORT-00`'s spirit: a
  workspace that refuses a third-party HTTP client while recommending a
  third-party HTTP server has not made a decision, it has made an exception.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md),
  [ADR-0006](0006-transport-customizability-wire-evasion.md),
  [ADR-0007](0007-owned-client-websocket-codec.md),
  [ADR-0010](0010-quic-ownership-and-trace-sink.md)
