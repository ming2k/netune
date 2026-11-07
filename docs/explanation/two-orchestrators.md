# Why Ingress Is a Second Orchestrator

`netune` was built for one direction of travel: bytes leaving a harness. Every invariant in
this repository was written in that frame, and one of them said so outright — *"server-side
accept/listen code exists nowhere in the workspace"* (`[INV-WS-01]`, as originally written).

Then the workspace grew a server. This article is about why that was the right change, why
it could not be a small one, and what it cost the design.

---

## The observation that made it necessary

The contract this project sells is single and specific: **every timing a surface shows is a
pure function of a recorded trace** (`INV-TRACE-01`). Not a `tracing` span around a handler.
Not an elapsed clock. A recorded event, and a derivation from it.

On the egress side, that contract is already load-bearing. It is why the harness can say
`server_ttft_us` was 180 ms rather than "the request felt slow", and why it refuses to
report the number at all when the head and the first body byte arrived in one flush
(`Reason::TransportBatched`). Honest absence over flattering numbers.

The same programme had nothing on the ingress side, and the reason is structural rather
than accidental. A deployed service can report its handler duration and still cannot answer:

- How long did the request sit between the kernel accept queue and the first byte read?
- Did the client spend 40 ms sending its head, and was that the client or our worker being
  descheduled?
- The response took 3 s — was the handler slow, or was the peer's receive window closed and
  our write blocked?
- Did we delay this request *after* parsing it and *before* the handler, and why?

Those numbers exist in every server. They are simply never recorded, because a third-party
HTTP server owns the read loop and exposes what it chose to. `hyper` is excellent and is
still the oracle this workspace measures itself against — but from the outside, its read
loop is opaque in exactly the way `ADR-0001` rejected for the client.

So: the workspace that refuses a third-party HTTP client while recommending a third-party
HTTP server has not made a decision. It has made an exception.

## Why it could not be `--features server`

The fastest path would have been a flag. It is also the one `ADR-0003` had already rejected
for a different purpose, for a reason that does not weaken here:

> Cargo features are additive across the dependency graph.

If `netune` grew a `server` feature, then any transitive dependency enabling it would compile
an accept loop and a listener into every consumer of `netune` — including the ones whose
security posture rests on being structurally unable to accept an inbound connection. A
boundary you can only hold by asking politely is not a boundary.

Two products in one crate is also the failure `ADR-0007` rejected once already: an egress
connector and an ingress listener share no state machine. One is DNS, confinement, TLS
identity and pooling; the other is an accept queue, admission control, slow-peer bounds and a
drain. Merging them would produce a crate with two lifetimes, two configurations and one
name.

## The shape that works: two orchestrators, shared leaves

```text
        netune (egress)          netune-server (ingress)
              │                          │
              │   must not depend on    │
              └──────────╳───────────────┘
              │                          │
              ▼                          ▼
   netune-http1 · netune-http2 · netune-trace · netune-io   (leaves: no socket, no policy)
   (netune-ws is egress-only; probe links none of the stack)
```

Neither orchestrator depends on the other ([INV-SERVER-01]). They share only crates that own
nothing: two codecs, a trace model, and two `AsyncRead`/`AsyncWrite` adapters. This is what lets
two claims be *structural* rather than documented:

- A client-only binary cannot accept a connection, because no listener is compiled into it.
- An ingress binary cannot leak the egress stack, because it does not depend on it.

Moving `TimedIo` and `FaultIo` out of `netune` into `netune-io` was the price of that
symmetry. Both directions need the identical syscall tap — an ingress trace and an egress
trace must be joinable on a shared clock — and leaving the tap in `netune` would have forced
`netune-server` to depend on the egress orchestrator. That is precisely the inversion the
topology forbids, so the tap moved. `netune` re-exports it, so no consumer noticed.

## Why one framing core instead of a second parser

The tempting shortcut is to write a request parser inside `netune-server`. It is tempting
because the response parser already exists and "requests are just a different start line".

They are: a different start line, and four different rules, and the chunked decoder, and the
trailer drain, and the bounded line reader, and the `Content-Length`/`Transfer-Encoding`
conflict check. That list is a request-smuggling surface. Two copies means the client-side
copy is exercised by thirty differential cases while the server-side copy is exercised by
whatever was written for it — and a divergence between them surfaces as a smuggling
vulnerability, not as a failed test.

So `netune-http1` gained a private `Stream` that owns the body state machine, and two thin
role readers on top of it: `Http1Reader` for responses, `Http1ServerReader` for requests.
There is one implementation of chunked decoding ([INV-SERVER-04]). The roles differ exactly
where the protocol differs:

| Rule | Response (client role) | Request (server role) |
| :--- | :--- | :--- |
| Close-delimited body | permitted (RFC 9112 §6.3) | **never** — a request with no framing has no body |
| No framing headers | body runs to EOF | body is empty |
| `Transfer-Encoding` final coding | chunked or nothing to do | must be `chunked`, or the message cannot be framed |
| Both framing headers | refused as smuggling | refused as smuggling |
| Body-less status | `204`/`304`/`1xx` forbid a body | not applicable |

The request role is *stricter*, not merely different. Every refusal is a hardening rule.

## Why HTTP/2 ingress reuses the client's connection machine

`ADR-0011` deferred HTTP/2 ingress on the grounds that it needed "its own accept-time SETTINGS
exchange, a stream scheduler and flow-control accounting". That was the wrong axis to split on.
Frame reading with a negotiated maximum, the `SETTINGS` handshake and its acknowledgement, `PING`
echo, `GOAWAY` bookkeeping, HPACK's dynamic table and `CONTINUATION` contiguity are the same code
whichever end you are — only three things differ, and all three are data:

| Difference | How it is expressed |
| :--- | :--- |
| Who sends the preface | `Role::Client.preface()` is the magic string; `Role::Server`'s is empty |
| Which stream ids each may originate | `Role::own_parity()` — odd for a client, even for a server |
| Which direction `HEADERS` carries a request | the role module, not the connection |

So `netune-http2` became one `H2Connection` with a `Role` field and two thin role modules. The
parallel with HTTP/1.1's shared `Stream` is exact, and for the same reason: a second copy of
frame sequencing is a second place a fix lands in one direction only, and in HTTP/2 the shapes a
second copy gets wrong are `CONTINUATION` interleaving, zero-increment `WINDOW_UPDATE`, and
`PADDED` stripping.

The one thing HTTP/2 forced that HTTP/1.1 did not is a change to the trace model. A multiplexed
connection interleaves exchanges, so an event's *position* is not its exchange. `Event` gained a
`stream` field — `0` where the transport cannot multiplex, the protocol's stream id where it can —
and the ingress derivation groups by it. `[INV-SERVER-07]`'s refusal is unchanged; it now has a
shape that can actually be derived instead of only refused.

## What the red-lines had to become

`[INV-WS-01]`'s second sentence — no accept/listen code anywhere — was retired in place, with
its original wording kept for forensic use. The decision record says why: it forbade a
*capability* in order to protect a *direction*, and a direction is already enforced by crate
topology. The invariant now states what it was actually protecting — the WebSocket transport
surface in `netune` is client-only — and the directional claim moved to `[INV-SERVER-01]`,
where it is enforced by `cargo tree` rather than by prose.

That is the general lesson, and it is the one worth taking from this change: **an invariant
that names a capability is usually a proxy for one that names a boundary.** When the
capability becomes legitimate somewhere else, the proxy has to be replaced by the boundary it
was standing in for, not simply deleted.

## What this deliberately does not do

- **No priority scheduling.** `PRIORITY` frames are accepted and ignored, which RFC 9113 §5.3.1
  permits. A scheduler is policy: it decides which stream's bytes go next, and a transport that
  made that decision would be wrong for every application that wanted a different one.
- **No push.** `PUSH_PROMISE` is never sent and `ENABLE_PUSH=0` is advertised, because a pushed
  resource is a cache hint no handler here can opt into.
- **No WebSocket upgrade serving.** The codec's `Role::Server` path is complete; wiring it to a
  listener is a separate decision with its own framing and liveness questions, and there is still
  no `netune-ws` edge in `netune-server`'s manifest to pretend otherwise.
- **No framework.** No routing, no extractors, no middleware, no JSON. A transport that knows
  how your application routes is useful to one application.
- **No TLS termination.** TLS belongs in front of the listener or in the application's own accept
  loop; `Protocols::alpn()` is the list a terminator should offer, in the order that makes a
  browser choose HTTP/2.
- **No metrics façade.** A trace is not a metric (`ADR-0010`). A consumer that wants counters
  writes them; this crate owes the event vocabulary and the guarantee that an event is emitted
  before the operation it records returns.

---

For the ratified decision see [ADR-0011](../adr/0011-server-side-ingress-transport.md). For
the task-oriented version, see [Serve HTTP/1.1 and HTTP/2](../how-to/serve-http.md).
