---
id: ADR-0013
title: "A Response Is a State Machine, and Its Body May Still Be Arriving"
status: accepted
date: 2026-11-06
scope: [protocol/rfc9112, transport/ingress, api/handler]
superseded_by: null
---

# 0013. A Response Is a State Machine, and Its Body May Still Be Arriving

- Status: Accepted
- Date: 2026-11-06
- Deciders: Ming Li
- Amends: [ADR-0011](0011-server-side-ingress-transport.md)

---

## Context and Problem Statement

ADR-0011 shipped a server whose response was a function: `write_response(writer, head, body)` where
`body` was a `&[u8]`. That is enough for an echo server and wrong for every production origin.

Two failures follow from it, and they are not the same failure:

1. **A large response cannot be produced incrementally.** Server-sent events, an LLM token stream, a
   generated file and a database cursor all produce bytes over time. Buffering them means the first
   byte reaches the peer only after the last one exists — which turns "streaming" into "slow".
2. **The framing was enforced by convention.** Three values have to agree for a response to be
   well-formed: what the head declared (`Content-Length: 5`), what the request forbids (`HEAD` carries
   no body, `204` and `304` never do, a `CONNECT` 2xx is a tunnel boundary), and how many bytes were
   actually written. With a function, every one of those agreements is left to the caller.

The second failure is the dangerous one. A head declaring `Content-Length: 5` followed by 4 bytes hangs
the peer forever; a body written under `204` becomes the *next* response's status line on a keep-alive
connection. Both are complete responses from the writer's point of view, and both are undetectable
without state that spans the head, the body and the end.

There is a third, smaller problem with the same root: "one handler, two protocols" (ADR-0012) needs the
HTTP/2 server to write a body it did not buffer, and a per-call `&[u8]` API cannot express that at all.

## Decision Drivers

- A response must be writable incrementally, so a stream is a first-class body, not a special case.
- The framing declarations must be enforced where they can be checked, which is where the state lives.
- The two protocols must share one application-facing body type, or every handler writes its streaming
  twice.
- No third-party HTTP body or streaming crate in the production graph (`ADR-0001`, `INV-TRANSPORT-00`).

## Considered Options

- **Option 1**: keep `write_response` and add `write_response_chunk` + `write_response_end` beside it.
- **Option 2**: take `Stream<Item = Result<Bytes>>` from `futures` and store it in the response.
- **Option 3**: a `ResponseWriter` typestate that owns the transport for the duration of one response,
  plus an object-safe `BodyStream` the transport pulls from, and a `ResponseBody` enum that names the
  three shapes (`Empty`, `Bytes`, `Stream`).
- **Option 4**: hand the handler the raw socket and let it write the response itself.

## Decision Outcome

Chosen option: **"Option 3"**, for four reasons:

1. **The state is where the check is.** `ResponseWriter::start` receives the request *method* as well as
   the head, so it can decide `write_body` from `HEAD`, `1xx`, `204`, `304` and `CONNECT`-success before
   a byte reaches the wire. `write` refuses a body that exceeds the declared length, and refuses any
   body at all when `write_body` is false. `finish` refuses to report success when the declared length
   was not reached. The three-way agreement is now a type, not a convention.
2. **A stream is a body, not an entry point.** `ResponseBody::Stream(Box<dyn BodyStream>)` is one of
   three shapes, and the transport pulls from it with `next_chunk()`. There is no second code path for
   incremental writes, which means the framing rules cannot be enforced on one path and forgotten on
   the other.
3. **`BodyStream` is object-safe by construction.** One method, one boxed future, no generics. A handler
   that has a concrete async source wraps it; a `tokio::sync::mpsc::Receiver<Bytes>` already *is* one,
   because the token-stream case is common enough to deserve a blanket implementation.
4. **One body type serves both protocols.** HTTP/1.1 turns `Stream` into chunked framing and HTTP/2
   turns it into a channel of `DATA` frames, but a handler returns the same `ResponseBody`. The
   protocol-specific framing lives in the protocol adapters, which is the only place it can be correct.

### Invariants & Behavioral Boundaries

- **`[INV-SERVER-12]` A Response Cannot Contradict Its Head**: for every response, the bytes on the wire
  agree with the framing the head declared and with what the request method and status permit. A writer
  refuses a body under `1xx`/`204`/`304`/`HEAD`/`CONNECT`-2xx, a body beyond a declared
  `Content-Length`, and a `finish` that did not reach it. *Enforced by*:
  `netune_http1::ResponseWriter`'s `start`/`write`/`finish` refuse each shape, and
  `crates/netune-http1/src/response.rs` has one test per refusal;
  `a_streaming_response_to_head_carries_no_body_and_no_chunks` proves it through a real socket.
- **`[INV-SERVER-13]` A Streamed Body Ends Exactly Once**: a streaming body's terminator is written once,
  by `finish`, and a zero-length chunk is not a terminator a caller can produce by accident. *Enforced
  by*: `ResponseWriter::write` treats an empty slice as a no-op and `finish` is the only writer of
  `0\r\n\r\n`; `a_chunked_body_is_framed_and_terminated` pins the byte sequence.

### Consequences

- **Positive**:
  - Streaming is a first-class response shape, so SSE, token streams and generated files are written as
    they are produced.
  - Every framing contradiction fails locally, at the write that would have produced it, instead of at
    the peer that misparses it.
  - A `HEAD` response can declare the length its body *would* have had without the transport having to
    generate one, which is what makes `HEAD` cheap for a large resource.
  - The `write_response` / `write_response_head` / `write_chunked_chunk` / `write_chunked_end` family is
    deleted rather than deprecated: four functions each enforcing part of one rule became one type that
    enforces all of it.
- **Negative & Trade-offs**:
  - A response is consumed by value when it is written, because a stream cannot be written twice. A
    caller that wanted to inspect the body after the write no longer can; nothing in this workspace
    wanted to.
  - A streaming handler that errors *after* its head is sent leaves the peer with a truncated message.
    There is no status left to send at that point, and truncation is the honest signal — so the only
    remedy is for the handler to produce its first chunk before the head where it can.
  - `ResponseWriter` holds the transport for the cost of one response, so the call site borrows rather
    than owns. That is deliberate: a writer that owned the socket could not hand back the receive
    buffer that holds the next pipelined request.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): `write_response_chunk` Beside `write_response`

- **Why considered**: additive, no break, and the existing function keeps working.
- **Why rejected**: a function-per-write API has no state, so "the declared length is what you wrote"
  is unenforceable — the exact agreement this decision exists to enforce. It also leaves two ways to
  write a body, and the one that skips the checks is the one that gets used.

### Option 2 (Rejected): `futures::Stream` In The Response

- **Why considered**: it is the idiomatic shape, and `StreamExt` gives back-pressure for free.
- **Why rejected**: `futures` in the production graph of a transport whose entire dependency argument is
  `tokio` + `bytes` + `http` (`ARCH-006`, `INV-TRANSPORT-00`). `BodyStream` is one method and one boxed
  future; the alternative was a large crate for forty lines of `poll` forwarding.

### Option 4 (Rejected): Hand The Handler The Socket

- **Why considered**: full duplex, maximum flexibility, no framing code at all.
- **Why rejected**: the transport would lose every guarantee it sells. It could not enforce the
  declared length, could not keep the connection alive afterwards (it no longer knows where the response
  ended), could not apply the write deadline, and could not trace `ResponseEnd`. It also makes HTTP/2
  impossible, because two writers on one connection interleave frames into a corrupt stream.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0011](0011-server-side-ingress-transport.md),
  [ADR-0012](0012-http2-ingress.md)
