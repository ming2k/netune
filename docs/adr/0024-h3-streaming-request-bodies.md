---
id: ADR-0024
title: "H3 Request Bodies Are Streamed, Not Buffered by the API"
status: accepted
date: 2026-11-09
scope: [protocol/http3, api/handler, trace/model]
superseded_by: null
---

# 0024. H3 Request Bodies Are Streamed, Not Buffered by the API

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amended by: [ADR-0027](0027-owned-h3-qpack.md) — the implementation moved from the h3 runtime to the owned H3/QPACK state machine; the streaming API shape is unchanged.
- Amends: [ADR-0016](0016-quic-and-http3-transport.md), [ADR-0022](0022-http3-connection-identity.md)

---

## Context and Problem Statement

The first H3 client accepted `http::Request<Bytes>` and wrote the whole body
before reading the response. That is sufficient for JSON API calls, but it is
not the shape of an industrial HTTP/3 client: large uploads, proxy tunnels and
generated request streams would have to be assembled in memory first, while the
response side was already streaming.

`h3::client::RequestStream` supports repeated `send_data`; the limitation was
ours, not the runtime's.

## Decision Drivers

- An upload must not require memory proportional to the body.
- The streaming response and the streaming request should be symmetric.
- Request trailers are part of HTTP/3 and must remain expressible.
- The trace must start at the same point whether the body is empty, buffered
  or streamed.

## Decision

### 1. `open_request` is the primitive

`H3Client::open_request(Request<()>)` writes the request head and returns
`H3RequestBody`. It records `H3StreamStart` immediately, allocates one exchange
id, and applies `request_timeout` to the head.

`H3RequestBody` owns the QUIC bidirectional stream and exposes:

```rust
send_data(Bytes) -> Result<(), H3Error>
finish() -> Result<H3ResponseStream, H3Error>
send_trailers(HeaderMap) -> Result<H3ResponseStream, H3Error>
```

`finish` and `send_trailers` consume the body, complete the send side, wait for
the response head under `response_head_timeout`, and return the existing
streaming response type. Request trailers finish the request by definition.

### 2. Buffered `send` composes the primitive

`H3Client::send(Request<Bytes>)` is now:

```text
open_request(head) ─► send_data(body) ─► finish()
```

It is a convenience, not a second implementation. `execute` remains the bounded
buffered-response convenience.

### 3. Empty chunks do not become frames

An empty `Bytes` is a no-op on both request and response paths. A DATA frame
with no payload spends a frame and cannot carry information; the framing layer
still knows how to read one.

## Invariants & Behavioral Boundaries

- **`[INV-H3-01]` Request Streaming Is the Primitive**: the H3 client must not
  implement a second buffered request path. `send` composes `open_request`, and
  the integration test writes two body chunks before `finish`. *Enforced by*:
  the public `H3RequestBody` API and `http3_e2e`.

- **`[INV-H3-02]` Exchange Identity Starts at Open**: `H3StreamStart` is recorded
  before any body byte, and the exchange id is the one carried by the response
  stream and its per-exchange trace. *Enforced by*: `H3Client::open_request` is
  the only exchange allocator for requests.

## Consequences

- **Positive**:
  - Uploads are bounded by chunk size, not body size.
  - Request and response streaming have the same lifecycle shape.
  - Trailers are available without a separate API.
- **Negative & Trade-offs**:
  - The caller must drive `finish` (or `send_trailers`) to obtain a response;
    dropping the body aborts the stream.
  - `H3Client` is still `&mut self` for opening a request because the h3
    `SendRequest` handle is mutable. Concurrent requests require one client per
    stream or a future shared-handle design; the connection remains shared.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): keep only `Request<Bytes>`

It makes the memory cost of an upload the caller's unstated problem and leaves
the response side as the only streaming half.

### Option 2 (Rejected): an unbounded `mpsc` body pumped by a background task

A background pump hides backpressure and makes the transport's write deadline
unobservable. The caller owns the pace; each `send_data` is bounded.

## Links

- Related ADRs: [ADR-0016](0016-quic-and-http3-transport.md),
  [ADR-0022](0022-http3-connection-identity.md),
  [ADR-0025](0025-h3-ingress-peer-transport.md)
