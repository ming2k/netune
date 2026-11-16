---
id: ADR-0055
title: "HTTP/1.1 Full-Duplex Exchange Over a Split, Tap-Preserving Transport"
status: accepted
date: 2026-11-16
scope: [transport/http1, transport/egress, observability, security/replay]
superseded_by: null
---

# 0055. HTTP/1.1 Full-Duplex Exchange Over a Split, Tap-Preserving Transport

- Status: Accepted
- Date: 2026-11-16
- Deciders: Ming Li
- Amends: [ADR-0005](0005-keepalive-socket-culling-absorption.md)

---

## Context and Problem Statement

The HTTP/1.1 client used one `Http1Reader` as both the response parser and the
write path: it wrote the whole request body through `Http1Reader::transport_mut`
and only then called `read_response_head`. A server that answers before reading
the upload (413, 401, an early 200) cannot be observed until the client has
finished writing, so a streaming upload can stall behind a peer that stopped
reading.

H2 and H3 already read the response head while the request body is still
running. HTTP/1.1 needs the same shape without losing the socket tap: the tap
lives inside the one transport object, and splitting the stream must not
detach observability from either direction.

## Decision Drivers

- An early response must be surfaced without waiting for the upload.
- A half-written HTTP/1.1 connection must never return to the pool.
- The socket tap must record both request writes and response reads.
- `100 Continue` / `103 Early Hints` must not become final responses.
- The split must be an implementation detail; the public `Client` surface stays
  protocol-neutral.

## Decision Outcome

Chosen option: "one shared transport, two halves, concurrent exchange".

1. **Split, but keep the tap.** `SplitShared` owns the original
   `Box<dyn Transport>`. `SplitRead` and `SplitWrite` share it through an
   `Arc<Mutex<...>>`, and every poll still passes through the transport's
   `TimedIo` tap. A `SplitHandle` recovers the original transport when both
   halves have been dropped; if an early response abandons the upload, the last
   shared reference finishes the tap and merges the log into the recorder.
2. **Write and read concurrently.** The request writer runs in its own task.
   The response head is awaited in the main task. If the head wins, the body
   retains the upload task; if the upload wins, its write half is retained for
   pooling.
3. **Cancel on early response.** The response body ends or is dropped before
   the upload finishes: the upload task is aborted, the write half is discarded,
   and the connection is not pooled.
4. **Pool only the complete shape.** A connection is returned to the pool only
   when the request body is fully written, the response body is fully read, the
   response permits keep-alive, and no upload was cancelled.
5. **Interim heads are not final.** `100`, `102` and `103` are skipped; `101`
   is final because the protocol changes underneath. A bounded number of
   interim heads prevents a peer from keeping the parser in a loop.

### Invariants & Behavioral Boundaries

- `[INV-TRANSPORT-11]` An HTTP/1.1 response head and body are readable while
  the request body is still being uploaded. *Enforced by*:
  `an_early_h1_response_does_not_wait_for_the_upload` and
  `an_h1_response_body_is_readable_while_the_upload_is_still_running`.
- `[INV-TRANSPORT-12]` A half-written HTTP/1.1 connection is never pooled.
  *Enforced by*: the `upload_done` precondition in `Body::release` and the
  early-response tests.
- `[INV-TRANSPORT-13]` Interim `1xx` heads do not become final responses and
  are bounded. *Enforced by*: `Http1Reader::read_response_head` and the corpus
  tests `informational_heads_are_skipped_until_the_final_response` /
  `a_stream_of_interim_heads_is_bounded`.

## Considered Options

### Keep the serialized write-then-read path (Rejected)

- **Why considered**: no transport split, smallest change.
- **Why rejected**: it leaves the early-response stall and makes
  `request_timeout` the only exit.

### Use `tokio::io::split` without a shared owner (Rejected)

- **Why considered**: less custom code.
- **Why rejected**: the tap is inside the original transport and cannot be
  recovered from a half after the other half is dropped; the trace would lose
  socket events on the exact failure path that matters.

### Always cancel the upload when the head arrives (Rejected as the only mode)

- **Why considered**: simple and safe.
- **Why rejected**: a full-duplex peer may legitimately produce response bytes
  while the upload continues. Cancellation is the fallback when the response
  ends or the caller drops it, not the first response to every head.

## Consequences

- **Positive**: early responses are observable, stalled uploads no longer
  depend on the outer timeout, and the socket tap still covers both directions.
- **Negative & Trade-offs**: each split poll takes a shared mutex, so H1
  request/response interleaving is serialized at the transport boundary; the
  write half may remain alive until the upload task observes cancellation.
  A cancelled upload deliberately forgoes pooling.
- **Compatibility**: no public API change; the split is internal to
  `netune::wire::h1`.

## Links

- Related ADRs: [ADR-0005](0005-keepalive-socket-culling-absorption.md),
  [ADR-0040](0040-egress-handshakes-share-a-bound.md),
  [ADR-0052](0052-replay-and-exchange-bounds.md),
  [ADR-0054](0054-audited-tls-default-and-owned-fingerprint-opt-in.md)
