---
id: ADR-0014
title: "Request Framing Is Validated Before Any Handler Runs"
status: accepted
date: 2026-11-06
scope: [protocol/rfc9112, security/smuggling, transport/ingress]
superseded_by: null
---

# 0014. Request Framing Is Validated Before Any Handler Runs

- Status: Accepted
- Date: 2026-11-06
- Deciders: Ming Li
- Amends: [ADR-0011](0011-server-side-ingress-transport.md)

---

## Context and Problem Statement

ADR-0011 shipped a request direction that refused the classic smuggling shapes — `CL.TE`, conflicting
`Content-Length`, obsolete line folding — and stopped there. Four gaps remained, and each one is a
class of bug rather than an instance:

1. **The request target was never checked.** The codec copied the bytes between two spaces and handed
   them to the handler. `GET /a b HTTP/1.1` is not a target with a space in it: it is a line that three
   parsers split three ways. `/page#section` is a target no origin can interpret, and it is the
   primitive that makes a cache key differ from the path an origin resolves.
2. **`Host` was never validated.** RFC 9112 §3.2 makes `Host` mandatory for HTTP/1.1, and a request
   with none, or with two, or with one that disagrees with an absolute-form target is how two hops
   route one request to two origins. The listener accepted all three and called the handler.
3. **The body bound was per call, not cumulative.** `Limits::max_body_bytes` was checked in
   `read_body_to_end` only, so a handler that called `read_body_chunk` in a loop — the streaming case,
   which is what `RequestBody` is *for* — had no bound at all. A declared `Content-Length` beyond the
   bound was also not refused at the head, so the server would read toward a size the operator never
   granted.
4. **A bare LF terminated a line.** RFC 9112 §2.2 defines the terminator as CRLF; a second hop that
   only recognises CRLF reads the difference as part of the next header. That is the same desync class
   as `CL.TE` and it was accepted.

The common shape of all four is the same: **the codec validated framing, and framing is not the whole
of what a request must be before application code may see it.** The question is where the rest belongs
— in the codec, in the orchestrator, or split — and what must happen when it fails.

## Decision Drivers

- A request that two conforming implementations would classify differently must never reach a handler
  (`INV-SERVER-03`'s spirit: bounded *before* it is served).
- The refusal must be a *status line*, not a reset socket, so a client can tell a bad request from a
  network failure and can decide whether retrying is safe.
- The codec must stay protocol-pure: it classifies grammar and refuses what has no safe reading; it does
  not decide routing policy or read a clock.
- The same rules must hold for both protocols, and HTTP/2 has no bare LF, no chunked coding and no
  `Host` — so the *shared* part is the target and host grammar, not the framing.

## Considered Options

- **Option 1**: validate everything in the codec, including `Host`, and fail the connection inside
  `read_request_head`.
- **Option 2**: validate everything in the orchestrator, including chunked framing and the target.
- **Option 3**: split by nature — grammar and framing in the codec, protocol-mandated field rules in the
  codec too (they are grammar), and the *response* to a violation in the orchestrator, which is the only
  layer that can write one.
- **Option 4**: keep accepting, and normalise (trim the space, split the duplicate `Host`, truncate the
  body). "Be liberal in what you accept."

## Decision Outcome

Chosen option: **"Option 3"**, with the boundary stated precisely:

- **The codec classifies and refuses.** `target::classify` implements the four RFC 9112 §3.2 forms and
  refuses the bytes that are in none of them; `validate_host_field` implements the `Host` grammar
  (which is the authority grammar, because §3.2 compares them); `Limits::require_crlf` makes a bare LF a
  protocol error in the server role; `Stream` counts body bytes cumulatively and
  `check_declared_length` refuses an oversized `Content-Length` at the head. Every one of these is a
  question about *bytes*, which is what a codec answers.
- **The orchestrator answers, and decides the remaining policy.** A codec cannot write a `400`. The
  listener therefore keeps `require_host` as a named switch, compares an absolute-form target's
  authority with `Host`, refuses two `Host` headers, and writes the status line before closing. It also
  owns the bounds a codec has no vocabulary for: wall-clock timeouts, the connection cap, the reuse
  quota.
- **Nothing is normalised.** A space in a target is refused, not trimmed; two `Host` headers are refused,
  not merged; an oversized declared length is refused, not truncated. Normalisation is how a desync
  becomes a vulnerability instead of a 400.

### Invariants & Behavioral Boundaries

- **`[INV-SERVER-14]` A Request Is Grammatical Before It Is Routed**: a request reaches a `Handler` only
  if its target is one of the four RFC 9112 forms, its `Host` (where required) is exactly one
  syntactically valid value consistent with the target, and its framing is a shape a request may have.
  *Enforced by*: `crates/netune-http1/src/target.rs`'s classification tests,
  `a_request_without_host_never_reaches_the_handler`, `two_host_headers_never_reach_the_handler`, and
  `a_target_with_a_space_is_refused_before_the_header_block_is_read`.
- **`[INV-SERVER-15]` A Body Bound Is Cumulative And Pre-Declared**: `max_body_bytes` bounds every
  message across all reads, on the streaming path as well as the buffered one, and a declared
  `Content-Length` beyond it is refused before the first body byte is read. *Enforced by*:
  `Stream::account_body` and `Stream::check_declared_length`;
  `an_oversized_declared_length_is_refused_before_the_body_is_read`.
- **`[INV-SERVER-16]` A Refusal Is A Status Line**: every pre-dispatch refusal is answered with a status
  the client can act on (`400`, `408`, `413`, `431`, `505`) when a response can still be written, and the
  connection closes afterwards because its framing position is unknown. *Enforced by*: `validate`
  returns a `Response` rather than closing the socket, and each refusal test asserts the status line.

### Consequences

- **Positive**:
  - The four smuggling classes are closed where they are cheapest to close, and the same target and host
    grammar now protects HTTP/2, which has no `Host` header to differ on but does have `:path` and
    `:authority`.
  - A hostile client cannot make the server read toward a size the operator never granted, because the
    declaration is refused before the body.
  - A refusal is diagnosable: a client sees `400` and knows to stop, where a reset socket is
    indistinguishable from the network.
- **Negative & Trade-offs**:
  - `IncomingRequest` gained a `form` field, and `Limits` gained `require_crlf`. Both are breaks with no
    compatibility shim, by design: a shim would let a caller keep the leniency.
  - The client role still tolerates a bare LF, deliberately. It is not a security boundary — a sloppy
    origin is the client's problem — and refusing it would fail a request the origin did answer. The
    asymmetry is the point, and it is a named field rather than a hidden difference.
  - The `email`-style registered-name character set is narrower than what DNS permits. A `Host` with an
    unusual byte is refused rather than passed through, which is the right trade for a server and would
    be wrong for a proxy.
  - There is no `Host`-to-route mapping here. This crate validates the field and does not use it, because
    routing is the application's business; a virtual-host framework on top would consume `host()`.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): All In The Codec, Connection Fatal

- **Why considered**: one place, no policy split to explain.
- **Why rejected**: a codec cannot write a `400`, so the client would get a reset socket for a
  recoverable mistake. It also drags `require_host` into a crate that must serve HTTP/2 (which has no
  such header) and the client role (which has no such obligation).

### Option 2 (Rejected): All In The Orchestrator

- **Why considered**: the codec stays a pure parser; every policy decision is in one crate.
- **Why rejected**: the orchestrator would have to re-parse the request line and the header block to
  classify them, which is the duplicated-parser failure `[INV-SERVER-04]` exists to prevent — and the
  target grammar is exactly where two parsers disagree.

### Option 4 (Rejected): Normalise Instead Of Refuse

- **Why considered**: "be liberal in what you accept" is the older, kinder rule, and it makes more
  clients work.
- **Why rejected**: it is the rule that produced every request-smuggling CVE of the last decade. A space
  in a target has no correct normalisation (trim it and `/a/../admin` becomes `/admin`); two `Host`
  headers have no correct merge; an oversized body has no correct truncation. Refusal is the only answer
  that cannot be reinterpreted by the next hop.

## Links

- Related ADRs: [ADR-0006](0006-transport-customizability-wire-evasion.md),
  [ADR-0011](0011-server-side-ingress-transport.md),
  [ADR-0012](0012-http2-ingress.md),
  [ADR-0013](0013-response-writer-state-machine.md)
