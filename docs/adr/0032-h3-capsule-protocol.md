---
id: ADR-0032
title: "Own the RFC 9297 Capsule Protocol"
status: accepted
date: 2026-11-09
scope: [protocol/http3, protocol/rfc9297, api/http3]
superseded_by: null
---

# 0032. Own the RFC 9297 Capsule Protocol

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0030](0030-h3-datagrams-and-extended-connect.md)
- Related: [ADR-0027](0027-owned-h3-qpack.md), [ADR-0031](0031-quic-0rtt-and-session-resumption.md)

---

## Context

ADR-0030 added HTTP/3 datagrams and extended CONNECT but left the Capsule
Protocol out. That is not an application detail: RFC 9297 defines both HTTP
Datagrams and the Capsule Protocol. A CONNECT session that cannot frame capsules
cannot carry the generic message layer the RFC specifies. Extended CONNECT alone
is only the request/response handshake.

At the same time, WebTransport over HTTP/3 is a separate, still-evolving
application-layer draft. Implementing its session IDs, stream scopes, close
codes and W3C API is not implied by owning RFC 9297.

## Decision

### 1. Own the generic capsule codec

- `Capsule { kind, value }` is encoded as varint type, varint length, value.
- Decoding distinguishes incomplete prefixes from malformed/oversized
  capsules; the retained value ceiling is 16 MiB by default.
- The codec owns no socket, stream or HTTP/3 state.

### 2. Capsules live in the HTTP message body

- `H3Stream::send_capsule` writes the capsule bytes as HTTP/3 DATA frames.
- `H3Stream::next_capsule` reads DATA payloads through the existing body
  reader, retains partial capsule bytes, and rejects a stream that ends inside a
  capsule.
- Capsules are exposed on `H3RequestBody`, `H3ResponseStream` and
  `H3ServerStream`.
- `H3RequestBody::into_duplex` reads the response head without finishing the
  request body, so CONNECT sessions retain both directions.
- `H3Client::connect_extended` is the convenience path for an RFC 9220
  CONNECT + capsule session.

### 3. WebTransport remains a product boundary, not a transport gap

- This ADR does not implement WebTransport session state, WT stream mapping,
  WebTransport close/drain semantics, or the W3C API.
- Those are draft application semantics layered on top of the now-owned
  extended CONNECT, datagrams and capsule framing.
- A future WebTransport feature must get its own ADR and API decision; it must
  not silently accrete into `netune-http3`'s transport surface.

## Invariants

- **`[INV-H3-13]` Capsule Framing Is Bounded and Recoverable**: capsule values
  obey a configured ceiling; incomplete prefixes are retained, never
  misdecoded, and truncated final capsules are errors. *Enforced by*:
  `Capsule::decode`, `CapsuleError`, `H3Stream::next_capsule`, and codec tests.
- **`[INV-H3-14]` Duplex CONNECT Does Not Finish Early**: `into_duplex` reads the
  response head without sending FIN, so both directions remain usable for
  capsules and datagrams. *Enforced by*: `H3RequestBody::into_duplex` and the
  capsule round-trip test.

## Consequences

- RFC 9297 is now covered at the generic framing level, not just QUIC
  datagrams.
- CONNECT sessions can carry capsules without a parallel HTTP stack.
- WebTransport remains an explicit future product decision instead of an
  accidental by-product.

## Known gaps

WebTransport over HTTP/3 draft session semantics are intentionally out of scope.
