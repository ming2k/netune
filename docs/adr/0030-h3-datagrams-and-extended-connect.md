---
id: ADR-0030
title: "Own HTTP/3 Datagrams and Extended CONNECT"
status: accepted
date: 2026-11-09
scope: [protocol/http3, protocol/rfc9220, protocol/rfc9297, transport/quic, api/http3]
superseded_by: null
---

# 0030. Own HTTP/3 Datagrams and Extended CONNECT

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0027](0027-owned-h3-qpack.md)
- Related: [ADR-0028](0028-owned-quic.md), [ADR-0029](0029-quic-lifecycle-hardening.md)

---

## Context

ADR-0027 made HTTP/3 and QPACK owned but deliberately withheld two extension
surfaces until their transport semantics existed: HTTP/3 datagrams (RFC 9297)
and extended CONNECT (RFC 9220). Both were hard-coded off in SETTINGS. QUIC
datagrams now exist in the owned engine (ADR-0028), and the H3 field-section
codec already understands `:protocol` as a pseudo-header it rejected.

Keeping them off was honest, but incomplete: applications could not associate
QUIC datagrams with a request stream, and CONNECT requests carrying `:protocol`
were unusable.

## Decision

### 1. HTTP/3 datagrams are connection-negotiated and stream-routed

- `H3SettingsProfile` carries `SETTINGS_H3_DATAGRAM`; SETTINGS are emitted and
  parsed by the owned codec.
- Datagrams are enabled only when both local and peer SETTINGS advertise
  `H3_DATAGRAM`. A datagram received before negotiation is an
  `H3_MESSAGE_ERROR`.
- Every request stream registers a datagram route keyed by its wire stream id.
  An H3 datagram payload is a QUIC varint Quarter Stream ID followed by the
  application payload; the driver routes it to `quarter * 4`.
- Datagrams that arrive before a stream route exists are retained in a bounded
  per-stream queue (32 entries); the route drains that queue on registration.
- `H3RequestBody::send_datagram`, `H3ResponseStream::next_datagram` and the
  server stream equivalents are the public surface. Sending waits for peer
  SETTINGS when negotiation has not been observed yet.

### 2. Extended CONNECT is a typed request extension

- `H3SettingsProfile` carries `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
- `ExtendedConnectProtocol` is an `http::Request` extension. Encoding emits
  `:protocol` on a `CONNECT` request; decoding reconstructs the extension.
- Extended CONNECT requires `CONNECT`, `:scheme`, `:path`, `:authority` and a
  non-empty ASCII protocol token.
- `H3Client::open_request` waits for peer SETTINGS before sending an extended
  CONNECT request; it fails if the peer did not enable the setting. The server
  rejects a received extended CONNECT when it did not negotiate the setting.
- Regular CONNECT remains unchanged and does not require the setting.

## Invariants

- **`[INV-H3-09]` Datagram Negotiation Is Bilateral**: no HTTP/3 datagram is
  sent or accepted unless both SETTINGS profiles advertised `H3_DATAGRAM`.
  *Enforced by*: `Shared::datagrams_enabled`, `H3Stream::send_datagram`, and the
  driver's negotiated-receive check.
- **`[INV-H3-10]` Datagram Routing Is Stream-Scoped**: a datagram is delivered
  only to the request stream identified by its Quarter Stream ID; unmatched
  datagrams are bounded or dropped, never broadcast. *Enforced by*:
  `Shared::route_datagram` and the per-stream route map.
- **`[INV-H3-11]` Extended CONNECT Is Opt-In**: `:protocol` is accepted only on
  `CONNECT`, only with scheme/path/authority, and only after both endpoints
  advertised `SETTINGS_ENABLE_CONNECT_PROTOCOL`. *Enforced by*:
  `ExtendedConnectProtocol`, header encode/decode, client wait gate and server
  accept gate.

## Consequences

- The H3 SETTINGS surface is honest again: both extension flags reflect whether
  the implementation can actually enforce them.
- Datagrams survive the request-stream race through the bounded pending queue.
- Extended CONNECT uses the existing `http::Request` extension map rather than a
  parallel request type.
- WebTransport capsule protocols remain an application-layer concern; this ADR
  provides the HTTP/3 CONNECT and datagram transport, not the capsule state
  machine.

## Known gaps


- WebTransport capsules and stream-per-session semantics are not part of this
  decision.
