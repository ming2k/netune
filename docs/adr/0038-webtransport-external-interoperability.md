---
id: ADR-0038
title: "WebTransport External Interoperability and Role-Correct Framing"
status: accepted
date: 2026-11-10
scope: [protocol/webtransport, protocol/quic, protocol/http3, api/webtransport, product/web]
superseded_by: null
---

# 0038. WebTransport External Interoperability and Role-Correct Framing

- Status: Accepted
- Date: 2026-11-10
- Deciders: Ming Li
- Related: [ADR-0030](0030-h3-datagrams-and-extended-connect.md),
  [ADR-0033](0033-webtransport-over-http3.md),
  [ADR-0037](0037-webtransport-draft17-completion-gate.md)

---

> Implementation status: the non-Rust half of ADR-0037 Gate 4 now passes
> against `quic-go/webtransport-go` for bidirectional streams, unidirectional
> streams and datagrams. The browser half remains blocked: Chrome 157 does not
> advertise the `reset_stream_at` QUIC transport parameter required by
> draft-ietf-webtrans-http3-17. Gate 4 is therefore not complete.

## Context and Problem Statement

The owned stack passed its own loopback and `quinn`/`h3` oracle suites while
remaining unable to complete a WebTransport session with an external peer. The
failures were not certificate or timing noise; they were role and capability
mistakes that an independent implementation exposes immediately:

- the server used the client's source connection ID as its **own** local
  connection ID, so a client that legally chose a zero-length source CID
  received a server Initial with a zero-length source CID;
- the server treated RFC 9220 extended CONNECT as a bilateral SETTINGS
  requirement, but `SETTINGS_ENABLE_CONNECT_PROTOCOL` is a server capability;
- the WebTransport server required clients to echo a server-only SETTINGS
  parameter, contrary to draft-17 Section 3.1; and
- draft-16 peers still in the field advertise `0x2c7cf000`, while draft-17 uses
  `0x20b8933b`; without multi-codepoint SETTINGS negotiation there is no common
  version.

These defects turn an interop gate into a permanent excuse if left as prose.
They are fixed as protocol rules with regression tests and an external harness.

## Decision

### 1. Connection ID roles are independent

A server chooses its own non-zero-length source connection ID when it creates
the server core. Its Initial and Handshake packets use the client's source
connection ID as the destination connection ID, including the legal
zero-length value. It never reuses the client's source CID as its local CID.

`[INV-QUIC-25]` is enforced by
`server_addresses_a_client_with_a_zero_length_source_cid`.

### 2. Extended CONNECT is a server capability

`SETTINGS_ENABLE_CONNECT_PROTOCOL` is advertised by the endpoint that accepts
extended CONNECT requests. A server requires its own setting to be enabled; it
does not require the client to advertise it. A client requires the server's
setting before opening an extended CONNECT request.

`[INV-H3-15]` is enforced by
`extended_connect_requires_only_the_server_setting`.

### 3. Draft-16 SETTINGS codepoint compatibility

A draft-17 endpoint that can speak the shared wire subset advertises both
`SETTINGS_WT_ENABLED` codepoints:

- `0x20b8933b` (draft-17), and
- `0x2c7cf000` (draft-16).

The peer selects the highest common version by the codepoint it sends. The
client accepts either codepoint from the server. The server ignores the client's
`SETTINGS_WT_ENABLED` entirely, as draft-17 requires; it still enforces the
QUIC `reset_stream_at`, H3 datagram and extended CONNECT requirements.

This is a wire-negotiation decision, not a claim of draft-16 feature
completeness. Neither the draft pin nor the public API moves.

`[INV-WT-07]` is enforced by the settings round-trip test and the Go interop
harness.

### 4. An independent peer is a required executable gate

`interop/webtransport-go` runs `quic-go/webtransport-go` against the example
WebTransport origin. The harness must complete a bidirectional stream, a
unidirectional stream in each direction and a datagram exchange in both
directions. It runs locally through `scripts/webtransport-go-interop.sh` and in
the `WebTransport non-Rust interop (Go)` CI job.

The browser half of ADR-0037 Gate 4 stays explicitly open until an installed
browser advertises `reset_stream_at`. A failing browser harness is not checked
in as if it were a gate.

## Consequences

- An external, non-Rust peer now drives the same session, stream and datagram
  state machine as the Rust tests.
- The draft-16 codepoint remains an interop surface only; it does not relax
  `RESET_STREAM_AT`, flow-control or teardown requirements.
- The browser gate cannot be closed by documentation or by a locally patched
  peer. It closes when a browser implementation carries the required QUIC
  extension.
- `netune-webtransport` is still not production-complete; ADR-0037 Gates 4
  (browser half) and 5 (adversarial replay) remain outstanding.

## Rejected Alternatives

### Keep the server CID bug and require non-empty client CIDs

- Why considered: all in-tree clients use non-empty source CIDs, so the bug was
  invisible.
- Why rejected: a zero-length source CID is legal, and an external client is
  exactly the oracle that must expose the assumption.

### Require the client to echo every server SETTINGS parameter

- Why considered: symmetric validation is easier to reason about.
- Why rejected: RFC 9220 and draft-17 define these as server capabilities; the
  requirement makes compliant peers fail.

### Support only draft-17 and wait for the ecosystem

- Why considered: one codepoint is simpler and the draft pin is explicit.
- Why rejected: multi-codepoint negotiation is defined by draft-17 Section 7.1;
  refusing the older codepoint would leave the non-Rust gate permanently
  untestable, while the shared wire subset is already implemented.

## Links

- [ADR-0030](0030-h3-datagrams-and-extended-connect.md)
- [ADR-0033](0033-webtransport-over-http3.md)
- [ADR-0037](0037-webtransport-draft17-completion-gate.md)
- `draft-ietf-webtrans-http3-17` Sections 3.1 and 7.1
- `draft-ietf-quic-reliable-stream-reset-11` Section 3
