---
id: ADR-0039
title: "WebTransport Request Admission and Adversarial Control"
status: accepted
date: 2026-11-10
scope: [protocol/webtransport, protocol/http3, protocol/quic, api/webtransport, security/ingress]
superseded_by: null
---

# 0039. WebTransport Request Admission and Adversarial Control

- Status: Accepted
- Date: 2026-11-10
- Deciders: Ming Li
- Related: [ADR-0033](0033-webtransport-over-http3.md),
  [ADR-0037](0037-webtransport-draft17-completion-gate.md),
  [ADR-0038](0038-webtransport-external-interoperability.md)

---

> Implementation status: ADR-0037 Gate 5 is now exercised by
> `crates/netune-webtransport/tests/security.rs` and the focused validation
> tests in `netune-http3`. Browser interoperability remains blocked by Chrome's
> missing `reset_stream_at`, so this ADR does not lift the WebTransport
> production gate.

## Context

A session-establishment happy path is not an admission policy. Before this ADR,
`WebTransportServer::accept` checked only `:protocol = webtransport-h3`; it did
not enforce `https`, require `:authority`, validate an `Origin`, reject a
non-success client response, or validate the session ID carried by generic H3
extension streams. The flow-control and close state machines also accepted
control after a terminal close and did not mark a flow-control violation as
terminal.

Those are peer-controlled inputs. Leaving them to "the caller" would make every
consumer reimplement the same checks, and an omitted check would be invisible
until a hostile peer exploited it.

## Decision

### 1. Admission is a server-side contract

`WebTransportServer::accept` rejects a request before creating a session unless:

- the method is `CONNECT`;
- `:scheme` is exactly `https`;
- `:authority` is present and parses as an authority without userinfo;
- `:path` is present and absolute (begins with `/`);
- `:protocol` is exactly `webtransport-h3`; and
- the optional `Origin` header is acceptable under the configured
  [`OriginPolicy`].

Malformed requests receive `400`; a valid but disallowed Origin receives `403`.
The rejected request stream is finished; other H3 requests remain serviceable.

`OriginPolicy` defaults to `SameOrigin`, which accepts an absent Origin or one
equal to the request's `https` origin. `Any` is available for explicitly
cross-origin deployments and `Allowlist` accepts only exact normalized
`WebTransportOrigin` values. Multiple Origin values and malformed origins are
always rejected, regardless of policy.

`[INV-WT-08]` is enforced by `security.rs` and the request-validation unit tests.

### 2. The client validates both ends of admission

`WebTransportClient::connect_session` requires an absolute `https` URI with an
authority and path, and refuses a non-2xx extended CONNECT response before
constructing a session. A server refusal is an error, not a session with a
dangling CONNECT stream.

### 3. Extension session IDs are validated before routing

The generic H3 extension seam accepts a validator. WebTransport supplies
`SessionId::new`, so an incoming WT stream whose second varint is not a
client-initiated bidirectional stream ID closes the H3 connection with
`H3_ID_ERROR` instead of being queued as an unknown session. This applies to
both `0x54` unidirectional streams and `0x41` bidirectional signals.

`[INV-WT-09]` is enforced by the two spoofed-session-ID tests and the existing
`SessionId` unit test.

### 4. Terminal states are monotonic

- A peer-close or local close terminates the session: new streams, datagrams,
  control capsules, and further control reads are refused.
- A drain prevents new local streams while allowing the close handshake to
  complete.
- A regressed `WT_MAX_DATA` or `WT_MAX_STREAMS` capsule marks the session
  closed and returns `FlowControl`; it cannot be replayed to regain credit or
  continue using the session.
- A reliable reset is checked against the buffered stream data in the QUIC
  engine; the WebTransport layer adds the stream header to the reliable prefix.

`[INV-WT-10]` is enforced by the flow-control replay, peer-close, and drain
tests.

### 5. Gate 5 is executable

ADR-0037 Gate 5 is satisfied by the following test classes:

| Input | Test |
| :--- | :--- |
| spoofed `:scheme` | `a_spoofed_scheme_is_rejected` |
| missing `:authority` | `a_missing_authority_never_establishes_a_session` |
| missing `:path` | `extended_connect_without_a_path_is_rejected` |
| spoofed Origin | `a_default_same_origin_policy_rejects_a_spoofed_origin` |
| replayed/duplicate Origin | `multiple_origin_headers_are_rejected` |
| configured cross-origin | `an_allowlisted_cross_origin_is_accepted` |
| spoofed bidi session ID | `a_spoofed_bidi_session_id_closes_the_h3_connection` |
| spoofed uni session ID | `a_spoofed_uni_session_id_closes_the_h3_connection` |
| replayed data credit | `a_replayed_flow_control_capsule_is_rejected` |
| replayed stream credit | `a_replayed_stream_limit_capsule_is_rejected` |
| post-close control/stream | `a_peer_close_refuses_control_and_new_streams` |
| post-drain stream | `a_drain_refuses_new_streams` |
| early client enable setting | `a_client_enable_setting_does_not_gate_server_admission` |
| reset before payload | `a_reset_before_payload_surfaces_only_the_stream_header` |
| incoming data overrun | `an_incoming_data_overrun_terminates_the_session` |

This table is the gate definition, not a claim that every possible WebTransport
security property has been tested.

## Consequences

- A user must choose an Origin policy deliberately for cross-origin browser
  clients; the safe default does not silently permit them.
- `OriginPolicy` and `WebTransportOrigin` become public API and must remain
  normalized and case-insensitive for hosts.
- The generic H3 extension seam now has a validator slot. H3 still knows no
  WebTransport constants; it only enforces the caller's identifier predicate.
- Invalid session IDs close the whole H3 connection. That is intentional: a
  stream claiming an impossible session is a connection-level protocol error,
  not a recoverable session error.
- ADR-0037 Gate 4 still cannot close until a browser advertises
  `reset_stream_at`; the Go non-Rust harness remains the independent peer gate.

## Rejected Alternatives

### Require Origin on every request

- Why considered: a browser always sends one and absence could look suspicious.
- Why rejected: non-browser peers such as the Go interop harness are legitimate
  and have no Origin; rejecting them would make the non-Rust gate impossible
  without inventing a meaningless header.

### Accept any Origin by default

- Why considered: less configuration for cross-origin WebTransport.
- Why rejected: it makes the default an open cross-origin gate. Security
  defaults are part of the API, and `Any` remains an explicit choice.

### Drop an invalid extension session ID

- Why considered: it avoids closing a connection for one bad stream.
- Why rejected: draft-17 defines an invalid session ID as `H3_ID_ERROR`; silently
  dropping it hides a protocol violation and leaves the peer believing the
  stream was accepted.

## Links

- [ADR-0033](0033-webtransport-over-http3.md)
- [ADR-0037](0037-webtransport-draft17-completion-gate.md)
- [ADR-0038](0038-webtransport-external-interoperability.md)
- `draft-ietf-webtrans-http3-17` Sections 3 and 4
