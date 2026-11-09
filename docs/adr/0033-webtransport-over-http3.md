---
id: ADR-0033
title: "Own WebTransport over HTTP/3 as a Separate Product Layer"
status: accepted
date: 2026-11-09
scope: [protocol/webtransport, protocol/http3, protocol/quic, api/webtransport, product/web]
superseded_by: null
---

# 0033. Own WebTransport over HTTP/3 as a Separate Product Layer

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0030](0030-h3-datagrams-and-extended-connect.md), [ADR-0032](0032-h3-capsule-protocol.md)
- Related: [ADR-0027](0027-owned-h3-qpack.md), [ADR-0028](0028-owned-quic.md), [ADR-0031](0031-quic-0rtt-and-session-resumption.md)

---

> Implementation status: phases 1-4 baseline is landed — WT wire model,
> generic H3 extension SETTINGS/stream routing, session establishment,
> bidi/uni streams, datagrams and close/drain capsules. Phase 3 reliable reset
> (`RESET_STREAM_AT`) and full WT flow-control enforcement/browser interop are
> still outstanding; this ADR does not claim complete draft-17 compliance yet.

## Context

WebTransport over HTTP/3 provides browser-visible multiplexed reliable streams
and unreliable datagrams inside an HTTP/3 connection. It is not an RFC 9114
feature; it is a separate binding currently defined by
`draft-ietf-webtrans-http3-17`, with the W3C API at Candidate Recommendation.

The project goal includes simulating modern web pages, not only RFC transport
primitives. That makes WebTransport a required web capability. It must not be
silently folded into `netune-http3`: the draft has its own SETTINGS, stream
types, capsules, flow control and error space, and it depends on another draft
QUIC extension (`RESET_STREAM_AT`).

## Decision

### 1. Separate crate and dependency direction

```text
netune-webtransport
        ↓
netune-http3
        ↓
netune-quic
```

`netune-webtransport` is a leaf product crate. It may depend on the H3 and QUIC
leaves; neither leaf may depend on it.

### 2. Pin draft-17

- Wire behavior is pinned to `draft-ietf-webtrans-http3-17`.
- Draft-specific constants and APIs are documented as draft, not RFC.
- A future draft change gets a new explicit implementation step; it is not
  silently absorbed into the RFC core.

### 3. Required wire surface

- `SETTINGS_WT_ENABLED` (`0x20b8933b`, value 1).
- `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (`0x2b64`),
  `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` (`0x2b65`),
  `SETTINGS_WT_INITIAL_MAX_DATA` (`0x2b61`).
- Extended CONNECT with `:protocol = webtransport-h3`.
- Session ID = CONNECT stream ID; it must identify a client-initiated
  bidirectional stream.
- Unidirectional stream type `0x54` followed by Session ID.
- Bidirectional WT_STREAM signal `0x41` followed by Session ID.
- `WT_CLOSE_SESSION` (`0x2843`), `WT_DRAIN_SESSION` (`0x78ae`).
- `WT_MAX_STREAMS` (`0x190B4D3F`/`0x190B4D40`),
  `WT_STREAMS_BLOCKED` (`0x190B4D43`/`0x190B4D44`),
  `WT_MAX_DATA` (`0x190B4D3D`), `WT_DATA_BLOCKED` (`0x190B4D41`).
- WT error codes and application-error range mapping.
- QUIC `reset_stream_at` (`0x1d`) and `RESET_STREAM_AT` (`0x24`).
- HTTP/3 datagrams with the CONNECT stream's Quarter Stream ID.
- The Capsule Protocol from ADR-0032 for session control and flow control.

### 4. H3 extension seams, not WT inside H3

`netune-http3` gains generic extension seams:

- extra SETTINGS and peer SETTINGS access;
- reserved unidirectional stream types;
- a bidirectional stream signal;
- stream routing to an extension receiver.

The seams are protocol-neutral. WebTransport installs `0x54`/`0x41`; HTTP/3
core never names WebTransport.

### 5. QUIC reliable partial reset

`netune-quic` gains the `RESET_STREAM_AT` frame and `reset_stream_at`
transport parameter. WebTransport resets a data stream with reliable size
covering the WT stream header plus application-requested prefix. A peer that
does not advertise the extension cannot be used for WebTransport.

### 6. API model

- `WebTransportClient`: owns one H3 client connection and a stream-extension
  receiver.
- `WebTransportSession`: CONNECT stream, session ID, stream/datagram/capsule
  endpoints, close/drain.
- `WebTransportSendStream` / `WebTransportRecvStream`: reliable stream halves
  after header consumption.
- Datagrams preserve message boundaries and may be lost.
- Flow control uses initial SETTINGS and WT capsules; limits are session-scoped
  in addition to QUIC limits.
- Session close resets all associated streams with `WT_SESSION_GONE`.
- 0-RTT cannot establish a WebTransport session; CONNECT is not safe in 0-RTT.
  Data after session establishment follows the underlying 0-RTT boundary only
  after the session exists.

### 7. Security boundaries

- Verify `:authority`, `:scheme = https`, `:path`, and Origin when supplied.
- Session ID must be a client-initiated bidirectional stream ID.
- Bounded buffers for streams/datagrams that arrive before session acceptance.
- WT flow-control limits are enforced; exceeding them closes the session with
  `WT_FLOW_CONTROL_ERROR`.
- Draft extension settings are read from the current connection, never replayed
  from a previous connection's retained values.

## Invariants

- **`[INV-WT-01]` Session ID Is a Client Bidi Stream ID**: every WT stream and
  datagram session ID must satisfy `id % 4 == 0`; otherwise H3_ID_ERROR.
- **`[INV-WT-02]` Draft Is Isolated**: no WebTransport draft constant or state
  machine enters `netune-http3`/`netune-quic`; they expose only generic seams
  and the QUIC reliable-reset extension.
- **`[INV-WT-03]` Early Data Cannot Establish a Session**: a WebTransport
  CONNECT is never sent in 0-RTT; early settings are discarded across
  connections.
- **`[INV-WT-04]` Flow Control Is Enforced**: WT_MAX_STREAMS and WT_MAX_DATA
  are cumulative, monotonic, and enforced in addition to QUIC limits.

## Phases

1. ADR, WT wire constants, Session ID/error mapping, SETTINGS model.
2. H3 generic extension seams and peer SETTINGS.
3. QUIC `RESET_STREAM_AT`/`reset_stream_at`.
4. `netune-webtransport` session + stream + datagram integration.
5. WT flow-control capsules + close/drain + error mapping.
6. Browser/oracle interop and web-simulation tests.

Each phase is independently reviewable; none may silently claim the whole draft.
