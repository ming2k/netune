---
id: ADR-0037
title: "WebTransport Draft-17 Completion Gate"
status: accepted
date: 2026-11-10
scope: [protocol/webtransport, protocol/quic, api/webtransport, product/web]
superseded_by: null
---

# 0037. WebTransport Draft-17 Completion Gate

- Status: Accepted
- Date: 2026-11-10
- Deciders: Ming Li
- Related: [ADR-0033](0033-webtransport-over-http3.md),
  [ADR-0028](0028-owned-quic.md), [ADR-0032](0032-h3-capsule-protocol.md)

---

> Implementation status: Gates 1-3 have landed — `RESET_STREAM_AT` wire and
> transport parameter, reliable-prefix delivery, reliable partial reset on the
> send side, session close/drain/peer-close, GOAWAY session refusal and
> flow-control rejection. Gate 4 is partially landed: the non-Rust
> `quic-go/webtransport-go` peer completes bidi, uni and datagram exchanges
> (ADR-0038), but Chrome 157 and Chrome 159 unstable do not advertise `reset_stream_at`, so the browser
> half remains blocked. Gate 5 is now exercised by the admission, Origin,
> session-ID and adversarial control suite in ADR-0039. This ADR does not claim
> draft-17 completeness while the browser gate remains open.

## Context and Problem Statement

ADR-0033 delivered a draft-17 baseline, but explicitly did not claim complete
compliance. The remaining gaps are not cosmetic:

- `RESET_STREAM_AT` reliable partial reset is absent from the owned QUIC wire
  and send/recv state;
- teardown/GOAWAY behavior is not exercised against an independent peer;
- browser interop is unverified;
- flow-control capsule enforcement needs an adversarial test, not only a happy
  path.

Calling WebTransport production-ready now would be a false claim. The correct
response is a gated completion track, separate from the core QUIC/H3 release
line.

### Invariants & Behavioral Boundaries

- **`[INV-WT-05]` Reliable Reset Preserves the Prefix**: a reliable reset must
  deliver exactly the bytes up to its reliable size, then surface the reset; it
  never delivers bytes beyond that prefix, and it requires the peer's
  `reset_stream_at` advertisement. *Enforced by*:
  `a_reliable_partial_reset_delivers_the_prefix_before_the_reset` and
  `reset_at_before_stream_data_opens_the_stream_and_keeps_the_prefix`.
- **`[INV-WT-06]` Closed Sessions Refuse New Streams**: a local or peer
  `WT_CLOSE_SESSION`, and a drain acknowledgement, must terminate the session;
  no new stream may be opened after the close is observed. *Enforced by*:
  the close/drain session test and the peer-close test.

## Completion Gate

WebTransport leaves the experimental posture only when all of the following
hold:

1. **Reliable reset.** `RESET_STREAM_AT` (type `0x24`) and the
   `reset_stream_at` transport parameter (`0x1d`) are encoded, decoded and
   applied with reliable-size semantics, with a lost-reset test.
2. **Teardown.** Peer-initiated and local session close, CONNECT-stream
   termination, GOAWAY and drain are tested from both roles.
3. **Flow control.** Over-limit streams/data and malformed capsule sequences
   close the session with the correct WT error code, not a generic transport
   error.
4. **Independent interop.** A browser/W3C-compatible peer and one non-Rust
   implementation complete a bidirectional stream, a unidirectional stream and
   a datagram exchange against `netune-webtransport`.
5. **Security.** `:authority`, `:scheme`, `:path`, Origin and Session ID
   validation are tested against spoofed and replayed inputs.

Each gate is an independent test suite in `crates/netune-webtransport/tests/`;
a gate that cannot run in CI is not a gate.

## Boundaries

- Core QUIC/H3 may ship without Gate 1–5; WebTransport may not claim production
  completeness.
- The draft pin stays `draft-ietf-webtrans-http3-17`; a draft change is a new
  explicit implementation step, never silent absorption.
- No WebTransport constant enters `netune-http3` or `netune-quic`; only generic
  extension seams and `RESET_STREAM_AT` do.

## Rejected Alternatives

### Declare the baseline production-ready

- **Why considered**: the happy-path tests pass.
- **Why rejected**: the stated gaps are correctness and interop gaps, not polish.

### Fold WebTransport into the H3 core release gate

- **Why considered**: one release train.
- **Why rejected**: a draft product layer must be able to lag the stable
  transport without blocking it or borrowing its credibility.

## Links

- [ADR-0033](0033-webtransport-over-http3.md),
  [ADR-0038](0038-webtransport-external-interoperability.md),
  [ADR-0039](0039-webtransport-request-admission.md)
- `draft-ietf-webtrans-http3-17`
