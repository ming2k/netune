---
id: ADR-0007
title: "Owned Client-Side WebSocket Codec and Egress Stream"
status: accepted
date: 2026-10-20
scope: [websocket/codec, transport/egress, protocol/rfc6455]
superseded_by: null
---

# 0007. Owned Client-Side WebSocket Codec and Egress Stream

- Status: Accepted
- Date: 2026-10-20
- Deciders: Ming Li

---

## Context and Problem Statement

The workspace owns HTTP/1.1 ([`netune-http1`]) and HTTP/2 ([`netune-http2`]) codecs end to end, but bidirectional long-lived sessions — OpenAI Realtime, Gemini Live, MCP over WebSocket — currently force the harness onto a third-party WebSocket runtime (`tokio-tungstenite` and friends). A foreign WS runtime brings its own private buffers, its own TLS stack wiring, and its own opaque read loop, which breaks three standing contracts:

1. `[INV-TRACE-01]` — frame arrival timings must be pure derivations of a recorded trace; a third-party read loop hides the syscall boundary where each frame actually arrived.
2. `[INV-TRANSPORT-00]` — no third-party HTTP/protocol implementations in the production path.
3. `[INV-CUSTOM-01]` — wire determinism; a foreign library offers no control over write chunking, masking cadence, or the exact bytes of the upgrade request.

WebSocket is defined by RFC 6455 as an HTTP/1.1 upgrade (or an HTTP/2 extended CONNECT). Its handshake, masking rules, and framing are tightly bound to the endpoint role, so the decision is as much about *which side of the protocol to own* as it is about *whether to own it at all*.

## Decision Drivers

- Preserve the zero-blackbox observability programme across long-lived bidirectional streams, not just request/response attempts.
- TLS fingerprint continuity: a WS connection must present the same `TlsProfile` identity (and JA4 shape) as any other egress attempt from the same client.
- `FaultIo` chaos injection must be able to wrap a live WebSocket session (delayed pongs, split reads, mid-stream resets) exactly as it wraps HTTP bodies.
- Structural privilege separation and crate focus ([ADR-0003]): pure wire math must not live beside transport policy.
- Client egress orientation: the crate is an egress stack ([ADR-0001], [ADR-0002]); there is no listening socket, accept loop, or server session table anywhere in the workspace.

## Considered Options

- Option 1: Adopt `tokio-tungstenite` (or `fastwebsockets`) as a production dependency.
- Option 2: Adopt a WS library for the codec but wrap it in `TimedIo` for tracing.
- Option 3: Own the codec in a new pure crate (`netune-ws`) and own the client transport integration in `netune`; server-side logic is excluded from production entirely and only ever appears in tests as a mock origin.

## Decision Outcome

Chosen option: "Option 3".

Two crates, two strictly separated concerns:

1. `netune-ws` — a pure RFC 6455 codec: `Frame`/`Opcode`/`CloseCode`, a stateless `FrameDecoder`/`FrameEncoder` pair, a role-parameterised masking engine (64-bit word XOR), a fragmented-message `MessageAssembler` with interleaved-control-frame support, and a self-contained SHA-1 `compute_accept_key`/`verify_handshake` pair. No I/O, no clock, no runtime dependency beyond `bytes` and `base64`.
2. `netune` — `Client::connect_ws` performs the RFC 6455 upgrade over the existing connector stack (`TimedIo` tap, TLS profiles, egress confinement), validates the 101 response and `Sec-WebSocket-Accept`, then hands the transport to `WsStream`, a full-duplex client stream that auto-pongs pings, completes the close handshake, and marks `ProtocolFrame` events (with `FrameClass`) into the attempt's `Recorder`. Session liveness for long-lived sockets is enforced by `WsSession`, a client-driven heartbeat layer (ping interval + pong deadline) that lives in `netune` beside the other transport policy.

### Role asymmetry is deliberate

WebSocket is not a symmetric peer protocol. RFC 6455 §5.1 mandates that client→server frames are masked and server→client frames are not; the handshake likewise assigns nonce generation to the client and accept-key computation to the server. The workspace therefore owns the **client role only**:

- `netune-ws`'s decoder accepts a `Role` and enforces the masking rule for that role (the client role rejects masked inbound frames), so the codec itself is complete and testable from both sides, but the *transport* surface exposed by `netune` is client-only. There is no `ws_listen`, no `TcpListener`, no accept loop.
- A WS connection is long-lived, full-duplex, and stateful. It is **never pooled**: unlike the 20 s keep-alive pool ([ADR-0005]), an upgraded socket belongs to its `WsStream` until closed. The stale-socket absorption retry does not apply — a WS session's identity *is* its connection.

### Invariants & Behavioral Boundaries

- **`[INV-WS-01]` Client Role Exclusivity**: The production transport surface exposes only client-side WebSocket egress. Server-side accept/listen code must never compile into any workspace crate; mock origins in tests are the only server implementations.
- **`[INV-WS-02]` Masking Direction Enforcement**: Frames the client sends carry a fresh 4-byte mask; masked frames received from a server are a `PROTOCOL_ERROR` (close code 1002), per RFC 6455 §5.1.
- **`[INV-WS-03]` Bounded Reassembly**: A fragmented message may not exceed `max_message_bytes`; a control frame may not exceed 125 bytes and may not be fragmented. A frame *declaring* more than `max_frame_bytes` is refused before its body arrives. Violations are terminal protocol errors, never silent truncation.
- **`[INV-WS-04]` Frame-Level Observability**: Every frame crossing the wire is recorded as an `EventKind::WsFrame` event (payload class + byte count), so fragmented messages stay individually visible in the trace; message-level accounting is a `ProtocolFrame` event. Any handshake failure closes the attempt's trace with an `Error` event — a trace never ends as a headless corpse.
- **`[INV-WS-05]` No WS Connection Pooling**: Upgraded sockets are excluded from `Pool`; they are dedicated to the `WsStream` lifetime.
- **`[INV-WS-06]` Liveness Is Proven, Not Assumed**: Session liveness is enforced by client-driven ping/pong with an explicit pong deadline (`WsSession`); only a pong whose payload matches the outstanding ping discharges the probe — a peer-initiated pong is liveness evidence, not an answer. A dead session is a terminal `NetError`, never a hung read. Automatic reconnection is excluded from the session layer, preserving the replay-safety posture of `[INV-TRANSPORT-01]`.
- **`[INV-WS-07]` Incremental Text Validation**: UTF-8 validity of text messages is enforced incrementally across fragments (RFC 6455 §8.1): an invalid byte fails that frame (close code 1007), never the whole reassembly, and a sequence split across frames must assemble correctly.
- **`[INV-WS-08]` Differential Wire Parity**: The codec's encoding must agree byte-for-byte with a battle-tested RFC 6455 oracle (`tungstenite`, dev-dependency only) across all length boundaries (125/126/65535/65536), and its decoder must accept the oracle's wire bytes, in both masked and unmasked directions.

### Consequences

- **Positive**:
  - Realtime/MCP sessions inherit TLS fingerprint presets, proxy egress, SSRF confinement, syscall-level tracing, and `FaultIo` chaos injection.
  - The codec crate is usable stand-alone (pure, `no_std`-adjacent, trivially fuzzable) and symmetrically testable even though the transport is client-only.
  - No third-party protocol runtime enters the production graph.
- **Negative & Trade-offs**:
  - The workspace now owns WS wire maintenance, including edge cases (interleaved control frames, UTF-8 incremental validation across fragments).
  - Permessage-deflate (RFC 7692) is not implemented; compressed WS extensions remain future work.
  - RFC 8441 (WS over HTTP/2 extended CONNECT) is not implemented and depends on the H2 client's maturity.

### Verification Artifacts

- `netune-ws` unit tests pin RFC 3174 SHA-1 vectors, the RFC 6455 §1.3 handshake example, and the UTF-8 grammar's exclusion ranges (overlong, surrogates, >U+10FFFF).
- `netune-ws/tests/differential.rs` proves wire parity with `tungstenite` (`[INV-WS-08]`) across length boundaries, masked and unmasked.
- `netune/tests/ws.rs` and `netune/tests/ws_session.rs` run the client against local mock origins: full-duplex echo, auto-pong, close-code echo, subprotocol negotiation (match and mismatch), pong-deadline death, and decoy-pong non-discharge.
- `netune/tests/guide_examples.rs` compile-and-runs every snippet in `docs/how-to/websocket-client.md`, so the guide cannot silently drift from the API.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Adopt `tokio-tungstenite` as a Production Dependency

- **Why considered**: Immediate, battle-tested RFC 6455 coverage including extensions.
- **Why rejected**: It owns the socket read loop, its own handshake validation, and its own buffering; frame arrival times become visible only after the fact through callbacks, breaking `[INV-TRACE-01]`'s pure-derivation contract. Its dependency tree also drags foreign TLS wiring into the production graph, which `[INV-TRANSPORT-00]` forbids.

### Option 2 (Rejected): Wrap a Third-Party Codec in `TimedIo`

- **Why considered**: Keeps the transport tap while outsourcing protocol math.
- **Why rejected**: The third-party codec still dictates read-loop granularity and buffer ownership, so the tap records whatever chunks the foreign loop decided to produce — synthetic measurement bias (`[INV-CUSTOM-02]`). Masking cadence and write chunking remain outside our control, violating `[INV-CUSTOM-01]`.

### Server-Side Implementation (Rejected)

- **Why considered**: Symmetry with the client codec; "a complete library" feel.
- **Why rejected**: `netune` is structurally an egress stack ([ADR-0002] confines egress; [ADR-0003] separates privileged capabilities). A WS server would require an HTTP/1.1 *server* codec (request parsing, response writing) that `netune-http1` deliberately excludes, plus a listening runtime — a second product inside the first. The codec-level `Role::Server` support inside `netune-ws` is the correct amount of "server": enough to prove the wire format from both sides in tests, none of it reachable from production transport APIs.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0002](0002-egress-confinement-policy.md), [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md), [ADR-0005](0005-keepalive-socket-culling-absorption.md), [ADR-0006](0006-transport-customizability-wire-evasion.md)
