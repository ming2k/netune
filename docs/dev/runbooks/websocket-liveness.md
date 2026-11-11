# WebSocket Liveness Playbook

## Target Subsystem & Reference Environment

- `netune::WsStream` and `WsSession` over an owned upgraded connection.
- A trace with `WsFrame`, `ProtocolFrame`, or `NET-E-WS-FAILED` / `NET-I-WS-CLOSED`.
- A loopback WebSocket origin that can delay, fragment, or drop frames.

## Core Protocol Rules & Invariants

- The codec enforces role-correct masking and bounded reassembly (`[INV-WS-01..08]`).
- An upgraded socket belongs to its `WsStream`; it never enters the pool (`[INV-WS-05]`).
- Heartbeat liveness is explicit; automatic reconnect is not a transport policy.
- A peer close is echoed once, and the close frame surfaces as a message.

## Diagnostic Playbook

1. Check the upgrade status and subprotocol before reading frame events; a non-101 is an upgrade failure, not a frame failure.
2. `NET-I-WS-CLOSED` records the peer/local close code; a close without a status is `1005`, which must never be sent on the wire.
3. A pong deadline failure is a liveness failure, not a decode failure: confirm the ping payload matches the outstanding probe.
4. A fragmented message that fails UTF-8 validation is a payload error; inspect the frame boundary, not the message text.
5. Reproduce with `FaultIo` splits/truncations and the loopback WebSocket harness.

## Do-Not-Regress Checklist

- [ ] Masking direction is enforced for the client role.
- [ ] A fragmented message is bounded and validated incrementally.
- [ ] The close handshake completes once and echoes the peer code.
- [ ] The upgraded socket is never pooled.
