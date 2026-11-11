# Operational Runbooks

Runbooks are durable diagnostic manuals for subsystems that require hands-on inspection, packet capture, or A/B isolation. The authoring standard is [`../standards/runbooks.md`](../standards/runbooks.md).

## Playbooks

| Playbook | Scope |
| :--- | :--- |
| [First Response](first-response.md) | Triage a failed `netune` attempt from its diagnostic and trace bundle |
| [Trace Bundle](trace-bundle.md) | Capture, redact, read and attach a review bundle |
| [QUIC and HTTP/3](quic-h3.md) | Diagnose owned QUIC handshakes, H3 stream failures and path MTU |
| [Pool and Replay](pool-replay.md) | Diagnose stale pooled sockets and replay safety |
| [WebSocket Liveness](websocket-liveness.md) | Diagnose upgrade, frame, close and heartbeat failures |
