# Establish a WebSocket Client Connection

This guide shows how to open a client-side WebSocket session with `netune`'s
owned RFC 6455 stack: the handshake rides the same connector, TLS fingerprint
profiles, proxy egress, and syscall tap as every HTTP attempt.

The transport is **client-only** by design ([ADR-0007](../adr/0007-owned-client-websocket-codec.md)):
there is no listening or accept surface anywhere in the workspace.

> **Every snippet on this page is executed by the test suite**
> (`crates/netune/tests/guide_examples.rs`), so the code cannot silently
> drift from the real API.

---

## Prerequisites

- A `Client` with a connector and pool, as in [Getting Started](../tutorials/getting-started.md).
- Optionally, a `TlsProfile` preset if the target gateway fingerprints the
  ClientHello of the upgrade request (see
  [Configure TLS Profiles](configure-tls-profiles.md)).

## Connect and Echo

```rust
use netune::{Client, ClientConfig, Pool, Target, TcpConnector, WsMessage};
use netune_ws::CloseCode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(TcpConnector::new(), Pool::default(), ClientConfig::default());
    let target = Target::plain("ws.example.internal:8080");

    // Performs DNS → TCP → (TLS) → HTTP/1.1 101 upgrade, all traced.
    let mut ws = client.connect_ws(&target, "/v1/stream").await?;

    ws.send_text(r#"{"type":"subscribe","channel":"ticks"}"#).await?;

    while let Some(message) = ws.receive().await? {
        match message {
            WsMessage::Text(text) => println!("text: {text}"),
            WsMessage::Binary(data) => println!("binary: {} bytes", data.len()),
            WsMessage::Ping(_) | WsMessage::Pong(_) => { /* auto-ponged already */ }
            WsMessage::Close(reason) => {
                println!("server closed: {reason:?}");
                break;
            }
        }
    }

    // Idempotent: after a completed close handshake this is a no-op.
    ws.close(CloseCode::NORMAL, "done").await?;
    Ok(())
}
```

What the transport does for you during the session:

- **Automatic pong**: an inbound Ping is answered with a matching Pong before
  the ping is surfaced to your `receive` loop.
- **Close completion**: when the server closes first, the reply close frame
  echoes the server's status code (RFC 6455 §5.5.1), `receive` yields
  `Message::Close`, and a later `close()` of your own is a no-op.
- **Masking enforcement**: outbound frames carry a fresh 4-byte mask; an
  inbound masked frame (a server bug or an interceptor) fails fast with a
  `PROTOCOL_ERROR` classification.
- **Bounded reassembly**: fragmented text/binary messages are reassembled up
  to `WsLimits::max_message_bytes`; interleaved control frames pass through,
  and a text message's UTF-8 is validated *incrementally* — an invalid byte
  fails that frame (close code 1007), not the whole reassembly.

## Negotiate a Subprotocol

Offer `Sec-WebSocket-Protocol` values in preference order; the server must
echo exactly one of them, or none:

```rust
use netune::WsHandshake;

let handshake = WsHandshake::default()
    .with_subprotocol("mcp.v1")
    .with_subprotocol("mcp.v0")
    .with_extra_header("authorization", "Bearer <token>");

let mut ws = client.connect_ws_traced(&target, "/mcp", recorder, handshake).await?;
```

An echo of an unoffered subprotocol is a terminal handshake error — loud, by
[`INV-TLS-02`]'s fail-fast posture, never a silent fallback.

## Trace What Happened

Pass an explicit `Recorder` to keep the attempt's trace:

```rust
use std::sync::{Arc, Mutex};
use netune::WsHandshake;
use netune_trace::{EventKind, Recorder};

let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
let mut ws = client
    .connect_ws_traced(&target, "/v1/stream", Arc::clone(&recorder), WsHandshake::default())
    .await?;

// ... session, then read the log from the recorder you passed ...
let log = recorder.lock().unwrap().log().clone();
```

Event coverage on the WS path:

- `EventKind::WsFrame` — **every** frame crossing the wire, with its payload
  class (`FrameClass`) and byte count. Fragmented parts stay individually
  visible: one message in three frames is three `WsFrame` events.
- `EventKind::ProtocolFrame` — each *complete message*, for message-level
  accounting.
- `EventKind::Error` — any handshake failure, so a trace never ends as an
  unexplained headless corpse.

Derived timings work exactly as on the HTTP path (see
[Getting Started](../tutorials/getting-started.md)).

## Limits

Pass `WsLimits` to bound frame and message sizes for untrusted origins:

```rust
use netune::WsLimits;

let limits = WsLimits {
    max_frame_bytes: 1024 * 1024,
    max_message_bytes: 4 * 1024 * 1024,
};
```

A frame that *declares* more than `max_frame_bytes` is refused before its
body arrives, so an attacker cannot stream unbounded bytes while the parser
waits. A reassembled message beyond `max_message_bytes` is likewise a
terminal error — never a silent truncation.

## What This Is Not

- **No server side**: `netune` never listens. Test doubles for the server role
  live in test code only.
- **No pooling**: a WebSocket is a dedicated, stateful connection; it is never
  returned to the keep-alive pool ([ADR-0007], `INV-WS-05`).
- **No permessage-deflate**: the compression extension (RFC 7692) is not
  negotiated.

---

## Keep a Long Session Alive

For sessions that outlast middlebox idle windows, wrap the stream in a
`WsSession`: it sends a client ping on an interval and fails the session if
no pong arrives in time, so a silently culled socket becomes an explicit
error instead of a hung read.

```rust
use netune::{WsSession, WsSessionConfig};
use std::time::Duration;

let mut session = WsSession::new(
    ws,
    WsSessionConfig {
        // Default 20 s, aligned with the pool's idle bound and the 30–60 s
        // cull window edge gateways actually apply (ADR-0005).
        ping_interval: Duration::from_secs(20),
        pong_timeout: Duration::from_secs(10),
    },
);

while let Some(message) = session.next().await? {
    // same message handling as above; pings/pongs keep the wire proven
}

// Reconnection is intentionally NOT automatic: a WebSocket's identity is its
// connection, and a silent re-dial would silently drop in-flight messages.
// Build retry/resume policy in the harness above `NetError`.
```

One subtlety worth knowing: only a pong whose payload matches the outstanding
ping discharges the probe. A peer-initiated pong is still delivered to your
loop (RFC 6455 allows unsolicited pongs for application use), but it does not
answer the liveness question — so a peer that pongs arbitrarily while
ignoring your pings fails its deadline anyway.
