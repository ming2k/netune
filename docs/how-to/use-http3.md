# Use HTTP/3

HTTP/3 is a peer transport in both directions: `netune-http3` owns the RFC 9114
state machine, while each orchestrator owns its side of the socket. The client
can stream an upload; the server is a separate QUIC listener.

The decisions behind this guide are [ADR-0024](../adr/0024-h3-streaming-request-bodies.md)
(streaming request bodies), [ADR-0025](../adr/0025-h3-ingress-peer-transport.md)
(HTTP/3 ingress is a peer transport) and [ADR-0026](../adr/0026-controlled-dynamic-qpack.md)
(dynamic QPACK and typed SETTINGS).

---

## 1. Client: connect and stream an upload

```rust,no_run
use bytes::Bytes;
use netune_http3::{H3Client, H3SettingsProfile};
use netune_quic::QuicConnector;
use netune_quic::profile::QuicProfile;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let connector = QuicConnector::new(QuicProfile::chrome_quic());
let mut client = H3Client::connect_with_settings(
    &connector,
    "127.0.0.1:4433".parse()?,
    "api.example",
    None,
    H3SettingsProfile::dynamic(),
)
.await?;

let request = http::Request::builder()
    .method("POST")
    .uri("https://api.example/upload")
    .body(())?;
let mut body = client.open_request(request).await?;
body.send_data(Bytes::from_static(b"first chunk")).await?;
body.send_data(Bytes::from_static(b"second chunk")).await?;
let mut response = body.finish().await?;
let bytes = response.read_to_end().await?;
# Ok(())
# }
```

`send` remains the buffered convenience; it composes `open_request`, so there is
no second request implementation. `H3SettingsProfile::default()` advertises
zero QPACK capacity (stateless header blocks); `dynamic()` opts into the
controlled dynamic path. A SETTINGS profile is connection-fixed and is recorded
in the trace as `identity.h3_settings_profile`.

## 2. Server: bind a QUIC ingress listener

`H3Server` is not a mode of the TCP `Server`. It takes its own TLS
configuration, forces ALPN `h3`, and reuses the same handler, body reader,
timeouts, body ceiling and trace sink.

```rust,no_run
use std::sync::Arc;

use netune_http3::H3SettingsProfile;
use netune_server::{
    H3Server, Handler, HandlerFuture, IncomingRequest, RequestBody, Response, ServerConfig,
};

struct Echo;

impl Handler for Echo {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        mut body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move { Response::ok(body.read_to_end().await.unwrap_or_default()) })
    }
}

# async fn run(tls: Arc<rustls::ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
let server = H3Server::bind(
    "127.0.0.1:4433",
    ServerConfig::default(),
    tls,
    H3SettingsProfile::dynamic(),
    Arc::new(Echo),
)
.await?;
server.serve(async {}).await;
# Ok(())
# }
```

The listener admits at most `max_connections` QUIC connections, sheds excess
handshakes immediately, and drains in-flight request streams up to
`drain_timeout`. Each request is a handler task; the body is bounded by
`body_timeout` and `max_body_bytes`, and an unconsumed body is reset rather than
pinning the stream.

## 3. Read the trace

HTTP/3 ingress is connection-level L0, like HTTP/2. Each request gets a distinct,
non-zero trace exchange id because HTTP/3 wire stream `0` is a valid request
stream. The wire stream id is recorded in the H3 start event, while
`derive_ingress_exchanges` groups handler and response spans by the exchange id.

For the client, `H3ResponseStream::trace()` returns the per-exchange
`RequestTrace` once the response body is complete.
