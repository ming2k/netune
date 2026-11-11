# How-To Guides

Task-oriented guides for a competent user. Each assumes you have completed [Getting Started](../tutorials/getting-started.md) and know which crate you are working with.

---

## Guides

| Guide | Solves |
| :--- | :--- |
| [Diagnose a Failed Request](diagnose-failures.md) | Read the diagnostic and trace snapshot a failed attempt returns, and capture a review bundle. |
| [Configure TLS Profiles and Fingerprints](configure-tls-profiles.md) | Select a TLS identity per request and keep its wire fingerprint stable. |
| [Simulate Network Chaos with FaultIo](fault-injection.md) | Inject delays, splits, truncations, and resets into a connection. |
| [Configure Proxies](configure-proxies.md) | Route egress through HTTP CONNECT or SOCKS5. |
| [Establish a WebSocket Client Connection](websocket-client.md) | Upgrade an owned connection to RFC 6455, stream frames, and keep a long session alive. |
| [Serve HTTP/1.1 and HTTP/2](serve-http.md) | Stand up an observable listener that serves both protocols behind one handler: stream a response, bound what a hostile peer can cost, and derive a per-exchange trace. |
| [Use HTTP/3](use-http3.md) | Stream an H3 request body, select a typed SETTINGS/QPACK profile, and bind a separate QUIC ingress listener behind the same handler. |

For the full crate surface, consult the [Crates Reference](../reference/crates.md).
