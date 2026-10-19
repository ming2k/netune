# How-To Guides

Task-oriented guides for a competent user. Each assumes you have completed [Getting Started](../tutorials/getting-started.md) and know which crate you are working with.

---

## Guides

| Guide | Solves |
| :--- | :--- |
| [Configure TLS Profiles and Fingerprints](configure-tls-profiles.md) | Select a TLS identity per request and keep its wire fingerprint stable. |
| [Simulate Network Chaos with FaultIo](fault-injection.md) | Inject delays, splits, truncations, and resets into a connection. |
| [Configure Proxies](configure-proxies.md) | Route egress through HTTP CONNECT or SOCKS5. |
| [Establish a WebSocket Client Connection](websocket-client.md) | Upgrade an owned connection to RFC 6455, stream frames, and keep a long session alive. |

For the full crate surface, consult the [Crates Reference](../reference/crates.md).
