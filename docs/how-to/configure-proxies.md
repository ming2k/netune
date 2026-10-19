# Configure Proxies

This guide demonstrates how to tunnel requests through HTTP `CONNECT` or SOCKS5 proxies using `ProxyConnector`.

---

## Supported Proxy Types

`Proxy` supports two proxy protocols parsed from URL formats:
1. **HTTP CONNECT**: `http://host:port` or `http://user:password@host:port`
2. **SOCKS5**: `socks5://host:port` or `socks5://user:password@host:port` (with remote hostname resolution)

---

## Tunneling through an HTTP CONNECT Proxy

```rust
use netune::{Client, ClientConfig, Pool, Proxy, ProxyConnector, RequestHead, Target, TcpConnector, TlsConnector};
use netune_trace::Recorder;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Parse proxy target
    let proxy = Proxy::parse("http://corporate-proxy.internal:8080")?;

    // 2. Wrap the base TCP connector
    let proxy_connector = ProxyConnector::new(TcpConnector::new(), proxy);

    // 3. For HTTPS targets, wrap with TlsConnector
    let tls_connector = TlsConnector::platform(proxy_connector)?;
    let client = Client::new(tls_connector, Pool::default(), ClientConfig::default());

    // 4. Send request to the origin
    let target = Target::tls("api.openai.com:443", "api.openai.com");
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
    let head = RequestHead::new(http::Method::GET, "/v1/models");

    let mut response = client.send(&target, recorder, head, None).await?;
    let body = response.body.read_to_end().await?;
    println!("Response bytes: {}", body.len());

    Ok(())
}
```

---

## SOCKS5 with Authentication

To tunnel via SOCKS5 with credentials:

```rust
use netune::{Proxy, ProxyConnector, TcpConnector};

fn create_authenticated_socks_connector() -> Result<ProxyConnector<TcpConnector>, Box<dyn std::error::Error>> {
    let proxy = Proxy::parse("socks5://alice:hunter2@edge-relay.vpn:1080")?;
    Ok(ProxyConnector::new(TcpConnector::new(), proxy))
}
```

Tunnels are established before running TLS with the target, preserving the target's Server Name Indication (SNI) and certificate validation end-to-end.
