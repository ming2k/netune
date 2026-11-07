# Configure Proxies

This guide demonstrates how to tunnel requests through HTTP `CONNECT` or SOCKS5 proxies using `ProxyConnector`.

---

## Supported Proxy Types

`Proxy` supports two proxy protocols parsed from URL formats:
1. **HTTP CONNECT**: `http://host:port` or `http://user:password@host:port`
2. **SOCKS5**: `socks5://host:port` or `socks5://user:password@host:port` (with remote hostname resolution)

---

## Tunneling through an HTTP CONNECT Proxy

A proxy is a `Connector` wrapper: the inner connector dials the **proxy**, and
the wrapper opens a tunnel to the target inside it.

```rust,no_run
use netune::{Client, ClientConfig, Pool, Proxy, ProxyConnector, RequestHead, Target, TcpConnector, TlsConnector};
use netune_trace::Recorder;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Parse the proxy URL. Credentials in the URL become proxy auth.
    let proxy = Proxy::parse("http://corporate-proxy.internal:8080")?;

    // 2. Wrap the base TCP connector. This connector now dials the proxy.
    let proxy_connector = ProxyConnector::new(TcpConnector::new(), proxy);

    // 3. For an HTTPS target, run TLS *inside* the tunnel, so the target's SNI
    //    and certificate validation are unchanged by the proxy.
    let tls_connector = TlsConnector::platform(proxy_connector)?;
    let client = Client::new(tls_connector, Pool::default(), ClientConfig::default());

    // 4. The target is the origin, not the proxy.
    let target = Target::tls("api.openai.com:443", "api.openai.com");
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
    let head = RequestHead::new(http::Method::GET, "/v1/models");

    let mut response = client.send(&target, recorder, head, None).await?;
    let body = response.body.read_to_end().await?;
    println!("Response bytes: {}", body.len());

    Ok(())
}
```

The example carries `no_run` because the proxy host in it does not exist on
the test machine; it is still compiled, so its API cannot drift.

---

## SOCKS5 with Authentication

SOCKS5 is the same shape — the scheme decides the wire protocol, and the
hostname is resolved by the proxy rather than locally:

```rust
use netune::{Proxy, ProxyConnector, TcpConnector};

fn create_authenticated_socks_connector() -> Result<ProxyConnector<TcpConnector>, Box<dyn std::error::Error>> {
    let proxy = Proxy::parse("socks5://alice:hunter2@edge-relay.vpn:1080")?;
    Ok(ProxyConnector::new(TcpConnector::new(), proxy))
}
```

`socks5h://` is treated as SOCKS5: the target hostname travels inside the
SOCKS request, so a local DNS lookup — and the leak it implies — does not
happen.

Tunnels are established before TLS runs with the target, preserving the
target's Server Name Indication (SNI) and certificate validation end-to-end.
