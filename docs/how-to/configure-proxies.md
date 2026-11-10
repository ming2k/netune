# Configure Proxies

This guide demonstrates how to tunnel requests through HTTP `CONNECT` or SOCKS5 proxies using `ProxyConnector`.

---

## Supported Proxy Types

`Proxy` supports two proxy protocols parsed from URL formats:
1. **HTTP CONNECT**: `http://host:port` or `http://user:password@host:port`
2. **SOCKS5**: `socks5://host:port` or `socks5://user:password@host:port` (with remote hostname resolution)

The hop to the proxy is plaintext in both cases. An `https://` proxy URL is
refused rather than silently downgraded; if the proxy hop must be encrypted,
terminate TLS outside this connector.

---

## Tunneling through an HTTP CONNECT Proxy

A proxy is a `Connector` wrapper: the inner connector dials the **proxy**, and
the wrapper opens a tunnel to the target inside it.

```rust,no_run
use netune::{Client, ClientConfig, Pool, Proxy, ProxyConnector, RequestHead, Target, TcpConnector, TlsConnector, TraceConfig};

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
    let head = RequestHead::new(http::Method::GET, "/v1/models");

    let mut response = client
        .request_traced(&target, head, None, TraceConfig::default())
        .await?;
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

## Confinement and proxies

`EgressConfinement` checks the address of the socket netune opens. With a proxy
that address is the **proxy**, not the tunnel destination: an HTTP `CONNECT`
proxy and SOCKS5 both resolve or connect to the target on their side. If the
proxy can reach internal services, `StrictPublic` on the netune process does not
prevent that pivot. Use a trusted proxy, or enforce the destination policy at
the proxy and not only in the client.
