# Configure TLS Profiles and Fingerprints

This guide shows how to configure custom TLS ClientHello identities (JA4 fingerprints), select named presets per request, and maintain connection pool isolation across disparate TLS profiles.

---

## Select Built-In Presets

`netune` ships three named presets derived from observed production environments:
- `netune-default`: Platform trust store with HTTP/1.1 ALPN.
- `codex-reqwest`: Offers `h2,http/1.1` ALPN matching the Codex CLI runtime stack (hyper-rustls + rustls + aws-lc-rs).
- `codex-network-proxy`: Matching wire profile via network proxy connectors.

### Configure `TlsRouterConnector`

Wrap your connector with `TlsRouterConnector::with_defaults()`:

```rust
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TlsRouterConnector};
use std::sync::{Arc, Mutex};
use netune_trace::Recorder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build the router connector with standard presets
    let router = TlsRouterConnector::with_defaults(TcpConnector::new())?;
    let client = Client::new(router, Pool::default(), ClientConfig::default());

    // 2. Select profile at request time using Target
    let target = Target::tls("api.openai.com:443", "api.openai.com")
        .with_tls_profile("codex-reqwest");

    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
    let head = RequestHead::new(http::Method::GET, "/v1/models");

    let mut response = client.send(&target, recorder, head, None).await?;
    let _ = response.body.read_to_end().await?;
    Ok(())
}
```

---

## Define a Custom TLS Profile

You can construct a custom `TlsProfile` with custom protocol versions, cipher suite restrictions, and key-exchange groups:

```rust
use netune::{Preset, TlsProfile, TlsRouterConnector, TcpConnector, Verifier};
use std::sync::Arc;

fn build_custom_connector() -> Result<TlsRouterConnector<TcpConnector>, Box<dyn std::error::Error>> {
    // Define a TLS 1.3 only profile with restricted cipher suites
    let profile = TlsProfile {
        alpn: vec![b"http/1.1".to_vec()],
        tls12: false,
        tls13: true,
        ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
        kx_groups: vec!["x25519".to_string()],
        verifier: Verifier::Platform,
    };

    let mut router = TlsRouterConnector::with_defaults(TcpConnector::new())?;
    router.with_profile_named("custom-edge", profile);
    Ok(router)
}
```

---

## Pool Slicing and Isolation

Connections in `Pool` are keyed by `authority#profile`. A connection handshook under `codex-reqwest` is never reused for a request demanding `netune-default`, preventing cross-profile fingerprint leakage.

If an unknown profile name is supplied, `Target::with_tls_profile` will fail loudly at connection time with an error listing all registered profiles, preventing accidental silent fallback to a default fingerprint.
