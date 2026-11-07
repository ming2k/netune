# Configure TLS Profiles and Fingerprints

This guide shows how to select and define TLS ClientHello identities, route
requests to them, and keep the connection pool from mixing them.

A `TlsProfile` is **data**: it describes an identity, and it compiles into a
`rustls::ClientConfig` when a connection needs one. It is not a closure over a
builder, so a profile can be cloned, compared, and registered by name.

---

## Select a Built-In Preset

Six presets ship in `Preset::all()`, each modelled on an identity observed in
production:

| Preset | Wire identity |
| :--- | :--- |
| `netune-default` | Platform trust store, `http/1.1` ALPN, provider default ciphers and groups. |
| `codex-reqwest` | The Codex CLI's product traffic: `h2,http/1.1` ALPN (hyper-rustls always lists `h2` first). |
| `codex-network-proxy` | The identity the Codex network proxy presents on its upstream leg. |
| `chrome-current` | A current Chrome extension sequence, including GREASE and ALPS. |
| `safari-current` | The Safari counterpart. |
| `firefox-current` | The Firefox counterpart. |

### Route a request to a preset

`TlsRouterConnector` compiles a profile on first use and caches it. The profile
is selected per request through the target:

```rust,no_run
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TlsRouterConnector};
use netune_trace::Recorder;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The router wraps a connector; it owns no socket of its own.
    let router = TlsRouterConnector::new(TcpConnector::new());
    let client = Client::new(router, Pool::default(), ClientConfig::default());

    // The profile is named at request time, on the target.
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

## Define a Custom Profile

`TlsProfile` is a plain struct, so a custom identity is built by starting from a
preset and changing what you mean to change. That is deliberate: a preset is a
complete, coherent hello, and a struct literal written from scratch drifts from
the wire format the moment a field is added.

```rust
use netune::{Preset, TlsProfile};

// Start from a real identity, then narrow it.
let mut profile = Preset::ChromeCurrent.profile();
profile.name = "custom-edge";
// Offer only HTTP/1.1 (no h2) and drop GREASE: a hello a specific edge
// gateway is known to accept.
profile.alpn_protocols = vec![b"http/1.1".to_vec()];
profile.grease_enabled = false;
```

Register it under a name, and requests can then select it like any preset:

```rust,no_run
use netune::{Preset, TcpConnector, TlsRouterConnector};

let mut profile = Preset::ChromeCurrent.profile();
profile.name = "custom-edge";
profile.alpn_protocols = vec![b"http/1.1".to_vec()];
profile.grease_enabled = false;

let router = TlsRouterConnector::new(TcpConnector::new())
    .with_profile_named("custom-edge", profile);
# Ok::<(), Box<dyn std::error::Error>>(())
```

A custom registration may **override a preset name** — that is how a drift
experiment or a CA-pinned test replaces an identity without touching the
preset's definition.

---

## Pool Slicing and Isolation

Connections are keyed by `authority#profile`. A connection handshook under
`codex-reqwest` is never handed to a request that asked for `netune-default`,
because the pooled session's ClientHello is already on the wire and cannot be
changed. Fingerprint leakage across identities is therefore a key-space
property, not a policy someone has to remember.

An unknown profile name is a **loud** failure at connection time; the error
lists every registered name. Silently falling back to a default identity would
make a request succeed with the wrong fingerprint, which is the one outcome a
fingerprint configuration exists to prevent.

---

## What a Profile Can and Cannot Change

`TlsProfile` shapes what `rustls` can be told to do: ALPN protocols, protocol
versions, cipher suites, key-exchange groups, extension order, GREASE, signature
algorithms, ALPS, and the trust source. It cannot express a handshake `rustls`
has no API for — a caller-chosen `legacy_session_id`, or a verifier that skips
the CA chain. Those capabilities belong to the consumer, and
[ADR-0009](../adr/0009-reality-client-authentication-not-a-netune-capability.md)
records that decision for REALITY specifically.
