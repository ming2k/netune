# Configure TLS Profiles and Fingerprints

This guide shows how to select and define TLS ClientHello identities, route
requests to them, and keep the connection pool from mixing them.

A plain `Target::tls` uses **rustls with the platform verifier**, the audited
production default ([ADR-0054](../adr/0054-audited-tls-default-and-owned-fingerprint-opt-in.md)).
A `TlsProfile` selects the owned `netune-tls` engine for a measured ClientHello
identity; that path is Preview until its independent audit closes.

A `TlsProfile` is **data**: it describes a ClientHello identity via a declarative
`ClientHelloBlueprint` ([ADR-0048](../adr/0048-declarative-clienthello-blueprints.md))
fed to the owned `netune-tls` engine ([ADR-0045](../adr/0045-owned-egress-tls-engine.md)).
It controls cipher suites, key-exchange groups, independent `key_share` groups,
signature schemes, extension order, seeded extension permutation, RFC 8701
GREASE, RFC 7685 dynamic padding, RFC 8879 `compress_certificate`, ALPS, and
`session_ticket`.

---

## Select a Built-In Preset

Seven presets ship in `Preset::all()`:

| Preset | Wire identity |
| :--- | :--- |
| `netune-default` | Shipped identity: Go-shaped hello, `http/1.1` ALPN only. |
| `antigravity-cli-stream` | Antigravity CLI h2 telemetry paths (Clearcut `play.googleapis.com /log`, the auto-updater): `h2, http/1.1` ALPN (Go 1.28 `boringcrypto`). |
| `antigravity-cli-unary` | Antigravity CLI HTTP/1.1 paths: every `/v1internal:*` Cloud Code call **including the streaming model lane** (`http/1.1` ALPN only, Go 1.28 `boringcrypto`). |
| `go-standard` | Upstream Go `crypto/tls` (without `boringcrypto`). |
| `chrome-current` | Chrome/BoringSSL: GREASE, `compress_certificate(brotli)`, ALPS, seeded extension permutation, 517-byte padding. |
| `firefox-current` | Firefox/NSS: `record_size_limit`, `post_handshake_auth`, `compress_certificate(zlib, brotli)`, `session_ticket`. |
| `safari-current` | Safari/SecureTransport: GREASE, `compress_certificate(zlib)`, fixed extension order. |

### Route a request to a preset

`TlsRouterConnector` resolves the profile on each connection. The profile is
selected per request through the target:

```rust,no_run
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TlsRouterConnector, TraceConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The router wraps a connector; it owns no socket of its own.
    let router = TlsRouterConnector::new(TcpConnector::new());
    let client = Client::new(router, Pool::default(), ClientConfig::default());

    // The profile is named at request time, on the target.
    let target = Target::tls("api.openai.com:443", "api.openai.com")
        .with_tls_profile("antigravity-cli-stream");

    let head = RequestHead::new(http::Method::GET, "/v1/models");

    let mut response = client
        .request_traced(&target, head, None, TraceConfig::default())
        .await?;
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
let mut profile: TlsProfile = Preset::ChromeCurrent.profile();
profile.name = "custom-edge";
// Offer only HTTP/1.1 (no h2) and disable per-connection extension permutation.
profile = profile
    .with_alpn(&[b"http/1.1"])
    .with_extension_permutation(false);
```

Register it under a name, and requests can then select it like any preset:

```rust,no_run
use netune::{Preset, TcpConnector, TlsRouterConnector};

let mut profile = Preset::ChromeCurrent.profile();
profile.name = "custom-edge";
profile = profile.with_alpn(&[b"http/1.1"]);

let router = TlsRouterConnector::new(TcpConnector::new())
    .with_profile_named("custom-edge", profile);
# Ok::<(), Box<dyn std::error::Error>>(())
```

A custom registration may **override a preset name** — that is how a drift
experiment or a CA-pinned test replaces an identity without touching the
preset's definition.

---

## Pool Slicing and Isolation

Connections are keyed by the typed `(authority, ConnectionIdentity)` pair,
including the profile and engine. A connection handshook under
`antigravity-cli-stream` is never handed to a request that asked for
`netune-default` or rustls, because the pooled session's ClientHello is already
on the wire and cannot be changed. Fingerprint leakage across identities is
therefore a key-space property, not a policy someone has to remember.

An unknown profile name is a **loud** failure at connection time; the error
lists every registered name. Silently falling back to a default identity would
make a request succeed with the wrong fingerprint, which is the one outcome a
fingerprint configuration exists to prevent.

---

## What a Profile Can and Cannot Change

`TlsProfile` shapes the offer lists (`alpn_protocols`, `cipher_suites`,
`kx_groups`, `signature_algorithms`) that `netune-tls` serializes into the
ClientHello. Any narrowed value the engine cannot complete is refused at hello
construction (`[INV-TLS-06]`). Capabilities that skip CA chain verification
belong to the consumer, and
[ADR-0009](../adr/0009-reality-client-authentication-not-a-netune-capability.md)
records that decision for REALITY specifically.
