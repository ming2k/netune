# Migrating to 0.1.0 (GA)

`0.1.0` is the first Generally Available (GA) release of the **Stable** tier
(`netune`, `netune-server` HTTP/1.1 & HTTP/2, `netune-http1`, `netune-http2`,
`netune-ws`, `netune-io`, `netune-egress`, `netune-trace`, and
`netune-diagnostics`).

Starting at `0.1.0`:

- **Patch releases (`0.1.z`)** contain bug fixes, performance improvements, and
  security patches only; they never break Stable public APIs.
- **Minor releases (`0.y.0`)** may introduce additive APIs and deliberate
  behavior changes documented in `CHANGELOG.md`.
- **Preview** (`netune-http3`, `netune-quic`, `netune-tls`, `netune-probe`) and
  **Experimental** (`netune-webtransport`) crates remain on explicit
  pre-stability terms as described in [Stability and Production Boundaries](stability.md).

---

## Summary of breaking changes from `0.0.x`

### 1. Public structs and enums are `#[non_exhaustive]`

To keep `0.1.z` patch releases non-breaking when diagnostic variants or
configuration fields expand internally, core public types across the Stable tier
carry `#[non_exhaustive]`:

- `netune`: `ClientConfig`, `PoolConfig`, `TraceConfig`, `Target`, `Request`,
  `Response`, `Established`, `Released`, `Exchange`, `NetError`,
  `ConnectErrorKind`, `ConnectError`, `ResolveErrorKind`, `ResolveError`,
  `HttpProtocol`, `Observation`, `ObservationLevel`, `BodyState`, `RequestBody`.
- `netune-server`: `ServerConfig`, `H2Ingress`, `ProtocolVia`, `ListenerEvent`,
  `IngressTrace`, `ServedProtocol`, `BindError`, `ResponseBody`, `Response`.
- `netune-http1` & `netune-ws`: `Limits`, `HttpError`, `BodyKind`, `TargetForm`.
- `netune-http2`: `H2Error`.
- `netune-trace`: `DiagnosticPhase`, `RetryVerdict`, `EventKind`,
  `ConnectionIdentity`.

External callers that constructed configs with struct literals must switch to
`Default::default()` + `with_*` builders, and exhaustive `match` statements must
include a trailing `_ => ...` arm:

```rust,no_run
use std::time::Duration;
use netune::{ClientConfig, Observation, PoolConfig};

let client_cfg = ClientConfig::default()
    .with_enable_http2(true)
    .with_observation(Observation::Counters)
    .with_request_timeout(Some(Duration::from_secs(30)));

let pool_cfg = PoolConfig::default()
    .with_max_idle_per_authority(8)
    .with_idle_timeout(Duration::from_secs(20));
```

### 2. Ergonomic production `Client::builder()` and ALPN alignment

Previously, `Client::new(TcpConnector::new(), ...)` performed plaintext TCP only,
and `TlsRouterConnector` offered `["http/1.1"]` ALPN unless callers manually
constructed a `rustls::ClientConfig`.

In `0.1.0`:

- Use `Client::builder()` for production TLS deployments (powered by `rustls`
  and `rustls-platform-verifier`, cached cleanly across handshakes).
- Calling `.http2(true)` on `ClientBuilder` automatically synchronizes
  `ClientConfig::enable_http2` with the rustls ALPN offer (`["h2", "http/1.1"]`).
- When constructing a connector directly, use
  `TlsRouterConnector::platform_default()` or
  `TlsRouterConnector::with_rustls_alpn(config, enable_http2)`.

```rust,no_run
use netune::{Client, HttpProtocol, RequestHead, Target};
use http::Method;

async fn example() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .http2(true)
        .build();

    let target = Target::tls("example.com:443", "example.com")
        .with_protocol(HttpProtocol::Auto);
    let mut resp = client
        .request(&target, RequestHead::new(Method::GET, "/"), None)
        .await?;
    let _body = resp.body.read_to_end().await?;
    Ok(())
}
```

### 3. Plain TLS uses `rustls` by default; `netune-tls` is opt-in

Since `0.0.34` (carried into `0.1.0`), `Target::tls(...)` without a TLS
profile uses `rustls` for TLS negotiation. The owned TLS engine (`netune-tls`,
for byte-exact `ClientHello` fingerprint presets such as `"chrome-current"`)
is opt-in per request via `Target::with_tls_profile(...)` or when explicitly
configured on `TlsRouterConnector`.

### 4. `H2Client` removed in favor of unified `Client` + `Target::with_protocol`

`netune::H2Client` is removed. Route HTTP/2 through `Client` and `Pool` with
`Target::with_protocol(HttpProtocol::Http2)` (for prior-knowledge/forced H2) or
`HttpProtocol::Auto` with `ClientBuilder::http2(true)` (for ALPN-negotiated H2).
Direct session use without pooling lives in `netune_http2::client::Session`.

### 5. HTTP/1.1 full-duplex upload finality & `Body::trace()` (`TRACE_SCHEMA_VERSION = 3`)

- HTTP/1.1 request uploads now execute concurrently with reading the response
  head/body over a split transport.
- On early server responses, dropped response bodies, or aborted uploads, `netune`
  synchronously detaches the recording tap before closing the half-written
  connection, ensuring `Body::trace()` and `Response::trace` observe a complete
  socket timeline without waiting for background task teardown, and guaranteeing a
  half-written HTTP/1.1 connection is never returned to `Pool`.
- Trace schema is pinned at `TRACE_SCHEMA_VERSION = 3` (adding `TraceMeta`,
  `DiagnosticTable`, `ConnectionIdentity`, and HTTP/2/HTTP/3 profile fields).

### 6. Server `TCP_NODELAY` enabled by default

`netune_server::ServerConfig` adds `nodelay: bool` (default `true`), disabling
Nagle's algorithm (`TCP_NODELAY`) on accepted TCP connections to eliminate the
Linux 40ms Delayed-ACK stall on keep-alive responses. Override with
`ServerConfig::default().with_nodelay(false)` only if batching is specifically
desired.

### 7. HTTP/3 split request sender (`H3SplitSender`, Preview)

`netune_http3::H3RequestBody::split()` now returns
`(H3ResponseFuture, H3SplitSender)` instead of a second raw handle exposing
connection datagram registration (`send_datagram` / `into_duplex`). Use
`H3SplitSender` for streaming data chunks and trailers concurrently with the
response future.
