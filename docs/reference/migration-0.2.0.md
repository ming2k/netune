# Migrating to 0.2.0

`0.2.0` completes the API-stability, documentation, and CI hardening sweep
following `0.1.0`. Under the post-`0.1.0` SemVer rules, adding `#[non_exhaustive]`
to remaining Stable public structs with public fields and enums requires a minor
version bump (`0.2.0`) rather than a `0.1.z` patch.

---

## Summary of breaking changes from `0.1.0`

### 1. Remaining Stable structs and enums marked `#[non_exhaustive]`

All extensible public structs and enums across the Stable tier now carry
`#[non_exhaustive]`, eliminating struct-literal and exhaustive-match SemVer traps
for future `0.2.z` patch releases:

- `netune`: `SocketConfig`, `TcpSample`, `WsSessionConfig`, `Proxy`, `Preset`,
  `TlsProfile`, `HeaderCasing`.
- `netune-http1`: `RequestHead`, `ResponseHead`, `ReasonPhrase`,
  `IncomingResponse` (use `IncomingResponse::new(...)`), `IncomingRequest` (use
  `IncomingRequest::new(...)`), `TargetError`.
- `netune-http2`: `LocalSettings` (`with_*` builders added),
  `ServerSessionConfig` (`with_*` builders added), `H2ConnectionProfile`,
  `H2RequestProfile` (`H2RequestProfile::new(...)`), `H2Fingerprint`,
  `FrameHeader` (`FrameHeader::new(...)`), `Frame` (`Frame::data`,
  `Frame::headers`, `Frame::settings`, `Frame::goaway`), `H2Request`,
  `H2Response` (`H2Response::new(...)`), `H2ResponseBody`, `SessionEnd`,
  `StreamEvent`, `H2ResponseHead`, `H2ResponseEvent`.
- `netune-ws`: `WsError`, `Frame`, `Message`, `CloseReason`.
- `netune-io`: `Fault`.
- `netune-diagnostics`: `RedactionPolicy`, `TraceBundle`.
- `netune-trace`: `DerivedTimings`, `DerivedIngress`, `DerivedQuic`, `DerivedH3`,
  `Outcome`, `Diagnosis`, `DiagnosticRecord`, `DiagnosticField`, `EventView`,
  `Divergence`, `TraceDiff`, `Reason`, `Validity`, `TimeSource`, `FrameClass`,
  `Alpn`, `Event` (`Event::new(...)`), `TraceSummary` (`TraceSummary::new(...)`),
  `TracePropagation`, `TraceMeta`, `ConnectionInfo` (`with_*` builders added),
  `EvasionPolicy`, `RequestTrace` (`RequestTrace::new(...)` + `with_*`
  builders), `TraceSnapshot`.

```rust,no_run
use std::time::Duration;
use netune::{Client, StaticResolver, WsSessionConfig};

fn build_with_resolver(ip: std::net::IpAddr) -> (Client, WsSessionConfig) {
    let resolver = StaticResolver::new();
    resolver.insert("service.internal", ip);

    let client = Client::builder()
        .dns_resolver(resolver)
        .http2(true)
        .build();

    let ws_cfg = WsSessionConfig::default()
        .with_ping_interval(Duration::from_secs(15))
        .with_pong_timeout(Duration::from_secs(5));

    (client, ws_cfg)
}
```

### 2. Additive improvements

- `netune`: `ClientBuilder::dns_resolver(...)` allows custom [`crate::DnsResolver`]
  implementations (including `StaticResolver`) without falling back to manual
  connector wiring.
- All 14 publishable crates now enforce `#![deny(missing_docs)]` with zero
  `#[allow(missing_docs)]` exemptions anywhere in the workspace.
- CI enforces `cargo hack` feature powerset compilation, `--no-default-features`
  Clippy, and `cargo semver-checks` patch-compatibility verification.
