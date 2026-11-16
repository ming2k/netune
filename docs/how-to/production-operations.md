# Operate netune in Production

This guide summarizes the operational controls for running **Stable**-tier
`netune` (egress) and `netune-server` (ingress) safely under load.

---

## 1. Egress: `Client::builder()`, pooling, and confinement

Prefer `Client::builder()` for production HTTP/1.1 + HTTP/2 over TLS. It uses
the audited `rustls` platform verifier by default, caches OS certificate stores
once per process, and keeps ALPN synchronized with `http2`:

```rust,no_run
use std::time::Duration;
use netune::{
    Client, ClientConfig, EgressConfinement, Limits, Observation, PoolConfig,
};

fn build_production_client() -> Client {
    let pool = PoolConfig::default()
        .with_max_idle_per_authority(8)
        .with_max_idle_total(128)
        .with_max_in_flight_per_authority(Some(64))
        .with_max_in_flight_total(Some(512))
        .with_idle_timeout(Duration::from_secs(20));

    let client_cfg = ClientConfig::default()
        .with_enable_http2(true)
        .with_observation(Observation::Counters)
        .with_response_head_timeout(Some(Duration::from_secs(15)))
        .with_body_idle_timeout(Some(Duration::from_secs(30)))
        .with_request_timeout(Some(Duration::from_secs(120)))
        .with_limits(Limits::default().with_max_body_bytes(64 * 1024 * 1024));

    Client::builder()
        .config(client_cfg)
        .pool_config(pool)
        // Enforce non-private/non-loopback egress before connect() is ever called.
        .confinement(EgressConfinement::StrictPublic)
        .http2(true)
        .build()
}
```

### Operational guidelines for egress

- **Bounded timeouts**: keep `response_head_timeout`, `body_idle_timeout`, and
  `request_timeout` finite. Never set all three to `None` on untrusted peers.
- **Idle reaping & FD limits**: `Pool` spawns a weak-referenced reaper loop when
  created; on Linux deployments with `max_idle_total > 256` or high `max_in_flight_total`,
  raise `RLIMIT_NOFILE` accordingly. Call `Pool::reap()` synchronously if you
  want deterministic cleanup outside an async idle tick.
- **Observation cost**: leave `Observation::Counters` as the default (zero-clock,
  lock-free byte/call counters) or `Observation::Off` for maximum throughput. Enable
  `TraceConfig` (`Observation::Traced`) selectively or sampled per request.
- **Decompression bombs**: `Limits::max_body_bytes` caps decoded bytes *after*
  gzip/deflate/brotli expansion. Lower it from the 256 MiB default for public-facing
  crawlers or webhooks.

---

## 2. Diagnostic trace sinks and redaction

Never enable unredacted trace sinks in multi-tenant production unless the
output path is restricted to internal operators:

- Use `netune_diagnostics::RedactionPolicy::production()` (the default) when
  shipping failure bundles externally; it redacts secret headers and query values.
- Use `RedactionPolicy::internal()` only for local debugging and incident triage.
- Bounded sinks drop excess events (`Flow::Drop`) rather than backpressuring
  I/O; monitor `TraceSummary::sink_dropped` and `dropped_events`.

---

## 3. Ingress (`netune-server`): admission, slow-peer bounds, and drain

Configure `ServerConfig` explicitly based on expected concurrency and payload size:

```text
ServerConfig::default()
  .with_nodelay(true)                  // Keep true to prevent Linux 40 ms Nagle stalls
  .with_max_connections(1024)          // Sheds over capacity rather than unbounded queueing
  .with_head_timeout(10s)              // Aborts slow-loris header tricklers
  .with_body_timeout(30s)              // Caps total request body arrival time
  .with_handler_timeout(60s)           // Bounds application handler latency
  .with_write_timeout(30s)             // Bounds slow response readers
  .with_drain_timeout(15s)             // Caps graceful shutdown before aborting stalled sockets
```

Key behaviors:

- **Shedding over queueing**: connections above `max_connections` are shed
  immediately rather than buffered unboundedly in memory.
- **Early shutdown**: pass a clean shutdown signal to `Server::serve(shutdown)`.
  The listener stops accepting new connections immediately and gives in-flight
  requests up to `drain_timeout` to complete before closing stalled sockets.
- **HTTP/2 tuning**: adjust `ServerConfig::http2` (`H2Ingress`) for
  `max_concurrent_streams` and initial stream/connection flow-control windows
  before exposing HTTP/2 endpoints to untrusted traffic.
