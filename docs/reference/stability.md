# Stability and Production Boundaries

This page is the support contract for the workspace starting at **`0.1.0` (GA)**.
A crate or feature is production-ready only if it is listed under **Stable** here
and its defaults are the bounded defaults documented below. "It compiles with
`--all-features`" is not a stability claim.

---

## 1. Support tiers

| Tier | Surface | Promise |
| :--- | :--- | :--- |
| **Stable** | `netune` egress core: DNS, TCP, HTTP/1.1, HTTP/2, pool, redirects, decompression, proxies, WebSocket client, egress confinement; `netune-server` HTTP/1.1 and HTTP/2; `netune-http1`, `netune-http2`, `netune-ws`, `netune-io`, `netune-egress`, `netune-trace`, `netune-diagnostics` | Starting at `0.1.0`: Patch releases (`0.1.z`) never break public APIs; Minor releases (`0.y.0`) are required for additive API or documented behavior changes; security fixes target the latest tag; documented invariants are enforced by CI gates. |
| **Preview** | HTTP/3 client and ingress (`netune-http3`, `netune-quic` H3 paths, `netune-server` `http3` feature), owned TLS engine (`netune-tls`), `netune-probe` L2 capture/inject | Usable, tested, and supported on a best-effort basis, but APIs or wire behaviour may change between `0.x` releases. Do not make an audited production claim without passing the specific gates below. |
| **Experimental** | `netune-webtransport` (draft-17), browser WebTransport interop | Not production-stable. The draft, browser support, and API may change without compatibility guarantees. |
| **Test-only** | `netune::mock`, `netune::FaultIo`, `netune::FaultConnector`, `test-support` | Never a production dependency; the architecture gate rejects such an edge. |

Default features keep the **Stable** tier buildable and secure without the
Preview or Experimental tiers. `--all-features` is the CI verification posture,
not the recommended production posture.

### Feature-to-tier mapping

| Crate | Default features | Tier / Notes |
| :--- | :--- | :--- |
| `netune` | `http2`, `ws` | **Stable** egress core. `http3` and `quic` are **Preview** opt-ins. |
| `netune-server` | `http2` | **Stable** HTTP/1.1 & HTTP/2 ingress. `tls` is an opt-in **Stable** feature (rustls termination); `http3` is **Preview**. |
| `netune-trace` | `ja4` | **Stable** (`ja4` adds ClientHello JA3/JA4 parsing; `serde` is optional). |
| `netune-probe` | *(none)* | **Preview** read-only L2 parser/capture. `--features inject` requires `CAP_NET_RAW` and is never part of a daemon build. |

---

## 2. Platform and TLS engine matrix

| Target / Surface | Status | Scope & Notes |
| :--- | :--- | :--- |
| **Linux (`x86_64`, `aarch64`)** | **Tier-1 Supported** | Full CI coverage, `TCP_INFO` L1 kernel metrics, `netune-probe` `AF_PACKET` L2 capture, ASan and libFuzzer verification. |
| **macOS / other Unix** | **Best-effort (untested in CI)** | Core sockets compile where POSIX `RawFd` applies, but `TCP_INFO` kernel metrics (`None`) and `netune-probe` are Linux-only. |
| **Windows** | **Unsupported** | Workspace relies on Unix socket/fd inspection and is not tested or supported on Windows. |
| **TLS engine (default)** | **rustls (`aws-lc-rs`)** | Default for `Client::builder()` and plain `Target::tls(...)` (`ADR-0016`, `ADR-0054`). ALPN automatically includes `h2` when `ClientConfig::enable_http2` is enabled via `ClientBuilder::http2(true)`. |
| **Owned TLS (`netune-tls`)** | **Preview (opt-in)** | Selected only when a `Target` names a TLS fingerprint profile (e.g., `"chrome-current"`) or the caller wires `TlsProfile` explicitly. |

MSRV is **Rust 1.95.0**, enforced across every CI job.

---

## 3. Production defaults

| Setting | Default | Why |
| :--- | :--- | :--- |
| `ClientConfig::response_head_timeout` | 30 s | A peer that accepts and then goes silent must not hold an attempt. |
| `ClientConfig::body_idle_timeout` | 60 s | A long stream is allowed; a silent stream is not. |
| `ClientConfig::request_timeout` | 300 s | Bounds the total attempt, including redirects and the response body. |
| `PoolConfig::max_idle_per_authority` | 4 | Keeps a small reusable set per authority. |
| `PoolConfig::max_idle_total` | 64 | Caps idle descriptors across the process. |
| `PoolConfig::max_in_flight_per_authority` | 64 | Caps concurrent work aimed at one authority. |
| `PoolConfig::max_in_flight_total` | 512 | Caps concurrent work across every authority. |
| `PoolConfig::idle_timeout` | 20 s | Fits inside commonly observed gateway idle-cull windows. |
| `Limits::max_body_bytes` | 256 MiB | The decoded-body and compression-expansion budget; callers handling untrusted origins should lower it. |
| `ServerConfig::nodelay` | `true` | Disables Nagle's algorithm on accepted sockets to avoid Linux 40 ms delayed-ACK stalls. |

`None` is an explicit opt-out, not the production default. A deployment that
sets `None` owns the corresponding liveness/memory risk.

---

## 4. Known stable-tier limits

- **HTTP/1.1 uploads are concurrent and early responses cancel the upload.**
  The request writer and response reader share a split transport, so the
  response head and body are readable while the upload is still in flight. If
  the origin answers before the upload finishes, the remaining upload is
  cancelled, the recording tap is synchronously closed for complete trace
  finality, and the connection is never returned to the pool.
- **HTTP/1.1 `Expect: 100-continue` is caller-controlled.** The client does not
  synthesize the header automatically because it changes the HTTP/1 identity
  fingerprint. A caller that needs a pre-body rejection inserts it explicitly;
  the reader handles informational heads without treating them as final.
- **WebSocket is never pooled.** An upgraded socket belongs to its `WsStream`;
  reconnection is a session policy, not a transport behavior.
- **Direct HTTP/2 ALPN coupling.** Callers wiring `TlsRouterConnector` manually
  instead of `Client::builder()` must pass `TlsRouterConnector::with_rustls_alpn(..., enable_http2)`
  or include `"h2"` in `rustls::ClientConfig::alpn_protocols` so ALPN
  negotiates HTTP/2 on TLS connections.

---

## 5. Gates for a production claim (Preview / Experimental)

### HTTP/3

HTTP/3 remains **Preview** until all of the following are complete:

- the H3 client and ingress suites pass against an independent implementation (`h3` differential passed);
- early response heads during a streaming upload and cancellation/flow-control release are exercised across longer multi-hour churn campaigns;
- `response_head_timeout`, `body_idle_timeout` and `request_timeout` are covered over lossy QUIC sessions;
- multi-hour QUIC/H3 soak and coverage-guided fuzz evidence are collected continuously.

### Owned TLS (`netune-tls`)

The owned engine remains **Preview** until an independent third-party security audit covers:

- TLS 1.2 and TLS 1.3 handshake state machines, including HelloRetryRequest,
  PSK/resumption, KeyUpdate and post-handshake messages;
- record protection, CBC padding/MAC verification, and constant-time behavior;
- certificate parsing and path validation;
- the `aws-lc-sys` FFI boundary (`ffi.rs`) and key/session zeroization (`zeroize.rs`);
- side-channel and fault behavior under malformed/truncated input.

Until then, the `rustls` default via `Client::builder()` is the production
recommendation for callers that need an audited TLS implementation.

### WebTransport

WebTransport remains **Experimental** until:

- reliable `RESET_STREAM_AT` remains covered by the prefix/reset tests (landed);
- at least two independent browser engines pass the pinned interop matrix in
  [WebTransport Browser Interoperability](webtransport-interop.md);
- draft-version negotiation is tested across the supported browser versions;
- Web Platform Tests / external differential scenarios run in CI.

### L2 probe

`netune-probe` parsing and frame construction are **Preview**. The `inject`
feature stays strictly behind `--features inject` and `CAP_NET_RAW`, and must
never become a default-build path.

---

## 6. Post-`0.1.0` change policy

- **Stable tier (`0.1.z`)**: strictly SemVer-compatible bug fixes, security
  patches, and performance improvements. No breaking API changes.
- **Stable tier (`0.y.0`)**: additive APIs and documented behavioral updates,
  verified against `cargo semver-checks` and accompanied by migration notes.
- **Preview & Experimental**: may change in `0.x` releases when explicitly
  noted in `CHANGELOG.md`.
- Any new default bound, default feature, or tier promotion updates this page
  and `README.md` in the same change.
