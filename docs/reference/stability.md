# Stability and Production Boundaries

This page is the support contract for the workspace. A crate or feature is
production-ready only if it is listed under **Stable** here and its defaults are
the bounded defaults documented below. "It compiles with `--all-features`" is
not a stability claim.

---

## 1. Support tiers

| Tier | Surface | Promise |
| :--- | :--- | :--- |
| **Stable** | `netune` egress core: DNS, TCP, HTTP/1.1, HTTP/2, pool, redirects, decompression, proxies, WebSocket client, egress confinement; `netune-server` HTTP/1.1 and HTTP/2; `netune-http1`, `netune-http2`, `netune-ws`, `netune-io`, `netune-egress`, `netune-trace`, `netune-diagnostics` | Public APIs follow the workspace version; security fixes are issued for the latest tag; documented invariants are enforced by tests or gates. |
| **Preview** | HTTP/3 client and ingress (`netune-http3`, `netune-quic` H3 paths, `netune-server` `http3` feature), owned TLS engine (`netune-tls`), `netune-probe` L2 capture/inject | Usable, tested, and supported on a best-effort basis, but the API or wire behaviour may change between `0.0.x` releases. Do not make a production stability claim without the specific gate below. |
| **Experimental** | `netune-webtransport` (draft-17), browser WebTransport interop | Not production-stable. The draft, browser support, and API may change without the normal compatibility promise. |
| **Test-only** | `netune::mock`, `netune::FaultIo`, `netune::FaultConnector`, `test-support` | Never a production dependency; the architecture gate rejects such an edge. |

Default features must keep the **Stable** tier buildable and secure without the
Preview or Experimental tiers. `--all-features` is the CI execution posture, not
the recommended production posture.

---

## 2. Production defaults

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

`None` is an explicit opt-out, not the production default. A deployment that
sets `None` owns the corresponding liveness/memory risk.

---

## 3. Known stable-tier other limits

- **HTTP/1.1 request uploads are serialized.** The request body is written
  before the response head is read. `request_timeout` bounds the whole attempt,
  so an origin that answers early and stops reading cannot hold the attempt
  forever, but this is not full-duplex. A full-duplex H1 path requires a
  transport split that preserves the socket tap; until that lands, large
  uploads to untrusted origins should use HTTP/2 or a shorter
  `request_timeout`.
- **HTTP/1.1 `Expect: 100-continue` is caller-controlled.** The client does not
  synthesize the header automatically because it changes the HTTP/1 identity
  fingerprint. A caller that needs early rejection inserts it explicitly.
- **WebSocket is never pooled.** An upgraded socket belongs to its `WsStream`;
  reconnection is a session policy, not a transport behavior.

---

## 4. Gates for a production claim

### HTTP/3

HTTP/3 is **Preview** until the following are true:

- the H3 client and ingress suites pass against an independent implementation;
- the client supports early response heads while a streaming request body is
  still being sent, including cancellation and flow-control release;
- `response_head_timeout`, `body_idle_timeout` and `request_timeout` are
  exercised over real QUIC sessions;
- the QUIC/H3 fuzz and soak runs are part of the release evidence.

### Owned TLS (`netune-tls`)

The owned engine remains **Preview** until an independent security audit covers:

- TLS 1.2 and TLS 1.3 handshake state machines, including HelloRetryRequest,
  PSK/resumption, KeyUpdate and post-handshake messages;
- record protection, CBC padding/MAC verification, and constant-time behavior;
- certificate parsing and path validation;
- the `aws-lc-sys` FFI boundary and key/session zeroization;
- side-channel and fault behavior under malformed/truncated input.

Until then, the rustls engine is the production recommendation for callers that
need an audited TLS implementation.

### WebTransport

WebTransport is **Experimental** until:

- `RESET_STREAM_AT` (and the associated close/drain semantics) is implemented;
- at least two independent browser engines pass a published interop matrix;
- draft-version negotiation is tested across the supported browser versions;
- the Web Platform Tests / external differential scenarios are part of CI.

### L2 probe

`netune-probe` parsing and frame construction are **Preview**. The `inject`
feature is a privileged capability: it stays behind `--features inject` and
`CAP_NET_RAW`, and must never become a default-build path.

---

## 5. Change policy

- Stable-tier breaking changes require a version bump and a migration note
  under `docs/reference/`; `0.0.x` patches may still break by Cargo semantics.
- Preview APIs may change between `0.0.x` releases, but the change must still
  be documented in `CHANGELOG.md`.
- Experimental APIs may change without a migration note, but must remain
  feature-gated and must not enter the default build.
- A new default bound, a new default feature, or a new production claim updates
  this page and the `README.md` in the same change.
