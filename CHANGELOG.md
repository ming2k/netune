# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-11-19

### Added

- **`H1WireProfile::antigravity_cli`**, registered in the default H1 registry: Go `net/http`'s HTTP/1.1 order and Title-Case spelling (`Host`, `User-Agent`, `Content-Length`/`Transfer-Encoding`, the caller's own headers, `Accept-Encoding` last), pinned to the captured head by a regression test.
- **`ClientConfig::accept_encoding_gzip`** (`with_accept_encoding_gzip`): offer `accept-encoding: gzip` on HTTP/1.1 requests that do not name an encoding, with the response decoded by the transport — the Go `net/http` behaviour, off by default because the header is part of a client's wire identity. Implemented in `wire::h1::stamp_transport_headers`, the now-pure-and-tested home of every transport-stamped HTTP/1.1 header.
- **Typed unreachability predicate (`[INV-TRANSPORT-14]` / [ADR-0056](docs/adr/0056-transport-reachability-pool-flush-and-ws-session-liveness.md))**: `ResolveError::is_unreachable()`, `ConnectError::is_unreachable()`, and `NetError::is_unreachable()` classify DNS failures (excluding `InvalidAuthority`) and OS routing unreachability (`NetworkUnreachable`, `HostUnreachable`, `NetworkDown`) as a pure boolean predicate while keeping `is_retryable() == true`.
- **Explicit pool flush (`[INV-TRANSPORT-15]` / [ADR-0056](docs/adr/0056-transport-reachability-pool-flush-and-ws-session-liveness.md))**: `Pool::clear() -> usize` and `Client::clear_pool() -> usize` synchronously evict all pooled HTTP/1.1, HTTP/2, and HTTP/3 connection entries without disturbing checked-out in-flight streams.
- **First-class WebSocket client ergonomics (`[INV-WS-09]` / [ADR-0056](docs/adr/0056-transport-reachability-pool-flush-and-ws-session-liveness.md))**: `Target::from_url` accepts `ws://` and `wss://` schemes directly, and `Client::connect_ws_with` establishes an untraced upgraded stream with explicit `WsHandshake` headers and bounds.

### Changed

- **The Antigravity identities follow the live 1.5.12 wire** (decrypted MITM capture of the shipped `agy` 1.5.12, 2026-11-19): the Cloud Code model lanes — unary *and* `v1internal:streamGenerateContent?alt=sse` — are HTTP/1.1 with the brand UA, so `antigravity-cli-unary` is the profile both lanes select; the `antigravity-cli-stream` preset remains the h2 *telemetry* lane identity (Clearcut `play.googleapis.com`, the auto-updater). `Preset` and `H2Registry::default_for_tls` documentation state the 1.5.12 facts.
- **`signature_algorithms_cert` in the Go `boringcrypto` offer carries the legacy SHA-1 tail** (`rsa_pkcs1_sha1`, `ecdsa_sha1`), arbitrated by the same capture — the extension payload is fifteen schemes, not the thirteen of `signature_algorithms`. The "pending arbitration" note is closed; a byte-level regression test pins the payload.
- **`Host` and `:authority` no longer carry a scheme-default port.** `host:443` on a TLS target (or `:80` in plaintext) stays in the dial authority and the pool key, but the *header* value is the bare host, which is what every mainstream client — the captured `agy` included — puts on the wire. Non-default ports are kept.
- `H2Fingerprint::go` documentation re-verified against the 1.5.12 capture (SETTINGS, connection window, pseudo-header order all exact) and now records the fixed transport-stamped tail (`content-length`, `accept-encoding: gzip`, default `user-agent`) that follows Go's randomized caller headers.

### Fixed

- **Cancel-safe full-duplex `WsSession` liveness (`[INV-WS-09]` / [ADR-0056](docs/adr/0056-transport-reachability-pool-flush-and-ws-session-liveness.md))**: `WsSession` stamps each heartbeat ping with a monotonic non-empty 8-byte probe payload, arms `ping_in_flight` before awaiting flush, and discharges across unlimited ping/pong cycles; `WsStream` drains `write_buf` incrementally so `WsSession::next()` is cancel-safe inside `tokio::select!`.

## [0.1.1] - 2026-11-16

SemVer-compatible stabilization, documentation, and CI hardening release on the
`0.1.z` GA line.

### Added

- `netune`: `ClientBuilder::dns_resolver(...)` and `impl DnsResolver for Arc<dyn DnsResolver>` so custom resolvers (`StaticResolver`, etc.) compose directly through `Client::builder()`.
- `netune`, `netune-http1`, `netune-http2`, `netune-trace`: additive `new(...)` and `with_*` builders across configuration, head, frame, and trace types (`RequestHead`, `IncomingResponse`, `IncomingRequest`, `LocalSettings`, `ServerSessionConfig`, `H2RequestProfile`, `FrameHeader`, `Frame`, `H2Response`, `Event`, `TraceSummary`, `ConnectionInfo`, `RequestTrace`, `WsSessionConfig`).
- `tests/e2e/soak.rs`: added `soak_h3_stream_churn_and_fd_bounds` (120 sequential HTTP/3 POST echoes with file-descriptor bound checks).
- `.github/workflows/ci.yml`: added `cargo hack` feature-powerset checks across the workspace and orchestrators, `cargo clippy --all-targets --no-default-features -- -D warnings`, and `cargo semver-checks` patch-compatibility enforcement on Stable crates.
- `crates/netune-webtransport/Cargo.toml`: completed `repository`, `keywords`, and `categories` package metadata.

### Changed

- Enabled `#![deny(missing_docs)]` and documented all public items across all 14 publishable crates (`netune-probe`, `netune-quic`, `netune-http3`, and `netune-webtransport` included), removing all remaining `#[allow(missing_docs)]` exemptions (`DiagnosticPhase`, `netune_http2::Frame`, `netune_http2::connection::error_code`).
- Updated stale `v0.0.29` documentation snippets (`getting-started.md`, `serve-http.md`, `release-and-versioning.md`) to `v0.1.1`.
- Fixed CI scheduler timing flake in `tests/e2e/request_lifecycle.rs::a_pooled_socket_the_peer_dropped_is_replaced_transparently` by explicitly shutting down the closed idle peer socket and allowing the reactor loop to observe FIN before checkout.

### Removed

- Removed unused `quinn-proto` from root `Cargo.toml` `[workspace.dependencies]` and dead helper placeholders from `crates/netune-http2/tests/differential.rs`.

## [0.1.0] - 2026-11-16

First Generally Available (GA) release of the **Stable** tier (`netune`,
`netune-server` HTTP/1.1 & HTTP/2, `netune-http1`, `netune-http2`, `netune-ws`,
`netune-io`, `netune-egress`, `netune-trace`, and `netune-diagnostics`). HTTP/3,
owned TLS (`netune-tls`), and `netune-probe` remain **Preview**;
`netune-webtransport` remains **Experimental**.

See [Migrating to 0.1.0](docs/reference/migration-0.1.0.md) for upgrade guidance.

### Added

- `netune`: `Client::builder()` / `ClientBuilder`, `TlsRouterConnector::platform_default()`, `TlsRouterConnector::with_rustls_alpn()`, and process-wide cached platform verifier roots (`OnceLock`). Calling `ClientBuilder::http2(true)` automatically synchronizes `ClientConfig::enable_http2` with rustls ALPN `["h2", "http/1.1"]`.
- `netune-http2` & `netune-server`: bidirectional independent differential oracle suites against `h2` (`crates/netune-http2/tests/differential.rs`, `crates/netune-server/tests/h2_oracle.rs`) covering `HEADERS`/`CONTINUATION`, HPACK dynamic table, `SETTINGS`, `WINDOW_UPDATE`, concurrent streams, trailers, early `RST_STREAM`, `GOAWAY`, and stray `CONTINUATION` rejection.
- `netune-server`: `ServerConfig::nodelay` (default `true`, setting `TCP_NODELAY` on accepted connections to eliminate Linux 40 ms delayed-ACK keep-alive stalls).
- `benches/baseline.rs` and `tests/e2e/soak.rs`: reproducible transport throughput/latency baseline (HTTP/1.1 pool/cold/duplex, mutex split vs `into_split`, HTTP/2 multiplexed, optional HTTP/3) and scheduled resource/FD/RSS churn soak tests.
- Coverage-guided `cargo-fuzz` libFuzzer + ASan harnesses inside `crates/{netune-http1,netune-http2,netune-http3,netune-quic,netune-tls}/fuzz/` plus CI MSRV (`1.95.0`) enforcement, feature-isolation matrix, `cargo package --list`, `cargo audit`, CycloneDX SBOM generation, and Dependabot configuration.
- Documentation: `docs/reference/migration-0.1.0.md`, `docs/how-to/production-operations.md`, and `0.1.0` GA SemVer + Linux Tier-1 support matrix in `docs/reference/stability.md`.

### Changed

- **Breaking (pre-GA clean break):** Core public structs and enums across all Stable crates are now `#[non_exhaustive]` with `with_*` builder methods (`ClientConfig`, `PoolConfig`, `ServerConfig`, `Limits`, `ws::Limits`, `NetError`, `ConnectErrorKind`, `ResolveErrorKind`, `HttpProtocol`, `Observation`, `BodyState`, `RequestBody`, `Target`, `Request`, `Response`, `Established`, `Released`, `Exchange`, `H2Error`, `DiagnosticPhase`, `RetryVerdict`, `EventKind`, `ConnectionIdentity`).
- **Breaking:** `#![deny(missing_docs)]` is enforced on all 9 Stable crates (and `netune-tls`).
- `netune-http3` (Preview): `H3RequestBody::split()` returns `(H3ResponseFuture, H3SplitSender)`, separating streaming send operations from connection-level datagrams.
- `netune-tls` (Preview): consolidated all `unsafe` FFI and `volatile_zeroize` memory wiping into `crates/netune-tls/src/ffi.rs` and `zeroize.rs` under `#![deny(unsafe_op_in_unsafe_fn)]`, with `Drop` zeroization on `ClientHandshake` and verified under AddressSanitizer.

### Fixed

- `netune`: H1 full-duplex `SplitHandle::release()` synchronously swaps `SocketTap::Off` when tearing down an unpooled/aborted exchange (including via an `ExchangeCleanup` guard around `select!`), guaranteeing complete `Body::trace()` socket timelines on early responses, half-read body drops, and upload task aborts without returning half-written connections to the pool.

## [0.0.35] - 2026-11-16

Release pipeline validation tag (`0.0.x` RC line).

## [0.0.34] - 2026-11-16

### Added

- `netune`: `ClientConfig::request_timeout` bounds the whole attempt, including redirects and the response body. `PoolConfig::max_in_flight_total` bounds concurrent exchanges across all authorities. `docs/reference/stability.md` defines the Stable/Preview/Experimental tiers and the gates for owned TLS, HTTP/3 and WebTransport production claims.
- `.github/SECURITY.md`: private vulnerability reporting, supported versions, response targets, scope and security boundaries.

### Changed

- **Breaking:** Plain egress TLS targets now use rustls with the platform verifier. The owned `netune-tls` engine is selected by `Target::with_tls_profile` or `Target::with_tls_engine("netune-tls")`; a profile is never silently downgraded. See [ADR-0054](docs/adr/0054-audited-tls-default-and-owned-fingerprint-opt-in.md).
- `netune`: Production defaults are now bounded: `response_head_timeout` 30 s, `body_idle_timeout` 60 s, `request_timeout` 300 s, `max_in_flight_per_authority` 64, `max_in_flight_total` 512. `None` is an explicit opt-out.
- `netune`: `Decoder::push` / `Decoder::finish` require the remaining decoded-body budget; a compressed chunk can no longer expand past the configured limit before failing.
- `netune`: HTTP/3 client uploads and body chunks now inherit `request_timeout` / `body_idle_timeout` instead of the previous one-day internal sentinel.
- `netune-http3`: `H3RequestBody::split` returns a concurrent response-head future and an upload sender; `netune` uses it so an early HTTP/3 response is surfaced and the remaining upload is cancelled instead of stalling behind a server that stopped reading.
- `netune`: HTTP/1.1 exchange now splits its transport into read/write halves sharing the socket tap, so the response head/body can be read while a request body is still uploading. An early response cancels the upload and a half-written connection is never pooled.
- `netune-http1`: `Http1Reader::read_response_head` skips `100`/`102`/`103` interim heads, treats `101` as final, and bounds a peer that emits interim heads forever.
- `netune-webtransport`: added `WebTransportVersion` negotiation and exposed the selected draft on the client/server/session; draft-17 is preferred and unknown enable values fail closed.
- `netune-tls`: secret-bearing key-schedule and TLS 1.2 record-cipher values zeroize on drop; added the contributor audit-readiness package in `docs/dev/security/tls-audit.md`.

### Fixed

- `netune-quic`: `Endpoint::close` is observable by `Connection::wait_established`, `Connection::closed` and `Connection::is_closed` even when the close races the waiter's subscription; the endpoint flag is authoritative, not just the broadcast notification.
- `netune-http3`: a split request sender and its response future share one `H3StreamPermit`, so neither half can release the session's active-stream slot while the other is still working.

## [0.0.33] - 2026-11-16

### Added

- `netune`: Introduced protocol-neutral `RoundTrip` seam (`Wire` for real connections, `mock::Mock` for request-level scripted tests and `FaultConnector` for connector fault injection), unified `Body` terminal trace recovery (`Body::trace()`), and post-dispatch `NetError::Timeout` bounds (`response_head_timeout`, `body_idle_timeout`, ADR-0050..0052).
- `netune`: Unified HTTP/1.1, HTTP/2, and HTTP/3 under `HttpProtocol` (`Client`, `Target::with_protocol`, `Wire::with_quic`, `wire::h3`), preserving inherited `EgressConfinement` across QUIC/H3 and streaming request bodies (`RequestBody::Stream`, `RequestBodySource`, `netune_http1::RequestWriter`).
- `netune-http2`: Added background multiplexed connection driver (`H2ClientSession`, `H2StreamPermit`, `H2RequestSender`, `H2StreamReader`) answering idle `PING`, `SETTINGS`, and `GOAWAY` while isolating early stream drops via `RST_STREAM(CANCEL)`.
- `netune-http3` & `netune-quic`: Added shareable `H3Session`, typed `H3Error::GoAway`, `H3RequestBody::close_send`, and `QuicConnector::for_profile`.
- `netune`: Added `PoolConfig::{max_idle_total, max_in_flight_per_authority}`, synchronous `Pool::reap()`, lazy weak-reference background idle reaper, shared multiplexed H2/H3 session pooling, and per-key cold-dial singleflight coalescing (ADR-0053).
- `netune-tls`: Added dual-tier in-workspace PR + `#[ignore]` soak fuzz targets (`crates/netune-tls/tests/fuzz.rs`) covering record unprotection, ASN.1 SPKI extraction, TLS 1.2/1.3 handshakes, and RFC 8879 `CompressedCertificate` (zlib/brotli).

### Changed

- `netune-trace`: Neutralized trace and transport vocabulary (v3 schema), moved socket-level `TappedSocket` / `Transport::socket_tap` strictly beneath TLS, and refined replay safety (`Request::is_replay_safe`, `NetError::RetryableProtocol`).

### Removed

- **Breaking:** Removed standalone `netune::H2Client` and `Target::with_force_h2` / `Pool::{Http2Idle, put_http2}` in favor of unified `Client` + `HttpProtocol` + multiplexed `H2ClientSession`.

### Fixed

- `netune-http2`: Stream credit received while a writer was waiting for connection credit is no longer discarded, and the server writes response chunks only up to the currently available windows so one blocked stream cannot hold the session's send path. Handler-completion wakes now name their stream, closing a race where `reap` could miss a response.
- `netune`: Cross-origin redirect sanitization strips credentials from `raw_headers` as well as the normalized map, and a scheme change (`https` -> `http`) is treated as an origin change even when the authority is unchanged.
- `netune-egress`: `is_public_ip` now rejects IPv4 multicast, 6to4/NAT64/IPv4-compatible forms that embed a non-public address, and additional IPv6 documentation/transition ranges.
- Tests: removed two timing races in the HTTP/2 large-body and stale-socket replay suites.

## [0.0.32] - 2026-11-16

### Fixed

- `netune-tls`: Eliminated out-of-bounds slice panics in the async TLS driver and hardened TLS 1.2/1.3 handshake, record, certificate, session, and `ClientHello` state-machine handling across edge-case framing and partial I/O paths.

### Changed

- `netune`: Replaced untyped connection and DNS resolution error strings with structured `ConnectError` and `ResolveError` types and updated TCP/UDP/proxy/TLS/WebSocket connect paths.

## [0.0.31] - 2026-11-15

### Added

- **In-workspace parser fuzzing and pure-Rust WebTransport differential gate (ADR-0049).**
  `test-support::fuzz` provides a deterministic corpus, truncation and mutation
  engine (`run_fuzz` and `run_fuzz_soak`), and every wire parser crate
  (`netune-http1`, `netune-http2`, `netune-http3`, `netune-quic`,
  `netune-webtransport`) owns a first-class `tests/fuzz.rs` target that compiles
  and runs on stable Rust in every PR and scales to deep soak campaigns under
  `--profile soak` (`[INV-TEST-05..06]`).
  `crates/netune-webtransport/tests/differential.rs` replaces the external Go
  harness with an in-process raw-H3 wire peer in both roles.

### Changed

- Removed top-level `fuzz/`, `interop/`, `scripts/` and
  `crates/netune-webtransport/examples/interop_server.rs`; architecture gate
  `ARCH-014` rejects out-of-workspace fuzz, interop or shell-runner trees
  (ADR-0049).
- Renamed the test-only support crate and root test package to `test-support`
  and `workspace-tests` (ADR-0044).

## [0.0.30] - 2026-11-15

### Fixed

- `netune-tls::driver::OwnedTlsStream`: fragment outbound `AsyncWrite`
  application payloads at `MAX_PLAINTEXT_LEN` (16,384 bytes) and drain buffered
  ciphertext across partial inner writes so callers never trip
  `RecordError::PlaintextTooLarge` or lose progress across `Poll::Pending`.

## [0.0.29] - 2026-11-15

### Added

- **Declarative ClientHello blueprints & TLS 1.3 PSK session resumption (ADR-0048).**
  `netune-tls::hello` and `netune::TlsProfile` move cleanly to declarative
  `ClientHelloBlueprint`s supporting arbitrary extension ordering, seeded
  extension permutation, RFC 8701 GREASE, RFC 7685 dynamic padding,
  independent `key_share` vs `supported_groups`, `alps`, `record_size_limit`,
  `post_handshake_auth`, `session_ticket`, and RFC 8879 `compress_certificate`
  (`zlib` and `brotli` decompression in `netune-tls::handshake`), alongside
  `go-standard`, `chrome-current`, `firefox-current`, and `safari-current`
  presets (`[INV-TLS-06]`, `[INV-TLS-11]`). `netune-tls::session` and
  `TlsRouterConnector` also cache incoming `NewSessionTicket` messages per
  `(server_name, profile_name, alpn)` and perform single-use TLS 1.3 PSK
  resumption with RFC 8446 §4.2.11.2 binder signing.

- **Owned egress TLS engine begins (ADR-0045).** New leaf crate `netune-tls`
  owns the egress TCP-TLS handshake: the TLS wire constants and framing
  (`wire`), a typed, byte-exact ClientHello model with pure serialization
  (`hello`), the RFC 8446 §7.1 key schedule (`key_schedule`), the TLS 1.3
  AEAD record layer (`record`), all seven key-exchange groups with RFC 10024
  hybrid combiners (`key_exchange`), and the sans-IO TLS 1.3 client
  state machine (`handshake`) with HelloRetryRequest, a mandatory
  `ServerCertVerifier` trust seam, CertificateVerify and Finished
  verification, and the full TLS 1.2 client handshake (ten completable
  suites: six AEAD differential against a TLS-1.2-only `rustls` server under
  both PRF hashes, four CBC+HMAC-SHA1 against openssl-derived goldens via
  the `aws-lc-sys` EVP interface) with the extended master secret as the
  mandatory derivation, plus the engine seam in `netune` (step 5):
  `Target::with_tls_engine` selects the engine per request, the choice
  enters the connection identity and pool key ([`INV-TLS-09`]), the
  `netune-tls` async driver wraps the established connection in
  `AsyncRead`/`AsyncWrite`, and the profile's lists map onto the Go-shaped
  hello with refusals for unmapped values — exercised end to end in the
  integration tier against `rustls` peers in both versions. Acceptance is
  golden corpora: the `go_identity`
  hello reproduces the measured 1.5.9 JA3 (`03117a8ed39ef02427ebbc39f121275c`)
  and both measured JA4 fingerprints; every intermediate key-schedule value
  and three record ciphertexts reproduce RFC 8448 §3 byte-for-byte; and the
  owned handshakes complete live differential runs against `rustls` servers
  in both versions — hybrid agreement, ALPN negotiation and an HTTP
  request/response over the owned record layer. Cryptographic primitives
  come from `aws-lc`;
  `rustls` is a dev-only oracle on this path (`[INV-TLS-04..09]`), and the
  architecture gate rejects a third-party TLS engine outside the
  ADR-0015/0028 paths (`ARCH-013`).
- **Antigravity CLI dual identity (ADR-0047).** The single `antigravity-cli`
  preset splits into `antigravity-cli-unary` (ALPN `http/1.1` only) and
  `antigravity-cli-stream` (`h2, http/1.1`, paired with the `go-nethttp` H2
  fingerprint through the registry); a path-named preset offers exactly that
  path's ALPN (`[INV-TLS-10]`).

### Changed

- **Breaking:** `Preset::AntigravityCli` and the name `"antigravity-cli"` are
  removed; use `AntigravityCliStream` / `antigravity-cli-stream` or
  `AntigravityCliUnary` / `antigravity-cli-unary`
  ([ADR-0047](docs/adr/0047-antigravity-cli-dual-identity.md)). The `0.0.x`
  line is already patch-breaking by policy.
- **Breaking: HTTP/2 regular-header order is named policy (ADR-0046).**
  `H2RequestProfile` gains `regular_header_order`
  (`CallerOrder` / `GoMapRandom` / `Fixed`), `order_request_headers` takes the
  connection seed, and `H2Fingerprint::go()` selects `GoMapRandom` with a
  per-request seed mixed from the stream id — the go-nethttp identity no
  longer presents the fixed regular-header order that Go never has
  (`[INV-CUSTOM-21..22]`).
- **Breaking:** `H2ClientConnection::handshake` draws a per-connection
  regular-header order seed from process entropy;
  `handshake_with_seed` makes the wire sequence reproducible.
- **Fixed:** `netune_trace::ja3` spelled the JA3 string with the field and
  list separators inverted (fields dash-joined, lists comma-joined); it now
  produces the standard JA3 format — fields comma-joined, values within a
  field dash-joined — so the MD5 of a hello matches the historical tooling
  and the measured corpus instead of an inverted private convention.

### Changed

- **Test architecture.** `cargo nextest` is the one test runner, configured in
  `.config/nextest.toml`; the only remaining `cargo test` command is the doctest
  gate, which nextest cannot execute. Shared fixtures moved to the dev-only
  `netune-test-support` crate, external integration/e2e tests moved under the
  root `tests/` harness with one entry point per tier, and oversized unit-test
  modules moved beside their source as `src/<module>/tests.rs`. No public API
  changes.

## [0.0.28] - 2026-11-12

### Added

- **Raw negotiated ALPN.** `Established` gains `alpn_protocol: Option<Vec<u8>>`, carrying
  the exact name rustls selected. The existing `alpn` trace enum is unchanged, so a
  consumer whose protocol uses a private ALPN name no longer has to infer it from
  `Unknown`.
- **QUIC authority resolution inside the connector.** `netune-quic` gains
  `QuicResolver`/`SystemQuicResolver` and `QuicConnector::with_resolver`. The new
  `connect_authority` brackets `DnsStart`/`DnsEnd`, applies `EgressConfinement` to every
  resolved address, and then enters the existing socket path. The `SocketAddr` entry point
  remains for callers that already hold a checked address.
- **Head-only HTTP/1.1 serialization.** `netune-http1::write_request_head` writes the
  request line and the caller's exact headers with no synthetic `Content-Length`,
  `User-Agent` or other field. `write_request` keeps its self-delimiting body behavior.

### Changed

- **Breaking:** external `Established` struct literals must set `alpn_protocol` (the
  `0.0.x` line is already patch-breaking by policy).
- `QuicConnector` carries a resolver; the default is `SystemQuicResolver`, so existing
  `connect` callers are unchanged.

## [0.0.27] - 2026-11-11

### Fixed

- Corrected the post-0.0.26 documentation references to the removed
  `ERROR_TLS_HANDSHAKE` constant. TLS handshake failure is documented as the
  registered `NET-E-SERVER-TLS-HANDSHAKE` diagnostic. No API or wire behaviour
  changed from 0.0.26.
- Corrected the ADR-0042 registry summary: listener-scoped events use the
  dedicated `ListenerObserver`, not the attempt `TraceSink`.

## [0.0.26] - 2026-11-11

### Added

- **Diagnostic Spine.** `netune-trace` now carries a bounded `DiagnosticTable`
  beside the event log. `DiagnosticCode` is a stable, registered classification
  with phase, level and retry verdict; `DiagnosticRecord` carries bounded
  message/field detail; `Diagnose` is the reviewed mapping implemented by the
  orchestrator error vocabularies (`INV-DIAG-01..06`, ADR-0041).
- **Failure evidence survives the observation tier.** `Client::request*`,
  `send*`, WebSocket connect, `H3Client::connect*` and `H3Client::execute`
  return an attempt error carrying a `TraceSnapshot`. `Observation::Off` still
  records the terminal diagnostic, and `diagnose()` derives the failure phase,
  retry verdict, fidelity caveat and next checks without reading a clock.
- **One trace identity and sink contract.** `TraceMeta` carries a generated
  UUIDv7-shaped id, direction, wall-clock start, build and process provenance.
  `TraceSink` v2 receives the envelope with every event, and listener events
  cover bind, accept failure, shed, protocol selection, drain expiry and H3
  handshake failure (`INV-DIAG-03..04`, `INV-DIAG-07`, ADR-0042). Trace-id
  propagation is an explicit policy (`TracePropagation::Off | Header`).
- **Native diagnostics crate.** `netune-diagnostics` provides `StderrSink`,
  `JsonLinesSink`, `FanoutSink`, production-safe `RedactionPolicy`, and
  `TraceBundle` (manifest, trace, diagnosis, notes) with restrictive Unix file
  permissions. `netune-diagnose inspect|diff` reviews a bundle offline.
- **Review workflow.** Postmortem and runbook indexes/templates, a failure
  report issue template, a pull-request failure record, `DOC-015`/`DOC-016`
  gates and `ARCH-011` (no direct `EventKind::Error` producer) are enforced.
- **More content hooks.** DNS/TCP/TLS/proxy failures carry phase detail; H2
  GOAWAY/RST_STREAM codes and debug data are recorded; QPACK blocked state,
  QUIC path MTU/close, pool stale-socket and WebSocket close code/abnormal EOF
  are recorded. `TraceDiff` compares two snapshots for regression review.

### Changed

- **Breaking: trace schema v2.** `RequestTrace` replaces the bare `id` with
  `TraceMeta` and adds `diagnostics`; `IngressTrace` does the same.
- **Breaking: sink v2.** `TraceSink::event` now takes `&TraceMeta` and the trait
  gains `trace_started` / `trace_finished`; sink drops are counted.
- **Breaking: error boundary.** `netune` request methods return `AttemptError`;
  `netune-http3` `connect*`/`execute` return `H3AttemptError`. `netune-server`
  deletes the public `ERROR_*` constants in favour of `DiagnosticCode`.
- **Breaking:** `ServerConfig` gains `listener_sink` and `trace_propagation`;
  `TraceConfig` gains `propagation`; `IngressTrace` gains `meta` and
  `diagnostics`.

### Fixed

- `log_from_events` preserves `Event::stream`; a multiplexed H2 log rebuilt
  through it no longer attributes one stream's events to stream 0.
- Handler panic messages and TLS handshake reasons are no longer discarded;
  they travel in the diagnostic side table.
- A listener accept failure, admission shed, drain expiry and H3 handshake
  failure are no longer silent.

### Security

- **Production-safe bundle redaction.** `RedactionPolicy::default()` keeps only
  public fields and text; `internal()` is the explicit local-review policy.
  `Secret` fields and text are always removed. Bundle directories are `0700`
  and files `0600` on Unix.
- Quiet defaults: no sink, no bundle, and no trace propagation unless the
  caller opts in.

## [0.0.25] - 2026-11-10

### Added

- **Per-phase handshake overrides.** `ClientConfig::h2_handshake_timeout`,
  `H2Client::with_handshake_timeout`, `ProxyConnector::with_handshake_timeout`,
  `Socks5DatagramConnector::with_handshake_timeout` and
  `WsHandshake::with_handshake_timeout` expose the bound on the phase each one
  owns. Every phase defaults to the same 10 s budget; `None` removes it only
  for a caller whose outer deadline reports the stall as a connection failure.

### Security

- **Every egress connection-establishment phase is bounded.** The HTTP/2
  preface + SETTINGS exchange, HTTP `CONNECT` and SOCKS5 proxy tunnels,
  WebSocket upgrade responses and SOCKS5 UDP associate now run under
  `[INV-TRANSPORT-05]` (ADR-0040). Previously a peer could accept TCP and, if
  TLS had already completed, never answer the next exchange; the stall
  surfaced at an outer streaming watchdog as a generation failure. Expiry is a
  retryable `NetError::Connect` naming the phase and peer, and a never-completed
  connection is never pooled.
- **The proxy module's "bounded" claim is now true.** Its HTTP `CONNECT` and
  SOCKS5 greeting/CONNECT exchanges had no clock attached; both now share the
  same bound.

## [0.0.24] - 2026-11-10

### Added

- **`QuicProfile.path_mtu_discovery`.** A consumer that needs fixed-size
  datagrams can disable DPLPMTUD instead of relying on an engine-internal
  constant. Disabling it advertises the 1200-byte QUIC minimum as the local
  `max_udp_payload_size`, so the probe ceiling cannot exceed the floor and the
  peer is told the same receive bound. It defaults to `true`; the existing
  `dplpmtud_*` suite remains the falsifier for the enabled path, and
  `dplpmtud_can_be_disabled_by_the_consumer` fails if the policy is ignored.

## [0.0.23] - 2026-11-10

### Added

- `ServerSessionConfig` carries `handshake_timeout` and `idle_timeout`; both
  have production defaults, and `netune-server` maps them from `head_timeout`.
- `TlsConnector::with_handshake_timeout` and
  `TlsRouterConnector::with_handshake_timeout` expose the new TLS handshake
  bound (10 s by default).

### Security

- **TLS handshakes are bounded.** `TlsConnector` and `TlsRouterConnector` now
  time out a peer that completes TCP and then never answers the ClientHello.
  `with_handshake_timeout(None)` keeps the old unbounded behaviour for callers
  with an outer deadline.
- **HTTP/2 ingress has handshake and idle bounds.** A peer that opens a
  connection and never completes SETTINGS, or that leaves an H2 connection with
  no open streams, no longer holds an admission permit indefinitely. The
  orchestrator maps both bounds to its existing `head_timeout`.
- **HTTP/2 header-block flood is bounded.** `CONTINUATION` reassembly now
  enforces the advertised `SETTINGS_MAX_HEADER_LIST_SIZE` on both the raw
  block and the decoded field list, and rejects an interleaved frame instead of
  buffering around it. A peer can no longer grow the reassembly buffer without
  limit (the "CONTINUATION flood" pattern).
- **QUIC CRYPTO reassembly is bounded.** Out-of-order handshake data is capped
  per packet space and per chunk count, so a peer that sends high offsets with
  a gap cannot grow an unbounded `BTreeMap`.
- **QUIC ACK processing is bounded.** A peer-controlled ACK frame is no longer
  expanded into a set of every packet number it claims; coverage is checked per
  outstanding packet. Received packet numbers retained for ACK generation are
  capped, and ACK frames now carry real ranges instead of collapsing to the
  largest packet whenever a gap exists.
- **`https://` proxy URLs are refused.** `Proxy::parse` previously accepted the
  scheme and then dialed the proxy in plaintext, putting `Proxy-Authorization`
  on the wire unencrypted. The proxy hop is documented as plaintext-only.

## [0.0.22] - 2026-11-10

### Documentation

- Record the browser probe result precisely: Chrome 159 unstable advertises the
  legacy draft-02 `0x2b603742` H3 setting, and neither Chrome 157 nor 159
  advertises `reset_stream_at`. The browser half of ADR-0037 Gate 4 remains
  externally blocked; no compatibility fallback is being mistaken for draft-17
  completion.

## [0.0.21] - 2026-11-10

### Added

- **WebTransport fuzz coverage.** `fuzz/fuzz_targets/webtransport_capsules.rs`
  fuzzes WT control capsules, unidirectional headers and bidirectional stream
  signals; the target is part of the scheduled fuzz matrix.
- **Incoming flow-control test.** A peer that exceeds the advertised
  `WT_MAX_DATA` via a raw WebTransport stream now has its session marked
  terminal and is covered by `an_incoming_data_overrun_terminates_the_session`.

### Notes

- Chrome 157 stable and Chrome 159 unstable were also probed against the owned
  origin. Chrome 159 advertises the legacy draft-02 `0x2b603742` H3 setting and
  neither browser advertises `reset_stream_at`, so the browser half of
  ADR-0037 Gate 4 remains externally blocked.

## [0.0.20] - 2026-11-10

### Security

- **WebTransport request admission (ADR-0039).** `WebTransportServer::accept`
  now requires CONNECT, `:scheme = https`, an authority and an absolute path,
  and validates the optional `Origin` against a new `OriginPolicy`. The safe
  default is same-origin; `Any` and normalized allowlists are explicit choices.
  Malformed requests receive 400 and disallowed origins 403.
- **Client admission checks.** `WebTransportClient::connect_session` validates
  the URI before sending and refuses a non-2xx extended CONNECT response instead
  of constructing a session from a rejected request.
- **Session-ID validation.** Incoming WebTransport unidirectional and
  bidirectional extension streams are validated as client-initiated bidi
  stream IDs before routing; an invalid ID closes H3 with `H3_ID_ERROR`.
- **Terminal control state.** A peer close refuses further control and new
  streams; drain refuses new local streams; a regressed `WT_MAX_DATA` or
  `WT_MAX_STREAMS` capsule marks the session closed instead of being replayed.

### Added

- `tests/security.rs`: spoofed scheme/missing authority/Origin, allowlisted
  cross-origin, duplicate Origin, invalid session IDs, flow-control replay,
  close and drain adversarial tests.
- `H3Client`/`H3ServerConnection::enable_stream_extension_with_validator` is
  the protocol-neutral H3 seam that validates extension stream IDs before
  delivery.

## [0.0.19] - 2026-11-10

### Added

- **Independent WebTransport peer.** `interop/webtransport-go` and
  `scripts/webtransport-go-interop.sh` drive a bidirectional stream, a
  unidirectional stream in each direction and a datagram exchange against
  `netune-webtransport` with `quic-go/webtransport-go`; the script runs in CI.
- **Draft-16 SETTINGS negotiation.** A draft-17 endpoint advertises both
  `SETTINGS_WT_ENABLED` codepoints and accepts either from the peer. The server
  ignores the client's server-only enable setting, as draft-17 requires.

### Fixed

- **QUIC connection-ID roles.** A server now chooses an independent non-zero
  local source CID and addresses the client by its source CID, including a legal
  zero-length CID. This was the reason browser and Go peers could not handshake.
- **Extended CONNECT capability.** `SETTINGS_ENABLE_CONNECT_PROTOCOL` is treated
  as a server capability; a server no longer requires the client to advertise
  it before accepting an extended CONNECT request.

### Known gaps

- ADR-0037 Gate 4 is still open for browsers: Chrome 157 does not advertise the
  `reset_stream_at` transport parameter required by draft-17. Gate 5's
  adversarial replay suite is also outstanding.

## [0.0.18] - 2026-11-10

### Added

- **WebTransport GOAWAY teardown.** `WebTransportServer::shutdown` sends an H3
  GOAWAY; existing sessions may finish, while a new `WebTransportSession` is
  refused by the peer's H3 stack. ADR-0037 gates 1-3 are now complete.

## [0.0.17] - 2026-11-10

### Added

- **Reliable partial stream reset.** QUIC implements `RESET_STREAM_AT` and the
  `reset_stream_at` transport parameter. WebTransport exposes
  `reset_reliable`, delivers exactly the reliable application prefix and then
  surfaces the reset; the receive path also handles a reset that arrives before
  the first STREAM frame.
- **WebTransport teardown.** Close/drain delivery, peer-initiated close and
  post-close stream refusal are covered by tests; flow-control overrun is
  rejected before it reaches the wire. ADR-0037 gates 1 and 3 are landed,
  close/drain/peer-close teardown is covered, and GOAWAY-specific teardown,
  browser interop and adversarial replay remain outstanding.

## [0.0.16] - 2026-11-10

### Added

- **DPLPMTUD.** QUIC starts at the 1200-byte floor and raises the validated
  path MTU only after a PING+PADDING probe is acknowledged. Probes are bounded
  by the local/peer `max_udp_payload_size` and a 1500-byte ceiling, carry no
  application frames, and a lost or black-holed probe leaves the MTU unchanged
  (`Connection::path_mtu`, ADR-0036, `[INV-QUIC-24]`).

## [0.0.15] - 2026-11-10

### Added

- **Ingress socket and server-policy seams.** `H3Server::bind_with_socket`
  accepts a caller-owned `QuicUdpSocket` stack, so inbound obfuscation/port-hop
  layers use the same listener lifecycle, admission and drain path.
  `ServerOptions` / `H3Server::bind_with_quic_options` expose server keep-alive
  and congestion policy without putting callbacks into a wire profile.
- **Scheduled fuzzing and soak.** `fuzz/` contains owned-parser targets for
  QUIC frames/packets, H3/QPACK, HTTP/2 frames and HTTP/1 targets; the weekly
  `Fuzz and soak` workflow also runs the ignored QUIC echo/keep-alive soak.

### Changed

- **Incoming handshake failures are observable.** `Endpoint::accept` now returns
  `Result<Connection, AcceptError>`; `AcceptError::Handshake` is a peer failure
  and `AcceptError::EndpointClosed` is listener shutdown. `H3Server` continues
  after a failed peer and exposes errors through
  `subscribe_handshake_errors()` (ADR-0035, `[INV-QUIC-23]`,
  `[INV-SERVER-25]`).

## [0.0.14] - 2026-11-10

### Fixed

- **Endpoint shutdown wakes every waiter and keeps accepted work alive.**
  `Endpoint::close` notifies `accept`, `Connection::wait_established`,
  `Connection::closed` and the per-connection drivers. Dropping the endpoint
  keeps already-accepted connections alive and stops the demultiplexer when the
  last connection ends; a socket receive failure closes the endpoint and wakes
  the same waiters.
- **QUIC connection routes are removed when a connection ends.** The endpoint
  routing table no longer grows for the lifetime of a long-running listener;
  each connection removes its connection-ID entries on driver exit or drop.
- **DATAGRAM payload limits include the frame overhead.** The advertised
  `max_datagram_frame_size` bounds the whole DATAGRAM frame, so the engine now
  solves `payload + 1 + varint_len(payload) <= frame_max` instead of assuming a
  two-byte overhead. A small peer limit can no longer produce an oversized
  frame that is queued forever.
- **Unsupported socket options fail loudly.** `SO_MARK` and
  `SO_BINDTODEVICE` return `Unsupported` on non-Linux targets instead of being
  silently ignored, matching `[INV-SOCKET-01]`.
- **A closed connection stores the same truncated close reason it sends**, so
  the local and wire views of the close cannot diverge.

## [0.0.13] - 2026-11-10

### Changed

- **QUIC consumer seams are per-connection factories.** The shared
  `QuicConnector::with_custom_socket` API is removed. A caller installs
  `QuicUdpSocketFactory` through `with_socket_factory`; the factory runs after
  egress confinement and before the first Initial packet, receives the target
  and `QuicSocketConfig`, and owns exactly one socket stack for one connection.
  `Endpoint::server_with_socket` exposes the low-level ingress counterpart
  (ADR-0034).
- **QUIC handshake waits return the failure.** `Connection::wait_established`
  and `H3Client::wait_handshake` now return `Result`, and
  `QuicConnector::connect` propagates it. A rejected certificate or protocol
  failure can no longer leave the caller waiting for an `established` watch that
  will never fire. rustls handshake errors map to `QuicError::Tls`, while packet
  protection errors remain protocol errors.
- **QUIC keep-alive is bounded by the negotiated idle timeout.** A zero
  `QuicProfile.keep_alive` is rejected. The engine now enforces RFC 9000
  Section 10.1: the effective idle timeout is the minimum non-zero advertised
  value, floored at three PTOs, and an idle close discards queued frames without
  sending `CONNECTION_CLOSE`.

### Fixed

- **QUIC packets respect the 1200-byte datagram limit.** Frame admission now
  runs against a per-packet budget; a custom congestion window can no longer
  make `poll_transmit` assemble an oversized UDP datagram. Initial padding
  iterates because adding PADDING can grow the long-header length varint, and a
  final guard rejects any packet or 0-RTT datagram above the limit.
- **The idle timer restarts on successful receive and on the first
  ack-eliciting send since that receive**, not on every arriving datagram.

## [0.0.12] - 2026-11-09

### Added

- **Consumer seams on the owned QUIC transport.** `netune-quic` exposes
  `QuicUdpSocket`, an abstract datagram socket accepted by
  `QuicConnector::with_custom_socket`, so protocol-specific obfuscation and
  port-hopping layers can sit below the engine without forking it.
  `CongestionControllerFactory` does the same for congestion control: a
  per-connection controller selected by `QuicConnector::with_congestion_factory`
  overrides the profile algorithm. `QuicProfile.keep_alive` sends a PING after
  the configured receive inactivity, and `Connection::peer_certificates` exposes
  the post-handshake chain a `pin-sha256` check needs. These are the capabilities
  daer's Hysteria 2 outbound consumed from `quinn` before the owned migration.

## [0.0.11] - 2026-11-09

### Added

- **Owned QUIC foundation.** `netune-quic` now owns the RFC 9000 wire codec
  (varints, long/short headers, all core frames, transport parameters), RFC 9001
  packet protection backed by `rustls`/`aws-lc-rs`, TLS handshake wiring, stream
  state, ACK generation, timestamp-driven RTT/PTO retransmission, flow control,
  RFC 9221 datagrams, UDP routing and the async client/server endpoint. The RFC
  9001 client Initial vector decrypts and re-protects byte-for-byte.
  `quinn`/`quinn-proto` are dev-only interop oracles; the H3 client and ingress
  now run over the owned transport.
- **Session resumption and 0-RTT.** The client caches authenticated QUIC
  transport parameters alongside rustls tickets; the server enables early data
  only with stateful single-use sessions; rejected early frames are replayed in
  1-RTT; H3 can send early requests before the handshake completes (ADR-0031).
- **WebTransport flow control and multi-session routing.** WT sessions now
  route streams by Session ID across multiple sessions on one H3 connection and
  enforce cumulative WT stream/data limits in send/receive wrappers, including
  `WT_MAX_STREAMS`/`WT_MAX_DATA` capsule updates. Reliable `RESET_STREAM_AT`
  and teardown/browser interop remain outstanding.
- **WebTransport runtime baseline.** `netune-webtransport` now establishes
  draft-17 sessions over extended CONNECT, routes `0x54`/`0x41` streams through
  generic H3 extension seams, and supports bidirectional/unidirectional
  streams, datagrams and close/drain capsules (ADR-0033). Reliable
  `RESET_STREAM_AT`, full flow-control-capsule enforcement and browser interop
  remain outstanding.
- **WebTransport over HTTP/3 ownership.** ADR-0033 establishes a separate
  `netune-webtransport` product crate pinned to draft-17, with generic H3
  extension seams, QUIC `RESET_STREAM_AT`, session/stream/datagram and WT
  flow-control/close semantics. This is a separate web-capability layer, not an
  RFC 9114 transport feature.
- **RFC 9297 Capsule Protocol.** Capsules are framed inside HTTP/3 message
  bodies with bounded partial reads, exposed on request/response/server streams,
  and usable on duplex extended CONNECT sessions (ADR-0032).
- **HTTP/3 extension surfaces.** SETTINGS-gated RFC 9297 datagrams are routed
  to their request streams by Quarter Stream ID, and RFC 9220 extended CONNECT
  uses a typed `ExtendedConnectProtocol` request extension (ADR-0030).
- **QUIC lifecycle hardening.** The owned engine now validates addresses with
  stateless Retry tokens, emits keyed stateless resets, rotates 1-RTT keys with
  key-phase reordering, performs fast loss detection, tops up `MAX_DATA` /
  `MAX_STREAM_DATA`, speaks QUIC v2, handles Version Negotiation, validates
  migrated paths and selects NewReno/Cubic/BBR congestion profiles (ADR-0029).

### Changed

- **HTTP/3 and QPACK are owned.** `netune-http3` now implements the RFC 9114
  state machine and the RFC 9204 QPACK codec, including the static table,
  Huffman coding, dynamic table, critical streams, acknowledgements and blocked
  streams. `h3` and `h3-quinn` are no longer production dependencies, and the
  `vendor/h3` / `vendor/h3-quinn` trees are deleted. QUIC is owned by
  `netune-quic` (ADR-0028, ADR-0029).
- **H3 interop is differential.** `crates/netune-http3/tests/h3_interop.rs`
  exercises the owned stack against crates.io `h3`/`h3-quinn` in both
  directions while keeping both crates dev-only.
- **SETTINGS honesty.** `H3SettingsProfile` no longer advertises HTTP/3
  datagrams or extended CONNECT until their public transport surface exists.
- **Benchmark harness.** The deterministic zero-cost instruction gate now uses
  `gungraun` 0.20 instead of `iai-callgrind` 0.16, removing the unmaintained
  `bincode`/`proc-macro-error2` dev-only chain while keeping the same
  `ir=0%` Callgrind baseline.

### Removed

- The controlled `h3` fork, its patch note, and its CI test job.

## [0.0.10] - 2026-11-09

### Added

- **Tiered observation.** `NoTap`, `Counters`, and `Ring` are typed taps owned
  by `TimedIo`; the hot path no longer shares a `Recorder` behind a mutex.
  `TraceCollector` is the only public cold-path handle, and fidelity is reported
  by the producing tap. H2/H3 remain connection-level L0 traces.
- **Typed connection identity and profile registries.** `ConnectionPlan` resolves
  H1/H2/QUIC names before connect; H2 connection and request profiles are split;
  named QUIC profiles resolve through one registry.
- **Controlled H3 request-header order.** The vendored `h3` fork applies ordered
  pseudo-headers and regular fields before QPACK encoding.
- **Streaming H3 request bodies and trailers.** `H3Client::open_request` returns
  `H3RequestBody`; buffered `send` composes it rather than opening a second path.
- **Controlled dynamic QPACK and typed H3 SETTINGS.** Request/response heads and
  trailers use the fork's encoder/decoder, acknowledge decoded sections, wait for
  blocked insertions, and expose enforceable QPACK capacity/blocked-stream
  profiles. The default remains stateless QPACK.
- **HTTP/3 ingress.** `H3Server` is a separate QUIC listener with the same
  handler, admission, timeout, body-ceiling, trace and drain model as the TCP
  listener. H3 exchange ids are distinct from wire stream ids because stream `0`
  is a valid request stream.
- **Deterministic CI coverage.** The vendored `h3` suite runs in the
  all-features job; architecture and documentation gates cover the new H3 edges
  and ADRs; the zero-cost instruction gate remains `4` (`NoTap`) and `9`
  (`Counters`) instructions.

### Changed

- HTTP/3 connection identity is the resolved QUIC profile plus a typed,
  connection-fixed SETTINGS profile name.
- The H2/H3 trace path reports protocol L0 instead of a synthetic syscall
  timeline.
- `H3Client::send` returns after the response head; `execute` remains the
  bounded buffering convenience.

### Fixed

- HTTP/3 trailers now finish the send side, so a peer no longer waits for
  END_STREAM after receiving them.
- QPACK instruction parsing retains partial instructions across QUIC chunks and
  bounds the retained buffer.
- H3 ingress refuses a single malformed or over-large request head without
  tearing down the QUIC connection's other streams.

## [0.0.9] - 2026-11-08

### Fixed

- **A draining HTTP/2 connection is replaced instead of failing the request.**
  When a pooled connection receives `GOAWAY` (covering only earlier streams) or
  `RST_STREAM(REFUSED_STREAM)` before the response head, the peer has said it did
  not process this stream. That is now `NetError::RetryableProtocol`, so the
  attempt is replayed on a fresh connection — transparently when the connection
  came from the pool, and through the caller's retry policy otherwise. Refusals
  after the response head remain non-retryable: the peer may already have
  processed the request.

## [0.0.8] - 2026-11-08

### Added

- **Streamed HTTP/2 responses.** The client role exposes `H2ResponseHead`,
  `H2ResponseEvent`, and `H2ResponseStream`: `send`/`request` now return once the
  response `HEADERS` arrive, and the body is delivered as `Data` / `Trailers` /
  `End` events with per-stream and connection-level flow control replenished
  incrementally. `Client` uses this path, so an SSE generation is consumed as it
  arrives instead of being buffered to the end of the stream.
- **HTTP/2 connection reuse.** The pool stores negotiated HTTP/2 connections
  alongside HTTP/1.1 keep-alive sockets and selects by protocol. A cleanly
  finished body returns its connection for the next request, continuing the
  stream id space instead of paying a second TLS + SETTINGS handshake. Prewarming
  performs the HTTP/2 handshake when the negotiated protocol is `h2`.
- **Advertised-settings enforcement.** The client's read bounds
  (`MAX_FRAME_SIZE`, `INITIAL_WINDOW_SIZE`, `HEADER_TABLE_SIZE`, …) are now
  derived from the `SETTINGS` it advertises, so a peer may use the limits it was
  told it had.

### Changed

- HTTP/2 response bodies are decoded through the same `Content-Encoding` path as
  HTTP/1.1, so a gzip/brotli response is no longer handed to callers still
  compressed.
- End-of-stream flow-control credit restores only the connection window (the
  stream is closed) and is best-effort: a peer that hangs up after `END_STREAM`
  cannot turn a completed response into a write error, and the connection is
  marked non-reusable instead of pooled.

### Fixed

- **HTTP/2 requests no longer carry a `Host` regular header.** `Client` added
  `Host` from the target authority for every request, including the HTTP/2 path,
  so `:authority` and `Host` were sent together. HTTP/2 clients SHOULD name the
  authority in `:authority` instead (RFC 9113 §8.3.1), and some origins treat
  the pair as malformed: Google's frontend answers
  `RST_STREAM(PROTOCOL_ERROR)` (error code 1), which surfaced as
  `protocol error: HTTP/2 request: HTTP/2 stream 1 reset with error code 1`
  before a response existed. The header is now added only on the HTTP/1.1 path;
  a caller-supplied `Host` is promoted into `:authority` instead of being
  forwarded, and regular header names from `raw_headers` are lowercased because
  HTTP/2 requires it.
- Transport failures while writing a request on a reused HTTP/2 connection are
  classified as I/O errors again, so the stale-connection retry replaces the dead
  socket instead of surfacing a protocol failure to the caller.

## [0.0.7] - 2026-11-07

### Fixed

- **HTTP/3 traces are per-exchange.** One `H3Client` serves many requests over one
  connection and one recorder. Each request now takes an exchange id and records
  `H3StreamStart` / `H3HeadComplete` / `H3Finished` against it (`Event::stream`, numbered
  from 1; `0` stays connection-level). A reader that took the first event of each kind
  attributed every later request to the first; `derive_h3` now refuses a multi-exchange log
  with `Reason::MultipleExchanges`, and the new `derive_h3_exchanges` returns the
  per-request view. The e2e test executes two requests and asserts two distinct, fully
  derivable exchanges.

## [0.0.6] - 2026-11-07

### Added

- **First-class QUIC and HTTP/3 client transport** (`netune-quic`, `netune-http3`)
  ([ADR-0016](docs/adr/0016-quic-and-http3-transport.md)). QUIC endpoints carry an explicit
  identity (`QuicProfile`, `QuicTransportParameters`), RFC 9221 datagram sessions, bidirectional
  `QuicStream`s, and an abstract socket seam (`QuicUdpSocket`) that applies every `SocketConfig`
  option before the first packet is sent. HTTP/3 (RFC 9114) request dispatch builds on it. Both
  are opt-in (`netune` features `quic` / `http3`); the default feature set is unchanged, and
  every crate compiles against `aws-lc-rs` only (`[INV-QUIC-01..04]`, `[INV-SOCKET-01]`).
  The trace vocabulary is ordered boundaries only: `QuicStart`/`QuicEnd`, `QuicStreamOpen`,
  `H3StreamStart`/`H3HeadComplete`/`H3Finished`, with new `derive_quic` and `derive_h3` pure
  derivations for the handshake, TTFB, body and end-to-end spans. Congestion and loss counters
  stay transport state (`QuicConnection::stats()`), not events. The never-emitted
  `QuicLoss`, `QuicCongestion` and `QuicStreamClose` kinds are removed rather than left as
  vocabulary no producer writes.
- **`netune-egress`: the egress-confinement rule as one pure leaf** (ADR-0002).
  `is_public_ip`, `EgressConfinement` and `ConfinementRefused` moved out of `netune` so TCP,
  UDP/QUIC datagrams and the QUIC connector share one predicate instead of copies that can
  drift. `netune` re-exports them, so existing consumers compile unchanged; confinement still
  strictly precedes socket creation (`[INV-EGRESS-01]`, `[INV-QUIC-02]`).
- **Per-request TLS and HTTP/2 identities** (ADR-0004, ADR-0006).
  `Target::with_tls_profile` selects a named `TlsProfile` for one request and
  `TlsRouterConnector` reads it, so a client is no longer fixed to the identity it was
  constructed with. One profile name pairs both halves of the wire identity — the TLS hello
  *and* the HTTP/2 framing (`safari-current`, `firefox-current`, `antigravity-cli`) — because a
  Go hello over Chrome framing is more distinctive than either choice alone. `Client::send`
  resolves the pairing in one place.
- **The Go `net/http` identity: `Preset::AntigravityCli` and `H2Fingerprint::go()`** (ADR-0006).
  Live-captured from Antigravity CLI 1.5.3: Go's `crypto/tls` hello (`h2,http/1.1`, no GREASE,
  Go cipher and group order) and Go's `net/http` HTTP/2 framing (four SETTINGS in
  `writeSettings` order, a 1 GiB connection window, no PRIORITY frames, and `:authority`-first
  pseudo-headers through the new `PseudoHeaderOrder::AuthorityMethodPathScheme`). Divergences
  from Go that rustls cannot emit are stated in `TlsProfile::antigravity_cli` rather than
  hidden.
- **`netune-server`: an observable ingress orchestrator serving HTTP/1.1 and HTTP/2**
  ([ADR-0011](docs/adr/0011-server-side-ingress-transport.md),
  [ADR-0012](docs/adr/0012-http2-ingress.md)). A crate that owns the workspace's only
  listening socket: an accept loop with explicit admission control (`max_connections`
  sheds, never an unbounded queue), bounded per-phase timeouts applied before application
  code runs, per-connection ingress traces, and a graceful drain that lets in-flight
  exchanges finish up to `drain_timeout`. It depends on the codecs, the trace model and
  `netune-io` only — never on `netune` (`INV-SERVER-01`). It is a transport, not a
  framework: no routing, extractors or middleware.
- **HTTP/2 ingress, decided once per connection** ([ADR-0012](docs/adr/0012-http2-ingress.md)).
  The protocol comes from the connection's first bytes (prior knowledge) or from ALPN and
  is never upgraded in place (`INV-SERVER-09`). A listener that does not offer the protocol
  a peer asked for refuses it with `505` rather than downgrading. One `Handler` answers
  both: `:authority` and `Host` are translated so one field names the authority, and
  `Connection` — which HTTP/2 forbids — is dropped.
- **One HTTP/2 connection machine behind two thin roles** ([ADR-0012](docs/adr/0012-http2-ingress.md)).
  `H2Connection` owns frame reading bounded by the *local* advertised maximum, the SETTINGS
  exchange, PING echo, GOAWAY bookkeeping, HPACK and `CONTINUATION` contiguity, with `Role`
  as a field (`INV-SERVER-08`). `client::H2ClientConnection` and `server::ServerSession` are
  the roles. The server role keeps a stream table, sheds with `REFUSED_STREAM` instead of
  closing the connection, replenishes receive credit only as the handler consumes
  (`INV-SERVER-11`), and wakes on handler completion instead of sitting in a socket read.
- **A response is a state machine whose body may still be arriving**
  ([ADR-0013](docs/adr/0013-response-writer-state-machine.md)).
  `netune_http1::ResponseWriter` takes the request method, so it refuses a body under
  `HEAD`/`1xx`/`204`/`304`/`CONNECT`-2xx, refuses a body past a declared `Content-Length`,
  and refuses a `finish` short of it (`INV-SERVER-12`). `ResponseBody::Stream` /
  `Response::stream` make incremental bodies first class in both protocols — chunked framing
  on HTTP/1.1, `DATA` frames on HTTP/2 — from one handler return type.
- **Request framing is validated before any handler runs**
  ([ADR-0014](docs/adr/0014-request-validation-before-dispatch.md)). The RFC 9112 §3.2
  request-target grammar and the `Host` grammar it is compared against are enforced in the
  codec; the listener additionally refuses two `Host` headers and an absolute-form target
  whose authority disagrees with `Host`. A bare LF is a protocol error in the server role.
  `max_body_bytes` is cumulative across every `next_chunk`, and a declared `Content-Length`
  beyond it is refused before the first body byte (`INV-SERVER-14..16`).
- **`Expect: 100-continue`, a per-write deadline, a reuse quota, and panic containment.**
  A peer that asks permission before uploading is answered immediately rather than paying its
  own timeout; a peer that stops reading is cut off by `write_timeout` instead of holding a
  slot for `handler_timeout`; a connection closes after `max_requests_per_connection`, which
  is how a configuration rollout drains; and a panicking handler is answered with `500`
  instead of resetting the socket.
- **Per-event stream identity in the trace model** ([ADR-0012](docs/adr/0012-http2-ingress.md)).
  `Event` and `EncodedEvent` gained `stream`: `0` where the transport cannot multiplex, the
  protocol's stream id for HTTP/2. `derive_ingress_exchanges` splits a multiplexed log *by
  stream* rather than by position, and a connection-level failure is copied into every
  sub-log it ended (`INV-SERVER-10`). `derive_ingress` still refuses a multi-exchange log.
  Because `EncodedEvent` serializes the new field, a log persisted by `0.0.5` does not
  deserialize into `0.0.6`; re-record rather than re-read old on-disk logs.
- **`netune-io`: the byte-path adapters as a shared leaf**
  ([ADR-0011](docs/adr/0011-server-side-ingress-transport.md)). `TimedIo` and `FaultIo`
  moved out of `netune` because ingress needs the identical syscall tap and the two
  orchestrators must not depend on each other. `netune` re-exports both, so existing
  consumers compile unchanged.
- **Request-direction HTTP/1.1 codec (`netune-http1`)** ([ADR-0011](docs/adr/0011-server-side-ingress-transport.md)).
  `Http1ServerReader` applies the framing rules a *request* obeys: no close-delimited body,
  a `Transfer-Encoding` that must end in `chunked`, and both framing headers refused as
  smuggling. Request and response directions share one framing core, so chunked decoding
  exists once (`INV-SERVER-04`).
- **Ingress event vocabulary and pure derivations (`netune-trace`)**
  ([ADR-0011](docs/adr/0011-server-side-ingress-transport.md)). Ten ingress `EventKind`s
  (`IngressDispatch` … `ResponseEnd`) with `Recorder::start_ingress`, plus
  `derive_ingress`, which computes `request_read_us`, `queue_us`, `handler_us`, `write_us`,
  `response_write_us` and `ingress_e2e_us` as pure functions of the recorded trace
  (`INV-SERVER-02`). `derive` (egress) is untouched.
- **Differential coverage in both directions (`netune-http1`).**
  `tests/differential_server.rs` uses hyper as the *client* against our server role: hyper's
  requests must be framed by us the way hyper intended, and our responses must be accepted
  by hyper unmodified — including a `HEAD` response that declares a length and writes no
  body.

### Changed

- **The WebSocket assembler models a fragmented message as `DataOpcode`** (`netune-ws`).
  `MessageAssembler` holds `Option<DataOpcode>` instead of `Option<Opcode>`, so a control
  opcode or a `Continuation` starting a data message is an explicit `PROTOCOL_ERROR` rather
  than an `unreachable!()` branch. `pending_opcode()` still returns the wire `Opcode`. The new
  `DataOpcode` is exported.
- **The shared client negotiates HTTP/2.** `shared_client()` now sets
  `ClientConfig::enable_http2`, so an `h2` ALPN result is framed as HTTP/2 instead of being
  downgraded to HTTP/1.1; the request's `tls_profile` selects the matching framing identity.
- **`Response::no_content`, `version_not_supported` and `unavailable` are removed**
  (`netune-server`). They were public constructors no code path reached; `not_implemented` stays because
  the transport now uses it for `CONNECT`.
- **`netune-http2`'s `PADDED` and `PRIORITY` handling.** A conforming client may pad
  `DATA`/`HEADERS`/`PUSH_PROMISE` (privacy-preserving clients do), and the previous decoder
  returned the pad-length octet as if it began a header block. Both are now stripped once,
  for both roles, and `PRIORITY` is parsed and ignored as RFC 9113 §5.3.1 permits.
- **The HPACK encoder can grow to the peer's advertised table size.**
  `DynamicTable::set_max_size` refused any increase, which made a peer's
  `SETTINGS_HEADER_TABLE_SIZE` unusable and, in the server role, a stream error. The encoder
  now resizes to whatever the peer granted and emits the §4.2 size update ahead of the next
  header block.
- **`netune-server` gained a default-on `http2` feature.** Both protocols are on by default; turning
  it off compiles out HPACK and the frame decoder for a listener that serves one protocol, and refuses
  `Protocols::HTTP2` at bind time rather than accepting connections it would close.
- **`ServerConfig` gained `max_requests_per_connection`, `write_timeout`, `require_host`,
  `expect_continue`, `protocols` and `http2`.** Every zero-valued bound is refused at bind
  time, because a zero bound is a configuration error rather than "unlimited".
  `ServerConfig::for_tests` tightens exactly the bounds a test would otherwise wait on.
- **`RequestHead` / `ResponseHead` mean "a head this role builds"; parsed heads are
  `IncomingRequest` / `IncomingResponse`** (`netune-http1`). A `*Head` carries what an
  author controls (raw wire header casing, a chosen reason phrase, a declared framing); an
  `Incoming*` carries what a peer controls (the version actually spoken, the request target
  as raw bytes, the target form). No compatibility alias is provided: the distinction is
  the point.
- **`ServerConfig` is not `Copy`** (`netune-server`), because it can carry a `trace_sink`.
  Take it by reference or clone it.
- **`netune-http2`'s client role is `client::H2ClientConnection`.** The connection machine
  is shared, so a `handshake` that was implicitly a client is no longer a method on it.
  `netune` re-exports the new name.

- **TLS termination inside the listener** ([ADR-0015](docs/adr/0015-self-terminated-tls.md)).
  A new off-by-default `tls` feature adds `TlsTermination`, which reads the ClientHello with
  `LazyConfigAcceptor`, selects a `rustls::ServerConfig` from the SNI name (with a required fallback),
  lets ALPN decide the protocol, and records the handshake as `IngressTlsEnd` or
  `ERROR_TLS_HANDSHAKE`. The handshake is bounded by `head_timeout`, and a TLS configuration whose ALPN
  list cannot serve what `protocols` claims is refused at bind time (`INV-SERVER-18..21`). The TLS path
  shares the entire connection pipeline with the plaintext one.

### Removed

- **`netune_http1::write_response`, `write_response_head`, `write_chunked_chunk`,
  `write_chunked_end`, `ResponseBody` and `default_reason`.** Replaced by `ResponseWriter`
  and `write_interim`. Four functions each enforcing part of one rule became one type that
  enforces all of it. There is no compatibility shim, because a shim would let a caller keep
  producing a message that contradicts its own head.

### Fixed

- **`CONNECT` was answered as if a tunnel had opened.** `netune-server` never dials a peer
  (`INV-SERVER-01`), so it cannot open one — but it answered `200 OK` and the client's tunnel bytes went
  to the HTTP parser, after the client had already committed to a relay that was not happening. Both
  protocols now refuse `CONNECT` with `501` before dispatch.
- **A listener served a protocol it did not offer.** The refusal existed for HTTP/2 on an
  HTTP/1.1-only listener but not for HTTP/1.1 on an `HTTP2`-only one, so the latter served requests it
  never advertised — the downgrade `INV-SERVER-09` forbids, through the door nobody checked.
  `Protocols::default()` is now what the compiled feature set can serve, an explicit request for an
  absent protocol fails at bind time, and both directions are refused.
- **An HTTP/2 shutdown never drained an in-flight stream.** The session was handed
  `std::future::pending()`, so a request in flight at shutdown was aborted by the drain deadline
  instead of being finished — `INV-SERVER-06` silently did not hold for the multiplexed protocol. The
  listener now propagates a drain signal through a `watch` channel, and the session finishes every
  handler that completes before announcing `GOAWAY`.
- **Any HTTP/2 request body larger than one stream window deadlocked.** Credit was accounted against
  the connection window only and replenished unconditionally, so the per-stream window was never
  restored: a peer correctly stopped sending at 64 KiB and the request hung. Both windows are now
  charged on receipt and restored on handler consumption, and an overrun is a `FLOW_CONTROL_ERROR`.
- **`write_timeout` was dead on the HTTP/2 path.** The field was documented as the slow-read defence
  and no code read it; a peer that stopped reading held the connection for the length of
  `handler_timeout`. Every frame write is now bounded by it.
- **A streaming handler that returned and then stalled held a connection forever.** `handler_timeout`
  bounds the handler's future, not the stream it returns, so a stream that never produced a chunk was
  unbounded. The interval between chunks is now bounded by the same timeout.
- **An HTTP/2 handler timeout was recorded on stream `0`.** `split_multiplexed` copies connection-level
  events into every sub-log, so one stream's timeout poisoned the derivation of every other stream on
  the connection. Both the timeout and the panic are now recorded against the stream that failed.
- **A request body was reported as `BodyKind::Chunked` on HTTP/2.** HTTP/2 has no transfer coding; a
  handler branching on that value took a path the protocol cannot produce. It is now `UntilClose`,
  which is what `END_STREAM` means.
- **A chunked response head could be written with an unframed body.** The old
  `write_response` accepted raw bytes under a head declaring `Transfer-Encoding: chunked`
  and returned `Ok`, putting a message on the wire that every conforming peer misparses —
  and the malformation stayed invisible until the peer failed. The writer now refuses both
  mismatches, and `netune-server` streams a chunked response through the framed path so the
  capability is reachable rather than merely declared.
- **`ResponseHead::with_chunked_body` / `with_body` left the previous framing declaration
  in place (`netune-http1`).** Converting a `Content-Length` response into a streamed one
  produced a head declaring both, which the writer correctly refused — so the caller got an
  empty response instead of an error at the point of the mistake. Each setter now clears the
  other framing header.
- **`derive_ingress` reported one set of spans for a keep-alive connection that served
  several requests, describing only the first (`netune-trace`).** It now returns
  `NotEstimable(MultipleExchanges)`, and `derive_ingress_exchanges` gives the per-request
  view with each exchange anchored where its connection became free. A multiplexed HTTP/2
  connection derives per stream rather than refusing.
- **Ingress traces ended at the event sink and never reached a running server
  (`netune-server`).** `ServerConfig::trace_sink` took a raw `TraceSink`, whose events carry
  no connection boundary, so a consumer could not recover a derivable trace from them. It now
  takes a `TraceObserver` and hands over a complete `IngressTrace` per finished connection,
  with `SinkObserver` and `CollectingObserver` provided.
- **A bare LF terminated a request line.** RFC 9112 §2.2 defines CRLF; a second hop that
  recognises only CRLF reads the difference as part of the next header, which is the same
  desync class as `CL.TE`. The server role now refuses it while the client role still
  tolerates it, because a sloppy origin is not a security boundary.
- **A streaming body reader had no size bound.** `max_body_bytes` was only checked by
  `read_body_to_end`, so a handler calling `read_body_chunk` in a loop — the case
  `RequestBody` exists for — could read without limit. The bound is now applied per chunk,
  cumulatively.
- **A timing test failed roughly one run in eight (`netune::e2e`).** The prefill gap between
  a response head and its first body byte was 5 ms, the same order as the 2 ms
  `BATCH_GAP_NS` window that refuses `server_ttft_us` as batched; under parallel load the
  two arrived in one read and the promised estimability collapsed. The prefill window is now
  80 ms, so the property under test is unchanged and the flake is gone.

## [0.0.5] - 2026-11-01

### Added

- **`TraceSink` trait and streaming trace export (`netune-trace`)** ([ADR-0010](docs/adr/0010-quic-ownership-and-trace-sink.md)).
  `Recorder::with_sink` streams events as they occur to an installed `TraceSink`
  while continuing to populate the bounded `EventLog` ring buffer. Long-lived
  transparent proxy relays can stream trace events without ring-window overflow
  loss, while request/response attempts retain the ring as their record of truth
  (`INV-TRACE-03`).
- **`SocketConfig` pre-connect routing options and enforcement (`netune`)** ([ADR-0010](docs/adr/0010-quic-ownership-and-trace-sink.md)).
  Added `bind_device` (`SO_BINDTODEVICE`), `bind_address`, `keepalive` (`SO_KEEPALIVE`),
  `tos` (`IP_TOS`/`IPV6_TCLASS`), and `tcp_fast_open` (`TCP_FASTOPEN_CONNECT`).
  `needs_manual_socket` guarantees every pre-connect option forces manual socket
  creation before `connect(2)` so that none are silently skipped by the fast path,
  and OS errors propagate immediately (`INV-SOCKET-01`).
- **RFC 9113 HTTP/2 GOAWAY match guard (`netune-http2`).**
  Pattern guard `last_stream_id < stream_id` cleanly distinguishes abandoned
  streams from active requests covered by the GOAWAY frame.

## [0.0.4] - 2026-10-30

### Added

- **`SocketConfig::mark` applies `SO_MARK` before `connect(2)`.** The mark is
  consulted when the kernel picks the route for the SYN, so a post-handshake
  `setsockopt` cannot influence it. When a mark is configured, `TcpConnector`
  now creates the socket itself (non-blocking, marked) and drives the connect to
  completion instead of delegating to `TcpStream::connect`; without a mark the
  original path is used unchanged. Linux only (`CAP_NET_ADMIN` or
  `CAP_NET_RAW`); other platforms report `ErrorKind::Unsupported` rather than
  silently ignoring the request. This is what a transparent proxy needs so its
  own outbound connections are not captured by its own routing rules.
- **Datagram transport: `DatagramConnector`, `DatagramTransport`, `UdpConnector`
  and `Socks5DatagramConnector`** ([ADR-0008](../docs/adr/0008-datagram-transport-and-socks5-udp-association.md)).
  netune can now open and drive UDP sockets for the first time. Sessions are
  **connected to one peer**, decided when the session opens, so
  `EgressConfinement` remains a precondition of opening a socket
  (`INV-UDP-01..02`) instead of a per-datagram filter. `UdpConnector` is the
  datagram twin of `TcpConnector`: same `DnsResolver`, same `EgressConfinement`,
  same `SocketConfig`, with `SO_MARK` applied before `connect` because the mark
  is consulted when the first datagram's route is chosen. `max_datagram_size`
  derives from `SO_SNDBUF` and is capped at the IP ceiling, so a caller sizing a
  buffer from it cannot build a payload guaranteed to fail. A SOCKS5 UDP
  associate is available for the one case where the *proxy* names the peer;
  association lasts as long as its TCP control connection, datagrams whose
  wrapper claims a foreign source are dropped (`INV-UDP-03`), and fragments are
  refused (`INV-UDP-04`). Only a SOCKS5 proxy can construct that connector — an
  HTTP proxy has no UDP associate and is refused at construction rather than at
  the first datagram.
- **`EventKind::UdpOpen` (30) and `EventKind::UdpDatagram` (31).** A datagram
  session is now visible in the trace, and `Event::is_send` reads the direction.
  New codes are appended; no existing code is renumbered, so an older reader
  degrades to "unknown kind" instead of misreading an event.

## [0.0.3] - 2026-10-23

### Fixed

- **A pooled connection is no longer handed to a different runtime.** The pool is
  process-scoped by design — one `Client` is shared by every task, so a keep-alive
  socket can outlive the code path that dialled it. But a socket is a *tokio I/O
  resource*: it is registered with the reactor that created it, and when that
  runtime is dropped tokio marks the registration shut down. The pool kept the
  socket anyway and handed it to the next caller, whose first read then failed
  with `RUNTIME_SHUTTING_DOWN_ERROR` — "A Tokio 1.x context was found, but it is
  being shutdown." The caller saw an unattributable transport failure for a
  request that had not been sent yet, and retrying the *provider* could not fix
  it.

  `Idle` now records the id of the runtime that dialled the connection
  (`Handle::try_current().id()`), and `Pool::take` discards a candidate whose
  owner is not the current runtime. The caller pays one handshake instead of
  receiving an error, and the stale registration never leaves the pool. `None`
  (synchronous context) matches `None`, so a pool driven entirely from
  synchronous code is unaffected.

  In `nuo` this surfaced as an intermittent transport error from a provider
  request that ran while another test's runtime was being torn down: the
  process-global `shared_client()` holds sockets across every runtime in the
  process, so concurrent test binaries could take each other's dead
  registrations.

### Added

- `crates/netune/tests/pool_runtime_affinity.rs`: a two-runtime regression test
  that dials under runtime A, drops it with a keep-alive socket still pooled, and
  requires runtime B to succeed. Verified to fail with the exact shutdown error
  when the ownership check is removed.

## [0.0.2] - 2026-10-22

### Added

- `netune` feature flags `http2` and `ws` (both enabled in `default`): allow
  HTTP/1.1-only consumers like Estuary to compile out unused protocol codecs
  (`netune-http2` and `netune-ws`) and minimize credential-egress attack surface.
- Fail-closed handling when attempting to negotiate `http2` or connect WebSocket
  without the corresponding feature compiled in.
- CI supply-chain checking (`deny.toml`) and `cargo check --no-default-features`.

## [0.0.1] - 2026-10-19

### Added

- `netune-trace`: zero-allocation trace ring buffer and pure timing derivations, ClientHello parsing, the pure-data ClientHello forge/assembly engine, and JA3/JA4 fingerprinting (ADR-0001, ADR-0006).
- `netune-http1`: HTTP/1.1 line protocol parser and writer, differential-tested against `hyper` (dev-dependency only); raw header casing and duplicate preservation (ADR-0001, ADR-0006).
- `netune-http2`: HTTP/2 wire protocol (RFC 9113) with HPACK (RFC 7541) and the 257-symbol Huffman coder, client connection lifecycle, and declarative Akamai HTTP/2 fingerprint impersonation (ADR-0006).
- `netune-ws`: pure RFC 6455 WebSocket codec — role-enforced masking, fragmented-message reassembly with interleaved control frames, incremental UTF-8 validation, and SHA-1 handshake keys (ADR-0007).
- `netune`: owned transport substrate — asynchronous `DnsResolver` (`SystemResolver`, `StaticResolver`); DNS, TCP and TLS over `rustls`; TLS fingerprint profiles (`TlsProfile` and presets) with per-request selection and `authority#profile` pool isolation; syscall boundary tap (`TimedIo`); `TCP_INFO` sampler; connection pool; HTTP CONNECT and SOCKS5 proxies; redirect policy; streaming decompression; `FaultIo` chaos injection; L3/L4 `SocketConfig`; `SegmentingIo` SNI segmentation; transparent HTTP/2 execution; and client WebSocket upgrade (`connect_ws`, `WsStream`, `WsSession`) (ADR-0001, ADR-0004, ADR-0005, ADR-0006, ADR-0007).
- `netune-probe`: pure L2 Ethernet/IPv4/TCP frame parser and builder; socket transmission gated behind the opt-in `inject` feature and requiring Linux `CAP_NET_RAW` (ADR-0003).
- Egress confinement: `EgressConfinement::StrictPublic` and `is_public_ip`, rejecting loopback, RFC 1918 private, link-local, and cloud-metadata ranges (ADR-0002).
- Structural privilege separation: packet generation and packet transmission never compile into the same default artifact (ADR-0003).
- Transparent keep-alive stale-socket recovery: pre-head replay-safe retry, idle-age telemetry (`ConnectStaleDiscarded`), and the `INV-TRANSPORT-01` through `INV-TRANSPORT-04` invariants (ADR-0005).

### Changed

- Distribution is by git tag; no registry publication participates in a release. The workspace version
  line is flattened back to `0.0.1` for every crate, including `netune-http2`, which had briefly carried
  `0.0.2` only because the registry's `0.0.1` slot for that name was already taken. The earlier
  crates.io artifacts (the `0.0.1` stub and the `0.0.2` implementation, plus the yanked `0.1.x` line) are
  left as they are and are not maintained.
- Keep-alive idle pool bound set to 20 s, below intermediate gateway keep-alive cull boundaries (ADR-0005).
- `Client::send` retries transparently on a dead keep-alive socket when the drop occurs before response headers are received (ADR-0005).
- `HttpError::Incomplete` (socket closed mid-stream, potentially retryable) separated from malformed protocol violations (terminal) (ADR-0005).

### Fixed

- CI installs `cargo-nextest` via `taiki-e/install-action@nextest`; without it the test job fails on the missing subcommand.
