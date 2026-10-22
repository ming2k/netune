# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
