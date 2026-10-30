# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
