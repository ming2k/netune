# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  origin. Neither advertises `reset_stream_at`, so the browser half of
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
