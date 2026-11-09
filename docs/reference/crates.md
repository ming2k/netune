# Crates Reference

This document provides a factual overview of all crates comprising the `netune` workspace.

---

## Workspace Crates Overview

| Crate | Directory | Current Version | Primary Responsibility |
| :--- | :--- | :--- | :--- |
| `netune-trace` | `crates/netune-trace` | `0.0.10` | Zero-allocation trace ring buffer, pure timing derivations, JA3/JA4 TLS ClientHello parser |
| `netune-http1` | `crates/netune-http1` | `0.0.10` | HTTP/1.1 line protocol parser and serializer, differential-tested against `hyper` |
| `netune-http2` | `crates/netune-http2` | `0.0.10` | HTTP/2 wire protocol (RFC 9113) in both roles, HPACK header compression (RFC 7541), and Akamai fingerprint impersonation |
| `netune-ws` | `crates/netune-ws` | `0.0.10` | Pure RFC 6455 WebSocket codec: frame encoder/decoder, role-enforced masking, fragmented-message reassembly, SHA-1 handshake keys |
| `netune-io` | `crates/netune-io` | `0.0.10` | Byte-path transport adapters shared by both orchestrators: the `TimedIo` syscall tap and the `FaultIo` chaos twin. No socket, no policy |
| `netune-egress` | `crates/netune-egress` | `0.0.10` | Pure egress-address policy: `is_public_ip` and `EgressConfinement`, the single source of truth every outbound transport (TCP, UDP, QUIC) confines with. No I/O, no socket |
| `netune` | `crates/netune` | `0.0.10` | **Egress** orchestrator: DNS, TCP, TLS, **UDP datagrams**, pool, proxy (incl. SOCKS5 UDP associate), egress confinement, and client request orchestration |
| `netune-server` | `crates/netune-server` | `0.0.10` | **Ingress** orchestrator: TCP accept loop, admission control, slow-peer bounds, per-connection ingress tracing, graceful drain, HTTP/1.1 + HTTP/2 + optional HTTP/3 over one handler |
| `netune-quic` | `crates/netune-quic` | `0.0.10` | First-class QUIC transport (RFC 9000, RFC 9221) with `QuicProfile` handshake shaping, abstract socket stack, and unified `aws-lc-rs` crypto (`[INV-QUIC-01..04]`) |
| `netune-http3` | `crates/netune-http3` | `0.0.10` | Owned HTTP/3 client and server transport (RFC 9114), owned dynamic QPACK (RFC 9204), and typed SETTINGS profiles |
| `netune-probe` | `crates/netune-probe` | `0.0.10` | Pure L2 Ethernet/IPv4/TCP frame builder and opt-in wire injector |

---

## Crate Details

### `netune-trace`
- **Dependencies**: `serde`, `serde_json` (dev). No runtime networking or clock dependencies.
- **Key Types**:
  - `RequestTrace`: Envelope storing attempt identifiers, connection identity, fidelity, and event logs.
  - `EventLog`: Ring buffer supporting delta-encoded microsecond timestamps with loss tracking.
  - `TraceCollector`: the only public cold-path handle; control/protocol marks go here, never byte events.
  - `Tap` / `NoTap` / `Counters` / `Ring`: the typed byte-path observation strategy owned by `TimedIo`/`RingIo`; `TapLog` is the only artifact that can be merged into a collector ([ADR-0017](../adr/0017-tiered-observation-and-connection-identity.md), [ADR-0018](../adr/0018-one-trace-collector-per-attempt.md)).
  - `DerivedTimings`: Pure derived metrics (`connect_us`, `tcp_us`, `tls_us`, `ttfb_us`, `stream_us`, `e2e_us`).
  - `TraceSink`: optional per-event stream, for a consumer that needs more than the bounded ring window (a long-lived relay); the ring stays the record of truth for the attempt ([ADR-0010](../adr/0010-quic-ownership-and-trace-sink.md)).
  - `ja4::ja4`: Computes JA4 TLS fingerprint from raw ClientHello bytes.

### `netune-http1`
- **Dependencies**: `bytes`, `http`, `tokio` (io-util). `hyper` is strictly a `dev-dependency`, used as a differential oracle **in both directions**.
- **Key Types**:
  - `RequestHead` / `ResponseHead`: the heads a role **builds** — method/target plus raw wire headers, and status plus a caller-chosen `ReasonPhrase` and declared body framing.
  - `IncomingRequest` / `IncomingResponse`: the heads a role **receives** — including the version the peer actually spoke and the request target preserved as raw bytes.
  - `Http1Reader`: response-direction reader (client role). `Http1ServerReader`: request-direction reader (server role). Both sit on one private `StreamState`, so chunked decoding exists once ([INV-SERVER-04](../adr/0011-server-side-ingress-transport.md)).
  - `Limits`: `Content-Length`/chunked bounds with tighten-by-default `for_ingress()` values for a listener.
  - `write_request`: request serialization (client role). A request is always self-delimiting, and a target a server would reject is refused before a byte is written.
  - `ResponseWriter`: response serialization (server role) as a state machine — `start` takes the request *method* so it can lock out a body under `HEAD`/`1xx`/`204`/`304`/`CONNECT`-2xx, `write` refuses a body past the declared length, `finish` refuses a short one ([INV-SERVER-12](../adr/0013-response-writer-state-machine.md)).
  - `write_interim`: `1xx` heads (`100 Continue`, `103 Early Hints`) that precede a final response.
  - `TargetForm` / `classify_target` / `validate_host_field`: the RFC 9112 §3.2 target grammar and the `Host` grammar it is compared against ([INV-SERVER-14](../adr/0014-request-validation-before-dispatch.md)).

### `netune-io`
- **Dependencies**: `netune-trace`, `tokio` (io-util, rt, time). No socket, no policy, no clock of its own.
- **Key Types**:
  - `TimedIo`: `AsyncRead`/`AsyncWrite` wrapper owning a typed `Tap` (`NoTap`/`Counters`/`Ring`); the tap's artifact is merged into a `TraceCollector` on the cold path.
  - `FaultIo` / `FaultScript` / `Fault`: scripted delays, splits, truncations and resets, recorded nowhere by design.
- **Why a crate**: both orchestrators need the identical tap, and neither may depend on the other ([ADR-0011](../adr/0011-server-side-ingress-transport.md)). `netune` re-exports both, so its surface is unchanged.

### `netune-egress`
- **Dependencies**: none. Pure `std::net::IpAddr` arithmetic; no I/O, no clock, no runtime.
- **Key Types**:
  - `is_public_ip`: true only for globally-routable addresses — rejects loopback, RFC 1918 private, link-local, cloud metadata (`169.254.169.254`), carrier-grade NAT (`100.64/10`), documentation/benchmark, reserved, and IPv4-mapped IPv6 forms.
  - `EgressConfinement`: `Unrestricted` (default) or `StrictPublic`, with `check(ip)` as the one call site every transport uses.
- **Why a crate**: `netune`'s TCP connector, `netune`'s datagram sessions, and `netune-quic`'s QUIC connector must refuse the same address classes. `netune-quic` may not depend on the egress orchestrator ([ARCH-003]/[ADR-0003](../adr/0003-workspace-decomposition-privilege-boundaries.md)), so the predicate lives here — one definition, no copies to drift ([INV-EGRESS-01](../adr/0002-egress-confinement-policy.md), [INV-QUIC-02](../adr/0016-quic-and-http3-transport.md)).

### `netune-http2`
- **Dependencies**: `bytes`, `http`, `tokio` (io-util, sync, time). No third-party HTTP/2 or HPACK implementation.
- **Key Types**:
  - `H2Connection` / `Role`: the direction-agnostic connection machine — frame reading bounded by the *local* advertised maximum, SETTINGS exchange and acknowledgement, PING echo, GOAWAY bookkeeping, HPACK table, `CONTINUATION` contiguity, and both flow-control windows. `Role` is a field, not a second module ([INV-SERVER-08](../adr/0012-http2-ingress.md)).
  - `client::H2ClientConnection`: the client role — preface, odd stream ids, fingerprinted SETTINGS and pseudo-header order.
  - `server::ServerSession` / `H2Handler` / `H2Request` / `SessionObserver`: the server role — stream table, `REFUSED_STREAM` shedding, credit replenished on handler consumption, one writer task, and a wake-up channel so a finished handler is written without waiting for the peer to speak ([INV-SERVER-11](../adr/0012-http2-ingress.md)).
  - `HpackEncoder` / `HpackDecoder`: RFC 7541 static and dynamic tables plus the 257-symbol Huffman coder.
  - `H2ConnectionProfile`: initial SETTINGS order/values, connection window, HPACK table size and priority-frame policy; this half keys the pool.
  - `H2RequestProfile`: pseudo-header order; applied per `HEADERS` block and not part of connection identity. `H2RequestRegistry` resolves custom request profiles independently.
  - `H2Fingerprint`: a preset pairing of the two halves; use `.connection` or `.request` when the lifetime matters.
  - `H2ClientConnection`: stores the halves separately; `start_request` reads only the request half ([ADR-0020](../adr/0020-split-multiplexed-profiles.md)).
- **Distribution**: consumed from this repository by git tag; the version is inherited from the workspace.

### `netune-ws`
- **Dependencies**: `bytes`, `base64`, `http`. No I/O runtime; purely synchronous wire math.
- **Key Types**:
  - `Frame` / `Opcode` / `CloseCode`: RFC 6455 §5.2 wire vocabulary.
  - `FrameDecoder` / `FrameEncoder`: Stateless codec pair; the decoder enforces role-correct masking ([ADR-0007](../adr/0007-owned-client-websocket-codec.md)).
  - `MessageAssembler`: Fragmented-message reassembly with interleaved control frames and bounded message size.
  - `compute_accept_key` / `verify_handshake`: Self-contained SHA-1 handshake digest (RFC 6455 §1.3).
- **Role Boundary**: The codec understands both endpoint roles for testability, but server transport code exists nowhere in the workspace ([INV-WS-01]).

### `netune`
- **Key Types**:
  - `Client`: Drives the request lifecycle, redirect handling, and response body streaming.
  - `Client::connect_ws` / `WsStream`: RFC 6455 client upgrade over the owned transport, with automatic pong and close-handshake completion ([ADR-0007](../adr/0007-owned-client-websocket-codec.md)).
  - `WsSession` / `WsSessionConfig`: Client-driven heartbeat liveness (ping interval + pong deadline) for long-lived WebSocket sessions; automatic reconnection is deliberately excluded as harness policy.
  - `Pool` / `PoolKey`: Connection reuse keyed on `(authority, ConnectionIdentity)` with a 20 s idle timeout. The typed key makes an omitted identity axis a compile error, not a cache bug.
  - `ConnectionPlan` / `ProfileId`: every TLS/H1/H2 name resolves through `Client::plan` before a socket is opened; unknown profiles fail loudly ([ADR-0019](../adr/0019-connection-plan-and-wire-profile-registry.md)).
  - `H1WireProfile` / `H1Registry`: declarative HTTP/1 header order and casing, applied per request (not part of the pool key).
  - `H2Registry`: built-in and caller-supplied HTTP/2 fingerprints, resolved independently of the TLS-name match.
  - `TlsProfile` & `TlsRouterConnector`: Configures and lazily compiles TLS identities.
  - `FaultIo`: In-process fault injection engine.
  - `DnsResolver` & `StaticResolver`: Asynchronous, mockable DNS resolution.
  - `SocketConfig`: L3/L4 transport tuning — TTL, buffer sizing, MSS, `SO_MARK`,
    `SO_BINDTODEVICE`, a bound source address, TCP keepalive, `IP_TOS`/`IPV6_TCLASS`,
    and `TCP_FASTOPEN_CONNECT`. Every pre-connect option forces the manual-socket path
    (`needs_manual_socket`), so none of them can be silently skipped
    ([ADR-0010](../adr/0010-quic-ownership-and-trace-sink.md), `INV-SOCKET-01`).
    Applies to both TCP and datagram sockets.
  - `SegmentingIo`: Early flight wire segmentation for SNI middlebox evasion.
  - `DatagramConnector` / `DatagramTransport`: Per-peer datagram sessions whose
    peer is fixed at open time, so egress confinement precedes the socket
    ([ADR-0008](../adr/0008-datagram-transport-and-socks5-udp-association.md)).
  - `UdpConnector`: The datagram twin of `TcpConnector` — same resolver,
    confinement and `SocketConfig`, with `SO_MARK` before `connect`.
  - `Socks5DatagramConnector`: SOCKS5 UDP associate; destinations are literal IP
    addresses, foreign-source datagrams are dropped, fragments are refused.
  - **Not implemented, by decision**: REALITY client authentication. It needs a
    caller-chosen `legacy_session_id` and a CA-bypassing verifier, neither of
    which `rustls` 0.23 exposes; see
    [ADR-0009](../adr/0009-reality-client-authentication-not-a-netune-capability.md).

### `netune-server`
- **Dependencies**: `netune-http1`, `netune-http2`, `netune-trace`, `netune-io`, `bytes`, `http`, `tokio`; with `http3`, also `netune-http3`, `netune-quic` and `rustls`. It depends on no egress crate ([INV-SERVER-01](../adr/0011-server-side-ingress-transport.md)). `netune` appears as a `dev-dependency` only, for the interop suite.
- **Key Types**:
  - `Server`: a bound listener. `Server::bind` validates configuration *before* taking a port; `serve` accepts until shutdown, then drains in-flight exchanges up to `drain_timeout`.
  - `ServerConfig`: codec limits, `max_connections` (shedding, never an unbounded queue), `max_requests_per_connection` (keep-alive is not forever), separate `head_timeout`/`body_timeout`/`handler_timeout`/`write_timeout`, `require_host`, `expect_continue`, `protocols`, `http2` bounds, and an optional `trace_sink` ([ADR-0010](../adr/0010-quic-ownership-and-trace-sink.md)).
  - `Protocols`: which of HTTP/1.1 and HTTP/2 the TCP listener offers, and `Protocols::alpn()` — the list a TLS terminator in front should offer, in preference order.
  - `H3Server`: a separate QUIC listener behind the `http3` feature, with the same handler, admission, timeout, body-ceiling and drain configuration; it forces ALPN `h3` and records `ServedProtocol::Http3` at L0 ([ADR-0025](../adr/0025-h3-ingress-peer-transport.md)).
  - `H2Ingress`: the HTTP/2 bounds that are also the SETTINGS the peer is told (`max_concurrent_streams`, `initial_window_size`, `connection_window_size`, `max_frame_size`, `header_table_size`, `max_header_list_size`).
  - `Handler` / `HandlerFuture` / `Response` / `ResponseBody` / `BodyStream`: the single application boundary, serving both protocols. No routing, no extractors, no middleware.
  - `TraceObserver` / `IngressTrace` / `ServedProtocol`: every finished connection's complete trace, tagged with the protocol that served it and with each event carrying its stream identity. `SinkObserver` bridges to an existing `netune_trace::TraceSink`; `CollectingObserver` keeps everything.
  - `RequestBody`: a borrow of the connection's decoder, so a handler can read exactly its body and never the next request's bytes, with `read_to_end_within` for an application-level ceiling.
- **Not a framework**: it is a transport. Routing, deserialization and authorization belong above it.
- **Features**: `http2` (default), `tls` (off by default), and `http3` (off by default; implies `tls`).
  Each compiles out its codec entirely when off; asking for a protocol the build cannot serve fails at
  bind time, and HTTP/3 is a separate `H3Server` rather than a `Protocols` mode.
- **TLS**: `TlsTermination` (`single` / `per_name`) terminates TLS inside the connection pipeline,
  selects the configuration from the SNI name, lets ALPN decide the protocol, and records the handshake as
  `IngressTlsEnd` or an `ERROR_TLS_HANDSHAKE` error ([ADR-0015](../adr/0015-self-terminated-tls.md)).
- **Not implemented, by decision**: WebSocket upgrade serving is a separate, later decision ([ADR-0011](../adr/0011-server-side-ingress-transport.md)); client certificates and resumption tuning belong to the deployment's `rustls::ServerConfig`.

### `netune-quic`
- **Dependencies**: `netune-egress`, `netune-trace`, `bytes`, `rustls`, `rustls-platform-verifier`, `socket2`, `thiserror`, `tokio`. Compiles strictly against `aws-lc-rs` (`[INV-QUIC-01]`). Dev-only oracles: `quinn`.
- **Owned H3 extensions (ADR-0030)**: SETTINGS-gated RFC 9297 datagrams routed by Quarter Stream ID, and RFC 9220 extended CONNECT through `ExtendedConnectProtocol`.
- **Owned QUIC engine (ADR-0028)**: `wire` owns the packet/frame/transport-parameter codec, `crypto` owns rustls packet protection and TLS key changes, and `owned::{core,endpoint}` owns handshake, stream, ACK, flow-control, UDP routing and async handles. `quinn` is dev-only.
- **Key Types**:
  - `QuicConnector`: Coordinates egress confinement (`with_confinement` / `strict_public`), manual socket pre-configuration, and QUIC client endpoint creation. Confinement is checked on the resolved address **before** the UDP socket is created ([INV-QUIC-02](../adr/0016-quic-and-http3-transport.md)).
  - `QuicConnection`: Established or handshaking QUIC session with bidirectional/unidirectional stream allocation, `connect_early`, `early_data_available`, `early_data_accepted` and `wait_established`.
  - `SessionCache`: authenticated peer transport parameters used for 0-RTT stream limits.
  - `QuicProfile` / `QuicTransportParameters`: Explicit declarative control over QUIC transport parameters, ALPN and congestion policy (NewReno/Cubic/BBR). Retry/address validation, keyed stateless reset, 1-RTT key update, QUIC v2 and Version Negotiation are owned (ADR-0029). Migration uses PATH_CHALLENGE/PATH_RESPONSE. RFC 9297 datagrams and RFC 9220 extended CONNECT are owned (ADR-0030). Session resumption and 0-RTT use a transport-parameter cache, stateful single-use tickets, early-frame replay and early H3 requests (ADR-0031).
  - `QuicProfileRegistry`: one resolution path for built-in and caller-supplied profiles; `QuicConnector::from_registry` fails loudly on unknown names ([ADR-0021](../adr/0021-named-quic-profiles.md)).
  - `QuicDatagramSession`: RFC 9221 unreliable datagram session with MTU bound checks (`[INV-QUIC-04]`).
  - `QuicSocketConfig`: L3/L4 socket options applied before the first packet ([INV-SOCKET-01]).

### `netune-http3`
- **Dependencies**: `netune-quic`, `netune-trace`, `bytes`, `http`, `thiserror`, `tokio`. Dev-only interop oracles: `h3`, `h3-quinn`, `quinn` (never linked into the shipping crate).
- **Key Types**:
  - `H3Client`: Dispatches RFC 9114 HTTP/3 requests over `netune-quic` connections. `open_request` returns a streaming `H3RequestBody`; `send` composes it; `execute` buffers with a configured body ceiling ([ADR-0024](../adr/0024-h3-streaming-request-bodies.md)).
  - `H3Client::connect` / `connect_with_config`: resolves a `QuicConnector` profile, retains the `QuicConnection` (and endpoint) for the H3 driver's lifetime, and exposes `quic_profile()` as the connection identity ([ADR-0022](../adr/0022-http3-connection-identity.md)).
  - `H3ClientConfig`: request/response-head/body-chunk deadlines and `max_body_bytes`.
  - `H3SettingsProfile` / `H3SettingsRegistry`: typed, validated SETTINGS (QPACK capacity/blocked streams, max field section, grease). `H3SettingsProfile::dynamic()` opts into dynamic QPACK; the default is stateless ([ADR-0027](../adr/0027-owned-h3-qpack.md)).
  - `H3ServerConnection` / `H3ServerRequest` / `H3ServerStream`: the server-side adapter over the owned H3 state machine, kept in this leaf so `netune-server` does not import a third-party H3 runtime.
  - `H3TraceContext` / `H3ResponseStream::trace` / `H3Response.trace`: per-exchange `RequestTrace` with `Fidelity::l0()`, the resolved QUIC profile as `identity.h3_profile`, and the SETTINGS profile as `identity.h3_settings_profile`.
  - `H3RequestProfile` / `H3RequestRegistry`: named pseudo-header and regular-header order, applied by the owned QPACK encoder before field lines are emitted ([ADR-0027](../adr/0027-owned-h3-qpack.md)).
  - `H3RequestBody`: chunked upload, trailers, and transition to `H3ResponseStream`.
  - Dynamic QPACK: request/response head and trailer blocks use the owned encoder/decoder, acknowledge decoded sections, and wait for missing insertions. The encoder references a dynamic entry only after acknowledgement; the decoder enforces the advertised capacity and blocked-stream budget.
  - Request/response lifecycle with deterministic timing derivation in `netune-trace` (`[INV-QUIC-03]`).

### `netune-probe`
- **Privilege Separation**:
  - Default build: Pure frame parsing (`parse_ethernet_ipv4_tcp`) and construction (`build_ethernet_ipv4_tcp`).
  - `--features inject`: Compiles socket transmit path (`Capture::send_frame`), requiring Linux `CAP_NET_RAW`.
