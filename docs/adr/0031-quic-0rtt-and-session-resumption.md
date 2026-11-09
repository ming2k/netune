---
id: ADR-0031
title: "Own QUIC 0-RTT and Session Resumption"
status: accepted
date: 2026-11-09
scope: [transport/quic, protocol/rfc9001, crypto/provider, api/http3, security/replay]
superseded_by: null
---

# 0031. Own QUIC 0-RTT and Session Resumption

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0028](0028-owned-quic.md), [ADR-0029](0029-quic-lifecycle-hardening.md), [ADR-0030](0030-h3-datagrams-and-extended-connect.md)
- Related: [ADR-0016](0016-quic-and-http3-transport.md), [ADR-0027](0027-owned-h3-qpack.md)

---

## Context

The owned QUIC engine could resume TLS sessions through rustls, but it had no
QUIC transport-parameter cache, no 0-RTT packet path, and no early-stream API.
H3 therefore always waited for the handshake. A correct 0-RTT implementation
needs more than early keys: the client must remember peer stream limits from an
authenticated session, the server must make tickets single-use to reject
replays, and early stream data must be replayed after rejection.

## Decision

### 1. Two caches, one authenticated session

- **TLS tickets** stay owned by rustls' client resumption store. The connector
  keeps one `Arc<rustls::ClientConfig>` so the store survives reconnects.
- **QUIC transport parameters** are stored in `SessionCache`, keyed by the
  authenticated server name. The cache stores the complete peer
  `TransportParameters` after a completed handshake.
- A client may use 0-RTT only when both the TLS early keys and the cached
  transport parameters exist. No remembered limits means no early streams.

### 2. Stateful, single-use server tickets

- `ServerConfigOwned::enable_early_data` configures the server with
  `max_early_data_size = u32::MAX` and a stateful
  `ServerSessionMemoryCache`. The default stateless ticketer stays disabled.
- rustls takes the session value out of the stateful store when accepting a
  resumed handshake. A replayed ticket therefore cannot be resumed or used for
  0-RTT again.
- The server validates ticket freshness, ALPN, cipher suite and TLS version
  before exposing early keys.

### 3. 0-RTT packet path

- 0-RTT packets use `LongType::ZeroRtt`, early keys from
  `TlsSession::zero_rtt_keys`, and the application packet-number space shared
  with 1-RTT.
- The client emits only STREAM, DATAGRAM, PING, PADDING and flow-control
  updates in 0-RTT. ACK/CRYPTO and connection-lifecycle frames are rejected in
  the early frame path.
- The server records early packet numbers in the application space and ACKs
  them once 1-RTT keys are installed.
- Early frames are retained. If the handshake reports that early data was
  accepted, they are discarded after handshake completion; if it was rejected,
  the same frames are moved to the 1-RTT retransmission queue. STREAM offsets
  make the replay idempotent.
- Retry and Version Negotiation reset early stream send offsets and resend the
  retained early frames under the new DCID/version.

### 4. Public early API

- `Endpoint::connect_early` and `QuicConnector::connect_early` start the
  handshake without waiting.
- `Connection::early_data_available`, `early_data_accepted` and
  `wait_established` expose the state transition.
- `H3Client::connect_early` starts H3 before the QUIC handshake. If no early
  session is available it waits for establishment. Early H3 headers, SETTINGS
  and requests use the same 0-RTT frame retention/replay path.
- `H3Client::wait_handshake` and `H3Client::early_data_accepted` expose the
  final decision.

## Invariants

- **`[INV-QUIC-16]` Early Data Requires Remembered Parameters**: no 0-RTT stream
  is opened without both TLS early keys and an authenticated cached peer
  transport-parameter set. *Enforced by*: `Core::early_data_available`,
  `SessionCache`, and the resumed-session tests.
- **`[INV-QUIC-17]` Server Tickets Are Single-Use**: the server enables early
  data only with stateful resumption storage; stateless-ticket replay cannot
  produce a second early-data acceptance. *Enforced by*:
  `ServerConfigOwned::enable_early_data` and rustls' session-storage take.
- **`[INV-H3-12]` Early H3 Requests Are Replayable**: early H3 stream frames are
  retained until the handshake decision; rejected early data is replayed in
  1-RTT rather than silently lost. *Enforced by*: `Core::early_frames`,
  `update_established`, and the H3 resumed-session test.

## Consequences

- A resumed H3 session can send a request before the QUIC handshake completes.
- A server that does not enable early data remains safe: the client falls back
  to waiting, and a rejected 0-RTT attempt is retried in 1-RTT.
- The server's stateful session cache is bounded by its configured capacity; it
  is a replay store, not an unbounded ticket database.
- 0-RTT remains subject to application replay semantics; HTTP/3 methods with
  side effects must still be idempotent or protected by an application replay
  key. The transport does not invent idempotence.

## Known gaps

None at the transport level. WebTransport session semantics remain outside this
ADR; generic capsules are owned by ADR-0032.
