---
id: ADR-0029
title: "Harden the Owned QUIC Connection Lifecycle"
status: accepted
date: 2026-11-09
scope: [transport/quic, protocol/rfc9000, protocol/rfc9001, protocol/rfc9369, crypto/provider, recovery/congestion]
superseded_by: null
---

# 0029. Harden the Owned QUIC Connection Lifecycle

- Status: Accepted
- Date: 2026-11-09
- Deciders: Ming Li
- Amends: [ADR-0016](0016-quic-and-http3-transport.md), [ADR-0028](0028-owned-quic.md)
- Related: [ADR-0027](0027-owned-h3-qpack.md)

## Context

ADR-0028 made the owned QUIC engine the production path for handshake, streams,
ACK/RTT/PTO retransmission, flow control and RFC 9221 datagrams. That left the
connection lifecycle incomplete: a server could allocate state from an
unvalidated address, unknown connection IDs did not produce a stateless reset,
1-RTT keys never rotated, and there was no version negotiation or QUIC v2 path.
Fast loss detection and receive-window top-up were also missing.

These are not optional decorations. They decide whether the engine is safe to
expose to an untrusted network, whether long-lived connections can rotate keys,
and whether peer implementations can negotiate a version at all.

## Decision

### 1. Retry is the default server address-validation gate

- The server endpoint validates every fresh Initial through a stateless Retry
  token before allocating connection state.
- The token is an HMAC-SHA256 over version, peer IP/port, issuance time,
  original destination CID and Retry source CID. It is bound to the peer address
  and expires after 60 seconds.
- Retry packets use the fixed RFC 9001 integrity tag key/nonce for the selected
  version. The client verifies the tag against the original destination CID,
  re-derives Initial keys from the Retry source CID, includes the token, and
  restarts TLS with fresh transport parameters.
- The client validates the server's `retry_source_connection_id` and
  `original_destination_connection_id` transport parameters after a Retry.

### 2. Stateless reset is keyed by connection ID

- Every server endpoint owns a random reset key. The stateless reset token for
  a connection ID is HMAC-SHA256(reset key, CID) truncated to 16 bytes.
- The server advertises the token in its transport parameters. Unknown
  short-header datagrams of at least 21 bytes receive a reset whose last 16
  bytes authenticate the destination CID. Unknown long-header or too-short
  datagrams are dropped.
- A client treats a short packet that fails AEAD and whose final 16 bytes match
  the peer's advertised reset token as `ConnectionClosed`; it does not invent a
  different error.

### 3. Key update is a first-class 1-RTT state transition

- `rustls::quic::Secrets` from `KeyChange::OneRtt` is retained.
- The engine tracks the key phase, the next local/remote packet keys, and the
  previous remote packet key. Header-protection keys are not rotated.
- Receiving a packet that fails the current key tries the previous receive key
  (reordering) and then the next receive key. A successful next-key packet
  commits the update for both directions and retains the old receive key for
  in-flight packets.
- Sending may initiate an update explicitly or automatically after one million
  1-RTT packets.

### 4. Fast loss detection and receive-window top-up

- ACK processing marks packets older than `9/8 * srtt` and below the largest
  acknowledged packet as lost, retransmits their non-ACK frames, reduces the
  congestion window once per ACK event, and adjusts bytes-in-flight.
- Stream reads advance the connection and stream consumed counters. Crossing
  half the advertised window emits `MAX_DATA`/`MAX_STREAM_DATA` and raises the
  advertised limit.

### 5. Version negotiation and QUIC v2

- QUIC v1 and v2 long-header type mappings, Initial salts and Retry integrity
  tags are version-specific.
- A server that receives a long-header packet for an unsupported version sends
  Version Negotiation (v1, v2) without allocating connection state.
- A client that receives Version Negotiation ignores it if the current version
  is listed, otherwise restarts TLS and Initial keys using the first configured
  fallback version present in the offer.

## Invariants

- **`[INV-QUIC-10]` Retry Precedes State**: a Retry token is issued and verified
  before a server connection core exists. *Enforced by*: `validate_retry_token`
  on the endpoint path, `handle_retry` on the client, and Retry interop tests.
- **`[INV-QUIC-11]` Reset Tokens Are Keyed**: reset tokens are never random
  per packet; they are deterministic HMACs of the destination CID and the
  endpoint secret. *Enforced by*: `reset_token`, transport-parameter
  advertisement, and the unknown-CID reset test.
- **`[INV-QUIC-12]` Key Update Retains Reordering**: the previous receive key
  remains valid for one generation and header protection keys never rotate.
  *Enforced by*: `OneRttKeys`, `commit_key_update`, and the bidirectional key
  update test.
- **`[INV-QUIC-13]` No Unconfigured Downgrade**: Version Negotiation can select
  only a version in the client's configured list; a listed current version is
  not a downgrade signal. *Enforced by*: `handle_version_negotiation`.
- **`[INV-QUIC-14]` Migrate Only After Path Validation**: a source-address change
  starts PATH_CHALLENGE on the candidate path; the endpoint switches only after
  a matching PATH_RESPONSE, and drops the change when migration is disabled.
  *Enforced by*: `begin_path_validation`, `path_validated`, endpoint candidate
  routing, and the path-challenge unit tests.

## Consequences

- Servers no longer allocate per-connection state on spoofed Initials.
- Long-lived 1-RTT connections can rotate packet keys without changing header
  protection.
- Loss and receive flow control no longer depend on a lossless loopback.
- v2 and Version Negotiation are owned, not delegated to quinn.
- The default server path now performs a Retry round trip. That is intentional:
  the alternative is unauthenticated state allocation.

## Known gaps

Still deliberately absent and not implied by this ADR:

- 0-RTT and session resumption.
- Cubic/BBR congestion-control parity. Recovery is NewReno-style AIMD.
- H3 datagrams and extended CONNECT.
