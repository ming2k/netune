---
id: ADR-0043
title: "Consumer Seams for Raw ALPN, QUIC Authority Resolution, and Head-Only HTTP"
status: accepted
date: 2026-11-12
scope: [transport/tls, transport/quic, protocol/http1, api/egress, observability]
superseded_by: null
---

# 0043. Consumer Seams for Raw ALPN, QUIC Authority Resolution, and Head-Only HTTP

- Status: Accepted
- Date: 2026-11-12
- Deciders: Ming Li
- Amends: [ADR-0006](0006-dns-resolution.md), [ADR-0001](0001-http1-ownership.md)

---

## Context and Problem Statement

Three consumer-visible seams were missing from the public surface:

1. `Established.alpn` is a trace enum (`Unknown`, `Http11`, `H2`). A proxy protocol may negotiate
   a private ALPN name, and a consumer could not recover the exact wire value.
2. `QuicConnector::connect` takes a `SocketAddr`. A consumer had to resolve outside the connector,
   so the DNS phase was absent from the QUIC attempt trace and confinement could only be checked
   after resolution.
3. `write_request` always synthesizes `Content-Length` and the WebSocket client adds
   `User-Agent`/`Content-Length`. A proxy node's WebSocket upgrade is a fingerprint; the caller
   needs an exact header set/order with no synthetic fields.

## Decision

### 1. `Established` carries the raw ALPN name

`Established` gains `alpn_protocol: Option<Vec<u8>>`, the exact name rustls selected. The existing
`alpn` enum remains the trace classification, so trace consumers are unchanged. `None` means no
TLS handshake or no ALPN selected.

### 2. QUIC resolves an authority inside the connector

`netune-quic` gains a leaf resolver trait:

```rust
trait QuicResolver {
    fn resolve(&self, host: &str, port: u16) -> Future<Output = Result<Vec<SocketAddr>, QuicError>>;
}
```

`SystemQuicResolver` is the default. `QuicConnector::with_resolver` injects a policy-specific
resolver, and `connect_authority` brackets `DnsStart`/`DnsEnd`, applies `EgressConfinement` to every
resolved address, then calls the existing socket path. `connect(SocketAddr, …)` remains for callers
that already hold a checked address.

### 3. HTTP/1.1 has a head-only writer

`netune-http1` exports `write_request_head`, which serializes the request line and the caller's exact
headers, then the terminating blank line, and inserts no `Content-Length`, `User-Agent` or other
field. `write_request` keeps its self-delimiting behavior for ordinary request bodies. WebSocket
upgrades use the head-only writer, so the codec owns framing while the caller owns the fingerprint.

## Consequences

- A proxy protocol can report a private ALPN name without changing the trace enum.
- A QUIC attempt has one trace with DNS and handshake phases; no caller resolves outside the
  connector unless it deliberately uses the `SocketAddr` entry point.
- WebSocket upgrades are serialized by netune-http1 with exact headers; the daer-side HTTP request
  serializer is deleted.
- Adding a field to `Established` is a breaking change for external struct literals; the workspace
  is at `0.0.x`, where every patch is already breaking.
