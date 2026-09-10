# netune

An owned, observable, and *intervention-capable* network stack in Rust.

netune owns every layer from DNS to the HTTP/1.1 message — no third-party HTTP
implementation in the production dependency graph — and makes the transport
itself an object you can inspect, fingerprint, and change:

| Crate | What it is |
|---|---|
| [`netune-trace`] | The trace model and pure derivations. Every timing a surface shows is a pure function of a recorded trace. Also: TLS ClientHello parsing and JA3/JA4 fingerprints. |
| [`netune-http1`] | The HTTP/1.1 codec. Differential-tested against hyper (dev-dependency only) over recorded byte streams. |
| [`netune`] | The transport: DNS, TCP, TLS (rustls), the syscall tap, connection pool, proxies, redirects, decompression — and `FaultIo`, the chaos twin that injects delays, splits, truncations, and resets. |
| [`netune-probe`] | The L2 probe: pure Ethernet/IPv4/TCP parse **and build** (forge) plus an opt-in `inject` feature for frame transmission. |

## Capability surface

**Observe** — a three-level tap with graceful degradation:

- **L0** protocol events, portable, always on
- **L1** syscall boundaries + `TCP_INFO` sampling (RTT, retransmits, cwnd)
- **L2** per-segment capture (Linux, `CAP_NET_RAW`, opt-in)

**Fingerprint** — see your own TLS identity: `netune-trace::ja4` parses a
ClientHello and computes the JA4 fingerprint, cross-tool anchored against
FoxIO's published vectors. `netune`'s test suite snapshots the fingerprint the
shipped configuration presents, so a dependency bump that changes our visible
TLS identity is a reviewed diff, not a silent drift.

**Intervene** — change behaviour, at two privilege levels:

- **In-process, zero privileges** (`netune::FaultIo`): script delays, split
  reads, truncations, and connection resets against any stream. How does the
  retry classifier, the timeout policy, the streaming pipeline behave when the
  transport is hostile? Ask it directly, hermetically.
- **On the wire, feature-gated** (`netune-probe` with `--features inject`):
  build arbitrary TCP frames (forged seq/ack, RSTs, window games) with pure,
  fully tested functions; transmit them only when the feature is compiled in
  *and* `CAP_NET_RAW` is held. The default build has no transmit path at all.

## The privilege boundary is structural

```
                 default build      --features inject + CAP_NET_RAW
parse/build      ✅ present         ✅ present        (pure, tested)
transmit         ❌ not compiled    ✅ present        (socket)
```

Injection changes the network rather than measuring it; it is never a default
capability of anything long-running.

## Status

Pre-1.0, lockstep-versioned (all four crates share one version). The
fingerprint and forge surfaces are young and moving; the HTTP/1.1 codec and
the trace model are stable and differential/property tested.

MSRV: 1.95. License: MIT.

[`netune-trace`]: crates/netune-trace
[`netune-http1`]: crates/netune-http1
[`netune`]: crates/netune
[`netune-probe`]: crates/netune-probe
