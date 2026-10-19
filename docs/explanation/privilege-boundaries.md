# Structural Privilege Boundaries

This document explains why and how `netune` isolates network packet construction from frame transmission using compilation boundaries rather than runtime checks.

---

## The Principle of Least Privilege in Network Stacks

Long-running application processes, such as API daemons and agent harnesses, must never hold raw socket privileges (`CAP_NET_RAW` on Linux or root privileges). If a long-running service possesses raw packet transmission sockets, any remote code execution vulnerability or memory corruption bug can be leveraged to forge arbitrary packets across the local network segment.

Conversely, testing network failure modes, evaluating middlebox behaviors, and auditing TLS defenses requires forging custom TCP sequence numbers, crafting reset packets (`RST`), and simulating window starvation.

---

## The Compile-Time Boundary

To resolve this conflict, `netune-probe` splits packet construction from transmission at compile time:

```text
                 Default Build              --features inject + CAP_NET_RAW
                 (What Ships in Prod)       (Explicit Standalone Tool)
─────────────────────────────────────────────────────────────────────────────
Frame Parsing    ✅ Available (Pure)         ✅ Available (Pure)
Packet Forging   ✅ Available (Pure)         ✅ Available (Pure)
Socket Transmit  ❌ Not Compiled In          ✅ Compiled In (Direct Syscall)
```

### Pure Mathematical Construction
Methods like `netune_probe::packet::build_ethernet_ipv4_tcp` take a `FrameSpec` struct and return a `Vec<u8>`. They:
- Allocate nothing beyond the output byte buffer.
- Never open sockets, descriptors, or system handles.
- Can be tested completely offline in unprivileged continuous integration environments.

### Feature-Gated Socket Transmission
The method `Capture::send_frame` is placed behind `#[cfg(all(target_os = "linux", feature = "inject"))]`.
In standard builds without `--features inject`:
1. The transmit symbol does not exist in the compiled artifact.
2. The binary cannot transmit raw frames even if run as root or with `CAP_NET_RAW` set.

This makes privilege confinement an architectural property enforced by the Rust compiler, rather than a runtime flag that might accidentally be flipped in production.
