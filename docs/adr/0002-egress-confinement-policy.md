---
id: ADR-0002
title: "Egress Confinement Policy and Public Network Boundary"
status: accepted
date: 2026-09-09
scope: [security/egress, transport/connect]
superseded_by: null
---

# 0002. Egress Confinement Policy and Public Network Boundary

- Status: Accepted
- Date: 2026-09-09
- Deciders: Ming Li

---

## Context and Problem Statement

When operating network clients driven by untrusted model outputs, user inputs, or web-browsing integrations, outgoing requests pose severe Server-Side Request Forgery (SSRF) and data exfiltration risks. Attackers can provide URLs pointing to loopback addresses (`127.0.0.1`), private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local services, or cloud instance metadata endpoints (`169.254.169.254` on AWS, GCP, Azure).

Standard HTTP clients blindly connect to any IP address returned by DNS. We need an owned, structurally enforced egress confinement policy that inspects resolved destination IPs before opening TCP sockets.

## Decision Drivers

- Absolute SSRF protection against private network pivoting and cloud metadata credential theft.
- Structural separation between unrestricted egress (for trusted endpoints/proxies) and strict public egress.
- Complete IP space coverage: IPv4, IPv6, mapped IPv4-in-IPv6 (`::ffff:0:0/96`), CGNAT (`100.64.0.0/10`), documentation/benchmarking ranges, and multicast/broadcast.
- Clean error typing: security rejections must be explicit (`NetError::Security`) rather than presenting as generic timeout or connection failures.

## Considered Options

- Option 1: URL string validation prior to dispatch.
- Option 2: Post-resolution socket confinement (`EgressConfinement::StrictPublic` and `is_public_ip`) directly in the connector.

## Decision Outcome

Chosen option: "Option 2: Post-resolution socket confinement in the connector".

Validating URLs before DNS resolution is vulnerable to DNS rebinding attacks (time-of-check to time-of-use flaw). `TcpConnector` validates every IP address returned by DNS immediately before `TcpStream::connect`.

### Invariants & Behavioral Boundaries

- **`[INV-EGRESS-01] Post-Resolution Validation`**: Confinement checks must execute on resolved `SocketAddr` IP literals immediately before socket establishment, eliminating DNS rebinding vulnerabilities.
- **`[INV-EGRESS-02] Zero-Tolerance Private Egress in Strict Mode`**: When `EgressConfinement::StrictPublic` is active, any resolved address falling into loopback, private RFC 1918, link-local, carrier-grade NAT, cloud metadata (`169.254.169.254`), or reserved ranges must immediately abort with `NetError::Security`.
- **`[INV-EGRESS-03] Non-Retryable Security Violations`**: Security rejections must be classified as non-retryable; attempts must not be repeated.

### Consequences

- **Positive**:
  - Hermetic protection against SSRF, internal port scanning, and cloud metadata theft.
  - Correct unwrapping of IPv4-mapped IPv6 literals (`::ffff:127.0.0.1`).
- **Negative & Trade-offs**:
  - Strict mode cannot connect to local mock servers or internal test fixtures. Mitigated by explicit `EgressConfinement::Unrestricted` configuration in integration test suites.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): URL Hostname String Matching

- **Why considered**: Simple regex/string check at request creation time without touching socket code.
- **Why rejected**: Vulnerable to DNS rebinding (domain resolves to public IP on first check, then to `169.254.169.254` upon socket connect). Also fails on decimal/octal/hex IP encodings and alternate loopback notations.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md), [ADR-0003](0003-workspace-decomposition-privilege-boundaries.md)
