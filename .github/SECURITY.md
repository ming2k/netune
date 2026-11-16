# Security Policy

`netune` is a network stack, so a security defect can affect every connection a
consumer makes. Please report suspected vulnerabilities privately and give the
maintainers time to investigate before opening a public issue.

## Supported versions

Only the latest `0.0.x` release (the most recent annotated `v*` tag) is
supported. Older `0.0.x` tags are historical snapshots and do not receive
backports.

## Reporting a vulnerability

Use **GitHub Private Vulnerability Reporting** on this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include the affected version/tag, the platform, a minimal reproduction, and
   whether the issue requires `netune-probe --features inject` or elevated
   capabilities.

Do not open a public issue, discussion, or pull request for a suspected
vulnerability before a coordinated disclosure date is agreed.

If GitHub private reporting is unavailable, contact the maintainer listed in the
repository profile and use an encrypted channel if one is published there.

## Response targets

These are targets, not a warranty:

| Step | Target |
| :--- | :--- |
| Acknowledge receipt | 3 business days |
| Initial triage and severity | 10 business days |
| Critical/high fix or mitigation | 30 days |
| Coordinated disclosure | After a fix is available, by agreement |

## Scope

In scope:

- `netune` egress: DNS, TCP, TLS (owned and rustls paths), HTTP/1.1, HTTP/2,
  HTTP/3, WebSocket, proxies, pool, replay and redirect handling;
- `netune-server` ingress: HTTP/1.1, HTTP/2, optional HTTP/3, admission,
  framing, draining, TLS termination;
- wire codecs: `netune-http1`, `netune-http2`, `netune-http3`, `netune-ws`,
  `netune-quic`, `netune-webtransport`;
- `netune-tls`: handshake state machine, record layer, certificate validation,
  ClientHello construction, PSK/session handling, and FFI boundary;
- `netune-probe`: parsing, frame construction, capture, and the opt-in inject
  path;
- egress confinement and diagnostic redaction.

Out of scope:

- vulnerabilities that require modifying the process, the kernel, or a root
  certificate store before the attack;
- a peer deliberately violating a documented protocol limit after the client
  has already returned a typed error;
- denial of service caused solely by a caller disabling every bound
  (`request_timeout`, `response_head_timeout`, `body_idle_timeout`) or by
  setting an explicitly unbounded pool limit;
- the `mock` and `FaultIo` test helpers when used only in tests.

## Security model and current boundaries

- **Owned TLS is under a production-readiness gate.** `netune-tls` passes
  RFC vectors, differential tests, live loopback handshakes, and fuzz targets,
  but it has not yet completed an independent external audit. Consumers that
  require an audited TLS stack should use the rustls engine until that audit is
  published.
- **WebTransport is experimental.** `netune-webtransport` targets
  draft-ietf-webtrans-http3-17; browser interoperability and the reliable
  `RESET_STREAM_AT` path are not yet a production stability claim.
- **Defaults are bounded.** `response_head_timeout`, `body_idle_timeout` and
  `request_timeout` default to finite values; pool in-flight concurrency is
  bounded per authority and globally. Turning a bound off is an explicit
  opt-out and moves the corresponding availability risk to the caller.
- **Decoded bodies are budgeted incrementally.** A compressed chunk cannot
  expand past the configured decoded-body limit before the decoder returns an
  error.
- **Privilege boundary.** `netune-probe`'s transmit path exists only with
  `--features inject` and `CAP_NET_RAW`; the default artifact is receive-only.
- **Confinement precedes connect.** Outbound transports check
  `EgressConfinement` against every resolved address before opening a socket.

See [Stability and Production Boundaries](../docs/reference/stability.md) for
the support tiers and the exact feature/default matrix. The audit scope,
threat model and acceptance criteria are maintained for contributors under
`docs/dev/security/tls-audit.md`.
