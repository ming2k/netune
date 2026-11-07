# netune Documentation

`netune` is an owned, observable, intervention-capable network transport
substrate for Rust, spanning both client-side egress and server-side ingress.
Start with the [README](../README.md) for the project overview and the shortest
run path.

## Sections

| Section | Purpose |
| :--- | :--- |
| [Tutorials](tutorials/index.md) | Learning-oriented step-by-step walkthroughs |
| [How-to guides](how-to/index.md) | Task-oriented recipes for daily transport operations |
| [Explanation](explanation/index.md) | Architecture and conceptual background |
| [Reference](reference/index.md) | Crate responsibilities, architecture reference, and API contracts |
| [Architecture Decision Records](adr/index.md) | Durable architectural decisions |
| [Contributor docs](dev/index.md) | Setup, testing, architecture, invariants, and engineering standards |

## Orientation

- First-time walkthrough: read [Getting Started](tutorials/getting-started.md).
- Architectural mental model: read [Two Orchestrators](explanation/two-orchestrators.md) and [Privilege Boundaries](explanation/privilege-boundaries.md).
- Looking for crate roles and topology: read [Crates Reference](reference/crates.md) and [Architecture Reference](reference/architecture.md).
- Configuring proxies (HTTP CONNECT, SOCKS5, auth): read [Configure Proxies](how-to/configure-proxies.md).
- Managing TLS fingerprint profiles: read [Configure TLS Profiles](how-to/configure-tls-profiles.md).
- Serving HTTP/1.1 and HTTP/2 ingress: read [Serve HTTP](how-to/serve-http.md).
- Establishing WebSocket client sessions: read [WebSocket Client](how-to/websocket-client.md).
- Simulating transport failures and chaos: read [Fault Injection](how-to/fault-injection.md).
- Setting up a development environment: read [Setup](dev/setup.md).
- Running tests and determinism rules: read [Testing Guide](dev/testing.md).
- Workspace topology and structural red-lines: read [Architecture Governance](dev/architecture.md).
- System invariants and constraint admissibility: read [Invariants Governance](dev/invariants.md).
- Pull request verification gates and hygiene: read [Workflows & Gates](dev/workflow.md).
- Looking for why a choice was made: scan the [ADR Index](adr/index.md).
- Engineering meta-standards: read [Engineering Standards](dev/standards/README.md).
