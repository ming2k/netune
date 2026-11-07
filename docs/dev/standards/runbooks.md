# Subsystem Runbook & Playbook Standards

This document establishes the standards for authoring, structuring, and
maintaining subsystem runbooks and diagnostic playbooks under `docs/dev/runbooks/`.

---

## 1. Scope & Intent

A **Runbook** is an operational and hands-on guide for complex network
subsystems, protocol stacks, raw packet injection, or external network
environments (such as raw Ethernet capture in `netune-probe`, TLS fingerprint
presets, SOCKS5 UDP association, connection pool socket culling, or HTTP/2
multiplexed flow control).

It captures hard-won operational know-how that cannot be fully expressed in
compiler types or automated tests alone—such as middlebox RST injection, MTU
blackholes, proxy authentication quirks, packet inspection filters with
`tcpdump`/`tshark`, and A/B diagnostic procedures.

### Boundary Matrix

| Document Class | Purpose | What It Contains | Location |
| :--- | :--- | :--- | :--- |
| **Explanation** | Conceptual understanding | High-level architecture, protocol state machines, timing and trace models. | `docs/explanation/` |
| **ADR** | Decision contracts | Why a protocol architecture or design boundary was chosen, rejected alternatives, trade-offs. | `docs/adr/` |
| **Runbook** | Operational execution | Wire quirks registries, diagnostic commands, packet capture recipes, A/B isolation steps. | `docs/dev/runbooks/` |
| **Postmortem** | Failure retrospective | Blameless timeline and defense-in-depth analysis of major transport or session failures. | `docs/dev/postmortems/` |

---

## 2. Anti-Patterns & Prohibitions

1. **No Ephemeral Task Handoffs**:
   A runbook is a durable operational manual, not a scratchpad for incomplete
   tasks. Ephemeral sprint notes (e.g., "local build flag workaround", "temporary
   mock server bug") must be resolved before merging, never recorded in a runbook.
2. **No Pure Rationale**:
   Design rationale belongs in ADRs. If a runbook explains *why* a protocol design
   was chosen over another, summarize it in one sentence and link to the governing
   ADR.
3. **No Unactionable Checklists**:
   Every item in a "Do-Not-Regress Checklist" must state a concrete verification
   method (e.g., a specific `cargo nextest` command, packet filter, or trace assertion).

---

## 3. Standard Runbook Structure

Every subsystem runbook under `docs/dev/runbooks/` must follow this structure:

### 1. Target Subsystem & Reference Environment
- Kernel, socket, and privilege baselines (e.g. `CAP_NET_RAW` for `netune-probe`, SO_BINDTODEVICE requirements).
- External tools and network topologies required (e.g. `tcpdump`, `tshark`, loopback mock servers, upstream proxies).
- Active feature gates (e.g. `--features inject`).

### 2. Core Protocol Rules & Invariants
- Summary of non-negotiable operational invariants (e.g. confinement checks before connect, no pooling of WebSocket sockets, unidirectional orchestrator constraints).
- Pointers to governing ADRs and architecture specifications.

### 3. Wire / Middlebox / Vendor Quirks Registry
- Known behaviors, anomalies, and edge cases of specific middleboxes, TLS endpoints, HTTP/2 peers, or proxy daemons.
- Concrete defensive mechanisms or byte-level mitigations implemented in code.

### 4. Diagnostic Playbook & Verification Recipes
- Step-by-step commands to reproduce, inspect, and verify transport behavior.
- Local mock/loopback recipes (no external network required).
- Packet capture filters and trace event inspection recipes (`TraceSink`, `EventLog`).
- Fast failure classification (symptom -> root cause -> verified fix).

### 5. Do-Not-Regress Checklist
- Explicit, verifiable checks that must pass before delivering changes to the subsystem.

---

## 4. Lifecycle & Maintenance

- **Active Maintenance (HOT)**: Runbooks must be updated in the same change that
  modifies a subsystem's operational behavior or discovers a new wire anomaly.
- **Mechanisms First**: Whenever a manual check in a runbook can be automated
  via a unit test, oracle differential test, `FaultIo` simulation, or CI assert,
  automate it and reduce the manual runbook footprint.
