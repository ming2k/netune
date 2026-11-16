# Automated Verification & Testing Guide

This guide defines how `netune` is tested, what each test tier is for, and the rules that keep the suite deterministic.

---

## 1. Test Tiers

```text
                  ▲
                 / \
                /   \     Tier 4: End-to-end
               /  E2E  \    TLS handshake, HTTP/2, WebSocket session over loopback
              /─────────\
             / Integr.  \  Tier 3: Integration
            /  ation     \ Mock origins, proxies, pool reuse, chaos (FaultIo)
           /─────────────\
          / Differential  \ Tier 2: Differential
         /   & golden      \ Owned codec vs `hyper` / `tungstenite`, JA3/JA4 vectors
        /───────────────────\
       /       Unit          \ Tier 1: Unit
      /      assertions       \ Decoders, framing, HPACK, masking, timings
     /─────────────────────────\
```

| Tier | Location | Runs against |
| :--- | :--- | :--- |
| 1. Unit | `#[cfg(test)]` inline modules in `src/`, or `src/<module>/tests.rs` when the module's tests outgrew the file | Pure functions, state machines |
| 2. Differential | `crates/*/tests/differential.rs`, `crates/*/tests/golden.rs`, `crates/netune-http3/tests/h3_interop.rs`, `crates/netune-quic/tests/owned_handshake.rs` | A battle-tested oracle as a **dev-dependency only** or an independent raw-wire peer (`netune-webtransport`); H3 against `h3`/`h3-quinn` and QUIC against `quinn` in both directions |
| 3. Integration | `tests/integration/main.rs` plus its modules | Loopback mock origins, TLS fixtures, `FaultIo`; ingress shedding, slow-peer bounds, drain; codec-to-orchestrator integration |
| 4. End-to-end | `tests/e2e/main.rs` plus its modules | A full client lifecycle over a real socket; our H1/H2/H3 client against our server; QUIC and WebTransport sessions over a real handshake |

The WebSocket guide's code samples are also compiled and executed by `tests/e2e/websocket_guide.rs`, so a drifting guide fails CI instead of misleading readers. The HTTP guide has the equivalent guard in `tests/integration/serve_http_guide.rs`.

`tests/e2e/interop.rs` is the only suite that may see both orchestrators, and it sees `netune` as a **dev-dependency**. It asserts two things at once: that a request completes between our own ends, and that neither orchestrator's production manifest names the other (`[INV-SERVER-01]`).

### 1.1 Unit-test placement

Inline is the default. A small or medium module keeps its tests beside the
code:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // ...
}
```

A test module moves to a sibling directory when the tests, not the business
logic, are what made the file large. The working threshold is **at least 150
lines of test code and at least 30% of the file**; a 2,000-line state machine
with 200 lines of tests stays inline, because the size is the behaviour it
implements. A moved module keeps the same access it had:

```text
src/pool.rs                 →  src/pool/tests.rs
src/http2/client.rs         →  src/http2/client/tests.rs
src/message.rs (two suites) →  src/message/tests/{mod.rs,utf8.rs,assembler.rs}
```

The declaration becomes `#[cfg(test)] mod tests;`, so `use super::*` still
names the production module and nothing has to become public for a test.

### 1.2 Shared test infrastructure

`crates/test-support` is the one home for fixtures that are not about a
single crate: scripted byte transports, loopback pairs, HTTP/1.1 wire constants
and generated self-signed TLS identities. It is a `dev-dependency` everywhere
it appears, declares `publish = false`, and depends on no workspace crate. The
architecture gate (`ARCH-001`) rejects any production dependency on it, so it
cannot drift into the shipping graph. A fixture that encodes transport policy
belongs in the owning crate's tests instead. The rule is
[ADR-0044](../adr/0044-test-architecture-nextest-and-tiered-entry-points.md)
(`[INV-TEST-02]`).

### 1.3 External test entry points

The workspace root is a test-only package (`workspace-tests`) because a
virtual workspace cannot own a `tests/` directory:

```text
tests/
  common/               shared fixtures; no #[test] functions
  integration/main.rs   one binary for all integration modules
  e2e/main.rs           one binary for all end-to-end modules
```

The two entry points are deliberate compilation units. A new scenario is a
module added to the matching `main.rs`; it is compiled and linked with its tier
instead of becoming another executable. `tests/common` is included by both
entry points with `#[path = "../common/mod.rs"]`, so a helper is written once.
The root package has only dev-dependencies, no library and no binary; `ARCH-012`
enforces that shape, and also requires both entry points to exist
(`[INV-TEST-03..04]`, [ADR-0044](../adr/0044-test-architecture-nextest-and-tiered-entry-points.md)).

---

## 2. Determinism Rules

1. **No live network.** Tests must not depend on the public internet or a real third-party service. Mock origins bind to `127.0.0.1:0`.
2. **No sleep-based synchronisation.** Wait on a condition, a channel, or a deadline; a `sleep` that "usually works" is a flaky test.
3. **No wall-clock assertions.** Timing invariants are asserted as *derivations from recorded events*, not as elapsed wall time. A benchmark may print elapsed numbers for a human, but the gate is deterministic: `size_of`, event counts, or instruction counts (e.g. `gungraun`). A wall-clock tolerance is a flake, not a budget.
4. **RAII fixtures.** Temporary files and directories clean up on drop; a test must not leave state behind for the next one.
5. **Feature isolation.** The default build carries no transmission path. The `inject` suite is run separately so both configurations are proven.

---

## 3. Invariant Tests

When an ADR defines an invariant that the type system cannot enforce, a test names it:

```rust
#[test]
fn inv_transport_01_replaces_a_socket_that_dies_before_the_head() { /* ... */ }
```

A test that verifies an invariant keeps the invariant tag in its name, so the ADR, the test, and the failure message are searchable as one unit.

### 3.1 Failure-first tests

A bug fix starts with a test that fails for the reported reason and is named for
the diagnostic it protects:

```text
diag_<diagnostic-code>_<symptom>
```

The test asserts the terminal `DiagnosticCode`, the phase, and the retry verdict,
not only the `Display` string. A failure that changes a public path must also
assert that a `TraceSnapshot` is returned, including under `Observation::Off`.
When the failure is reproducible through `FaultIo`, assert the diagnostic and the
recorded events together. A `TraceBundle` may be attached to a postmortem, but
the test itself must remain hermetic.

The `netune-trace` suite owns the registry contract: codes are unique, stable,
registered, documented, and never renumber. `netune-diagnostics` owns the
redaction and bundle-round-trip contract. The orchestrators own the mapping from
their error vocabulary to the registry.

---

## 4. Running the Suite

The workspace root is a test-only package, so a bare `cargo nextest run` would
select only the root harness. `--workspace` is the full suite, and every gate
uses it explicitly.

```bash
# Everything, default features
cargo nextest run --workspace

# The privileged transmission path, compiled and tested explicitly
cargo nextest run -p netune-probe --features inject

# A single crate's unit and differential suites
cargo nextest run -p netune-ws

# One external tier, complete feature posture
cargo nextest run -p workspace-tests --test integration --all-features
cargo nextest run -p workspace-tests --test e2e --all-features

# H3/QPACK differential interop against the dev-only h3 oracle
cargo nextest run -p netune-http3 --test h3_interop

# WebTransport admission, Origin, session-ID and control adversarial suite
cargo nextest run -p workspace-tests -E 'test(webtransport_security::)'

# Owned QUIC engine (ADR-0028): wire, packet protection, handshake and streams
cargo nextest run -p netune-quic

# Doctests: nextest does not execute them, so this one gate stays on cargo
cargo test --doc --workspace --all-features

# Deterministic zero-cost gate (requires valgrind + gungraun-runner)
cargo bench -p netune --bench zero_cost
```

`cargo nextest` is the test runner; there is no `xtask test` wrapper. Test
discovery, filtering, retries and timeouts belong to nextest, configured once
in `.config/nextest.toml`. A wrapper that reimplemented them would be a second,
weaker test runner.

The benchmark gate is intentionally separate from `cargo nextest run --workspace`: it
measures instructions, not wall time, and fails a regression against a baseline
generated in the same CI run (`ir=0%`).

### 4.1 Independent WebTransport wire-role differential interop

`crates/netune-webtransport/tests/differential.rs` drives an independent raw-H3
wire peer in both directions under `cargo nextest`
([ADR-0038](../adr/0038-webtransport-external-interoperability.md),
[ADR-0049](../adr/0049-in-workspace-fuzzing-and-differential-webtransport-gate.md)).
The peer must complete a bidirectional stream, a unidirectional stream in each
direction, a datagram exchange in both directions and session-close capsule
teardown against `netune-webtransport`, including when the client omits
server-only `SETTINGS_ENABLE_CONNECT_PROTOCOL` and `SETTINGS_WT_ENABLED` and
when the server advertises only draft-16 (`0x2c7cf000`) or draft-17
(`0x20b8933b`):

```bash
cargo nextest run -p netune-webtransport --test differential
```

The browser half of ADR-0037 Gate 4 is not automated yet: Chrome 157/159 do not
advertise the `reset_stream_at` transport parameter that draft-17 requires, so a
browser run fails before the first WebTransport session.

### 4.2 Fuzzing and soak

Every wire parser crate owns an in-workspace `tests/fuzz.rs` target backed by
`test_support::fuzz` (`crates/netune-http1/tests/fuzz.rs`,
`crates/netune-http2/tests/fuzz.rs`, `crates/netune-http3/tests/fuzz.rs`,
`crates/netune-quic/tests/fuzz.rs`, `crates/netune-tls/tests/fuzz.rs`,
`crates/netune-webtransport/tests/fuzz.rs`)
(`[INV-TEST-05..06]`, [ADR-0049](../adr/0049-in-workspace-fuzzing-and-differential-webtransport-gate.md)).
Each target runs a fast deterministic corpus, truncation and mutation pass on
every pull request as part of `cargo nextest run --workspace`, and exposes an
`#[ignore]` soak entry point (`soak_fuzz_*`) that runs alongside the
long-running QUIC echo/keep-alive test in the scheduled `Fuzz and soak`
workflow:

```bash
cargo nextest run --workspace --all-features \
  --run-ignored ignored-only --profile soak
```

A fuzz finding is added to the crate's `SEEDS` slice and paired with a minimal
regression test in the owning crate's test suite.

CI additionally sets `RUSTFLAGS="-D warnings"`, so warnings are failures on `main`.

---

## 5. Adding a Test

- Unit behaviour → a `#[cfg(test)]` module beside the code, or `src/<module>/tests.rs` when section 1.1's threshold applies.
- A fixture shared by unrelated crates → `test-support`, never a copy in each suite.
- A decoder or encoder that has a spec → add a differential or golden case, not only a hand-written expectation.
- A transport failure mode → a module under `tests/integration/`, asserting both the error variant and the recorded events.
- A full lifecycle over a real socket → a module under `tests/e2e/`.
- A documentation snippet → a ```` ```rust ```` block in the document itself. It is compiled automatically (section 6).

---

## 6. Documentation Examples Are Tests

A guide is consumed by copy-paste. Nothing about Markdown makes a stale snippet
fail, so the examples are compiled as doctests:

- `crates/netune/src/doc_examples.rs` includes `README.md` and every guide under
  `docs/{tutorials,how-to}/` with `#[doc = include_str!(…)]`, gated on
  `#[cfg(doctest)]`. Its `rust` blocks become real doctests.
- CI runs `cargo test --doc --workspace --all-features`, so a guide that names a
  type, method, or field that does not exist is a build failure. This is the one
  test tier that stays on `cargo test`: nextest does not execute doctests, and
  wrapping them in a second runner would only hide that fact.

The fencing rules that follow from this:

| The block… | Fence it as | Why |
| :--- | :--- | :--- |
| Is a complete program | ```` ```rust,no_run ```` | Compiled, not executed: it dials a host that only exists on the reader's machine. |
| Should actually run in CI | ```` ```rust ```` | Only for hermetic examples (a `FaultIo` script, a struct literal). |
| Is a fragment | ```` ```rust ```` + a `# async fn run()` wrapper | Still type-checked; hidden `#` lines keep the rendered page clean. |

Never use `ignore`: an ignored block is a block nobody checks, which is how the
examples drifted from the API in the first place. `docs/how-to/websocket-client.md`
additionally has an executed transcription in `tests/e2e/websocket_guide.rs` — that
one proves the *behaviour* the text describes, not just that it compiles.

---

## 7. Documentation Integrity Gate

`.github/scripts/check-docs.py` enforces the structural rules (links, anchors,
the public/internal firewall, the ADR registry, invariant governance, version
consistency). Its rule list is indexed in
[`standards/README.md`](standards/README.md); it is itself tested by
`test-check-docs.py`, so a rule cannot be weakened to make a build green.

```bash
python3 .github/scripts/check-docs.py        # run the gate
python3 .github/scripts/test-check-docs.py   # prove the gate still bites
```
