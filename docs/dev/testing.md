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
| 1. Unit | `#[cfg(test)]` modules in `src/` | Pure functions, state machines |
| 2. Differential | `crates/*/tests/differential.rs`, `tests/golden.rs`, `crates/netune-http3/tests/h3_interop.rs` | A battle-tested oracle as a **dev-dependency only**; the H3 suite runs the owned stack against `h3`/`h3-quinn` in both directions |
| 3. Integration | `crates/netune/tests/*.rs`, `crates/netune-server/tests/{ingress,http3_ingress}.rs`, `crates/netune-http3/tests/http3_e2e.rs` | Loopback mock origins, TLS fixtures, `FaultIo`; ingress shedding, slow-peer bounds, drain; H3 streaming upload, dynamic QPACK and per-exchange trace |
| 4. End-to-end | `crates/netune/tests/{e2e,tls_e2e,ws,ws_session}.rs`, `crates/netune-server/tests/interop.rs`, `crates/netune-server/tests/http3_ingress.rs` | A full client lifecycle over a real socket; our H1/H2 client against our server; our HTTP/3 client against `H3Server` over a real QUIC handshake |

The WebSocket guide's code samples are also compiled and executed by `crates/netune/tests/guide_examples.rs`, so a drifting guide fails CI instead of misleading readers.

`crates/netune-server/tests/interop.rs` is the only suite that may see both orchestrators, and it sees `netune` as a **dev-dependency**. It asserts two things at once: that a request completes between our own ends, and that neither orchestrator's production manifest names the other (`[INV-SERVER-01]`).

---

## 2. Determinism Rules

1. **No live network.** Tests must not depend on the public internet or a real third-party service. Mock origins bind to `127.0.0.1:0`.
2. **No sleep-based synchronisation.** Wait on a condition, a channel, or a deadline; a `sleep` that "usually works" is a flaky test.
3. **No wall-clock assertions.** Timing invariants are asserted as *derivations from recorded events*, not as elapsed wall time. A benchmark may print elapsed numbers for a human, but the gate is deterministic: `size_of`, event counts, or instruction counts (e.g. `iai-callgrind`). A wall-clock tolerance is a flake, not a budget.
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

---

## 4. Running the Suite

```bash
# Everything, default features
cargo nextest run

# The privileged transmission path, compiled and tested explicitly
cargo nextest run -p netune-probe --features inject

# A single crate
cargo nextest run -p netune-ws

# Plain cargo, if nextest is unavailable
cargo test --workspace

# H3/QPACK differential interop against the dev-only h3 oracle
cargo test -p netune-http3 --test h3_interop

# Deterministic zero-cost gate (requires valgrind + iai-callgrind-runner)
cargo bench -p netune --bench zero_cost
```

The benchmark gate is intentionally separate from `cargo test`: it measures
instructions, not wall time, and fails a regression against a baseline generated
in the same CI run (`ir=0%`).

CI additionally sets `RUSTFLAGS="-D warnings"`, so warnings are failures on `main`.

---

## 5. Adding a Test

- Unit behaviour → a `#[cfg(test)]` module beside the code.
- A decoder or encoder that has a spec → add a differential or golden case, not only a hand-written expectation.
- A transport failure mode → a `FaultIo` scenario in `crates/netune/tests/`, asserting both the error variant and the recorded events.
- A documentation snippet → a ```` ```rust ```` block in the document itself. It is compiled automatically (section 6).

---

## 6. Documentation Examples Are Tests

A guide is consumed by copy-paste. Nothing about Markdown makes a stale snippet
fail, so the examples are compiled as doctests:

- `crates/netune/src/doc_examples.rs` includes `README.md` and every guide under
  `docs/{tutorials,how-to}/` with `#[doc = include_str!(…)]`, gated on
  `#[cfg(doctest)]`. Its `rust` blocks become real doctests.
- CI runs `cargo test --doc --workspace --all-features`, so a guide that names a
  type, method, or field that does not exist is a build failure.

The fencing rules that follow from this:

| The block… | Fence it as | Why |
| :--- | :--- | :--- |
| Is a complete program | ```` ```rust,no_run ```` | Compiled, not executed: it dials a host that only exists on the reader's machine. |
| Should actually run in CI | ```` ```rust ```` | Only for hermetic examples (a `FaultIo` script, a struct literal). |
| Is a fragment | ```` ```rust ```` + a `# async fn run()` wrapper | Still type-checked; hidden `#` lines keep the rendered page clean. |

Never use `ignore`: an ignored block is a block nobody checks, which is how the
examples drifted from the API in the first place. `docs/how-to/websocket-client.md`
additionally has an executed transcription in `tests/guide_examples.rs` — that
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
