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
| 2. Differential | `crates/*/tests/differential.rs`, `tests/golden.rs` | A battle-tested oracle as a **dev-dependency only** |
| 3. Integration | `crates/netune/tests/*.rs` | Loopback mock origins, TLS fixtures, `FaultIo` |
| 4. End-to-end | `crates/netune/tests/{e2e,tls_e2e,ws,ws_session}.rs` | A full client lifecycle over a real socket |

The WebSocket guide's code samples are also compiled and executed by `crates/netune/tests/guide_examples.rs`, so a drifting guide fails CI instead of misleading readers.

---

## 2. Determinism Rules

1. **No live network.** Tests must not depend on the public internet or a real third-party service. Mock origins bind to `127.0.0.1:0`.
2. **No sleep-based synchronisation.** Wait on a condition, a channel, or a deadline; a `sleep` that "usually works" is a flaky test.
3. **No wall-clock assertions.** Timing invariants are asserted as *derivations from recorded events*, not as elapsed wall time.
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
```

CI additionally sets `RUSTFLAGS="-D warnings"`, so warnings are failures on `main`.

---

## 5. Adding a Test

- Unit behaviour → a `#[cfg(test)]` module beside the code.
- A decoder or encoder that has a spec → add a differential or golden case, not only a hand-written expectation.
- A transport failure mode → a `FaultIo` scenario in `crates/netune/tests/`, asserting both the error variant and the recorded events.
- A documentation snippet → a case in `guide_examples.rs`.
