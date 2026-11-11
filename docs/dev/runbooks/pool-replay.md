# Pool and Replay Playbook

## Target Subsystem & Reference Environment

- `netune::Pool` and the egress `Client` stale-socket absorption.
- A trace with `ConnectReused`, `ConnectStaleDiscarded`, or `NET-E-POOL-STALE`.
- A loopback origin that closes idle keep-alive sockets.

## Core Protocol Rules & Invariants

- A pooled socket that dies before any response-head byte is replaced; after that point it is never retried (`[INV-TRANSPORT-00..04]`).
- The pool is keyed by the typed `PoolKey`, including the whole connection identity (`[INV-CUSTOM-04]`).
- A WebSocket upgrade never enters the pool (`[INV-WS-05]`).

## Diagnostic Playbook

1. If `ConnectReused` is followed by `ConnectStaleDiscarded`, the attempt absorbed an idle-close; confirm the retry happened before `HeadComplete`.
2. If `NET-E-POOL-STALE` is absent but the request failed on a reused socket, check whether the failure occurred after a response-head byte; that is not replay-safe.
3. Compare `ConnectionInfo.reused`, `local_port`, and `age_ns` with the pool key identity.
4. For a pool miss across profiles, inspect `ConnectionIdentity`; a missing profile axis is a cache-isolation bug, not a performance issue.
5. Reproduce with a loopback origin that accepts once, closes, and then serves the retry.

## Do-Not-Regress Checklist

- [ ] The stale retry is recorded and the reuse claim is revoked.
- [ ] No retry occurs after a response head.
- [ ] The pool key contains the whole connection identity.
- [ ] An upgraded WebSocket is never returned to the pool.
