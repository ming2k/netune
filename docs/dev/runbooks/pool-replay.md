# Pool and Replay Playbook

## Target Subsystem & Reference Environment

- `netune::Pool` and the egress `Client` stale-socket recovery.
- A trace with `ConnectReused`, `ConnectStaleDiscarded`, or `NET-E-POOL-STALE`.
- A loopback origin that closes idle keep-alive sockets.

## Core Protocol Rules & Invariants

- A socket found dead at checkout is discarded before a request byte is written; nothing is replayed (`[INV-TRANSPORT-07]`).
- A reused socket that dies before a response head is re-sent only when the request is replay-safe or the peer refused the stream; after a response-head byte it is never retried (`[INV-TRANSPORT-06]`).
- The pool is keyed by the typed `PoolKey`, including the whole connection identity (`[INV-CUSTOM-04]`).
- A WebSocket upgrade never enters the pool (`[INV-WS-05]`).

## Diagnostic Playbook

1. If `ConnectStaleDiscarded` appears at checkout, the probe caught an idle close and no request was written; this is the safe path for every method.
2. If `ConnectReused` is followed by a failure before `HeadComplete`, check `Request::is_replay_safe` and whether the error was `RetryableProtocol`; only those may be replayed.
3. If `NET-E-POOL-STALE` is absent but the request failed on a reused socket, check whether the failure occurred after a response-head byte; that is not replay-safe.
4. Compare `ConnectionInfo.reused`, `local_port`, and `age_ns` with the pool key identity.
5. For a pool miss across profiles, inspect `ConnectionIdentity`; a missing profile axis is a cache-isolation bug, not a performance issue.
6. Reproduce with a loopback origin that accepts once, closes, and then serves a replay-safe retry.

## Do-Not-Regress Checklist

- [ ] The checkout probe records and discards a dead socket before any request byte.
- [ ] No request is replayed unless it is replay-safe or the peer refused it.
- [ ] No retry occurs after a response head.
- [ ] The pool key contains the whole connection identity.
- [ ] An upgraded WebSocket is never returned to the pool.
