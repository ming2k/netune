# Diagnostic Codes

A failed `netune` attempt returns an `AttemptError` carrying the original error, a real `TraceId`, and a `TraceSnapshot` with a bounded `DiagnosticTable`. Every terminal failure has a stable code in that table. The code is the machine-readable contract; the message and fields are the review context.

`AttemptError::diagnosis()` is a pure derivation over the snapshot. It names the terminal diagnostic, the last successful phase, the retry verdict, the fidelity caveat, and the next checks. It reads no clock and performs no I/O.

## Code ranges

| Range | Subsystem |
| :--- | :--- |
| `0x01xx` | DNS resolution |
| `0x02xx` | TCP / socket connect |
| `0x03xx` | TLS |
| `0x04xx` | Proxy tunnel |
| `0x05xx` | Pool |
| `0x06xx` | HTTP/1.1 |
| `0x07xx` | HTTP/2 |
| `0x08xx` | QUIC |
| `0x09xx` | HTTP/3 |
| `0x0a..0x0d` | WebSocket, security, body decoding, redirects |
| `0x0e` | Generic egress protocol/IO/config |
| `0x10` | Ingress server, listener, drain |
| `0x20` | Trace and sink health |

`NET-E-UNCLASSIFIED` (`0`) is a legacy/unknown value. New producers must never emit it.

## Registry

| Code | Level | Phase | Retry |
| :--- | :--- | :--- | :--- |
| `NET-E-DNS-FAILED` | error | dns | retryable |
| `NET-E-TCP-FAILED` | error | tcp | retryable |
| `NET-E-TLS-FAILED` | error | tls | terminal |
| `NET-E-PROXY-FAILED` | error | proxy | retryable |
| `NET-E-POOL-STALE` | warn | pool | retryable |
| `NET-E-HTTP1-PROTOCOL` | error | http1 | terminal |
| `NET-E-HTTP1-LIMIT` | error | http1 | terminal |
| `NET-E-HTTP1-INCOMPLETE` | error | http1 | retryable |
| `NET-E-HTTP1-IO` | error | http1 | retryable |
| `NET-E-HTTP2-PROTOCOL` | error | http2 | terminal |
| `NET-E-HTTP2-HANDSHAKE` | error | http2 | retryable |
| `NET-E-HTTP2-REFUSED` | error | http2 | retryable |
| `NET-E-QUIC-FAILED` | error | quic | retryable |
| `NET-I-QUIC-PATH-MTU` | info | quic | conditional |
| `NET-I-QUIC-CLOSED` | info | quic | conditional |
| `NET-E-H3-FAILED` | error | http3 | terminal |
| `NET-E-WS-FAILED` | error | websocket | terminal |
| `NET-I-WS-CLOSED` | info | websocket | terminal |
| `NET-E-EGRESS-SECURITY` | error | tcp | terminal |
| `NET-E-DECODE-FAILED` | error | response | terminal |
| `NET-E-UNSUPPORTED-ENCODING` | error | response | terminal |
| `NET-E-REDIRECT-LIMIT` | error | response | terminal |
| `NET-E-PROTOCOL` | error | unknown | terminal |
| `NET-E-IO` | error | unknown | retryable |
| `NET-E-TIMEOUT` | error | unknown | retryable |
| `NET-E-CONFIG` | error | request | terminal |
| `NET-E-TRACE-INCOMPLETE` | warn | trace | conditional |
| `NET-E-SERVER-PROTOCOL` | error | http1 | terminal |
| `NET-E-SERVER-LIMIT` | error | http1 | terminal |
| `NET-E-SERVER-INCOMPLETE` | error | http1 | retryable |
| `NET-E-SERVER-IO` | error | http1 | retryable |
| `NET-E-SERVER-HEAD-TIMEOUT` | error | http1 | terminal |
| `NET-E-SERVER-BODY-TIMEOUT` | error | http1 | terminal |
| `NET-E-SERVER-HANDLER-TIMEOUT` | error | server | terminal |
| `NET-E-SERVER-HANDLER-PANIC` | error | server | terminal |
| `NET-E-SERVER-INVALID-REQUEST` | error | http1 | terminal |
| `NET-E-SERVER-TLS-HANDSHAKE` | error | tls | terminal |
| `NET-E-SERVER-BIND` | error | listener | terminal |
| `NET-E-SERVER-SHED` | warn | listener | retryable |
| `NET-E-SERVER-ACCEPT` | warn | listener | retryable |
| `NET-E-SERVER-DRAIN-EXPIRED` | warn | drain | conditional |
| `NET-E-SERVER-H2-STREAM` | error | http2 | conditional |
| `NET-E-SERVER-CONFIG` | error | listener | terminal |
| `NET-E-SERVER-H3-HANDSHAKE` | warn | http3 | retryable |
| `NET-E-SERVER-BODY-LIMIT` | error | http1 | terminal |
| `NET-W-TRACE-DROPPED` | warn | trace | conditional |
| `NET-W-DIAGNOSTIC-DROPPED` | warn | trace | conditional |
| `NET-W-SINK-DROPPED` | warn | sink | conditional |
| `NET-W-TRACE-INCOMPLETE` | warn | trace | conditional |

## Review workflow

1. Capture the `AttemptError` and call `diagnosis()`.
2. Look up the terminal code in the table above.
3. If the record is incomplete, check `dropped_events`, `dropped_diagnostics`, and `fidelity` before trusting a missing phase.
4. For an offline review, write a `TraceBundle` with `netune-diagnostics` and attach it to the failure report. The default policy is production-safe (public fields/text only); `internal()` keeps internal context for local review. Secret fields and text are removed by both policies.
5. For a regression comparison, run `netune-diagnose diff <baseline> <regression>`. It reports outcome, terminal code, drop counts, and the first event where the logs diverge.
6. A postmortem action item must name a test, gate, or invariant that verifies the fix. See `docs/dev/postmortems/TEMPLATE.md`.
