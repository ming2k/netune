# QUIC and HTTP/3 Handshake Playbook

## Target Subsystem & Reference Environment

- `netune-quic` owned endpoint and `netune-http3` client/server state machines.
- A `TraceCollector` passed to `QuicConnector::connect` or an H3 `execute` failure.
- Loopback fixtures for owned QUIC/HTTP/3; no public network required.

## Core Protocol Rules & Invariants

- QUIC is owned by `netune-quic`; `quinn`/`quinn-proto` are dev-only oracles (`[INV-QUIC-05..09]`).
- HTTP/3 is owned by `netune-http3`; it does not grow a second handshake registry (`[INV-H3-03..08]`).
- A path MTU is raised only by an ACKed probe (`[INV-QUIC-24]`).
- A failed incoming handshake is a value, not listener shutdown (`[INV-QUIC-23]`).

## Diagnostic Playbook

1. Read the terminal code: `NET-E-QUIC-FAILED`, `NET-E-H3-FAILED`, `NET-E-TLS-FAILED`, or `NET-E-SERVER-H3-HANDSHAKE`.
2. Check `TraceMeta.identity.h3_profile` and `h3_settings_profile`; an unknown profile is a configuration failure, not a network failure.
3. For a handshake failure, compare `QuicStart`/`QuicEnd` and the TLS alert in the diagnostic message.
4. For H3 stream failure, inspect the `stream` field and the H3 code field; a connection-level close is not a request-level reset.
5. For MTU symptoms, read `NET-I-QUIC-PATH-MTU` and the validated MTU field; a black-holed probe must leave the old value unchanged.
6. Reproduce with the owned loopback tests before changing a timeout or a profile.

## Do-Not-Regress Checklist

- [ ] The failure has a registered diagnostic code and a trace id.
- [ ] A profile failure names the profile and fails before endpoint creation.
- [ ] A failed handshake does not stop the H3 listener.
- [ ] A path-MTU change is backed by an ACKed probe.
