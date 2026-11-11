---
id: ADR-0015
title: "The Listener Terminates Its Own TLS, and the Handshake Is a Recorded Fact"
status: accepted
date: 2026-11-06
scope: [transport/ingress, security/tls, trace/ingress]
superseded_by: null
---

# 0015. The Listener Terminates Its Own TLS, and the Handshake Is a Recorded Fact

- Status: Accepted
- Date: 2026-11-06
- Deciders: Ming Li
- Amends: [ADR-0011](0011-server-side-ingress-transport.md),
  [ADR-0012](0012-http2-ingress.md)

---

## Context and Problem Statement

[ADR-0011](0011-server-side-ingress-transport.md) shipped an ingress path that speaks plaintext, and
[ADR-0012](0012-http2-ingress.md) added HTTP/2 whose ALPN negotiation only exists over TLS. Together
they left the largest deployment gap in the workspace: an operator who wants a public HTTPS origin has
to put a third-party terminator in front of `netune-server`, at which point the majority of its traffic
is decided by software this repository does not observe.

That is not an aesthetic objection. It is the same objection ADR-0011 made against `hyper` and lost
ground on:

1. **The handshake cost disappears from the trace.** A proxy terminates TLS and forwards a plaintext
   request; the request's ingress trace therefore begins *after* the handshake, and `IngressTlsEnd`
   would be an event that never fires. The one number that distinguishes "the client is far away" from
   "the certificate chain is too long" is exactly the number a terminator keeps.
2. **The ALPN decision moves outside the process.** With TLS in front, HTTP/2 reaches this listener
   either as a prior-knowledge preface (so the listener's own ALPN list is decorative) or not at all.
   `Protocols::alpn()` would be a list an operator pastes into someone else's configuration file and
   this crate cannot check.
3. **The listener would ship a capability it requires someone else to exercise.** `Protocols::BOTH`
   over plaintext is only reachable by a client willing to speak HTTP/2 without a handshake first,
   which no browser is.

The question, then, is not "should there be TLS". It is: **does TLS termination belong inside the
ingress orchestrator, and if so, what does it cost the trace model, the protocol-selection rule, and the
dependency graph?**

## Decision Drivers

- The handshake's completion and cost must be derivable from recorded events like every other ingress
  span (`INV-TRACE-01`, `INV-SERVER-02`).
- The protocol must still be decided **once**. ALPN decides it for TLS; the first bytes decide it for
  plaintext; neither may be upgraded in place (`INV-SERVER-09`).
- A TLS stack is not an HTTP implementation. `rustls` must not cross the red-line `ADR-0001` and
  `ARCH-005` draw, or every argument in this repository about owning the wire becomes incoherent.
- A peer that opens a socket and never completes a handshake must cost the holder nothing more than any
  other incomplete request.
- A listener that is not terminating TLS must not link a TLS stack it never calls.

## Considered Options

- **Option 1**: keep plaintext only, document a fronting terminator, and accept the observability loss.
- **Option 2**: add TLS inside `netune-server` behind a non-default `tls` feature, using `rustls` through
  `tokio-rustls`'s `LazyConfigAcceptor` so SNI and ALPN are read from the ClientHello before a
  configuration is chosen.
- **Option 3**: a separate crate `netune-tls` owning the acceptor, with `netune` and `netune-server` both
  depending on it.
- **Option 4**: terminate TLS inside the `Handler`, handing every application a `TlsStream` and letting it
  do the handshake.

## Decision Outcome

Chosen option: **"Option 2"**, for four reasons:

1. **The handshake becomes an event, so its cost is a derivation.** `IngressTlsEnd` is written when the
   handshake completes, and a failed handshake is a `DiagnosticRecord` with
   `NET-E-SERVER-TLS-HANDSHAKE`. The trace
   therefore separates "the identity cost this much" from "the client was slow to speak", which is the
   whole argument ADR-0011 made and the thing a terminator cannot give back.
2. **`LazyConfigAcceptor`, not `TlsAcceptor`.** The acceptor reads the ClientHello, exposes the SNI and
   the ALPN offer, and *only then* selects a `ServerConfig`. A listener holding two certificates must
   serve the one the peer asked for; serving the wrong one verifies against the wrong name, which is a
   silent security failure rather than a visible one. The SNI also makes per-name selection testable
   without a mock.
3. **The protocol rule is unchanged, and its input changed.** `[INV-SERVER-09]` still says one protocol
   per connection, decided once. Over TLS the input is the ALPN result instead of the first bytes; the
   HTTP/2 preface is then still read *inside* the tunnel, because ALPN decided and the bytes are in the
   stream. Nothing is upgraded in place.
4. **The dependency is behind a default-off feature and is not an HTTP stack.** `rustls` parses TLS
   records, not HTTP messages, so `ARCH-005` is untouched: the workspace still owns every HTTP byte. The
   feature is off by default for the same reason `http2` is optional in `netune`: a listener behind a
   terminator must not link a TLS stack it never calls.

### Invariants & Behavioral Boundaries

- **`[INV-SERVER-18]` TLS Termination Is Inside the Trace**: a listener that terminates TLS records the
  handshake's completion as `IngressTlsEnd` and its failure as a `DiagnosticRecord` with
  `NET-E-SERVER-TLS-HANDSHAKE`; a handshake cost is never inferred from wall-clock around the connection.
  *Enforced by*: `a_completed_handshake_is_a_recorded_fact` and
  `a_client_that_stalls_mid_handshake_is_cut_off_at_the_bound`.
- **`[INV-SERVER-19]` The Configuration Serves the Name the Peer Asked For**: a TLS listener selects its
  `ServerConfig` from the SNI name, with a required fallback for a peer that sends none, and never
  serves a certificate for a name it was not given. *Enforced by*:
  `per_name_selection_serves_the_certificate_the_peer_asked_for` and
  `an_untrusted_name_fails_the_handshake_rather_than_serving`.
- **`[INV-SERVER-20]` A Handshake Is Bounded Before It Is Trusted**: the whole handshake is bounded by
  `head_timeout`, so an idle peer costs a permit for no longer than a slow request would. *Enforced by*:
  `crate::tls::accept` wraps the handshake in one timeout, and the stall test above.
- **`[INV-SERVER-21]` ALPN and `Protocols` Cannot Disagree**: binding is refused when the TLS
  configuration's ALPN list does not advertise every protocol `protocols` claims to serve, because that
  listener would negotiate a protocol it then refuses on every connection. *Enforced by*:
  `a_bind_is_refused_when_the_tls_configuration_does_not_advertise_what_is_served`.

### Consequences

- **Positive**:
  - A public HTTPS origin is this crate's own, so every span it reports is one it measured, including
    the handshake.
  - `Protocols::alpn()` stops being advice for someone else's configuration file: it is what the
    listener offers, and a mismatch between it and the served set is refused at bind time.
  - The TLS path shares the whole connection pipeline with the plaintext one — the same admission
    control, the same drain, the same dispatch — because `serve_selected` takes a transport and a
    protocol rather than a `TcpStream`.
- **Negative & Trade-offs**:
  - `netune-server`'s dependency graph grows `rustls` and `tokio-rustls` when the feature is on. A TLS
    implementation is a large, security-sensitive dependency, and this repository's standing answer is
    the same as `netune`'s egress side: own the HTTP, use a vetted TLS, verify it with real handshakes
    rather than mocks.
  - The `tls` feature is not on by default, so the default build cannot serve HTTPS. That is deliberate:
    a feature that is additive must not be compiled into a plaintext deployment, and a deployment that
    needs TLS turns one feature on.
  - No session-resumption tuning, no client certificates, no cipher or version policy. Each is a
    deployment decision whose correct answer depends on session volume and client population, and a
    transport that guessed would be wrong for most deployments.
  - The handshake's *duration* is derivable but its internal phases (TCP, ClientHello, verify) are not
    separately recorded: `rustls` does not expose them, and splitting them would require an
    `AsyncRead`/`AsyncWrite` tap that records bytes without recording meaning.

## Rejected Alternatives & Negative Knowledge

### Option 1 (Rejected): Plaintext Only, Terminate Elsewhere

- **Why considered**: zero new dependencies, and every production deployment already has a terminator.
- **Why rejected**: it is the observability forfeit ADR-0011 rejected, applied to the one phase a
  terminator exists to perform. The trace would begin after the handshake, so the transport could not
  answer "was this slow because of the identity or the client" — the question its entire trace model is
  built to answer. It also makes `Protocols::alpn()` unverifiable advice.

### Option 3 (Rejected): A Separate `netune-tls` Crate

- **Why considered**: TLS is a distinct concern, and a leaf would keep `netune-server`'s graph small.
- **Why rejected**: the acceptor needs the listener's `head_timeout`, its trace recorder and its
  protocol set — all of which live in the orchestrator. A leaf that took them as parameters would either
  duplicate the connection lifecycle or need a fourth orchestrator to own it. The code is one module;
  a crate for one module that depends on the orchestrator's policies is a crate that inverts the
  topology.

### Option 4 (Rejected): Terminate Inside the Handler

- **Why considered**: maximum flexibility; an application could pick its own certificate per route.
- **Why rejected**: the handler is called *after* the head is parsed, and there is no head until the
  handshake is done. It would also put a private key inside application code, and make the admission
  control and the handshake bound unreachable — a peer could hold a permit through an unbounded
  handshake before any handler ran.

## Links

- Related ADRs: [ADR-0001](0001-owned-transport-trace-model.md),
  [ADR-0004](0004-tls-fingerprint-profiles-pool-isolation.md),
  [ADR-0011](0011-server-side-ingress-transport.md),
  [ADR-0012](0012-http2-ingress.md)
