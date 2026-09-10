//! HTTP/2 for the netune stack — **reserved, not yet implemented**.
//!
//! This crate exists for three honest reasons, stated up front:
//!
//! 1. **The name is part of the design.** `netune-http1` states exactly what
//!    it contains; when HTTP/2 arrives it belongs in a sibling that says the
//!    same thing about itself, not behind a feature flag that turns a line
//!    protocol crate into a framing grab-bag. Publishing this placeholder
//!    now keeps that naming plan executable instead of blocked on a
//!    first-come-first-served registry.
//! 2. **It documents the shape before the code exists**, so the decision is
//!    reviewable (see "The plan", below) and does not get reinvented under
//!    deadline pressure.
//! 3. **It compiles, links into nothing, and costs nothing.** There is no
//!    half-built implementation here pretending to be a feature: one symbol,
//!    zero dependencies, tested as absent.
//!
//! # Status
//!
//! **Not implemented. Nothing in this crate performs I/O or speaks HTTP/2.**
//! The stack it belongs to is HTTP/1.1-only today, deliberately (ADR-0200's
//! "neutral" consequences: the trace model is protocol-neutral, so adopting
//! HTTP/2 later is an additive change to the codec and the frame-level tap,
//! not a rewrite). This crate is built when a consumer needs it — not
//! before.
//!
//! # The plan (recorded 2026-09, ADR-0210)
//!
//! HTTP/2 (RFC 9113) shares no implementation code with HTTP/1.1, so it is a
//! new crate rather than a feature of [`netune-http1`]:
//!
//! - **Wire format**: binary frames (a fixed 9-byte header, then payload)
//!   versus 1.1's text lines.
//! - **Multiplexing**: many concurrent streams on one connection, with
//!   per-stream state machines, flow-control windows, and priority — versus
//!   one request at a time.
//! - **Header compression**: HPACK with a dynamic table that carries state
//!   *across* frames; encoding decisions on one stream affect every later
//!   one. This is the piece that most resolutely cannot live inside the 1.1
//!   codec.
//! - **Connection pool**: a multiplexed pool (one connection, N in-flight
//!   requests, stream limits) is a different data structure from the
//!   keep-alive pool that owns one connection per request.
//! - **Test oracle**: differential-tested against the `h2` crate the way
//!   `netune-http1` is differential-tested against hyper — a different
//!   oracle for a different protocol.
//!
//! Shared surface (method, status, headers) comes from the `http` types both
//! protocols already speak. The transport changes additively at that point:
//! ALPN advertises `h2`, and the [`netune`]'s `TimedIo` tap semantics gain a
//! frame-boundary view (an HTTP/2 read returns a frame, not an arbitrary
//! byte slice — the trace model already distinguishes these).
//!
//! # Acceptance when it is built (the gate this placeholder sets)
//!
//! - Differential parity with `h2` across a recorded + adversarial corpus
//!   (same discipline that accepted `netune-http1` against hyper).
//! - The tap's frame events flow through the trace model without a new
//!   event vocabulary — `FrameClass`/chunk boundaries as recorded today.
//! - A multiplexed pool whose reuse attribution lands in the trace as
//!   `ConnectReused` does today.
//! - Fingerprint continuity: the JA4 `a`-section records `h2` ALPN the
//!   moment the stack offers it, and the baseline snapshot updates as a
//!   reviewed diff.
//!
//! [`netune-http1`]: https://crates.io/crates/netune-http1
//! [`netune`]: https://crates.io/crates/netune

/// Crate identity marker: the sole public symbol, present so the crate has a
/// minimal, honest API surface while it waits for implementation.
///
/// Not a feature switch, not a stub that might silently do something: it
/// exists so `netune-http2 = "=0.0.1"` in a Cargo.toml is *inspectable* —
/// a build can assert which placeholder generation it is linking against.
pub const RESERVED: &str = "netune-http2 0.0.1 (reserved; no HTTP/2 implementation)";

#[cfg(test)]
mod tests {
    use super::*;

    /// The promise this crate makes is that it does *nothing*; the test
    /// suite's job is to keep that promise true as generations change.
    #[test]
    fn the_crate_is_a_reservation_not_an_implementation() {
        assert!(RESERVED.contains("reserved"));
        assert!(RESERVED.contains("no HTTP/2 implementation"));
    }
}
