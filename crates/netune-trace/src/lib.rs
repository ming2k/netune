//! Request traces: the recorded artefact every displayed number derives from.
//!
//! ADR-0200 makes one promise the whole observability programme rests on:
//! **every timing and rate a surface renders is a pure function of a recorded
//! trace.** This crate is that trace and those functions. It owns no I/O, no
//! clock policy and no presentation: it is the data model ([`EventLog`]), the
//! vocabulary ([`EventKind`]) and the pure derivations ([`derive()`]).
//!
//! Rates are *not* computed here: a rate needs a token count, and only the
//! caller knows whether that count is the provider's or a local estimate. This
//! crate supplies the span; the ledger divides.
//!
//! # Layering
//!
//! ```text
//! netune (P1)          produces events: resolver, socket, TLS, IO tap, codec
//!        │  Recorder::read / write / mark
//!        ▼
//! netune-trace           stores them delta-encoded, derives timings + rates
//!        │  DerivedTimings
//!        ▼
//! frontends              render `Reading`s; never compute a timing themselves
//! ```
//!
//! The transport crate (`netune`) owns the monotonic clock and hands this
//! crate absolute nanosecond offsets; this crate never reads a clock except in
//! [`Recorder`], which exists so the offset conversion is written once.
//!
//! # The two invariants
//!
//! 1. **Honest absence.** A scope that was not measured, does not apply, or
//!    cannot be estimated is a [`Validity`], never a fabricated number. There is
//!    no accessor that yields a value without its verdict.
//! 2. **One rate, one anchor.** The streaming rate is `tokens / (last token −
//!    first token)`. There is no end-to-end rate: it answers a different
//!    question with the same units, and a reader cannot tell which one they
//!    are looking at.
//!
//! # Why the event log is delta-encoded
//!
//! A long streaming turn produces thousands of read and token events. Each is
//! stored as `(dt_ns: u32, kind, a, b)` relative to its predecessor — 13 bytes
//! plus padding, with gaps longer than 4.29 s carried losslessly by a
//! [`EventKind::TimeJump`] record (see the `log` module). A 10 000-event turn
//! is ~130 KB, bounded by a ring buffer that counts what it drops.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod derive;
mod event;
mod log;
mod record;
mod tlsfp;
mod trace;
mod verdict;

pub use derive::{DerivedTimings, derive};
pub use event::{Alpn, Event, EventKind, FrameClass, TimeSource};
pub use log::{EncodedEvent, EventLog, MAX_DELTA_NS};
pub use record::Recorder;
pub use tlsfp::{ClientHello, Ja3, Ja4, is_grease, ja3, ja4};
pub use trace::{AttemptRef, ConnectionInfo, EndpointRef, Fidelity, RequestTrace, TraceId};
pub use verdict::{Reading, Reason, Validity};

/// Default capacity of a request's event ring, in events.
///
/// Sized for the pathological case — a reasoning model streaming for minutes
/// with one event per token — while keeping a trace under 4 MB in memory. A
/// turn that exceeds it keeps the newest events and reports the drop count.
pub const DEFAULT_TRACE_CAPACITY: usize = 262_144;

/// Shortest span considered defensible for a streaming rate (20 ms), in
/// nanoseconds. Mirrors the ledger's historical floor so the two cannot drift.
pub const MIN_DEFENSIBLE_STREAM_SPAN_NS: u64 = 20_000_000;

/// Gap below which two protocol events are treated as one transport flush, in
/// nanoseconds. A response head and the first body byte arriving this close
/// together were delivered by one flush, which makes the server-side latency
/// unmeasurable rather than zero.
pub const BATCH_GAP_NS: u64 = 2_000_000;

/// Physically plausible ceiling for a client-observed single-stream rate
/// (tokens/second). A robust estimate above it indicates burst arrival rather
/// than decode, so the estimate is reported as not estimable rather than
/// clamped.
pub const MAX_PLAUSIBLE_TPS: f64 = 2_000.0;
