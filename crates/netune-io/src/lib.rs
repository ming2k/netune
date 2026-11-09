//! Transport byte-path wrappers: the syscall tap and the chaos twin.
//!
//! Both types in this crate answer a question about *one* socket, from inside
//! the process, with no policy of any kind: no resolution, no connection, no
//! TLS, no listening, no limits, no clock policy of their own, and no
//! knowledge of which direction the traffic travels.
//!
//! ```text
//! netune (egress)          ──┐
//!                            ├──► netune-io ──► netune-trace
//! netune-server (ingress)  ──┘
//! ```
//!
//! # Why this is a crate and not a module of an orchestrator
//!
//! `TimedIo` and `FaultIo` are `AsyncRead`/`AsyncWrite` adapters with no socket
//! and no policy. They are needed by **both** directions of travel — an ingress
//! reader must record the same syscall boundary an egress reader does, or the
//! two traces cannot be joined on a shared clock — and the two orchestrators
//! must not depend on each other (ADR-0011). Keeping them in `netune` would
//! have forced `netune-server` to depend on the egress stack, which is exactly
//! the inversion `docs/dev/architecture.md` §1 forbids.
//!
//! # The two wrappers
//!
//! - [`TimedIo`] observes what the transport did. The observation strategy is a
//!   type parameter: [`netune_trace::NoTap`] adds nothing, `Counters` is a
//!   clock-free L0 count, and `Ring` records one event per `poll_read` /
//!   `poll_write` that moved bytes. The wrapper owns the tap; it never holds a
//!   shared recorder or a mutex.
//! - [`RingIo`] is the same owned `Ring` tap for a protocol that boxes its
//!   transport and cannot hand the tap back explicitly; it merges the log into
//!   the connection recorder when the wrapper is dropped.
//! - [`FaultIo`] changes what the transport does: delayed reads, split reads,
//!   truncation, resets. It records nothing by design — a fault the harness
//!   injected itself must not pollute the trace the harness judges the
//!   transport with.
//!
//! They compose in either order over the same stream, which is what makes
//! "record the chaos" and "chaos the recording" both expressible without either
//! type knowing about the other.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod fault;
mod timed;

pub use fault::{Fault, FaultIo, FaultScript};
pub use timed::{RingIo, TimedIo};
