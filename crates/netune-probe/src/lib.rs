//! `netune-probe`: the opt-in L2 segment capture of ADR-0200.
//!
//! This is a **separate binary**, not a daemon capability. Reading segments
//! needs `CAP_NET_RAW`, and the always-running process must never carry
//! packet-sniffing authority; an operator who wants segment-level truth runs
//! this tool explicitly, for one 4-tuple, for a bounded window.
//!
//! What it produces is the one thing no HTTP-level library can: a per-segment
//! arrival timeline (`t`, direction, length, TCP flags, sequence number) that
//! can be compared against the syscall tap's read boundaries. When they agree,
//! the tap is faithful; when they diverge, the transport is batching and the
//! derived rates must say so.
//!
//! The parser is pure and unit-tested; only [`capture`] touches a socket, and it
//! compiles out on non-Linux.
//!
//! # The capability boundary (injection)
//!
//! This crate ships two halves with different privilege postures:
//!
//! - **Parse and build** ([`packet`]) are pure functions, always present:
//!   the forge is constructible and testable offline with no capability at
//!   all. An RST can be *described* in a test; only a socket can send it.
//! - **Transmit** ([`capture::Capture::send_frame`]) exists only under the
//!   `inject` feature and needs `CAP_NET_RAW` at runtime. The default build
//!   — the one that ships, the one CI builds — is receive-only, and a test
//!   in `packet::tests` asserts a trait bound that only the default build
//!   can satisfy... more directly: the default build's binary contains no
//!   send path, and `cargo check --no-default-features` style gates keep it
//!   that way.
//!
//! Nothing about the daemon changes: it links neither half by default, and
//! even with `inject`, the operator runs the binary explicitly, with the
//! capability, for one flow, for a bounded window — never as a service.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod packet;

#[cfg(target_os = "linux")]
pub mod capture;

/// One captured segment, as the probe reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Monotonic nanoseconds since the probe started.
    pub at_ns: u64,
    /// `true` for segments travelling toward the peer.
    pub outbound: bool,
    /// TCP payload length (0 for a bare ACK).
    pub payload_len: u32,
    /// TCP header flags.
    pub flags: u8,
    /// TCP sequence number.
    pub seq: u32,
    /// TCP acknowledgement number.
    pub ack: u32,
}

impl Segment {
    /// Whether this segment carried application data.
    pub const fn carries_data(&self) -> bool {
        self.payload_len > 0
    }

    /// Whether this segment is a bare acknowledgement.
    pub const fn is_bare_ack(&self) -> bool {
        self.payload_len == 0 && self.flags & packet::FLAG_ACK != 0
    }
}
