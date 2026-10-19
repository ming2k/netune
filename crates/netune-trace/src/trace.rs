//! The trace envelope: identity, endpoint, connection provenance, fidelity.
//!
//! The envelope answers the questions a bare event log cannot: *which* attempt
//! is this, *was the connection reused*, and *how fine is the tap that produced
//! it*. The last one is a contract, not a note: a consumer must never present an
//! L0 trace as if it had syscall-level detail.

use serde::{Deserialize, Serialize};

use crate::log::EventLog;

/// Correlation id carried on the request (`x-netune-request-id`), so the client
/// trace and the gateway trace can be joined.
///
/// Stored as text because it is a UUIDv7 rendered as a string, and because a
/// `u128` does not survive JSON in a JavaScript consumer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(String);

impl TraceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which model attempt this trace belongs to.
///
/// Deliberately a plain struct rather than an application-level contracts type: the trace
/// crate must not depend on the ledger, and the integration layer maps its
/// `RequestUsageKey` onto this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptRef {
    pub round: u64,
    pub turn: u32,
    pub attempt: u32,
}

/// Who was called.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRef {
    pub provider: String,
    pub model: String,
    /// `host:port` of the connection, never a URL with credentials.
    pub authority: String,
}

/// Provenance of the connection the attempt used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Taken from the pool: no DNS, TCP or TLS phase occurred.
    pub reused: bool,
    /// Ephemeral local port, when the tap can see it. Distinguishes concurrent
    /// connections to the same authority.
    pub local_port: Option<u16>,
    /// Age of the reused connection at dispatch, when known.
    pub age_ns: Option<u64>,
}

/// Which tap levels produced this trace.
///
/// A consumer's first duty is to check this before trusting a scope: an L0
/// trace has no `TCP_INFO`, no per-read timeline and no segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Fidelity {
    /// Protocol-level events only.
    pub protocol: bool,
    /// Syscall-boundary read/write timeline.
    pub syscall: bool,
    /// Kernel receive timestamps (`SO_TIMESTAMPING`).
    pub kernel_ts: bool,
    /// Per-segment capture (L2 probe).
    pub segments: bool,
}

impl Fidelity {
    /// Protocol events only: the floor every platform supports.
    pub const fn l0() -> Self {
        Self {
            protocol: true,
            syscall: false,
            kernel_ts: false,
            segments: false,
        }
    }

    /// Protocol events plus the syscall tap and `TCP_INFO`.
    pub const fn l1() -> Self {
        Self {
            protocol: true,
            syscall: true,
            kernel_ts: false,
            segments: false,
        }
    }

    /// Full fidelity: syscall tap, kernel timestamps and segment capture.
    pub const fn l2() -> Self {
        Self {
            protocol: true,
            syscall: true,
            kernel_ts: true,
            segments: true,
        }
    }

    /// True when the trace can answer questions that need per-read detail.
    pub const fn has_byte_timeline(self) -> bool {
        self.syscall || self.kernel_ts || self.segments
    }
}

/// One request attempt's complete recorded trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestTrace {
    pub id: TraceId,
    pub attempt: AttemptRef,
    pub endpoint: EndpointRef,
    pub connection: ConnectionInfo,
    pub fidelity: Fidelity,
    pub log: EventLog,
}

impl RequestTrace {
    /// Total events evicted by the ring. Non-zero means the trace is a window,
    /// not the whole story — a consumer must say so rather than assume it is
    /// complete.
    pub fn dropped_events(&self) -> u32 {
        self.log.dropped()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fidelity_levels_are_ordered_and_explicit() {
        assert!(Fidelity::l0().protocol);
        assert!(!Fidelity::l0().has_byte_timeline());
        assert!(Fidelity::l1().has_byte_timeline());
        assert!(!Fidelity::l1().kernel_ts);
        assert!(Fidelity::l2().kernel_ts);
        assert!(Fidelity::l2().segments);
    }

    #[test]
    fn trace_id_renders_as_text() {
        let id = TraceId::new("01924f4e-0000-7000-8000-000000000000");
        assert_eq!(id.as_str(), "01924f4e-0000-7000-8000-000000000000");
        assert_eq!(id.to_string(), id.as_str());
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, "\"01924f4e-0000-7000-8000-000000000000\"");
    }
}
