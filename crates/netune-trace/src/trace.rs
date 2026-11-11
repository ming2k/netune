//! The trace envelope: identity, endpoint, connection provenance, fidelity.
//!
//! The envelope answers the questions a bare event log cannot: *which* attempt
//! is this, *was the connection reused*, and *how fine is the tap that produced
//! it*. The last one is a contract, not a note: a consumer must never present an
//! L0 trace as if it had syscall-level detail.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::diagnostic::DiagnosticTable;
use crate::log::EventLog;

/// Direction of travel a trace describes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Direction {
    Egress,
    Ingress,
}

/// Whether a trace identity is propagated on the wire.
///
/// Adding a header changes HTTP/1 header order and the HTTP/2 header set, which
/// are fingerprint-relevant. Propagation is therefore a named policy, never a
/// silent default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TracePropagation {
    /// No header is added or read.
    #[default]
    Off,
    /// Carry the trace id in this header. The name must be a valid HTTP field
    /// name; the orchestrator validates it at bind/config time.
    Header(&'static str),
}

impl TracePropagation {
    pub const fn header(self) -> Option<&'static str> {
        match self {
            Self::Off => None,
            Self::Header(name) => Some(name),
        }
    }
}

/// Correlation id carried on the request, so the client trace and the gateway
/// trace can be joined.
///
/// Stored as text because it is a UUIDv7 rendered as a string, and because a
/// `u128` does not survive JSON in a JavaScript consumer. It is a correlation
/// id, not a secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceId(String);

impl TraceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a UUIDv7-shaped correlation id.
    ///
    /// The value combines wall-clock milliseconds, process-local entropy and a
    /// monotonic counter. It is unique enough to join records; it is not a
    /// cryptographic token and must never be used as one.
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        static SEED: AtomicU64 = AtomicU64::new(0);

        let seed = match SEED.load(Ordering::Relaxed) {
            0 => {
                let now = now_unix_ns();
                let pid = u64::from(std::process::id());
                let stack = &SEED as *const _ as u64;
                let candidate = now ^ pid.rotate_left(32) ^ stack;
                SEED.compare_exchange(0, candidate, Ordering::Relaxed, Ordering::Relaxed)
                    .unwrap_or(candidate)
            }
            seed => seed,
        };
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let ms = now_unix_ns() / 1_000_000;
        let random = splitmix64(seed ^ ms ^ counter);

        let time_low = (ms & 0xffff_ffff) as u32;
        let time_mid = ((ms >> 32) & 0xffff) as u16;
        let time_hi = 0x7000 | ((ms >> 48) & 0x0fff) as u16;
        let variant = 0x8000 | ((random >> 12) & 0x3fff) as u16;
        let node = (random & 0xffff_ffff_ffff) as u64;
        Self(format!(
            "{time_low:08x}-{time_mid:04x}-{time_hi:04x}-{variant:04x}-{node:012x}"
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Identity and provenance that travels with every trace.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceMeta {
    /// The one correlation id for this attempt or connection.
    pub id: TraceId,
    /// Which direction of travel this record describes.
    pub direction: Direction,
    /// Wall-clock start, for joining logs; never used to derive a timing.
    pub started_unix_ns: u64,
    /// The build that produced the record.
    pub build_version: String,
    /// The operating-system process that produced the record.
    pub process_id: u32,
}

impl TraceMeta {
    pub fn new(id: TraceId, direction: Direction) -> Self {
        Self {
            id,
            direction,
            started_unix_ns: now_unix_ns(),
            build_version: env!("CARGO_PKG_VERSION").to_owned(),
            process_id: std::process::id(),
        }
    }

    pub fn egress() -> Self {
        Self::new(TraceId::generate(), Direction::Egress)
    }

    pub fn ingress() -> Self {
        Self::new(TraceId::generate(), Direction::Ingress)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttemptRef {
    pub round: u64,
    pub turn: u32,
    pub attempt: u32,
}

/// Who was called.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EndpointRef {
    pub provider: String,
    pub model: String,
    /// `host:port` of the connection, never a URL with credentials.
    pub authority: String,
}

/// Provenance of the connection the attempt used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// Nothing was recorded. This is the truthful envelope for `NoTap`.
    pub const fn none() -> Self {
        Self {
            protocol: false,
            syscall: false,
            kernel_ts: false,
            segments: false,
        }
    }

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

/// A named wire-shaping policy applied to a connection's early flight.
///
/// This is intentionally a value, not a boolean on a target: it can be compared,
/// hashed into a pool key and recorded in a trace envelope. The `SniSplit`
/// preset matches the long-standing `SegmentingIo::for_sni` shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EvasionPolicy {
    /// No wire shaping.
    #[default]
    None,
    /// Split the first `segment_limit` bytes into `chunk_size` writes, with an
    /// optional gap in microseconds between chunks.
    SniSplit {
        chunk_size: u16,
        segment_limit: u16,
        gap_us: u32,
    },
}

impl EvasionPolicy {
    /// The preset used for SNI micro-segmentation: 24-byte chunks, first 512
    /// bytes, 2 ms between chunks.
    pub const fn sni_split() -> Self {
        Self::SniSplit {
            chunk_size: 24,
            segment_limit: 512,
            gap_us: 2_000,
        }
    }

    pub const fn is_none(self) -> bool {
        matches!(self, Self::None)
    }
}

/// Everything fixed at connection establishment that can change what the peer
/// sees or which socket may serve a request.
///
/// Request-only wire details (HTTP/1 header order and casing, HTTP/2
/// pseudo-header order) are deliberately not here: they are applied per
/// request and do not make two sockets interchangeable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConnectionIdentity {
    pub tls_profile: Option<String>,
    pub tls_server_name: Option<String>,
    pub evasion: EvasionPolicy,
    pub h2_profile: Option<String>,
    /// The resolved QUIC profile that supplies the H3 connection's transport
    /// identity.
    pub h3_profile: Option<String>,
    /// The HTTP/3 SETTINGS profile, when the connection was established with a
    /// named one. SETTINGS are connection-level: they shape the peer's view of
    /// the connection and cannot be changed per request.
    pub h3_settings_profile: Option<String>,
    pub socket_shape: Option<String>,
    /// The route a connection took (for example a proxy authority), when it is
    /// not a direct dial. Credentials are deliberately excluded.
    pub route: Option<String>,
}

/// Current schema of the trace envelope. Bumped when a consumer must change
/// how it interprets the envelope; event-kind discriminants remain stable.
pub const TRACE_SCHEMA_VERSION: u32 = 2;

/// One request attempt's complete recorded trace.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequestTrace {
    /// Identity, direction, start time and build provenance.
    pub meta: TraceMeta,
    pub attempt: AttemptRef,
    pub endpoint: EndpointRef,
    pub connection: ConnectionInfo,
    /// The wire identity requested for the connection this attempt used.
    pub identity: ConnectionIdentity,
    /// Envelope schema version; see [`TRACE_SCHEMA_VERSION`].
    pub schema_version: u32,
    pub fidelity: Fidelity,
    pub log: EventLog,
    /// Bounded failure narration for this attempt.
    pub diagnostics: DiagnosticTable,
}

impl RequestTrace {
    /// The trace's correlation id.
    pub fn id(&self) -> &TraceId {
        &self.meta.id
    }

    /// Total events evicted by the ring. Non-zero means the trace is a window,
    /// not the whole story — a consumer must say so rather than assume it is
    /// complete.
    pub fn dropped_events(&self) -> u32 {
        self.log.dropped()
    }

    /// Total diagnostics evicted by the side table.
    pub fn dropped_diagnostics(&self) -> u32 {
        self.diagnostics.dropped()
    }

    /// The terminal diagnostic code, when one was recorded.
    pub fn diagnostic_code(&self) -> Option<crate::diagnostic::DiagnosticCode> {
        self.diagnostics.last_error().map(|record| record.code)
    }

    /// Diagnose this attempt from its recorded evidence.
    pub fn diagnose(&self) -> crate::diagnose::Diagnosis {
        crate::diagnose::diagnose(&self.meta, self.fidelity, &self.log, &self.diagnostics)
    }
}

/// A bounded snapshot of an attempt's evidence, suitable for attaching to an
/// error or writing into a review bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceSnapshot {
    pub meta: TraceMeta,
    pub fidelity: Fidelity,
    pub log: EventLog,
    pub diagnostics: DiagnosticTable,
}

impl TraceSnapshot {
    pub fn new(
        meta: TraceMeta,
        fidelity: Fidelity,
        log: EventLog,
        diagnostics: DiagnosticTable,
    ) -> Self {
        Self {
            meta,
            fidelity,
            log,
            diagnostics,
        }
    }

    pub fn dropped_events(&self) -> u32 {
        self.log.dropped()
    }

    pub fn dropped_diagnostics(&self) -> u32 {
        self.diagnostics.dropped()
    }

    /// The terminal diagnostic code, when one was recorded.
    pub fn diagnostic_code(&self) -> Option<crate::diagnostic::DiagnosticCode> {
        self.diagnostics.last_error().map(|record| record.code)
    }

    pub fn diagnose(&self) -> crate::diagnose::Diagnosis {
        crate::diagnose::diagnose(&self.meta, self.fidelity, &self.log, &self.diagnostics)
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

    #[cfg(feature = "serde")]
    #[test]
    fn trace_id_renders_as_text() {
        let id = TraceId::new("01924f4e-0000-7000-8000-000000000000");
        assert_eq!(id.as_str(), "01924f4e-0000-7000-8000-000000000000");
        assert_eq!(id.to_string(), id.as_str());
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, "\"01924f4e-0000-7000-8000-000000000000\"");
    }

    #[test]
    fn generated_ids_are_uuidv7_shaped_and_unique() {
        let first = TraceId::generate();
        let second = TraceId::generate();
        assert_ne!(first, second);
        let text = first.as_str();
        assert_eq!(text.len(), 36);
        let parts: Vec<&str> = text.split('-').collect();
        assert_eq!(
            parts.iter().map(|part| part.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert_eq!(&parts[2][..1], "7", "version nibble");
        assert!(matches!(&parts[3][..1], "8" | "9" | "a" | "b"), "variant");
    }
}
