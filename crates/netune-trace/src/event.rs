//! The event vocabulary.
//!
//! Kinds are protocol-neutral: they describe what the *transport* did (a read,
//! a head, a chunk boundary) and what the *origin* said (a protocol frame, an
//! output token), never how a particular provider spells it. Adding HTTP/2 or a
//! new provider therefore adds frame classes, not a new event model.

use serde::{Deserialize, Serialize};

/// What an [`crate::Event`] records.
///
/// Discriminants are stable: they are the persisted code for a kind, so a kind
/// may be added but never renumbered.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Origin of the trace: the request left the harness. Always at offset 0.
    Dispatch = 0,
    /// Name resolution begins / ends. Absent on a reused connection.
    DnsStart = 1,
    DnsEnd = 2,
    /// TCP connect begins / ends (`SYN` sent → connection established).
    TcpStart = 3,
    TcpEnd = 4,
    /// TLS handshake begins / ends. `a` = 1 when the session was resumed.
    TlsStart = 5,
    TlsEnd = 6,
    /// The connection came from the pool: no DNS/TCP/TLS phases occurred.
    ConnectReused = 7,
    /// Request bytes handed to the kernel / fully written. `a` = bytes.
    RequestWriteStart = 8,
    RequestWriteEnd = 9,
    /// One successful socket read. `a` = bytes, `b` = [`TimeSource`] code.
    Read = 10,
    /// One captured segment (L2). `a` = bytes, `b` = TCP flag bits.
    Segment = 11,
    /// A `TCP_INFO` sample. `a` = smoothed RTT µs, `b` = retransmit count.
    TcpInfo = 12,
    /// Response head parsed: status line and headers complete.
    HeadComplete = 13,
    /// First byte of the response body.
    BodyStart = 14,
    /// A decoded body-chunk boundary (chunked transfer, or one read's worth of
    /// a length-delimited body). `a` = bytes.
    ChunkBoundary = 15,
    /// Trailers parsed.
    Trailers = 16,
    /// Response body fully consumed.
    BodyEnd = 17,
    /// One origin-emitted protocol frame. `a` = [`FrameClass`] code.
    ProtocolFrame = 18,
    /// One output-bearing event: `a` = tokens carried (text, reasoning or
    /// tool-call payload, counted by the caller).
    OutputToken = 19,
    /// The response was validated by the harness; the attempt is complete.
    Validated = 20,
    /// A failure observed at the transport or protocol layer. `a` = class code.
    Error = 21,
    /// The attempt was retried. `a` = attempt ordinal that follows.
    Retry = 22,
    /// Encoding aid, never emitted by a producer: carries the high 32 bits of a
    /// gap longer than [`crate::MAX_DELTA_NS`]. Consumers skip it.
    TimeJump = 23,
    /// One successful socket write. `a` = bytes.
    Write = 24,
    /// Negotiated TLS parameters: `a` = ALPN code, `b` = version code.
    TlsInfo = 25,
    /// A redirect was followed. `a` = the 3xx status that caused it.
    Redirect = 26,
    /// The connection reaches its target through a proxy tunnel.
    ProxyTunnel = 27,
}

impl EventKind {
    /// Stable persisted code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Decode a persisted code. `None` for an unknown (newer) kind, so a reader
    /// degrades instead of failing.
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Dispatch,
            1 => Self::DnsStart,
            2 => Self::DnsEnd,
            3 => Self::TcpStart,
            4 => Self::TcpEnd,
            5 => Self::TlsStart,
            6 => Self::TlsEnd,
            7 => Self::ConnectReused,
            8 => Self::RequestWriteStart,
            9 => Self::RequestWriteEnd,
            10 => Self::Read,
            11 => Self::Segment,
            12 => Self::TcpInfo,
            13 => Self::HeadComplete,
            14 => Self::BodyStart,
            15 => Self::ChunkBoundary,
            16 => Self::Trailers,
            17 => Self::BodyEnd,
            18 => Self::ProtocolFrame,
            19 => Self::OutputToken,
            20 => Self::Validated,
            21 => Self::Error,
            22 => Self::Retry,
            23 => Self::TimeJump,
            24 => Self::Write,
            25 => Self::TlsInfo,
            26 => Self::Redirect,
            27 => Self::ProxyTunnel,
            _ => return None,
        })
    }

    /// Whether this kind is an encoding aid rather than a recorded fact.
    pub const fn is_synthetic(self) -> bool {
        matches!(self, Self::TimeJump)
    }
}

/// Which clock produced a read event's timestamp.
///
/// A trace may mix sources (syscall boundaries on one platform, kernel software
/// timestamps on another), so the source travels with the event instead of being
/// assumed from the trace's fidelity level.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSource {
    /// `Instant::now()` immediately after a read returned.
    #[default]
    Syscall = 0,
    /// Kernel receive timestamp (`SO_TIMESTAMPING`), converted to the
    /// monotonic domain.
    KernelSoftware = 1,
    /// Packet capture (L2 probe).
    PacketCapture = 2,
}

impl TimeSource {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Syscall,
            1 => Self::KernelSoftware,
            2 => Self::PacketCapture,
            _ => return None,
        })
    }
}

/// What an origin protocol frame is, at the granularity a trace needs.
///
/// Only the distinction that changes a metric's meaning is kept: whether the
/// origin had *started responding* (a frame of any class) and whether it was
/// still preamble. Provider-specific shapes map onto these classes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameClass {
    #[default]
    Unknown = 0,
    /// Preamble: `message_start`, a role-only chunk, a stream-open marker.
    /// Emitted before the origin begins generating content.
    Open = 1,
    /// Usage / accounting frame.
    Usage = 2,
    /// Assistant text.
    Text = 3,
    /// Reasoning / thinking text.
    Reasoning = 4,
    /// Tool-call payload.
    Tool = 5,
    /// A keep-alive or empty frame: proves liveness, carries no output.
    KeepAlive = 6,
}

impl FrameClass {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Unknown,
            1 => Self::Open,
            2 => Self::Usage,
            3 => Self::Text,
            4 => Self::Reasoning,
            5 => Self::Tool,
            6 => Self::KeepAlive,
            _ => return None,
        })
    }
}

/// ALPN protocol negotiated on a TLS connection, as recorded in
/// [`EventKind::TlsInfo`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alpn {
    #[default]
    Unknown = 0,
    Http11 = 1,
    H2 = 2,
}

impl Alpn {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Unknown,
            1 => Self::Http11,
            2 => Self::H2,
            _ => return None,
        })
    }

    /// Classify the negotiated protocol name.
    pub fn from_name(name: Option<&[u8]>) -> Self {
        match name {
            Some(b"http/1.1") => Self::Http11,
            Some(b"h2") => Self::H2,
            _ => Self::Unknown,
        }
    }
}

/// One decoded event, positioned by its offset from the trace origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Nanoseconds since dispatch (the trace origin).
    pub at_ns: u64,
    pub kind: EventKind,
    /// Kind-specific first payload word (see each [`EventKind`]).
    pub a: u32,
    /// Kind-specific second payload word.
    pub b: u32,
}

impl Event {
    /// The read's byte count, for [`EventKind::Read`].
    pub const fn bytes(self) -> Option<u32> {
        match self.kind {
            EventKind::Read
            | EventKind::Write
            | EventKind::Segment
            | EventKind::RequestWriteEnd
            | EventKind::ChunkBoundary => Some(self.a),
            _ => None,
        }
    }

    /// The tokens carried, for [`EventKind::OutputToken`].
    pub const fn tokens(self) -> Option<u32> {
        match self.kind {
            EventKind::OutputToken => Some(self.a),
            _ => None,
        }
    }

    /// The frame class, for [`EventKind::ProtocolFrame`].
    pub const fn frame_class(self) -> Option<FrameClass> {
        match self.kind {
            EventKind::ProtocolFrame => FrameClass::from_code(self.a as u8),
            _ => None,
        }
    }

    /// The timestamp source, for [`EventKind::Read`].
    pub const fn time_source(self) -> Option<TimeSource> {
        match self.kind {
            EventKind::Read => TimeSource::from_code(self.b as u8),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_codes_round_trip_and_are_stable() {
        // The exact numbers are the persisted contract: never renumber.
        for (code, kind) in [
            (0u8, EventKind::Dispatch),
            (10, EventKind::Read),
            (18, EventKind::ProtocolFrame),
            (19, EventKind::OutputToken),
            (20, EventKind::Validated),
            (23, EventKind::TimeJump),
        ] {
            assert_eq!(kind.code(), code);
            assert_eq!(EventKind::from_code(code), Some(kind));
        }
        assert_eq!(EventKind::from_code(200), None);
        assert!(EventKind::TimeJump.is_synthetic());
        assert!(!EventKind::Read.is_synthetic());
    }

    #[test]
    fn frame_class_and_time_source_codes_round_trip() {
        for code in 0..=6 {
            let class = FrameClass::from_code(code).expect("known class");
            assert_eq!(class.code(), code);
        }
        assert_eq!(FrameClass::from_code(9), None);
        for code in 0..=2 {
            let source = TimeSource::from_code(code).expect("known source");
            assert_eq!(source.code(), code);
        }
        assert_eq!(TimeSource::from_code(9), None);
    }

    #[test]
    fn accessors_read_the_right_word() {
        let read = Event {
            at_ns: 7,
            kind: EventKind::Read,
            a: 1448,
            b: TimeSource::KernelSoftware.code() as u32,
        };
        assert_eq!(read.bytes(), Some(1448));
        assert_eq!(read.time_source(), Some(TimeSource::KernelSoftware));
        assert_eq!(read.tokens(), None);

        let token = Event {
            at_ns: 9,
            kind: EventKind::OutputToken,
            a: 3,
            b: 0,
        };
        assert_eq!(token.tokens(), Some(3));
        assert_eq!(token.frame_class(), None);

        let frame = Event {
            at_ns: 11,
            kind: EventKind::ProtocolFrame,
            a: FrameClass::Open.code() as u32,
            b: 0,
        };
        assert_eq!(frame.frame_class(), Some(FrameClass::Open));
    }
}
