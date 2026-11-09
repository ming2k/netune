//! The event vocabulary.
//!
//! Kinds are protocol-neutral: they describe what the *transport* did (a read,
//! a head, a chunk boundary) and what the *origin* said (a protocol frame, an
//! output token), never how a particular provider spells it. Adding HTTP/2 or a
//! new provider therefore adds frame classes, not a new event model.

/// What an [`crate::Event`] records.
///
/// Discriminants are stable: they are the persisted code for a kind, so a kind
/// may be added but never renumbered.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
    /// A pooled connection was found dead and abandoned before the request was
    /// answered; a fresh connection was established for the same attempt.
    ///
    /// This is the one event that revokes a preceding
    /// [`EventKind::ConnectReused`]: the attempt did *not* ultimately ride a
    /// pooled socket, so its connection phases were really paid and must be
    /// measured rather than reported not-applicable. `a` = the idle age in ms of
    /// the socket that was discarded.
    ConnectStaleDiscarded = 28,
    /// One WebSocket wire frame crossed the socket boundary (in either
    /// direction). `a` = [`FrameClass`]-style payload class code (client roles
    /// reuse the same vocabulary; ping/pong/close map to `KeepAlive`,
    /// text/binary to their data classes). `b` = payload bytes carried.
    ///
    /// Recorded per *frame*, not per message: a fragmented message's parts
    /// stay individually visible, so a trace can distinguish one flush of two
    /// frames from two arrivals. Message-level accounting is a derivation over
    /// these (`ProtocolFrame` remains the message-completion event).
    WsFrame = 29,
    /// A datagram session was opened (association established, or a connected
    /// socket bound). `a` = 1 when the session is connected to a single peer, 0
    /// when it is an association that may address several.
    ///
    /// Datagrams have no connection to hand off, so the session — not a socket
    /// accept — is the unit that is traced. An association that the peer
    /// refuses records [`EventKind::Error`] instead and never this event.
    UdpOpen = 30,
    /// One datagram crossed the socket boundary, in either direction. `a` =
    /// payload bytes carried, `b` = direction (0 sent, 1 received).
    UdpDatagram = 31,
    /// Origin of an *ingress* trace: a connection was accepted. Always at offset
    /// 0 of an ingress attempt, and never present in an egress one.
    ///
    /// The two directions have separate origins on purpose. An egress trace is
    /// anchored on `Dispatch` — the harness deciding to send — while an ingress
    /// trace is anchored on the kernel handing over a socket, so no ingress
    /// timing can be silently measured against a client's clock.
    IngressDispatch = 32,
    /// A TLS handshake completed on an accepted connection. `a` = 1 when the
    /// session was resumed.
    IngressTlsEnd = 33,
    /// A client's request head was parsed: start line and headers complete.
    /// `a` = head bytes read.
    RequestHeadComplete = 34,
    /// First body byte of a request arrived.
    RequestBodyStart = 35,
    /// The request body was fully consumed. `a` = body bytes read.
    RequestBodyEnd = 36,
    /// The handler was entered. Brackets the one span that is application time
    /// rather than transport time.
    HandlerStart = 37,
    /// The handler returned a response. `a` = the status code it produced.
    HandlerEnd = 38,
    /// The response head was flushed to the kernel.
    ResponseHeadSent = 39,
    /// One chunk of a response body was flushed. `a` = payload bytes in this
    /// chunk.
    ResponseChunkSent = 40,
    /// The response was fully written. `a` = total body bytes written.
    ResponseEnd = 41,
    /// QUIC connection handshake started.
    QuicStart = 42,
    /// QUIC connection handshake completed. `a` = 1 on success, 0 on failure.
    QuicEnd = 43,
    /// QUIC stream opened. `a` = stream ID, `b` = 1 for bidi, 0 for uni.
    QuicStreamOpen = 46,
    /// HTTP/3 request stream started.
    H3StreamStart = 48,
    /// HTTP/3 response headers received. `a` = status code.
    H3HeadComplete = 49,
    /// HTTP/3 response body fully received. `a` = body bytes received.
    H3Finished = 50,
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
            28 => Self::ConnectStaleDiscarded,
            29 => Self::WsFrame,
            30 => Self::UdpOpen,
            31 => Self::UdpDatagram,
            32 => Self::IngressDispatch,
            33 => Self::IngressTlsEnd,
            34 => Self::RequestHeadComplete,
            35 => Self::RequestBodyStart,
            36 => Self::RequestBodyEnd,
            37 => Self::HandlerStart,
            38 => Self::HandlerEnd,
            39 => Self::ResponseHeadSent,
            40 => Self::ResponseChunkSent,
            41 => Self::ResponseEnd,
            42 => Self::QuicStart,
            43 => Self::QuicEnd,
            46 => Self::QuicStreamOpen,
            48 => Self::H3StreamStart,
            49 => Self::H3HeadComplete,
            50 => Self::H3Finished,
            _ => return None,
        })
    }

    /// Whether this kind belongs to an ingress trace rather than an egress one.
    ///
    /// The check is exhaustive over the ingress family on purpose: adding an
    /// ingress kind and forgetting to classify it would let a reader treat it as
    /// an egress fact.
    pub const fn is_ingress(self) -> bool {
        matches!(
            self,
            Self::IngressDispatch
                | Self::IngressTlsEnd
                | Self::RequestHeadComplete
                | Self::RequestBodyStart
                | Self::RequestBodyEnd
                | Self::HandlerStart
                | Self::HandlerEnd
                | Self::ResponseHeadSent
                | Self::ResponseChunkSent
                | Self::ResponseEnd
        )
    }

    /// Whether this kind is an encoding aid rather than a recorded fact.
    pub const fn is_synthetic(self) -> bool {
        matches!(self, Self::TimeJump)
    }

    /// Whether this kind may only be produced by a byte-path [`crate::Tap`].
    ///
    /// `TraceCollector::mark` rejects these kinds: a control/protocol producer
    /// must not be able to manufacture a syscall timeline.
    pub const fn is_byte_path(self) -> bool {
        matches!(self, Self::Read | Self::Write | Self::Segment)
    }
}

/// Which clock produced a read event's timestamp.
///
/// A trace may mix sources (syscall boundaries on one platform, kernel software
/// timestamps on another), so the source travels with the event instead of being
/// assumed from the trace's fidelity level.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
    /// Which exchange on the connection this event belongs to.
    ///
    /// `0` for an exchange the transport could not multiplex (all of egress, and HTTP/1.1
    /// ingress, where a connection carries one request at a time), and the protocol's own
    /// stream identifier for HTTP/2, where one connection carries many concurrently.
    ///
    /// It travels with the event rather than being inferred from position because a
    /// multiplexed log *interleaves*: an event's neighbour is not its predecessor, so a
    /// reader that grouped by position would attribute one stream's read to another's
    /// handler span. Grouping by this field is the only way a derivation can describe two
    /// exchanges that were genuinely simultaneous.
    pub stream: u32,
    /// Kind-specific first payload word (see each [`EventKind`]).
    pub a: u32,
    /// Kind-specific second payload word.
    pub b: u32,
}

impl Event {
    /// The read's byte count, for the kinds that carry one.
    pub const fn bytes(self) -> Option<u32> {
        match self.kind {
            EventKind::Read
            | EventKind::Write
            | EventKind::Segment
            | EventKind::RequestWriteEnd
            | EventKind::ChunkBoundary
            | EventKind::UdpDatagram
            | EventKind::RequestHeadComplete
            | EventKind::RequestBodyEnd
            | EventKind::ResponseChunkSent
            | EventKind::ResponseEnd => Some(self.a),
            _ => None,
        }
    }

    /// The status code a handler produced, for [`EventKind::HandlerEnd`].
    pub const fn status(self) -> Option<u16> {
        match self.kind {
            EventKind::HandlerEnd => Some(self.a as u16),
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

    /// Whether a [`EventKind::UdpDatagram`] was sent by us (`true`) rather than
    /// received (`false`).
    ///
    /// `None` for every other kind, so a caller cannot read a direction out of
    /// an event that has none.
    pub const fn is_send(self) -> Option<bool> {
        match self.kind {
            EventKind::UdpDatagram => Some(self.b == 0),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_decoded_event_stays_compact() {
        assert_eq!(std::mem::size_of::<Event>(), 24);
    }

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
            (29, EventKind::WsFrame),
            (30, EventKind::UdpOpen),
            (31, EventKind::UdpDatagram),
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
            stream: 0,
            kind: EventKind::Read,
            a: 1448,
            b: TimeSource::KernelSoftware.code() as u32,
        };
        assert_eq!(read.bytes(), Some(1448));
        assert_eq!(read.time_source(), Some(TimeSource::KernelSoftware));
        assert_eq!(read.tokens(), None);

        let token = Event {
            at_ns: 9,
            stream: 0,
            kind: EventKind::OutputToken,
            a: 3,
            b: 0,
        };
        assert_eq!(token.tokens(), Some(3));
        assert_eq!(token.frame_class(), None);

        let frame = Event {
            at_ns: 11,
            stream: 0,
            kind: EventKind::ProtocolFrame,
            a: FrameClass::Open.code() as u32,
            b: 0,
        };
        assert_eq!(frame.frame_class(), Some(FrameClass::Open));

        let sent = Event {
            at_ns: 12,
            stream: 0,
            kind: EventKind::UdpDatagram,
            a: 1200,
            b: 0,
        };
        assert_eq!(sent.bytes(), Some(1200));
        assert_eq!(sent.is_send(), Some(true));
        let received = Event {
            at_ns: 13,
            stream: 0,
            kind: EventKind::UdpDatagram,
            a: 40,
            b: 1,
        };
        assert_eq!(received.is_send(), Some(false));
        // A kind with no direction must not answer the question at all.
        assert_eq!(read.is_send(), None);
    }
}
