use bytes::Bytes;

/// The 4-bit opcode defined in RFC 6455 §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl Opcode {
    /// Parse an opcode from a 4-bit nibble.
    pub fn try_from_u8(val: u8) -> Result<Self, u8> {
        match val {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            other => Err(other),
        }
    }

    /// Whether this opcode is a control frame (Close, Ping, Pong).
    pub const fn is_control(&self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    /// Whether this opcode is a data frame (Text, Binary, Continuation).
    pub const fn is_data(&self) -> bool {
        matches!(self, Self::Text | Self::Binary | Self::Continuation)
    }
}

/// Size ceilings enforced by the framing layer.
///
/// These live here, beside the decoder that enforces them (mirroring
/// `netune-http1::Limits`): a limit is part of the codec's contract with the
/// wire, not a transport policy.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum allowed payload size for a single frame (default 16 MiB).
    pub max_frame_bytes: usize,
    /// Maximum allowed size for a reassembled multi-frame message (default 64 MiB).
    pub max_message_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 16 * 1024 * 1024,
            max_message_bytes: 64 * 1024 * 1024,
        }
    }
}

/// A standard 16-bit status code for connection close (RFC 6455 §7.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CloseCode(pub u16);

impl CloseCode {
    /// 1000: Normal Closure.
    pub const NORMAL: Self = Self(1000);
    /// 1001: Going Away.
    pub const GOING_AWAY: Self = Self(1001);
    /// 1002: Protocol Error.
    pub const PROTOCOL_ERROR: Self = Self(1002);
    /// 1003: Unsupported Data.
    pub const UNSUPPORTED: Self = Self(1003);
    /// 1005: No Status Received (Designation only; must NOT be sent on the wire).
    pub const NO_STATUS_RECEIVED: Self = Self(1005);
    /// 1006: Abnormal Closure (Designation only; must NOT be sent on the wire).
    pub const ABNORMAL: Self = Self(1006);
    /// 1007: Invalid Frame Payload Data (e.g. non-UTF-8 text).
    pub const INVALID_PAYLOAD: Self = Self(1007);
    /// 1008: Policy Violation.
    pub const POLICY_VIOLATION: Self = Self(1008);
    /// 1009: Message Too Big.
    pub const MESSAGE_TOO_BIG: Self = Self(1009);
    /// 1010: Mandatory Extension missing.
    pub const MANDATORY_EXTENSION: Self = Self(1010);
    /// 1011: Internal Server Error.
    pub const INTERNAL_ERROR: Self = Self(1011);
    /// 1015: TLS Handshake failure (Designation only; must NOT be sent on the wire).
    pub const TLS_HANDSHAKE: Self = Self(1015);

    /// Checks if a close code is legal to transmit on the wire according to RFC 6455 §7.4.2.
    pub fn is_wire_legal(&self) -> bool {
        matches!(self.0, 1000..=1003 | 1007..=1011 | 3000..=4999)
    }
}

/// Endpoint role for RFC 6455 masking enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client endpoint: MUST mask outbound frames, MUST reject inbound masked frames.
    Client,
    /// Server endpoint: MUST NOT mask outbound frames, MUST reject inbound unmasked frames.
    Server,
}

/// A decoded or in-flight WebSocket wire frame (RFC 6455 §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub rsv: [bool; 3],
    pub opcode: Opcode,
    pub payload: Bytes,
}

impl Frame {
    /// Construct a new frame.
    pub fn new(fin: bool, opcode: Opcode, payload: Bytes) -> Self {
        Self {
            fin,
            rsv: [false; 3],
            opcode,
            payload,
        }
    }

    /// Construct a complete unfragmented text frame.
    pub fn text(payload: impl Into<Bytes>) -> Self {
        Self::new(true, Opcode::Text, payload.into())
    }

    /// Construct a complete unfragmented binary frame.
    pub fn binary(payload: impl Into<Bytes>) -> Self {
        Self::new(true, Opcode::Binary, payload.into())
    }

    /// Construct a ping control frame.
    pub fn ping(payload: impl Into<Bytes>) -> Self {
        Self::new(true, Opcode::Ping, payload.into())
    }

    /// Construct a pong control frame.
    pub fn pong(payload: impl Into<Bytes>) -> Self {
        Self::new(true, Opcode::Pong, payload.into())
    }

    /// Construct a close control frame with an optional code and reason.
    pub fn close(code: Option<CloseCode>, reason: &str) -> Self {
        let payload = match code {
            Some(c) => {
                let mut buf = Vec::with_capacity(2 + reason.len());
                buf.extend_from_slice(&c.0.to_be_bytes());
                buf.extend_from_slice(reason.as_bytes());
                Bytes::from(buf)
            }
            None => Bytes::new(),
        };
        Self::new(true, Opcode::Close, payload)
    }
}
