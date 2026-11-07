//! The HTTP/2 connection state machine, shared by both roles (RFC 9113).
//!
//! # Why one machine and two thin roles
//!
//! HTTP/2's *connection* layer is direction-agnostic in exactly the places a bug is
//! expensive: frame reading with the negotiated maximum, `SETTINGS` exchange and
//! acknowledgement, `PING` echo, `GOAWAY` bookkeeping, HPACK's dynamic table and the
//! `CONTINUATION` reassembly rules. Only three things differ between a client and a server:
//!
//! 1. who sends the connection preface (§3.4 — the client), and who sends the first
//!    `SETTINGS`;
//! 2. which stream ids each side may originate (client odd, server even);
//! 3. which direction `HEADERS` carries a request rather than a response.
//!
//! This module owns (1) as a [`Role`] parameter and (2) as an id-allocation rule, and leaves
//! (3) to the role module. That is the same argument ADR-0011 made for HTTP/1.1: a second
//! implementation of the framing rules is a second place a smuggling fix can be forgotten. In
//! HTTP/2 the equivalent surface is not chunked encoding but *frame sequencing* — a
//! `CONTINUATION` interleaved with a foreign frame, a `SETTINGS` ACK with a payload, a
//! `PRIORITY` frame on stream 0 — and it is a connection error when it is wrong.
//!
//! # The three things a naive HTTP/2 implementation gets wrong
//!
//! | Behaviour | RFC 9113 | Consequence when missing |
//! | :--- | :--- | :--- |
//! | `CONTINUATION` must be contiguous | §6.10 | A truncated header block is accepted, so a request is routed on a prefix |
//! | Flow control is per stream *and* per connection | §6.9 | A response over 65 535 bytes hangs |
//! | `SETTINGS` changes the peer's window, not ours | §6.5.2 | Every stream's window is off by the delta, in both directions |
//!
//! # What this machine is not
//!
//! It is not a scheduler: it does not decide which stream's `DATA` goes next, because
//! prioritisation is a policy an orchestrator owns and this layer must be testable without
//! one. It is not a codec for `HEADERS` *payloads* either — HPACK lives in [`crate::hpack`] and
//! the header model (request or response, pseudo-header ordering) lives in the role.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::H2Error;
use crate::frame::*;
use crate::hpack::{HpackDecoder, HpackEncoder};

/// HTTP/2 connection preface magic string (RFC 9113 §3.4).
///
/// Sent by the *client* only. A server that received it from itself would be a server with
/// the roles inverted, which is why [`Role::Server`] rejects a preface arriving from the peer
/// instead of skipping it.
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The default flow-control window (RFC 9113 §6.9.2).
pub const DEFAULT_WINDOW: i64 = 65_535;

/// The default maximum frame payload (RFC 9113 §6.5.2).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The smallest legal `SETTINGS_MAX_FRAME_SIZE` (RFC 9113 §6.5.2).
pub const MIN_MAX_FRAME_SIZE: u32 = 16_384;

/// The largest legal `SETTINGS_MAX_FRAME_SIZE` (RFC 9113 §6.5.2).
pub const MAX_MAX_FRAME_SIZE: u32 = 16_777_215;

/// Protocol error codes (RFC 9113 §7).
pub mod error_code {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const SETTINGS_TIMEOUT: u32 = 0x4;
    pub const STREAM_CLOSED: u32 = 0x5;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const CANCEL: u32 = 0x8;
    pub const COMPRESSION_ERROR: u32 = 0x9;
    pub const CONNECT_ERROR: u32 = 0xa;
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;
    pub const INADEQUATE_SECURITY: u32 = 0xc;
    pub const HTTP_1_1_REQUIRED: u32 = 0xd;
}

/// Which end of the connection this machine is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Opens the connection: sends the preface, originates odd stream ids, sends requests.
    Client,
    /// Accepts the connection: sends no preface, originates even stream ids, sends responses.
    Server,
}

impl Role {
    /// The connections preface this role must *send* before any frame.
    pub const fn preface(self) -> &'static [u8] {
        match self {
            Self::Client => CLIENT_PREFACE,
            Self::Server => b"",
        }
    }

    /// The parity of the stream ids this role originates (RFC 9113 §5.1.1).
    ///
    /// A client's streams are odd, a server's are even. The rule exists so a stream id is
    /// never ambiguous in a capture taken from one direction only — and a server that got it
    /// backwards would answer a client's request on a stream the client considers its own.
    pub const fn own_parity(self) -> u32 {
        match self {
            Self::Client => 1,
            Self::Server => 0,
        }
    }

    /// The role that may send a `PUSH_PROMISE`.
    pub const fn may_push(self) -> bool {
        matches!(self, Self::Server)
    }

    /// One short name for a trace or a log line.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// The SETTINGS this end advertises.
///
/// Sent as the connection's first frame (client: right after the preface; server: immediately
/// on accept). The values are the bounds the *peer* must respect when sending to us, which is
/// why they are stated as a type rather than inferred from local buffers: a bound the peer was
/// not told about becomes a mid-request failure instead of a limit it could have respected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSettings {
    pub header_table_size: u32,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    /// `ENABLE_PUSH`; only meaningful for a server advertising to a client.
    pub enable_push: bool,
}

impl LocalSettings {
    /// The values a listener should advertise: 1 MiB stream windows, 16 KiB frames.
    pub const fn for_ingress() -> Self {
        Self {
            header_table_size: 4096,
            max_concurrent_streams: 128,
            initial_window_size: 1024 * 1024,
            max_frame_size: 16_384,
            max_header_list_size: 32 * 1024,
            enable_push: false,
        }
    }

    /// The values a client should advertise: the protocol defaults, plus `ENABLE_PUSH=0`
    /// because this client never accepts a pushed stream.
    pub const fn for_client() -> Self {
        Self {
            header_table_size: 4096,
            max_concurrent_streams: 1000,
            initial_window_size: 6_291_456,
            max_frame_size: 16_384,
            max_header_list_size: 262_144,
            enable_push: false,
        }
    }

    /// The in-order parameter list, as it will appear on the wire.
    ///
    /// Order is a fingerprint (ADR-0006), so a caller that impersonates a browser supplies its
    /// own list through [`H2Connection::client_handshake`]; this one is used when it does not.
    pub fn parameters(&self) -> Vec<(u16, u32)> {
        vec![
            (SETTING_HEADER_TABLE_SIZE, self.header_table_size),
            (SETTING_ENABLE_PUSH, u32::from(self.enable_push)),
            (SETTING_MAX_CONCURRENT_STREAMS, self.max_concurrent_streams),
            (SETTING_INITIAL_WINDOW_SIZE, self.initial_window_size),
            (SETTING_MAX_FRAME_SIZE, self.max_frame_size),
            (SETTING_MAX_HEADER_LIST_SIZE, self.max_header_list_size),
        ]
    }

    /// Refuse values RFC 9113 §6.5.2 makes illegal to advertise.
    pub fn validate(&self) -> Result<(), H2Error> {
        if self.initial_window_size > 0x7FFF_FFFF {
            return Err(H2Error::Protocol(
                "INITIAL_WINDOW_SIZE exceeds 2^31-1".into(),
            ));
        }
        if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&self.max_frame_size) {
            return Err(H2Error::Protocol(
                "MAX_FRAME_SIZE outside the legal range".into(),
            ));
        }
        Ok(())
    }
}

/// The peer's advertised SETTINGS, as they now apply to what we send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSettings {
    pub header_table_size: u32,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
    pub enable_push: bool,
}

impl Default for PeerSettings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            max_concurrent_streams: None,
            initial_window_size: DEFAULT_WINDOW as u32,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
            enable_push: true,
        }
    }
}

impl PeerSettings {
    /// Apply the parameters of one `SETTINGS` frame.
    ///
    /// Unknown parameters are ignored, as §6.5.3 requires: a peer may send an extension this
    /// end does not implement, and refusing it would break a connection that is conforming.
    ///
    /// # Errors
    ///
    /// [`H2Error::Protocol`] when a value is outside the range the RFC permits, and
    /// [`H2Error::Hpack`] when the new header table size cannot be adopted.
    pub fn apply(&mut self, settings: &[(u16, u32)]) -> Result<Vec<u16>, H2Error> {
        let mut acknowledged = Vec::with_capacity(settings.len());
        for &(id, value) in settings {
            match id {
                SETTING_HEADER_TABLE_SIZE => self.header_table_size = value,
                SETTING_ENABLE_PUSH => {
                    if value > 1 {
                        return Err(H2Error::Protocol("ENABLE_PUSH must be 0 or 1".into()));
                    }
                    self.enable_push = value == 1;
                }
                SETTING_MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = Some(value),
                SETTING_INITIAL_WINDOW_SIZE => {
                    if value > 0x7FFF_FFFF {
                        return Err(H2Error::Protocol(
                            "INITIAL_WINDOW_SIZE exceeds 2^31-1".into(),
                        ));
                    }
                    self.initial_window_size = value;
                }
                SETTING_MAX_FRAME_SIZE => {
                    if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
                        return Err(H2Error::Protocol(
                            "MAX_FRAME_SIZE outside the legal range".into(),
                        ));
                    }
                    self.max_frame_size = value;
                }
                SETTING_MAX_HEADER_LIST_SIZE => self.max_header_list_size = Some(value),
                // RFC 9113 §6.5.3: unknown identifiers MUST be ignored.
                _ => continue,
            }
            acknowledged.push(id);
        }
        Ok(acknowledged)
    }
}

/// The connection-level state both roles share.
///
/// Holds the transport, the read buffer, the HPACK pair and the framing bookkeeping. It has no
/// idea whether the headers it carries are requests or responses; [`crate::client`] and
/// [`crate::server`] are the two thin roles that do.
pub struct H2Connection<T> {
    pub(crate) stream: T,
    pub(crate) role: Role,
    pub(crate) local: LocalSettings,
    pub(crate) peer: PeerSettings,
    pub(crate) encoder: HpackEncoder,
    pub(crate) decoder: HpackDecoder,
    pub(crate) read_buf: BytesMut,
    /// Connection-level send window remaining (RFC 9113 §6.9.1).
    pub(crate) connection_send_window: i64,
    /// Connection-level receive window we advertise and replenish.
    pub(crate) connection_recv_window: i64,
    /// The next stream id this end may originate.
    pub(crate) next_stream_id: u32,
    /// Whether our `SETTINGS` has been acknowledged by the peer.
    pub(crate) settings_acked: bool,
    /// Whether the peer sent `GOAWAY`, and the last stream id it covered.
    pub(crate) goaway_last_stream: Option<u32>,
    /// A dynamic-table size update that must precede our next header block.
    pending_table_update: Vec<u8>,
    /// Bound on any single frame write, when the role set one.
    write_deadline: Option<std::time::Duration>,
}

impl<T> std::fmt::Debug for H2Connection<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Connection")
            .field("role", &self.role)
            .field("next_stream_id", &self.next_stream_id)
            .field("peer_max_frame_size", &self.peer.max_frame_size)
            .field("connection_send_window", &self.connection_send_window)
            .field("buffered", &self.read_buf.len())
            .finish_non_exhaustive()
    }
}

impl<T> H2Connection<T> {
    /// Build a connection with the protocol defaults, without touching the transport.
    ///
    /// Separate from the handshake so the bookkeeping (stream ids, windows, tables) is testable
    /// without a socket, and so a role can construct the type before it has decided to write the
    /// preface.
    pub fn new(stream: T, role: Role, local: LocalSettings) -> Self {
        let decoder = HpackDecoder::with_max_table_size(local.header_table_size as usize);
        Self {
            stream,
            role,
            local,
            peer: PeerSettings::default(),
            encoder: HpackEncoder::new(),
            decoder,
            read_buf: BytesMut::with_capacity(16 * 1024),
            connection_send_window: DEFAULT_WINDOW,
            connection_recv_window: DEFAULT_WINDOW,
            next_stream_id: role.own_parity(),
            settings_acked: false,
            goaway_last_stream: None,
            pending_table_update: Vec::new(),
            write_deadline: None,
        }
    }

    /// The next stream id this end will originate, or `None` when its parity space is exhausted.
    ///
    /// RFC 9113 §5.1.1: ids are 31-bit and strictly increasing, so a connection has served its
    /// lifetime after 2^30 streams of one parity. A caller that ignores this would eventually mask a
    /// wrapped id into one the peer has already closed.
    pub fn allocate_stream_id(&mut self) -> Option<u32> {
        let id = self.next_stream_id;
        if id > 0x7FFF_FFFE {
            return None;
        }
        self.next_stream_id = id.checked_add(2)?;
        Some(id)
    }

    /// The role this end plays.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The peer's advertised bounds, as they now govern what this end sends.
    pub const fn peer_settings(&self) -> &PeerSettings {
        &self.peer
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> H2Connection<T> {
    /// Start a client connection: write the preface, our `SETTINGS` and, when the caller asked
    /// for one, an initial connection-level `WINDOW_UPDATE`.
    ///
    /// `settings` is the in-order parameter list to advertise, which is what makes a browser
    /// fingerprint reproducible (ADR-0006). `connection_window` is the extra connection-level
    /// receive credit to grant immediately; `None` leaves the protocol default in place, which
    /// is what a fingerprint that sends no window update requires.
    ///
    /// # Errors
    ///
    /// A transport error, or a protocol error for a `SETTINGS` value the RFC forbids.
    pub async fn client_handshake(
        stream: T,
        local: LocalSettings,
        settings: Vec<(u16, u32)>,
        connection_window: Option<u32>,
    ) -> Result<Self, H2Error> {
        local.validate()?;
        let mut connection = Self::new(stream, Role::Client, local);
        connection.write_all(CLIENT_PREFACE).await?;
        connection
            .write_frame(&Frame::Settings {
                ack: false,
                settings,
            })
            .await?;
        if let Some(increment) = connection_window {
            connection
                .write_frame(&Frame::WindowUpdate {
                    stream_id: 0,
                    increment,
                })
                .await?;
            connection.connection_recv_window += i64::from(increment);
        }
        connection.flush().await?;
        Ok(connection)
    }

    /// Start a server connection: write our `SETTINGS` and the connection-level window we are
    /// willing to accept.
    ///
    /// The client preface is read by the caller *before* this, because a listener must decide
    /// which protocol it is speaking before it commits to an HTTP/2 connection (an HTTP/1.1
    /// request that happens to start with `PRI` would otherwise be misread).
    ///
    /// # Errors
    ///
    /// A transport error, or a protocol error for a `SETTINGS` value the RFC forbids.
    pub async fn server_handshake(
        stream: T,
        local: LocalSettings,
        settings: Vec<(u16, u32)>,
        connection_window: u32,
    ) -> Result<Self, H2Error> {
        local.validate()?;
        let mut connection = Self::new(stream, Role::Server, local);
        connection
            .write_frame(&Frame::Settings {
                ack: false,
                settings,
            })
            .await?;
        if connection_window > DEFAULT_WINDOW as u32 {
            let increment = connection_window - DEFAULT_WINDOW as u32;
            connection
                .write_frame(&Frame::WindowUpdate {
                    stream_id: 0,
                    increment,
                })
                .await?;
            connection.connection_recv_window += i64::from(increment);
        }
        connection.flush().await?;
        Ok(connection)
    }

    /// Write raw bytes (the connection preface).
    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), H2Error> {
        self.stream.write_all(bytes).await?;
        Ok(())
    }

    /// The largest number of streams the peer will accept, when it said.
    pub fn peer_max_concurrent_streams(&self) -> Option<u32> {
        self.peer.max_concurrent_streams
    }

    /// Whether the peer has acknowledged our `SETTINGS`.
    pub fn settings_acknowledged(&self) -> bool {
        self.settings_acked
    }

    /// The last stream id the peer's `GOAWAY` promised to finish, when it sent one.
    ///
    /// A `GOAWAY` is not a shutdown: every stream with a lower id may still complete, and a
    /// client that abandoned them would turn a graceful drain into a burst of failures.
    pub fn goaway_last_stream(&self) -> Option<u32> {
        self.goaway_last_stream
    }

    /// Write `GOAWAY` and flush, leaving the connection usable.
    ///
    /// `last_stream` is the highest peer-originated stream this end will finish. A server draining
    /// sends it once with the highest id it saw, keeps serving those streams, and closes when they
    /// are done — which is why this borrows rather than consumes: a drain that gave up the socket
    /// could not finish the streams it just promised to finish.
    ///
    /// # Errors
    ///
    /// Any transport failure.
    pub async fn send_goaway(
        &mut self,
        last_stream: u32,
        code: u32,
        debug: &[u8],
    ) -> Result<(), H2Error> {
        self.write_frame(&Frame::GoAway {
            last_stream_id: last_stream,
            error_code: code,
            debug_data: Bytes::copy_from_slice(debug),
        })
        .await?;
        self.flush().await?;
        Ok(())
    }

    /// Read exactly `buf.len()` bytes of the client preface.
    ///
    /// Exists for the server role when the protocol was recognised by ALPN rather than by the first
    /// bytes: the preface has not been consumed yet and must be before any frame is read.
    pub async fn read_preface_bytes(&mut self, buf: &mut [u8]) -> Result<(), H2Error> {
        let mut filled = 0;
        while filled < buf.len() {
            let read = self.stream.read(&mut buf[filled..]).await?;
            if read == 0 {
                return Err(H2Error::UnexpectedEof);
            }
            filled += read;
        }
        if buf != CLIENT_PREFACE {
            return Err(H2Error::Protocol(
                "the peer did not send the HTTP/2 connection preface".into(),
            ));
        }
        Ok(())
    }

    /// Read exactly one complete frame from the transport.
    ///
    /// # Errors
    ///
    /// [`H2Error::FrameSize`] for a frame larger than the negotiated maximum, which keeps a
    /// hostile length field from choosing our allocation; [`H2Error::UnexpectedEof`] at a clean
    /// end of stream.
    pub async fn read_frame(&mut self) -> Result<Frame, H2Error> {
        loop {
            if self.read_buf.len() >= FRAME_HEADER_LEN {
                let Some(header) = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_LEN]) else {
                    return Err(H2Error::Protocol("invalid frame header format".into()));
                };
                // The bound is *our* advertised maximum: it is we who must allocate the
                // payload, so it is our number that governs regardless of what we send.
                let limit = self.local.max_frame_size;
                if header.length > limit {
                    return Err(H2Error::FrameSize(format!(
                        "frame claims {} bytes, over the advertised maximum {limit}",
                        header.length
                    )));
                }
                let total_len = FRAME_HEADER_LEN + header.length as usize;
                if self.read_buf.len() >= total_len {
                    let _ = self.read_buf.split_to(FRAME_HEADER_LEN);
                    let payload = self.read_buf.split_to(header.length as usize).freeze();
                    return Frame::decode(&header, payload);
                }
            }

            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(H2Error::UnexpectedEof);
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Write one frame, splitting nothing: a frame's payload must already respect the peer's
    /// maximum, which [`Self::write_header_block`] and [`Self::write_data`] take care of.
    ///
    /// The write is bounded by [`Self::set_write_deadline`] when one was set. A peer that opens its
    /// receive window one byte at a time must not be able to hold a stream slot (or the whole
    /// connection) for the length of a handler timeout, and this is the only place a byte reaches the
    /// wire — so it is the only place the bound has to be enforced.
    pub(crate) async fn write_frame(&mut self, frame: &Frame) -> Result<(), H2Error> {
        let bytes = frame.encode();
        self.write_bytes(&bytes).await
    }

    /// Write raw bytes under the connection's write deadline.
    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), H2Error> {
        match self.write_deadline {
            Some(deadline) => {
                match tokio::time::timeout(deadline, self.stream.write_all(bytes)).await {
                    Ok(result) => Ok(result?),
                    Err(_) => Err(H2Error::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the peer did not accept a frame within the configured write bound",
                    ))),
                }
            }
            None => {
                self.stream.write_all(bytes).await?;
                Ok(())
            }
        }
    }

    pub(crate) async fn flush(&mut self) -> Result<(), H2Error> {
        match self.write_deadline {
            Some(deadline) => match tokio::time::timeout(deadline, self.stream.flush()).await {
                Ok(result) => Ok(result?),
                Err(_) => Err(H2Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the peer did not drain within the configured write bound",
                ))),
            },
            None => {
                self.stream.flush().await?;
                Ok(())
            }
        }
    }

    /// Bound every subsequent frame write by `deadline`.
    ///
    /// `None` disables the bound, which is what a client role wants: it is writing to an origin it
    /// chose, and a stalled origin is the caller's timeout to set. A server sets one, because the peer
    /// chose *it*.
    pub fn set_write_deadline(&mut self, deadline: Option<std::time::Duration>) {
        self.write_deadline = deadline;
    }

    /// Write a header block, splitting it across `CONTINUATION` frames as the peer's
    /// `MAX_FRAME_SIZE` requires.
    pub(crate) async fn write_header_block(
        &mut self,
        stream_id: u32,
        block: &[u8],
        end_stream: bool,
    ) -> Result<(), H2Error> {
        let max = self.peer.max_frame_size as usize;
        if block.len() <= max {
            return self
                .write_frame(&Frame::Headers {
                    stream_id,
                    end_stream,
                    end_headers: true,
                    header_block: Bytes::copy_from_slice(block),
                })
                .await;
        }

        let (head, rest) = block.split_at(max);
        self.write_frame(&Frame::Headers {
            stream_id,
            end_stream,
            end_headers: false,
            header_block: Bytes::copy_from_slice(head),
        })
        .await?;

        let mut chunks = rest.chunks(max).peekable();
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            self.write_frame(&Frame::Continuation {
                stream_id,
                end_headers: last,
                header_block: Bytes::copy_from_slice(chunk),
            })
            .await?;
        }
        Ok(())
    }

    /// Write body bytes, respecting both the connection and the stream window.
    ///
    /// `stream_window` is the caller's remaining credit for this stream; the returned value is
    /// what is left after the write, so a caller can resume without re-deriving it.
    ///
    /// # Errors
    ///
    /// Any transport failure, and a protocol error when a `WINDOW_UPDATE` the peer sends is
    /// zero — which §6.9 makes a connection error, and which is also the shape of a peer trying
    /// to make us spin.
    pub(crate) async fn write_data(
        &mut self,
        stream_id: u32,
        body: &[u8],
        end_stream: bool,
        mut stream_window: i64,
    ) -> Result<i64, H2Error> {
        let max = self.peer.max_frame_size as usize;
        let mut remaining = body;
        while !remaining.is_empty() {
            if self.connection_send_window <= 0 {
                self.flush().await?;
                self.wait_for_connection_credit().await?;
            }
            if stream_window <= 0 {
                self.flush().await?;
                stream_window += self.wait_for_stream_credit(stream_id).await?;
                continue;
            }
            let allowed = usize::try_from(self.connection_send_window)
                .unwrap_or(usize::MAX)
                .min(usize::try_from(stream_window).unwrap_or(usize::MAX))
                .min(max);
            if allowed == 0 {
                self.flush().await?;
                if self.connection_send_window <= 0 {
                    self.wait_for_connection_credit().await?;
                }
                if stream_window <= 0 {
                    stream_window += self.wait_for_stream_credit(stream_id).await?;
                }
                continue;
            }
            let take = remaining.len().min(allowed);
            let (chunk, rest) = remaining.split_at(take);
            let last = rest.is_empty();
            self.write_frame(&Frame::Data {
                stream_id,
                end_stream: end_stream && last,
                payload: Bytes::copy_from_slice(chunk),
            })
            .await?;
            self.connection_send_window -= chunk.len() as i64;
            stream_window -= chunk.len() as i64;
            remaining = rest;
            if stream_window <= 0 || self.connection_send_window <= 0 {
                self.flush().await?;
            }
        }
        if body.is_empty() && end_stream {
            self.write_frame(&Frame::Data {
                stream_id,
                end_stream: true,
                payload: Bytes::new(),
            })
            .await?;
        }
        Ok(stream_window)
    }

    async fn wait_for_connection_credit(&mut self) -> Result<(), H2Error> {
        while self.connection_send_window <= 0 {
            let frame = self.read_frame().await?;
            match frame {
                Frame::WindowUpdate {
                    stream_id: 0,
                    increment,
                } => self.apply_connection_window_update(increment)?,
                other => self.handle_housekeeping(other).await?,
            }
        }
        Ok(())
    }

    async fn wait_for_stream_credit(&mut self, stream_id: u32) -> Result<i64, H2Error> {
        loop {
            let frame = self.read_frame().await?;
            match frame {
                Frame::WindowUpdate {
                    stream_id: id,
                    increment,
                } if id == stream_id => {
                    if increment == 0 {
                        return Err(H2Error::Protocol(
                            "a zero WINDOW_UPDATE increment is a connection error".into(),
                        ));
                    }
                    return Ok(i64::from(increment));
                }
                Frame::RstStream {
                    stream_id: id,
                    error_code,
                } if id == stream_id => {
                    return Err(H2Error::StreamReset {
                        stream_id,
                        error_code,
                    });
                }
                other => self.handle_housekeeping(other).await?,
            }
        }
    }

    /// Apply a connection-level `WINDOW_UPDATE`, refusing an overflow.
    pub(crate) fn apply_connection_window_update(&mut self, increment: u32) -> Result<(), H2Error> {
        if increment == 0 {
            return Err(H2Error::Protocol(
                "a zero WINDOW_UPDATE increment is a connection error".into(),
            ));
        }
        self.connection_send_window += i64::from(increment);
        // RFC 9113 §6.9.1: a window above 2^31-1 is a flow-control error.
        if self.connection_send_window > 0x7FFF_FFFF {
            return Err(H2Error::Protocol(
                "connection flow-control window overflowed".into(),
            ));
        }
        Ok(())
    }

    /// Handle a frame that carries no application data but must be answered or recorded.
    ///
    /// Returns `Ok(())` for a frame it consumed, and an error for a frame that may not arrive
    /// where it did (an unexpected `CONTINUATION`, a `PUSH_PROMISE` from a client).
    pub(crate) async fn handle_housekeeping(&mut self, frame: Frame) -> Result<(), H2Error> {
        match frame {
            Frame::Settings {
                ack: false,
                settings,
            } => {
                self.apply_peer_settings(&settings)?;
                self.write_frame(&Frame::Settings {
                    ack: true,
                    settings: Vec::new(),
                })
                .await?;
                self.flush().await?;
                Ok(())
            }
            Frame::Settings { ack: true, .. } => {
                self.settings_acked = true;
                Ok(())
            }
            Frame::Ping {
                ack: false,
                opaque_data,
            } => {
                self.write_frame(&Frame::Ping {
                    ack: true,
                    opaque_data,
                })
                .await?;
                self.flush().await?;
                Ok(())
            }
            Frame::Ping { ack: true, .. } => Ok(()),
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                self.goaway_last_stream = Some(last_stream_id);
                if error_code != error_code::NO_ERROR {
                    return Err(H2Error::GoAway {
                        error_code,
                        debug_data: debug_data.to_vec(),
                    });
                }
                Ok(())
            }
            // A `PRIORITY` frame is advisory and may be ignored (§5.3.1 makes the dependency
            // tree a suggestion). Discarding it rather than erroring is what keeps a client that
            // sends priorities from breaking our connection.
            Frame::Priority { .. } => Ok(()),
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                if stream_id == 0 {
                    self.apply_connection_window_update(increment)
                } else if increment == 0 {
                    Err(H2Error::Protocol(
                        "a zero WINDOW_UPDATE increment is a stream error".into(),
                    ))
                } else {
                    // A stream-level update for a stream this layer does not track belongs to
                    // a role's own accounting; it is not a connection error.
                    Ok(())
                }
            }
            // A `PUSH_PROMISE` from a client, or an unsolicited one from a server, is a
            // protocol violation of the role's contract rather than of this layer; the role
            // decides (the client declines it, the server never expects one).
            Frame::PushPromise { .. } => Err(H2Error::Protocol(
                "PUSH_PROMISE is not legal from this peer".into(),
            )),
            Frame::Continuation { .. } => Err(H2Error::Protocol(
                "CONTINUATION outside a header block".into(),
            )),
            Frame::Headers { .. } | Frame::Data { .. } | Frame::RstStream { .. } => Err(
                H2Error::Protocol("a data-bearing frame arrived where none was expected".into()),
            ),
        }
    }

    /// Adopt the peer's `SETTINGS`, including its effect on our sends.
    ///
    /// A change to `HEADER_TABLE_SIZE` becomes a pending dynamic-table size update, emitted at
    /// the head of our next header block (RFC 7541 §4.2 requires it to be the first thing in the
    /// block, which is why it is buffered here rather than written immediately).
    pub(crate) fn apply_peer_settings(&mut self, settings: &[(u16, u32)]) -> Result<(), H2Error> {
        let previous_table_size = self.peer.header_table_size;
        self.peer.apply(settings)?;
        if self.peer.header_table_size != previous_table_size {
            self.encoder.set_max_size(
                self.peer.header_table_size as usize,
                &mut self.pending_table_update,
            );
        }
        Ok(())
    }

    /// Encode a header list, preceded by any pending dynamic-table size update.
    pub(crate) fn encode_header_block<'a, I>(&mut self, headers: I) -> Bytes
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        if self.pending_table_update.is_empty() {
            return self.encoder.encode(headers);
        }
        let mut out = std::mem::take(&mut self.pending_table_update);
        out.extend_from_slice(&self.encoder.encode(headers));
        Bytes::from(out)
    }

    /// Read a header block, reassembling `CONTINUATION` frames.
    ///
    /// # Errors
    ///
    /// [`H2Error::Protocol`] when a foreign frame interleaves: RFC 9113 §6.10 requires the
    /// continuation sequence to be contiguous, and a decoder that tolerated a gap would accept a
    /// header block assembled from two different streams' fragments.
    pub(crate) async fn read_header_block(&mut self, first: Bytes) -> Result<Bytes, H2Error> {
        let mut block = BytesMut::from(&first[..]);
        loop {
            let frame = self.read_frame().await?;
            match frame {
                Frame::Continuation {
                    end_headers,
                    header_block,
                    ..
                } => {
                    block.extend_from_slice(&header_block);
                    if end_headers {
                        return Ok(block.freeze());
                    }
                }
                Frame::Ping { .. }
                | Frame::WindowUpdate { .. }
                | Frame::Settings { .. }
                | Frame::GoAway { .. }
                | Frame::Priority { .. } => {
                    self.handle_housekeeping(frame).await?;
                }
                other => {
                    return Err(H2Error::Protocol(format!(
                        "expected CONTINUATION inside a header block, got {other:?}"
                    )));
                }
            }
        }
    }

    /// Account `bytes` of inbound `DATA` against the receive windows, refusing an overflow.
    ///
    /// RFC 9113 §6.9.1: a peer may not send more than the window allows. Enforcing it is what makes the
    /// advertised window a *bound* rather than a suggestion — a peer that ignores it must be failed, or
    /// every memory guarantee the window represents is fiction.
    ///
    /// # Errors
    ///
    /// [`H2Error::Protocol`] when either window is overrun, which §6.9 makes a connection error.
    pub(crate) fn consume_inbound(&mut self, bytes: u32) -> Result<(), H2Error> {
        if bytes == 0 {
            return Ok(());
        }
        self.connection_recv_window -= i64::from(bytes);
        if self.connection_recv_window < 0 {
            return Err(H2Error::Protocol(
                "the peer exceeded the connection receive window".into(),
            ));
        }
        Ok(())
    }

    /// Send a connection-level `WINDOW_UPDATE`, restoring credit we have given back.
    pub(crate) async fn replenish_connection(&mut self, bytes: u32) -> Result<(), H2Error> {
        if bytes == 0 {
            return Ok(());
        }
        self.connection_recv_window += i64::from(bytes);
        if self.connection_recv_window > 0x7FFF_FFFF {
            return Err(H2Error::Protocol(
                "connection receive window overflowed".into(),
            ));
        }
        self.write_frame(&Frame::WindowUpdate {
            stream_id: 0,
            increment: bytes,
        })
        .await?;
        Ok(())
    }

    /// Send a stream-level `WINDOW_UPDATE` after consuming `bytes` of body.
    pub(crate) async fn replenish(&mut self, stream_id: u32, bytes: u32) -> Result<(), H2Error> {
        if bytes == 0 {
            return Ok(());
        }
        self.write_frame(&Frame::WindowUpdate {
            stream_id,
            increment: bytes,
        })
        .await?;
        Ok(())
    }

    /// Send `RST_STREAM` for one stream.
    pub(crate) async fn reset_stream(
        &mut self,
        stream_id: u32,
        error_code: u32,
    ) -> Result<(), H2Error> {
        self.write_frame(&Frame::RstStream {
            stream_id,
            error_code,
        })
        .await
    }

    /// The transport, for a role that must hand it to something else (a `CONNECT` tunnel).
    pub fn into_inner(self) -> T {
        self.stream
    }

    /// The HPACK decoder, for a role that must decode a header block it just read.
    pub(crate) fn decoder(&mut self) -> &mut HpackDecoder {
        &mut self.decoder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_originates_odd_stream_ids_and_a_server_even() {
        assert_eq!(Role::Client.own_parity(), 1);
        assert_eq!(Role::Server.own_parity(), 0);
        assert_eq!(Role::Client.preface(), CLIENT_PREFACE);
        assert!(Role::Server.preface().is_empty());
        assert!(!Role::Client.may_push());
        assert!(Role::Server.may_push());
    }

    #[test]
    fn peer_settings_ignore_unknown_parameters() {
        let mut peer = PeerSettings::default();
        peer.apply(&[(0x99, 7), (SETTING_INITIAL_WINDOW_SIZE, 1_000_000)])
            .expect("an unknown parameter is not an error");
        assert_eq!(peer.initial_window_size, 1_000_000);
    }

    #[test]
    fn peer_settings_refuse_an_illegal_window() {
        let mut peer = PeerSettings::default();
        assert!(
            peer.apply(&[(SETTING_INITIAL_WINDOW_SIZE, 0x8000_0000)])
                .is_err()
        );
        assert!(peer.apply(&[(SETTING_MAX_FRAME_SIZE, 100)]).is_err());
        assert!(peer.apply(&[(SETTING_ENABLE_PUSH, 2)]).is_err());
    }

    #[test]
    fn local_settings_refuse_a_frame_size_the_rfc_forbids() {
        let mut local = LocalSettings::for_ingress();
        local.max_frame_size = 1024;
        assert!(local.validate().is_err());
        local.max_frame_size = MAX_MAX_FRAME_SIZE;
        assert!(local.validate().is_ok());
    }

    #[test]
    fn stream_ids_advance_by_two_and_stop_at_the_end_of_the_space() {
        let mut connection = H2Connection::new((), Role::Client, LocalSettings::for_client());
        assert_eq!(connection.allocate_stream_id(), Some(1));
        assert_eq!(connection.allocate_stream_id(), Some(3));
        connection.next_stream_id = 0x7FFF_FFFE;
        assert_eq!(connection.allocate_stream_id(), Some(0x7FFF_FFFE));
        assert_eq!(
            connection.allocate_stream_id(),
            None,
            "the parity space is exhausted, not wrapped"
        );
    }

    #[test]
    fn a_settings_ack_is_a_zero_length_frame_with_the_ack_flag() {
        let ack = Frame::Settings {
            ack: true,
            settings: Vec::new(),
        }
        .encode();
        assert_eq!(ack.len(), FRAME_HEADER_LEN);
        assert_eq!(ack[3], FRAME_SETTINGS);
        assert_eq!(ack[4], FLAG_ACK);
        assert_eq!(&ack[5..9], &[0, 0, 0, 0], "an ACK is always on stream 0");
    }
}
