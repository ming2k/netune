//! WebSocket transport stream and client orchestration.
//!
//! Provides an owned, full-duplex WebSocket stream ([`WsStream`]) over any
//! asynchronous transport, with automatic ping/pong heartbeat echoing, close
//! handshake completion, and nanosecond trace integration via [`TimedIo`].

use bytes::{Bytes, BytesMut};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use netune_trace::{EventKind, FrameClass, Recorder};
use netune_ws::{
    CloseCode, CloseReason, Frame, FrameDecoder, FrameEncoder, Limits, Message, MessageAssembler,
    Opcode, Role, generate_mask,
};

use crate::error::NetError;

/// Re-exported from the codec: frame/message size ceilings live with the
/// framing logic that enforces them.
pub use netune_ws::Limits as WsLimits;

/// Optional negotiation knobs for the WebSocket upgrade request.
#[derive(Debug, Clone, Default)]
pub struct WsHandshake {
    /// Subprotocols to offer, in preference order (RFC 6455 §4.1). Sent as
    /// `Sec-WebSocket-Protocol`; the server's echo must match one of these,
    /// or be absent (declining the negotiation).
    pub subprotocols: Vec<String>,
    /// Extra headers beyond the RFC-mandated set (e.g. `authorization`).
    /// Inserted into the upgrade request as-is; names must be valid HTTP
    /// header names.
    pub extra_headers: Vec<(String, String)>,
    /// Size ceilings for frames and reassembled messages.
    pub limits: WsLimits,
}

impl WsHandshake {
    /// Offer one subprotocol.
    pub fn with_subprotocol(mut self, subprotocol: impl Into<String>) -> Self {
        self.subprotocols.push(subprotocol.into());
        self
    }

    /// Attach one extra request header.
    pub fn with_extra_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }

    /// Override the size limits.
    pub fn with_limits(mut self, limits: WsLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// A full-duplex client-side WebSocket stream over an asynchronous transport.
pub struct WsStream<S> {
    stream: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    assembler: MessageAssembler,
    limits: Limits,
    recorder: Option<Arc<Mutex<Recorder>>>,
    closed: bool,
    /// Payload of the most recent client-issued ping, awaiting its matching
    /// pong. Incoming pongs that carry a different payload are peer-initiated
    /// pongs: liveness evidence, but not a discharge of our probe.
    outstanding_ping: Option<Bytes>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
    /// Wrap an established transport and optional residual buffer into a `WsStream`.
    pub fn new(
        stream: S,
        initial_buf: BytesMut,
        recorder: Option<Arc<Mutex<Recorder>>>,
        limits: Limits,
    ) -> Self {
        Self {
            stream,
            read_buf: initial_buf,
            write_buf: BytesMut::with_capacity(4096),
            assembler: MessageAssembler::new(limits.max_message_bytes),
            limits,
            recorder,
            closed: false,
            outstanding_ping: None,
        }
    }

    /// Send a high-level WebSocket message to the server.
    ///
    /// A `close` message on an already-closed stream is a no-op (the close
    /// handshake is complete; a second close frame would be a redundant send,
    /// which RFC 6455 §7.1.1 discards silently). Any other message on a
    /// closed stream is an error.
    pub async fn send(&mut self, message: Message) -> Result<(), NetError> {
        if self.closed {
            return match message {
                // Completing an already-completed handshake: nothing to do.
                Message::Close(_) => Ok(()),
                _ => Err(NetError::Protocol("WebSocket stream is closed".to_string())),
            };
        }

        let frame = match message {
            Message::Text(text) => Frame::text(Bytes::from(text)),
            Message::Binary(bytes) => Frame::binary(bytes),
            Message::Ping(payload) => {
                // Track this probe so only its own pong discharges it.
                self.outstanding_ping = Some(payload.clone());
                Frame::ping(payload)
            }
            Message::Pong(payload) => Frame::pong(payload),
            Message::Close(reason) => {
                self.closed = true;
                let (code, desc) = match reason {
                    Some(r) => (Some(r.code), r.description),
                    None => (None, String::new()),
                };
                Frame::close(code, &desc)
            }
        };

        self.write_frame(&frame).await
    }

    /// Send a UTF-8 text message.
    pub async fn send_text(&mut self, text: impl Into<String>) -> Result<(), NetError> {
        self.send(Message::Text(text.into())).await
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, data: impl Into<Bytes>) -> Result<(), NetError> {
        self.send(Message::Binary(data.into())).await
    }

    /// Send an unsolicited ping control frame.
    pub async fn send_ping(&mut self, payload: impl Into<Bytes>) -> Result<(), NetError> {
        self.send(Message::Ping(payload.into())).await
    }

    /// Send a pong control frame.
    pub async fn send_pong(&mut self, payload: impl Into<Bytes>) -> Result<(), NetError> {
        self.send(Message::Pong(payload.into())).await
    }

    /// Initiate an orderly connection close handshake (RFC 6455 §5.5.1).
    pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), NetError> {
        self.send(Message::Close(Some(CloseReason::new(code, reason))))
            .await
    }

    /// Receive the next application-level message.
    ///
    /// Automatically handles protocol-level requirements:
    /// - Echoes a Pong frame immediately upon receipt of a Ping (RFC 6455 §5.5.2).
    /// - Completes the Close handshake, echoing the peer's status code
    ///   (RFC 6455 §5.5.1: the endpoint *should* answer close with close,
    ///   matching the received code when one was given).
    /// - Reassembles fragmented data frames with incremental UTF-8 validation
    ///   for text messages.
    /// - Records each *frame* crossing the wire as `EventKind::WsFrame`, so
    ///   fragmented messages stay individually visible in the trace.
    pub async fn receive(&mut self) -> Result<Option<Message>, NetError> {
        loop {
            // First, try decoding any complete frames already in read_buf
            if let Some(frame) = FrameDecoder::decode(
                &mut self.read_buf,
                Role::Client,
                self.limits.max_frame_bytes,
            )
            .map_err(|e| NetError::Protocol(format!("WebSocket decode: {e}")))?
            {
                // Frame-level trace: every frame crossing the wire, with its
                // payload class and byte count. Fragmented parts remain
                // individually visible in the trace.
                let frame_class = match frame.opcode {
                    Opcode::Text => FrameClass::Text,
                    Opcode::Binary => FrameClass::Usage,
                    Opcode::Ping | Opcode::Pong | Opcode::Close => FrameClass::KeepAlive,
                    Opcode::Continuation => match self.assembler.pending_opcode() {
                        Some(Opcode::Text) => FrameClass::Text,
                        Some(Opcode::Binary) => FrameClass::Usage,
                        _ => FrameClass::Unknown,
                    },
                };
                if let Some(ref rec) = self.recorder {
                    rec.lock().unwrap_or_else(|e| e.into_inner()).mark(
                        EventKind::WsFrame,
                        frame_class.code() as u32,
                        frame.payload.len() as u32,
                    );
                }

                // Control frame automatic responses
                let peer_close = match frame.opcode {
                    Opcode::Ping => {
                        // Immediately respond with Pong carrying identical payload
                        let pong_frame = Frame::pong(frame.payload.clone());
                        self.write_frame(&pong_frame).await?;
                        None
                    }
                    Opcode::Close if !self.closed => {
                        // Peer initiated close: echo their code if given
                        // (RFC 6455 §5.5.1), else 1000.
                        let echo = FrameDecoder::parse_close_code(&frame.payload)
                            .unwrap_or(CloseCode::NORMAL);
                        let close_reply = Frame::close(Some(echo), "");
                        let _ = self.write_frame(&close_reply).await;
                        self.closed = true;
                        Some(echo)
                    }
                    Opcode::Close => Some(CloseCode::NORMAL),
                    Opcode::Pong => {
                        // Discharge our outstanding probe only if the payload
                        // matches; a peer-initiated pong is liveness evidence
                        // but not an answer to our question.
                        if let Some(expected) = self.outstanding_ping.as_ref()
                            && frame.payload == *expected
                        {
                            self.outstanding_ping = None;
                        }
                        None
                    }
                    _ => None,
                };

                // Assemble into a complete application Message
                if let Some(msg) = self
                    .assembler
                    .process_frame(frame)
                    .map_err(|e| NetError::Protocol(format!("WebSocket assemble: {e}")))?
                {
                    // Message-level event: the assembler saw a complete
                    // message; the frame-level events above already cover
                    // every frame that composed it.
                    if let Some(ref rec) = self.recorder {
                        let class = match &msg {
                            Message::Text(_) => FrameClass::Text,
                            Message::Binary(_) => FrameClass::Usage,
                            Message::Ping(_) | Message::Pong(_) => FrameClass::KeepAlive,
                            Message::Close(_) => FrameClass::Open,
                        };
                        rec.lock().unwrap_or_else(|e| e.into_inner()).mark(
                            EventKind::ProtocolFrame,
                            class.code() as u32,
                            0,
                        );
                    }
                    return Ok(Some(msg));
                }

                if let Some(echo_code) = peer_close {
                    // The close frame was consumed by the handshake reply, but
                    // the peer's close must still surface as a Message::Close.
                    return Ok(Some(Message::Close(Some(CloseReason::new(echo_code, "")))));
                }
                continue;
            }

            // Need more data from underlying socket
            let bytes_read = self
                .stream
                .read_buf(&mut self.read_buf)
                .await
                .map_err(|e| NetError::Connect(format!("WebSocket read failed: {e}")))?;

            if bytes_read == 0 {
                if self.closed {
                    return Ok(None);
                }
                return Err(NetError::Protocol(
                    "WebSocket connection closed prematurely by peer".to_string(),
                ));
            }
        }
    }

    /// Whether a pong carrying `payload` answers the currently outstanding
    /// client ping. The session layer asks this so only a *matching* pong
    /// discharges its probe; peer-initiated pongs are liveness evidence but
    /// not answers.
    pub fn outstanding_ping_matches(&self, payload: &[u8]) -> bool {
        self.outstanding_ping
            .as_ref()
            .map(|expected| expected.as_ref() == payload)
            .unwrap_or(false)
    }

    /// Internal helper: write a masked frame to the stream.
    async fn write_frame(&mut self, frame: &Frame) -> Result<(), NetError> {
        let mask = Some(generate_mask());
        self.write_buf.clear();
        FrameEncoder::encode(frame, mask, &mut self.write_buf);
        self.stream
            .write_all(&self.write_buf)
            .await
            .map_err(|e| NetError::Connect(format!("WebSocket write failed: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| NetError::Connect(format!("WebSocket flush failed: {e}")))?;
        Ok(())
    }
}
