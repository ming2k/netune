use bytes::{Bytes, BytesMut};

use crate::error::WsError;
use crate::frame::{CloseCode, Frame, Opcode};

/// The opcode of a *data* message (RFC 6455 §5.6): a fragmented message can be
/// started only by `Text` or `Binary`, never by a control opcode or a
/// `Continuation`. Encoding that in the type is what lets the assembler's
/// completion match be exhaustive without an `unreachable!()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataOpcode {
    /// A UTF-8 text message.
    Text,
    /// A raw binary message.
    Binary,
}

impl DataOpcode {
    /// Classify a frame opcode as a data-message start, or `None` when the
    /// opcode cannot begin a data message.
    const fn of(opcode: Opcode) -> Option<Self> {
        match opcode {
            Opcode::Text => Some(Self::Text),
            Opcode::Binary => Some(Self::Binary),
            Opcode::Continuation | Opcode::Close | Opcode::Ping | Opcode::Pong => None,
        }
    }

    /// The wire opcode this message is carried in.
    pub const fn as_opcode(self) -> Opcode {
        match self {
            Self::Text => Opcode::Text,
            Self::Binary => Opcode::Binary,
        }
    }
}

/// A reassembled WebSocket message ready for application processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A UTF-8 text message.
    Text(String),
    /// A raw binary message.
    Binary(Bytes),
    /// A ping frame with optional payload (up to 125 bytes).
    Ping(Bytes),
    /// A pong frame with optional payload (up to 125 bytes).
    Pong(Bytes),
    /// A close frame with optional code and description.
    Close(Option<CloseReason>),
}

/// Description of connection closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReason {
    /// Numeric WebSocket close code.
    pub code: CloseCode,
    /// UTF-8 close reason text.
    pub description: String,
}

impl CloseReason {
    /// Construct a close reason from code and description.
    pub fn new(code: CloseCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }
}

/// Incremental UTF-8 validation across fragmented text frames.
///
/// RFC 6455 §8.1 (closed sub-issue: a UTF-8 sequence spanning frame
/// boundaries) requires that a text message be validated incrementally:
/// an invalid byte anywhere fails the message *at that frame*, not after the
/// whole message has reassembled. Deferring to the end lets a hostile peer
/// stretch an attack window by feeding one illegal byte per message.
///
/// Design note: the canonical micro-implementation here is Hoehrmann's DFA,
/// whose 400-byte table is public domain but notorious for transcription
/// errors when hand-copied. Rather than embed a possibly-mistyped table, this
/// validator implements the *same* grammar directly: sequence classification
/// per RFC 3629 §4 (with overlong, surrogate, and >U+10FFFF exclusion), and
/// continuation-byte checks in a two-state machine. The test vectors below
/// (overlong, surrogates, plane-16 edge, split fragments) pin correctness.
#[derive(Debug)]
struct Utf8Validator {
    /// Bytes still needed to complete the current multi-byte sequence
    /// (0 = ground state). None means we're mid-sequence.
    remaining: u8,
    /// For the lead byte seen, the *low* and *high* bounds its first
    /// continuation byte must satisfy (overlong/surrogate/ceiling checks).
    range_lo: u8,
    range_hi: u8,
    /// Bytes of the current message so far, for the final assembly.
    buffer: BytesMut,
    /// Hard ceiling for reassembled text messages.
    max_bytes: usize,
}

impl Utf8Validator {
    fn new(max_bytes: usize) -> Self {
        Self {
            remaining: 0,
            range_lo: 0,
            range_hi: 0,
            buffer: BytesMut::new(),
            max_bytes,
        }
    }

    /// Feed one frame's payload; returns `Err` on the first invalid byte.
    fn push(&mut self, chunk: &[u8]) -> Result<(), WsError> {
        for &byte in chunk {
            if self.remaining == 0 {
                // Expecting a lead byte.
                let (needed, lo, hi): (u8, u8, u8) = match byte {
                    0x00..=0x7F => (0, 0, 0), // ASCII: complete immediately
                    0xC2..=0xDF => (1, 0x80, 0xBF),
                    0xE0 => (2, 0xA0, 0xBF), // excludes overlong E0 80..9F
                    0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
                    0xED => (2, 0x80, 0x9F), // excludes surrogates U+D800..DFFF
                    0xF0 => (3, 0x90, 0xBF), // excludes overlong F0 80..8F
                    0xF1..=0xF3 => (3, 0x80, 0xBF),
                    0xF4 => (3, 0x80, 0x8F), // excludes > U+10FFFF
                    // 0x80..=0xBF (stray continuation), 0xC0, 0xC1, 0xF5..=0xFF
                    _ => {
                        return Err(WsError::protocol(
                            "Invalid UTF-8 lead byte in text message",
                            CloseCode::INVALID_PAYLOAD,
                        ));
                    }
                };
                self.remaining = needed;
                self.range_lo = lo;
                self.range_hi = hi;
                if needed == 0 {
                    continue;
                }
            } else {
                // Expecting a continuation byte within the lead's window.
                let in_window = (self.range_lo..=self.range_hi).contains(&byte);
                let is_cont = (0x80..=0xBF).contains(&byte);
                if !is_cont || !in_window {
                    return Err(WsError::protocol(
                        "Invalid UTF-8 continuation byte in text message",
                        CloseCode::INVALID_PAYLOAD,
                    ));
                }
                self.remaining -= 1;
                // Subsequent continuations use the full 0x80..=0xBF window.
                self.range_lo = 0x80;
                self.range_hi = 0xBF;
            }
        }
        if self.buffer.len() + chunk.len() > self.max_bytes {
            return Err(WsError::PayloadTooLarge {
                length: self.buffer.len() + chunk.len(),
                max: self.max_bytes,
            });
        }
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    /// Consume the assembled buffer once the final frame carried `fin`.
    fn finish(&mut self) -> Result<String, WsError> {
        if self.remaining != 0 {
            return Err(WsError::protocol(
                "Fragmented text message ends mid-UTF-8-sequence",
                CloseCode::INVALID_PAYLOAD,
            ));
        }
        let assembled = std::mem::take(&mut self.buffer).freeze();
        String::from_utf8(assembled.to_vec()).map_err(|_| {
            // Unreachable in practice (the validator already enforced the
            // grammar), but the conversion is the honest final word.
            WsError::protocol(
                "Fragmented text message failed final UTF-8 conversion",
                CloseCode::INVALID_PAYLOAD,
            )
        })
    }

    fn clear(&mut self) {
        self.remaining = 0;
        self.range_lo = 0;
        self.range_hi = 0;
        self.buffer.clear();
    }
}

/// State machine for reassembling fragmented WebSocket data frames (RFC 6455 §5.4).
#[derive(Debug)]
pub struct MessageAssembler {
    fragmented_opcode: Option<DataOpcode>,
    /// Incremental UTF-8 validator, driven only while assembling a text message.
    utf8: Utf8Validator,
    /// Reassembled bytes for the in-flight binary message.
    binary_buffer: BytesMut,
    max_message_bytes: usize,
}

impl MessageAssembler {
    /// Create a new assembler with a byte ceiling for reassembled messages.
    pub fn new(max_message_bytes: usize) -> Self {
        Self {
            fragmented_opcode: None,
            utf8: Utf8Validator::new(max_message_bytes),
            binary_buffer: BytesMut::new(),
            max_message_bytes,
        }
    }

    /// The opcode of the fragmented message currently being assembled, if any.
    ///
    /// Returns the wire [`Opcode`] so callers classify the in-flight message
    /// (e.g. for tracing) without needing to know about `DataOpcode`.
    pub fn pending_opcode(&self) -> Option<Opcode> {
        self.fragmented_opcode.map(DataOpcode::as_opcode)
    }

    /// Reset any in-progress fragmented message state.
    pub fn reset(&mut self) {
        self.fragmented_opcode = None;
        self.utf8.clear();
        self.binary_buffer.clear();
    }

    /// Ingest a single frame and return a completed `Message` if ready.
    ///
    /// Control frames (Ping, Pong, Close) are returned immediately, even if
    /// a fragmented message is currently in-flight (RFC 6455 §5.4).
    pub fn process_frame(&mut self, frame: Frame) -> Result<Option<Message>, WsError> {
        match frame.opcode {
            // Control frames can interleave during fragmented data transmission
            Opcode::Ping => Ok(Some(Message::Ping(frame.payload))),
            Opcode::Pong => Ok(Some(Message::Pong(frame.payload))),
            Opcode::Close => {
                let reason = Self::parse_close_payload(&frame.payload)?;
                Ok(Some(Message::Close(reason)))
            }

            // Unfragmented data frames
            Opcode::Text if frame.fin && self.fragmented_opcode.is_none() => {
                // Full message in one frame: validate whole.
                let text = std::str::from_utf8(&frame.payload).map_err(|_| {
                    WsError::protocol("Invalid UTF-8 in text frame", CloseCode::INVALID_PAYLOAD)
                })?;
                Ok(Some(Message::Text(text.to_owned())))
            }
            Opcode::Binary if frame.fin && self.fragmented_opcode.is_none() => {
                if frame.payload.len() > self.max_message_bytes {
                    return Err(WsError::PayloadTooLarge {
                        length: frame.payload.len(),
                        max: self.max_message_bytes,
                    });
                }
                Ok(Some(Message::Binary(frame.payload)))
            }

            // Starting a fragmented data message
            Opcode::Text | Opcode::Binary if !frame.fin => {
                if self.fragmented_opcode.is_some() {
                    return Err(WsError::protocol(
                        "Cannot initiate new data frame while previous fragmented message is unclosed",
                        CloseCode::PROTOCOL_ERROR,
                    ));
                }
                // `DataOpcode::of` is total over `Text | Binary`, so the `let
                // Some` cannot fail here; expressing the state as `DataOpcode`
                // removes the "any Opcode" lie that the completion match below
                // used to paper over with `unreachable!()`.
                let Some(kind) = DataOpcode::of(frame.opcode) else {
                    return Err(WsError::protocol(
                        "fragmented message must begin with a data opcode",
                        CloseCode::PROTOCOL_ERROR,
                    ));
                };
                self.fragmented_opcode = Some(kind);
                match kind {
                    DataOpcode::Text => self.utf8.push(&frame.payload)?,
                    DataOpcode::Binary => {
                        if self.binary_buffer.len() + frame.payload.len() > self.max_message_bytes {
                            return Err(WsError::PayloadTooLarge {
                                length: self.binary_buffer.len() + frame.payload.len(),
                                max: self.max_message_bytes,
                            });
                        }
                        self.binary_buffer.extend_from_slice(&frame.payload);
                    }
                }
                Ok(None)
            }

            // Continuation frames
            Opcode::Continuation => {
                let Some(kind) = self.fragmented_opcode else {
                    return Err(WsError::protocol(
                        "Received continuation frame without preceding initial fragmented frame",
                        CloseCode::PROTOCOL_ERROR,
                    ));
                };

                match kind {
                    DataOpcode::Text => self.utf8.push(&frame.payload)?,
                    DataOpcode::Binary => {
                        let new_len = self.binary_buffer.len() + frame.payload.len();
                        if new_len > self.max_message_bytes {
                            return Err(WsError::PayloadTooLarge {
                                length: new_len,
                                max: self.max_message_bytes,
                            });
                        }
                        self.binary_buffer.extend_from_slice(&frame.payload);
                    }
                }

                if frame.fin {
                    self.fragmented_opcode = None;
                    match kind {
                        DataOpcode::Text => {
                            let text = self.utf8.finish()?;
                            self.utf8.clear();
                            Ok(Some(Message::Text(text)))
                        }
                        DataOpcode::Binary => {
                            let assembled = self.binary_buffer.split().freeze();
                            Ok(Some(Message::Binary(assembled)))
                        }
                    }
                } else {
                    Ok(None)
                }
            }

            // Invalid state: unfragmented data frame arrived while fragment in progress
            Opcode::Text | Opcode::Binary => Err(WsError::protocol(
                "Received unfragmented data frame while fragmented stream is active",
                CloseCode::PROTOCOL_ERROR,
            )),
        }
    }

    /// Parse close payload (RFC 6455 §5.5.1).
    fn parse_close_payload(payload: &[u8]) -> Result<Option<CloseReason>, WsError> {
        if payload.is_empty() {
            return Ok(None);
        }
        if payload.len() == 1 {
            return Err(WsError::protocol(
                "Close frame payload cannot be 1 byte",
                CloseCode::PROTOCOL_ERROR,
            ));
        }

        let code_raw = u16::from_be_bytes([payload[0], payload[1]]);
        let code = CloseCode(code_raw);

        // Reserved / illegal wire codes
        if !code.is_wire_legal() {
            return Err(WsError::protocol(
                format!("Received invalid close status code on wire: {code_raw}"),
                CloseCode::PROTOCOL_ERROR,
            ));
        }

        let desc_bytes = &payload[2..];
        let description = std::str::from_utf8(desc_bytes)
            .map_err(|_| {
                WsError::protocol(
                    "Close reason description is not valid UTF-8",
                    CloseCode::INVALID_PAYLOAD,
                )
            })?
            .to_owned();

        Ok(Some(CloseReason { code, description }))
    }
}

#[cfg(test)]
mod tests;
