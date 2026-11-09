// SPDX-License-Identifier: MIT

//! One HTTP/3 request or response stream.

use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;
use netune_quic::quinn;

use crate::error::H3Error;
use crate::proto::code::{error_code, frame_type};
use crate::proto::frame::{self, Frame};
use crate::proto::headers::{decode_request, decode_response, decode_trailers};
use crate::qpack::{DecoderInstruction, HeaderField};

use super::shared::Shared;

/// The bidirectional stream state machine shared by the client and server
/// adapters.
pub(crate) struct H3Stream {
    shared: Arc<Shared>,
    id: u64,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    data_remaining: u64,
    trailers: Option<HeaderMap>,
    head_sent: bool,
    trailers_sent: bool,
    writer_done: bool,
    reader_done: bool,
}

impl std::fmt::Debug for H3Stream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3Stream")
            .field("id", &self.id)
            .field("writer_done", &self.writer_done)
            .field("reader_done", &self.reader_done)
            .finish_non_exhaustive()
    }
}

impl H3Stream {
    pub fn new(
        shared: Arc<Shared>,
        id: u64,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Self {
        Self {
            shared,
            id,
            send,
            recv,
            data_remaining: 0,
            trailers: None,
            head_sent: false,
            trailers_sent: false,
            writer_done: false,
            reader_done: false,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn send_head(&mut self, fields: &[HeaderField]) -> Result<(), H3Error> {
        if self.head_sent || self.trailers_sent || self.writer_done {
            return Err(H3Error::H3(
                "a second request/response head was attempted".to_string(),
            ));
        }
        let block = self.shared.encode_headers(self.id, fields)?;
        frame::write_headers(&mut self.send, &block).await?;
        self.head_sent = true;
        Ok(())
    }

    pub async fn send_data(&mut self, bytes: &[u8]) -> Result<(), H3Error> {
        if !self.head_sent || self.trailers_sent || self.writer_done {
            return Err(H3Error::H3(
                "DATA sent before a head or after trailers".to_string(),
            ));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        frame::write_data_header(&mut self.send, bytes.len() as u64).await?;
        self.send
            .write_all(bytes)
            .await
            .map_err(|error| H3Error::H3(format!("request body write failed: {error}")))?;
        Ok(())
    }

    pub async fn send_trailers(&mut self, fields: &[HeaderField]) -> Result<(), H3Error> {
        if !self.head_sent || self.trailers_sent || self.writer_done {
            return Err(H3Error::H3(
                "trailers sent before a head or after the stream finished".to_string(),
            ));
        }
        let block = self.shared.encode_headers(self.id, fields)?;
        frame::write_headers(&mut self.send, &block).await?;
        self.trailers_sent = true;
        self.finish_send()
    }

    pub fn finish_send(&mut self) -> Result<(), H3Error> {
        if self.writer_done {
            return Ok(());
        }
        if !self.head_sent {
            return Err(H3Error::H3(
                "stream finished before a request/response head".to_string(),
            ));
        }
        self.send
            .finish()
            .map_err(|error| H3Error::H3(format!("finish request stream: {error}")))?;
        self.writer_done = true;
        Ok(())
    }

    pub async fn read_request_head(&mut self) -> Result<http::Request<()>, H3Error> {
        let fields = self.read_head_fields().await?;
        decode_request(&fields).map_err(H3Error::Header)
    }

    pub async fn read_response_head(&mut self) -> Result<http::Response<()>, H3Error> {
        let fields = self.read_head_fields().await?;
        decode_response(&fields).map_err(H3Error::Header)
    }

    async fn read_head_fields(&mut self) -> Result<Vec<HeaderField>, H3Error> {
        loop {
            let frame = frame::read_frame(&mut self.recv, self.shared.max_header_block())
                .await
                .map_err(|error| self.frame_error(error))?;
            match frame {
                Some(Frame::Headers(block)) => {
                    return self.shared.decode_headers(self.id, &block).await;
                }
                Some(Frame::Data(_)) => {
                    return Err(self.connection_error(
                        error_code::H3_FRAME_UNEXPECTED,
                        "DATA frame before the response/request head",
                    ));
                }
                Some(Frame::Settings(_))
                | Some(Frame::GoAway(_))
                | Some(Frame::CancelPush(_))
                | Some(Frame::MaxPushId(_)) => {
                    return Err(self.connection_error(
                        error_code::H3_FRAME_UNEXPECTED,
                        "control frame on a request stream",
                    ));
                }
                Some(Frame::Unknown { ty, .. }) => {
                    if ty == frame_type::PUSH_PROMISE || ty == frame_type::DUPLICATE_PUSH {
                        return Err(self.connection_error(
                            error_code::H3_ID_ERROR,
                            "push frame received without push support",
                        ));
                    }
                }
                None => {
                    return Err(H3Error::H3(
                        "stream ended before a field section".to_string(),
                    ));
                }
            }
        }
    }

    /// Read the next body chunk, or `None` at the end of the body. Trailers are
    /// decoded and stored before `None` is returned.
    pub async fn next_chunk(&mut self, max_bytes: usize) -> Result<Option<Bytes>, H3Error> {
        if self.reader_done {
            return Ok(None);
        }
        if self.data_remaining > 0 {
            return self.read_data_chunk(max_bytes).await;
        }

        loop {
            let frame = frame::read_frame(&mut self.recv, self.shared.max_header_block())
                .await
                .map_err(|error| self.frame_error(error))?;
            match frame {
                Some(Frame::Data(len)) => {
                    if len == 0 {
                        continue;
                    }
                    self.data_remaining = len;
                    return self.read_data_chunk(max_bytes).await;
                }
                Some(Frame::Headers(block)) => {
                    let fields = self.shared.decode_headers(self.id, &block).await?;
                    self.trailers = Some(decode_trailers(&fields)?);
                    self.reader_done = true;
                    return Ok(None);
                }
                Some(Frame::Settings(_))
                | Some(Frame::GoAway(_))
                | Some(Frame::CancelPush(_))
                | Some(Frame::MaxPushId(_)) => {
                    return Err(self.connection_error(
                        error_code::H3_FRAME_UNEXPECTED,
                        "control frame on a request stream",
                    ));
                }
                Some(Frame::Unknown { ty, .. }) => {
                    if ty == frame_type::PUSH_PROMISE || ty == frame_type::DUPLICATE_PUSH {
                        return Err(self.connection_error(
                            error_code::H3_ID_ERROR,
                            "push frame received without push support",
                        ));
                    }
                }
                None => {
                    self.reader_done = true;
                    return Ok(None);
                }
            }
        }
    }

    async fn read_data_chunk(&mut self, max_bytes: usize) -> Result<Option<Bytes>, H3Error> {
        let remaining = usize::try_from(self.data_remaining).unwrap_or(usize::MAX);
        let length = remaining.min(max_bytes.max(1));
        let mut buffer = vec![0u8; length];
        match self.recv.read(&mut buffer).await {
            Ok(Some(read)) => {
                if read == 0 {
                    return Err(self.connection_error(
                        error_code::H3_FRAME_ERROR,
                        "stream ended in the middle of a DATA frame",
                    ));
                }
                self.data_remaining -= read as u64;
                buffer.truncate(read);
                Ok(Some(Bytes::from(buffer)))
            }
            Ok(None) => Err(self.connection_error(
                error_code::H3_FRAME_ERROR,
                "stream ended in the middle of a DATA frame",
            )),
            Err(error) => Err(H3Error::H3(format!("response body read failed: {error}"))),
        }
    }

    /// Read to the end of the body and return any trailers.
    pub async fn read_trailers(&mut self) -> Result<Option<HeaderMap>, H3Error> {
        while !self.reader_done {
            let _ = self.next_chunk(64 * 1024).await?;
        }
        Ok(self.trailers.clone())
    }

    /// Stop reading the request body while keeping the response direction
    /// usable.
    pub fn cancel_body(&mut self) {
        if !self.reader_done {
            let _ = self.recv.stop(quinn::VarInt::from_u32(
                error_code::H3_REQUEST_CANCELLED as u32,
            ));
            self.reader_done = true;
            self.queue_cancellation();
        }
    }

    fn connection_error(&self, code: u64, message: impl Into<String>) -> H3Error {
        let message = message.into();
        self.shared.set_error(code, message.clone());
        H3Error::Connection { code, message }
    }

    fn frame_error(&self, error: frame::FrameError) -> H3Error {
        if matches!(error, frame::FrameError::Io(_)) {
            return H3Error::Frame(error);
        }
        self.connection_error(
            error_code::H3_FRAME_ERROR,
            format!("request/response stream: {error}"),
        )
    }

    fn queue_cancellation(&self) {
        let mut instruction = bytes::BytesMut::new();
        DecoderInstruction::StreamCancellation(self.id).encode(&mut instruction);
        // The shared state owns the queue; cancellation is best-effort because
        // the stream may already be gone.
        self.shared.queue_cancellation(instruction.freeze());
    }
}

impl Drop for H3Stream {
    fn drop(&mut self) {
        if !self.writer_done {
            let _ = self.send.reset(quinn::VarInt::from_u32(
                error_code::H3_REQUEST_CANCELLED as u32,
            ));
        }
        if !self.reader_done {
            let _ = self.recv.stop(quinn::VarInt::from_u32(
                error_code::H3_REQUEST_CANCELLED as u32,
            ));
            self.queue_cancellation();
        }
    }
}
