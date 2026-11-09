// SPDX-License-Identifier: MIT

//! Connection-scoped state shared by the H3 driver, request streams, and the
//! public client/server adapters.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::{Bytes, BytesMut};
use netune_quic::owned::Connection;
use tokio::sync::{mpsc, watch};

use crate::error::H3Error;
use crate::profile::H3SettingsProfile;
use crate::proto::code::error_code;
use crate::proto::settings::Settings;
use crate::qpack::{Decoder, DecoderInstruction, Encoder, HeaderField, QpackError};

/// An error that closes the whole H3 connection.
#[derive(Debug, Clone)]
pub struct ConnectionError {
    pub code: u64,
    pub message: String,
}

/// A GOAWAY value or control-stream command.
#[derive(Debug, Clone, Copy)]
pub enum ControlCommand {
    GoAway(u64),
}

/// State shared by every stream on one connection.
pub struct Shared {
    pub connection: Connection,
    encoder: Mutex<Encoder>,
    decoder: Mutex<Decoder>,
    qpack_encoder_tx: mpsc::UnboundedSender<Bytes>,
    qpack_decoder_tx: mpsc::UnboundedSender<Bytes>,
    control_tx: mpsc::UnboundedSender<ControlCommand>,
    insert_tx: watch::Sender<u64>,
    error_tx: watch::Sender<Option<Arc<ConnectionError>>>,
    goaway_tx: watch::Sender<Option<u64>>,
    settings_tx: watch::Sender<bool>,
    seen_control: AtomicBool,
    seen_encoder: AtomicBool,
    seen_decoder: AtomicBool,
    blocked: AtomicUsize,
    max_blocked: usize,
    max_field_section_size: usize,
    local_h3_datagram: bool,
    peer_h3_datagram: AtomicBool,
    local_connect_protocol: bool,
    peer_connect_protocol: AtomicBool,
    datagram_routes: Mutex<HashMap<u64, mpsc::UnboundedSender<Bytes>>>,
    pending_datagrams: Mutex<HashMap<u64, VecDeque<Bytes>>>,
    peer_extra_settings: Mutex<HashMap<u64, u64>>,
}

impl Shared {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection: Connection,
        settings: &H3SettingsProfile,
        qpack_encoder_tx: mpsc::UnboundedSender<Bytes>,
        qpack_decoder_tx: mpsc::UnboundedSender<Bytes>,
        control_tx: mpsc::UnboundedSender<ControlCommand>,
    ) -> Result<Self, H3Error> {
        settings
            .validate()
            .map_err(|reason| H3Error::Profile(reason.to_string()))?;
        let mut decoder = Decoder::new(settings.qpack_max_table_capacity as usize);
        decoder
            .set_max_blocked(settings.qpack_blocked_streams as usize)
            .map_err(H3Error::Qpack)?;
        let max_field_section_size =
            usize::try_from(settings.max_field_section_size).unwrap_or(usize::MAX);
        decoder.set_max_field_section_size(max_field_section_size);
        let (insert_tx, _) = watch::channel(0u64);
        let (error_tx, _) = watch::channel(None);
        let (goaway_tx, _) = watch::channel(None);
        let (settings_tx, _) = watch::channel(false);
        Ok(Self {
            connection,
            encoder: Mutex::new(Encoder::new()),
            decoder: Mutex::new(decoder),
            qpack_encoder_tx,
            qpack_decoder_tx,
            control_tx,
            insert_tx,
            error_tx,
            goaway_tx,
            settings_tx,
            seen_control: AtomicBool::new(false),
            seen_encoder: AtomicBool::new(false),
            seen_decoder: AtomicBool::new(false),
            blocked: AtomicUsize::new(0),
            max_blocked: settings.qpack_blocked_streams as usize,
            max_field_section_size,
            local_h3_datagram: settings.h3_datagram,
            peer_h3_datagram: AtomicBool::new(false),
            local_connect_protocol: settings.enable_connect_protocol,
            peer_connect_protocol: AtomicBool::new(false),
            datagram_routes: Mutex::new(HashMap::new()),
            pending_datagrams: Mutex::new(HashMap::new()),
            peer_extra_settings: Mutex::new(HashMap::new()),
        })
    }

    pub fn max_header_block(&self) -> usize {
        self.max_field_section_size.saturating_mul(2).max(64 * 1024)
    }

    pub fn max_qpack_instruction(&self) -> usize {
        self.max_field_section_size.max(64 * 1024)
    }

    pub fn check_error(&self) -> Result<(), H3Error> {
        let error = self.error_tx.borrow().clone();
        match error {
            Some(error) => Err(H3Error::Connection {
                code: error.code,
                message: error.message.clone(),
            }),
            None => Ok(()),
        }
    }

    pub fn set_error(&self, code: u64, message: impl Into<String>) {
        let message = message.into();
        if self.error_tx.borrow().is_some() {
            return;
        }
        let error = Arc::new(ConnectionError {
            code,
            message: message.clone(),
        });
        let _ = self.error_tx.send_replace(Some(error));
        self.connection.close(code, &message);
    }

    pub fn mark_control(&self) -> bool {
        !self.seen_control.swap(true, Ordering::SeqCst)
    }

    pub fn mark_encoder(&self) -> bool {
        !self.seen_encoder.swap(true, Ordering::SeqCst)
    }

    pub fn mark_decoder(&self) -> bool {
        !self.seen_decoder.swap(true, Ordering::SeqCst)
    }

    pub fn goaway(&self) -> Option<u64> {
        *self.goaway_tx.borrow()
    }

    pub fn set_goaway(&self, stream_id: u64) {
        let _ = self.goaway_tx.send_replace(Some(stream_id));
    }

    pub fn send_goaway(&self, stream_id: u64) {
        if self
            .control_tx
            .send(ControlCommand::GoAway(stream_id))
            .is_err()
        {
            self.set_error(
                error_code::H3_INTERNAL_ERROR,
                "control stream writer stopped",
            );
        }
    }

    /// Encode a field section and queue its encoder-stream instructions.
    pub fn encode_headers(&self, stream_id: u64, fields: &[HeaderField]) -> Result<Bytes, H3Error> {
        self.check_error()?;
        let mut encoder = self.lock_encoder();
        let section = encoder.encode_section(stream_id, fields)?;
        if !section.encoder_instructions.is_empty() {
            self.queue_encoder(section.encoder_instructions);
        }
        Ok(section.block)
    }

    /// Decode a field section, waiting for missing dynamic insertions.
    pub async fn decode_headers(
        &self,
        stream_id: u64,
        block: &[u8],
    ) -> Result<Vec<HeaderField>, H3Error> {
        let mut generation = self.insert_tx.subscribe();
        let mut guard: Option<BlockedGuard<'_>> = None;
        loop {
            self.check_error()?;
            let outcome = {
                let mut decoder = self.lock_decoder();
                decoder.decode_section(stream_id, block)
            };
            match outcome {
                Ok(decoded) => {
                    if decoded.required_insert_count > 0 {
                        let mut instruction = BytesMut::new();
                        DecoderInstruction::SectionAck(stream_id).encode(&mut instruction);
                        self.queue_decoder(instruction.freeze());
                    }
                    return Ok(decoded.fields);
                }
                Err(error @ QpackError::MissingInsertions { .. }) => {
                    let can_block = self.max_blocked > 0 && self.lock_decoder().max_capacity() > 0;
                    if !can_block {
                        self.set_error(
                            error_code::QPACK_DECOMPRESSION_FAILED,
                            "dynamic QPACK reference with a zero blocked-stream budget",
                        );
                        return Err(H3Error::Qpack(error));
                    }
                    if guard.is_none() {
                        let previous = self.blocked.fetch_add(1, Ordering::SeqCst);
                        if previous >= self.max_blocked {
                            self.blocked.fetch_sub(1, Ordering::SeqCst);
                            self.set_error(
                                error_code::QPACK_DECOMPRESSION_FAILED,
                                "blocked-stream budget exceeded",
                            );
                            return Err(H3Error::Qpack(QpackError::TooManyBlockedStreams {
                                limit: self.max_blocked,
                            }));
                        }
                        guard = Some(BlockedGuard(&self.blocked));
                    }
                    if generation.changed().await.is_err() {
                        self.check_error()?;
                        return Err(H3Error::H3("QPACK insertion generator closed".to_string()));
                    }
                }
                Err(error) => {
                    self.set_error(
                        error_code::QPACK_DECOMPRESSION_FAILED,
                        format!("qpack decode failed: {error}"),
                    );
                    return Err(H3Error::Qpack(error));
                }
            }
        }
    }

    /// Apply one instruction from the peer's encoder stream.
    pub fn apply_encoder_instruction(&self, instruction: crate::qpack::EncoderInstruction) {
        let result = {
            let mut decoder = self.lock_decoder();
            decoder.apply_encoder_instruction(instruction)
        };
        match result {
            Ok(insertions) if insertions > 0 => {
                let mut instruction = BytesMut::new();
                DecoderInstruction::InsertCountIncrement(insertions).encode(&mut instruction);
                self.queue_decoder(instruction.freeze());
                self.insert_tx
                    .send_modify(|generation| *generation = generation.saturating_add(1));
            }
            Ok(_) => {}
            Err(error) => {
                self.set_error(
                    error_code::QPACK_ENCODER_STREAM_ERROR,
                    format!("qpack encoder stream: {error}"),
                );
            }
        }
    }

    /// Apply one instruction from the peer's decoder stream.
    pub fn apply_decoder_instruction(&self, instruction: DecoderInstruction) {
        let result = {
            let mut encoder = self.lock_encoder();
            encoder.apply_decoder_instruction(instruction)
        };
        if let Err(error) = result {
            self.set_error(
                error_code::QPACK_DECODER_STREAM_ERROR,
                format!("qpack decoder stream: {error}"),
            );
        }
    }

    pub fn datagrams_enabled(&self) -> bool {
        self.local_h3_datagram && self.peer_h3_datagram.load(Ordering::SeqCst)
    }

    pub fn extended_connect_enabled(&self) -> bool {
        self.local_connect_protocol && self.peer_connect_protocol.load(Ordering::SeqCst)
    }

    pub async fn wait_settings(&self) {
        let mut settings = self.settings_tx.subscribe();
        if *settings.borrow() {
            return;
        }
        let _ = settings.changed().await;
    }

    pub fn register_datagrams(&self, stream_id: u64) -> mpsc::UnboundedReceiver<Bytes> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.datagram_routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(stream_id, tx);
        if let Some(pending) = self
            .pending_datagrams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&stream_id)
        {
            for datagram in pending {
                let _ = self
                    .datagram_routes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&stream_id)
                    .map(|sender| sender.send(datagram));
            }
        }
        rx
    }

    pub fn unregister_datagrams(&self, stream_id: u64) {
        self.datagram_routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&stream_id);
        self.pending_datagrams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&stream_id);
    }

    pub fn route_datagram(&self, stream_id: u64, data: Bytes) {
        let sender = self
            .datagram_routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&stream_id)
            .cloned();
        if let Some(sender) = sender {
            let _ = sender.send(data);
            return;
        }
        let mut pending = self
            .pending_datagrams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let queue = pending.entry(stream_id).or_default();
        if queue.len() < 32 {
            queue.push_back(data);
        }
    }

    /// Apply the peer's SETTINGS frame to the encoder.
    pub fn peer_extra_setting(&self, id: u64) -> Option<u64> {
        self.peer_extra_settings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .copied()
    }

    pub fn update_peer_settings(&self, settings: Settings) {
        {
            let mut extra = self
                .peer_extra_settings
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            extra.clear();
            extra.extend(settings.grease.iter().copied());
            extra.insert(0x08, u64::from(settings.enable_connect_protocol));
            extra.insert(0x33, u64::from(settings.h3_datagram));
        }
        self.peer_h3_datagram
            .store(settings.h3_datagram, Ordering::SeqCst);
        self.peer_connect_protocol
            .store(settings.enable_connect_protocol, Ordering::SeqCst);
        let _ = self.settings_tx.send_replace(true);
        let max_table = usize::try_from(settings.qpack_max_table_capacity).unwrap_or(usize::MAX);
        let max_field = settings
            .max_field_section_size
            .and_then(|size| usize::try_from(size).ok())
            .unwrap_or(usize::MAX);
        let result = {
            let mut encoder = self.lock_encoder();
            encoder.apply_peer_settings(max_table, max_field)
        };
        match result {
            Ok(instructions) if !instructions.is_empty() => self.queue_encoder(instructions),
            Ok(_) => {}
            Err(error) => {
                self.set_error(
                    error_code::H3_SETTINGS_ERROR,
                    format!("invalid peer SETTINGS: {error}"),
                );
            }
        }
    }

    fn queue_encoder(&self, bytes: Bytes) {
        if !bytes.is_empty() && self.qpack_encoder_tx.send(bytes).is_err() {
            self.set_error(
                error_code::H3_INTERNAL_ERROR,
                "encoder stream writer stopped",
            );
        }
    }

    fn queue_decoder(&self, bytes: Bytes) {
        if !bytes.is_empty() && self.qpack_decoder_tx.send(bytes).is_err() {
            self.set_error(
                error_code::H3_INTERNAL_ERROR,
                "decoder stream writer stopped",
            );
        }
    }

    pub fn queue_cancellation(&self, bytes: Bytes) {
        self.queue_decoder(bytes);
    }

    fn lock_encoder(&self) -> MutexGuard<'_, Encoder> {
        self.encoder
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn lock_decoder(&self) -> MutexGuard<'_, Decoder> {
        self.decoder
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

struct BlockedGuard<'a>(&'a AtomicUsize);

impl Drop for BlockedGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
