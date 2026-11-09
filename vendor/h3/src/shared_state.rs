//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    fmt,
    sync::{atomic::AtomicBool, Mutex, MutexGuard, OnceLock},
};

use bytes::Bytes;
use futures_util::task::AtomicWaker;
use tokio::sync::{mpsc, watch};

use crate::{config::Settings, error::internal_error::ErrorOrigin, qpack};

/// The mutable QPACK encoder and decoder tables for one connection.
///
/// Both are guarded by one lock because each is touched from two tasks: request
/// streams encode/decode header blocks, while the connection driver feeds the
/// peer's encoder/decoder streams. The lock is held only for parsing or
/// encoding a header block, never across I/O.
pub(crate) struct QpackTables {
    pub(crate) encoder: qpack::Encoder,
    pub(crate) decoder: qpack::Decoder,
}

impl Default for QpackTables {
    fn default() -> Self {
        Self {
            encoder: qpack::Encoder::new(),
            decoder: qpack::Decoder::new(),
        }
    }
}

impl fmt::Debug for QpackTables {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QpackTables")
            .field("encoder_capacity", &self.encoder.max_size())
            .field("decoder_capacity", &self.decoder.max_size())
            .finish()
    }
}

#[derive(Debug)]
/// This struct represents the shared state of the h3 connection and the stream structs
pub struct SharedState {
    /// The settings, sent by the peer
    settings: OnceLock<Settings>,
    /// The connection error
    connection_error: OnceLock<ErrorOrigin>,
    /// The connection is closing
    closing: AtomicBool,
    /// Waker for the connection
    waker: AtomicWaker,
    /// QPACK tables shared by request streams and the connection driver.
    pub(crate) qpack: Mutex<QpackTables>,
    /// Instructions for our QPACK encoder stream, drained by the driver.
    qpack_encoder_tx: OnceLock<mpsc::UnboundedSender<Bytes>>,
    /// Instructions for our QPACK decoder stream, drained by the driver.
    qpack_decoder_tx: OnceLock<mpsc::UnboundedSender<Bytes>>,
    /// Monotonic insertion counter; request/response streams wait on it when
    /// a header block references a not-yet-received dynamic entry.
    qpack_generation: watch::Sender<u64>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            settings: OnceLock::new(),
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            qpack: Mutex::new(QpackTables::default()),
            qpack_encoder_tx: OnceLock::new(),
            qpack_decoder_tx: OnceLock::new(),
            qpack_generation: watch::channel(0).0,
        }
    }
}

impl SharedState {
    pub(crate) fn qpack(&self) -> MutexGuard<'_, QpackTables> {
        self.qpack.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn set_qpack_channels(
        &self,
        encoder: mpsc::UnboundedSender<Bytes>,
        decoder: mpsc::UnboundedSender<Bytes>,
    ) {
        let _ = self.qpack_encoder_tx.set(encoder);
        let _ = self.qpack_decoder_tx.set(decoder);
    }

    /// Queue encoder instructions for the peer's decoder stream.
    pub(crate) fn send_qpack_encoder_instructions(&self, bytes: Bytes) {
        if bytes.is_empty() {
            return;
        }
        if let Some(sender) = self.qpack_encoder_tx.get() {
            let _ = sender.send(bytes);
        }
    }

    /// Queue decoder instructions for the peer's encoder stream.
    pub(crate) fn send_qpack_decoder_instructions(&self, bytes: Bytes) {
        if bytes.is_empty() {
            return;
        }
        if let Some(sender) = self.qpack_decoder_tx.get() {
            let _ = sender.send(bytes);
        }
    }

    /// Wake request streams that may have been blocked on an insertion.
    pub(crate) fn qpack_inserted(&self) {
        self.qpack_generation
            .send_modify(|generation| *generation = generation.saturating_add(1));
    }

    /// Decode one QPACK header block, waiting for missing dynamic insertions.
    pub(crate) async fn decode_headers(
        &self,
        stream_id: u64,
        encoded: &Bytes,
    ) -> Result<qpack::Decoded, qpack::DecoderError> {
        let mut generation = self.qpack_generation.subscribe();
        loop {
            let seen = *generation.borrow_and_update();
            let mut read = encoded.clone();
            let result = {
                let qpack = self.qpack();
                qpack.decoder.decode_header(&mut read)
            };
            match result {
                Err(qpack::DecoderError::MissingRefs(_)) => {
                    // If we advertised no dynamic table, a dynamic reference is
                    // a peer protocol violation, not a reason to wait forever.
                    if self.qpack().decoder.max_size() == 0 {
                        return Err(qpack::DecoderError::MissingRefs(0));
                    }
                    // An insertion may have landed between the decode attempt
                    // and the version check; retry before sleeping.
                    if *generation.borrow() != seen {
                        continue;
                    }
                    if generation.changed().await.is_err() {
                        return Err(qpack::DecoderError::MissingRefs(0));
                    }
                }
                Ok(decoded) => {
                    let mut ack = Vec::new();
                    qpack::ack_header(stream_id, &mut ack);
                    self.send_qpack_decoder_instructions(Bytes::from(ack));
                    return Ok(decoded);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl ConnectionState for SharedState {
    fn shared_state(&self) -> &SharedState {
        self
    }
}

/// This trait can be implemented for all types which have a shared state
pub trait ConnectionState {
    /// Get the shared state
    fn shared_state(&self) -> &SharedState;
    /// Get the connection error if the connection is in error state because of another task
    ///
    /// Return the error as an Err variant if it is set in order to allow using ? in the calling function
    fn get_conn_error(&self) -> Option<ErrorOrigin> {
        self.shared_state().connection_error.get().cloned()
    }

    /// tries to set the connection error
    fn set_conn_error(&self, error: ErrorOrigin) -> ErrorOrigin {
        let err = self
            .shared_state()
            .connection_error
            .get_or_init(move || error);
        err.clone()
    }

    /// set the connection error and wake the connection
    fn set_conn_error_and_wake<T: Into<ErrorOrigin>>(&self, error: T) -> ErrorOrigin {
        let err = self.set_conn_error(error.into());
        self.waker().wake();
        err
    }

    /// Get the settings
    fn settings(&self) -> Cow<Settings> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# Each endpoint SHOULD use
        //# these initial values to send messages before the peer's SETTINGS
        //# frame has arrived, as packets carrying the settings can be lost or
        //# delayed.
        self.shared_state()
            .settings
            .get()
            .map(|s| Cow::Borrowed(s))
            .unwrap_or_default()
    }
    /// Set the connection to closing
    fn set_closing(&self) {
        self.shared_state()
            .closing
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// Check if the connection is closing
    fn is_closing(&self) -> bool {
        self.shared_state()
            .closing
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Set the settings
    fn set_settings(&self, settings: Settings) {
        let _ = self.shared_state().settings.set(settings);
    }

    /// Returns the waker for the connection
    fn waker(&self) -> &AtomicWaker {
        &self.shared_state().waker
    }
}
