//! The async driver around the sans-IO handshake machine: the seam the
//! orchestrator drives.
//!
//! [`OwnedTlsConnector`] brackets the handshake over a caller-provided
//! stream — the engine writes what [`ClientHandshake::take_output`]
//! produced and feeds what arrives back — and hands back an
//! [`OwnedTlsStream`]: an `AsyncRead`/`AsyncWrite` whose record protection
//! is the engine's ([`INV-TLS-08`]). No socket is opened here; confinement
//! stays with the caller.
//!
//! Post-handshake message handling is deliberate and narrow: a
//! NewSessionTicket is parsed and cached when a session store is wired, a
//! TLS 1.3 KeyUpdate rotates application traffic keys per RFC 8446 §4.6.3,
//! and a peer close_notify reads as end-of-stream. Everything else is an
//! error.

use thiserror::Error;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::handshake::{
    ClientHandshake, Established, HandshakeError, HandshakeProgress, KEY_UPDATE, MAX_FLIGHT_BYTES,
    NEW_SESSION_TICKET, Protectors, ServerCertVerifier, suite_params,
};
use crate::hello::ClientHello;
use crate::key_exchange::ClientKeyShare;
use crate::key_schedule::{Hash, Secret};
use crate::record::{
    CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE, MAX_CIPHERTEXT_LEN,
    MAX_PLAINTEXT_LEN, RECORD_HEADER_LEN, RecordProtector13, RecordUnprotector13,
};
use crate::session::{ResumptionTicket, SessionCache, SessionKey, parse_new_session_ticket};

/// Why the owned engine could not deliver a TLS connection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OwnedTlsError {
    /// The handshake refused.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// The transport failed under the driver or the stream.
    #[error("transport failure: {reason}")]
    Transport {
        /// The underlying transport error.
        reason: String,
    },
    /// The connection ended mid-handshake.
    #[error("the peer closed the connection mid-handshake")]
    PeerClosed,
    /// A post-handshake message the engine does not carry.
    #[error("post-handshake message type {got:#04x} is not supported by the engine")]
    UnsupportedPostHandshake {
        /// The offending handshake type.
        got: u8,
    },
    /// An alert arrived from the peer.
    #[error("the peer sent an alert: level {level}, description {description:#04x}")]
    Alert {
        /// The alert level byte.
        level: u8,
        /// The alert description byte.
        description: u8,
    },
}

/// The handshake inputs for one owned connection: the hello (profile-shaped)
/// and the key shares it advertises.
#[derive(Debug)]
pub struct OwnedConnectParams {
    /// The ClientHello: built by the caller from the profile.
    pub hello: ClientHello,
    /// The key shares for the hello's `key_share` entries, in offer order.
    pub shares: Vec<ClientKeyShare>,
}

/// Drives the owned handshake over a transport and hands back the stream.
#[derive(Debug, Default)]
pub struct OwnedTlsConnector;

impl OwnedTlsConnector {
    /// Run the handshake on `socket` and return the protected stream.
    ///
    /// # Errors
    /// [`OwnedTlsError::Handshake`] for any refusal the machine reaches,
    /// [`OwnedTlsError::Transport`] for transport failures, and
    /// [`OwnedTlsError::PeerClosed`] when the connection dies mid-handshake.
    pub async fn connect<S>(
        &self,
        socket: S,
        params: OwnedConnectParams,
        verifier: impl ServerCertVerifier,
    ) -> Result<OwnedTlsStream<S>, OwnedTlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with_session(socket, params, verifier, None, None)
            .await
    }

    /// Drive a handshake with optional TLS 1.3 PSK resumption and ticket
    /// caching ([ADR-0048](../../adr/0048-declarative-clienthello-blueprints.md)).
    ///
    /// # Errors
    /// Same as [`OwnedTlsConnector::connect`].
    pub async fn connect_with_session<S>(
        &self,
        socket: S,
        params: OwnedConnectParams,
        verifier: impl ServerCertVerifier,
        offered_psk: Option<Vec<u8>>,
        session_store: Option<(SessionCache, SessionKey)>,
    ) -> Result<OwnedTlsStream<S>, OwnedTlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_for_server(socket, params, verifier, None, offered_psk, session_store)
            .await
    }

    /// Drive a handshake with an explicit verified server name (for literal IPv4
    /// or IPv6 targets where SNI is omitted per RFC 6066 §3) and optional TLS 1.3
    /// PSK resumption ([ADR-0048](../../adr/0048-declarative-clienthello-blueprints.md)).
    ///
    /// # Errors
    /// Same as [`OwnedTlsConnector::connect`].
    pub async fn connect_for_server<S>(
        &self,
        mut socket: S,
        params: OwnedConnectParams,
        verifier: impl ServerCertVerifier,
        verified_server_name: Option<&str>,
        offered_psk: Option<Vec<u8>>,
        session_store: Option<(SessionCache, SessionKey)>,
    ) -> Result<OwnedTlsStream<S>, OwnedTlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut machine =
            ClientHandshake::start_with_psk(params.hello, params.shares, verifier, offered_psk)
                .map_err(OwnedTlsError::from)?;
        if let Some(name) = verified_server_name {
            machine = machine.with_verified_server_name(name);
        }
        let output = machine.take_output();
        if !output.is_empty() {
            socket
                .write_all(&output)
                .await
                .map_err(|error| OwnedTlsError::Transport {
                    reason: error.to_string(),
                })?;
        }
        let established = loop {
            let mut buffer = vec![0u8; 16_384];
            let read =
                socket
                    .read(&mut buffer)
                    .await
                    .map_err(|error| OwnedTlsError::Transport {
                        reason: error.to_string(),
                    })?;
            if read == 0 {
                return Err(OwnedTlsError::PeerClosed);
            }
            match machine
                .progress(&buffer[..read])
                .map_err(OwnedTlsError::from)?
            {
                HandshakeProgress::Blocked => {}
                HandshakeProgress::Established(established) => break *established,
            }
            let pending = machine.take_output();
            if !pending.is_empty() {
                socket
                    .write_all(&pending)
                    .await
                    .map_err(|error| OwnedTlsError::Transport {
                        reason: error.to_string(),
                    })?;
            }
        };
        // A TLS 1.2 client's flight (CKE, change_cipher_spec, Finished) is
        // pending when establishment is detected inside the last progress
        // call; a TLS 1.3 client has nothing left to send.
        let tail = machine.take_output();
        if !tail.is_empty() {
            socket
                .write_all(&tail)
                .await
                .map_err(|error| OwnedTlsError::Transport {
                    reason: error.to_string(),
                })?;
        }
        // Preserve any post-handshake bytes (e.g., NewSessionTicket or early
        // server application data) that arrived in the same TCP read as the
        // final handshake record.
        let preroll = machine.take_buffered_input();
        Ok(OwnedTlsStream::new_with_preroll(
            socket,
            established,
            session_store,
            preroll,
        ))
    }
}

struct ResumptionContext {
    resumption_master: Secret,
    hash: Hash,
    cipher_suite: u16,
    cache: SessionCache,
    cache_key: SessionKey,
}

/// Which version's record protection an established connection carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectorsKind {
    /// TLS 1.3 (RFC 8446).
    Tls13,
    /// TLS 1.2 (RFC 5246).
    Tls12,
}

/// The established connection: an `AsyncRead`/`AsyncWrite` whose bytes are
/// record-protected by the engine.
pub struct OwnedTlsStream<S> {
    socket: S,
    protectors: Protectors,
    alpn: Option<Vec<u8>>,
    /// Wire bytes coalesced after the final handshake record in the connector's
    /// read buffer.
    preroll: Vec<u8>,
    /// Offset into `preroll` already consumed by the record reader.
    preroll_offset: usize,
    /// Decrypted application bytes waiting to be read.
    plaintext: Vec<u8>,
    /// Bytes consumed from `plaintext` by the reader.
    consumed: usize,
    /// Set when the peer sent close_notify; the reader reports EOF after
    /// draining.
    peer_closed: bool,
    /// The partial record-header read across polls.
    header_scratch: [u8; RECORD_HEADER_LEN],
    /// The record payload being read across polls.
    payload_scratch: Vec<u8>,
    /// Reassembly buffer for post-handshake handshake messages spanning
    /// multiple TLS records.
    post_handshake_buf: Vec<u8>,
    /// Where the read state machine stands.
    state: ReadState,
    /// Optional TLS 1.3 session resumption context for caching incoming
    /// `NewSessionTicket` messages.
    resumption: Option<ResumptionContext>,
    /// TLS 1.3 client application traffic secret for `KeyUpdate` (RFC 8446 §4.6.3).
    client_ap_secret: Option<Secret>,
    /// TLS 1.3 server application traffic secret for `KeyUpdate` (RFC 8446 §4.6.3).
    server_ap_secret: Option<Secret>,
    /// Negotiated TLS 1.3 cipher suite for `KeyUpdate`.
    cipher_suite: Option<u16>,
    /// Maximum plaintext bytes per outgoing record (RFC 8446 §5.1 / RFC 8449).
    max_write_plaintext: usize,
    /// Encrypted record bytes queued for the underlying socket across partial
    /// writes or `Poll::Pending`.
    write_buf: Vec<u8>,
    /// Offset into `write_buf` already accepted by `socket`.
    write_offset: usize,
    /// Plaintext byte count sealed into `write_buf` for an in-flight
    /// `AsyncWrite::poll_write` call waiting for the underlying socket to
    /// finish flushing `write_buf`.
    pending_plaintext_len: usize,
}

impl<S> OwnedTlsStream<S> {
    /// Wrap the established connection.
    #[cfg(test)]
    fn new(
        socket: S,
        established: Established,
        session_store: Option<(SessionCache, SessionKey)>,
    ) -> Self {
        Self::new_with_preroll(socket, established, session_store, Vec::new())
    }

    /// Wrap the established connection along with any coalesced post-handshake
    /// wire bytes read during the final handshake flight.
    fn new_with_preroll(
        socket: S,
        established: Established,
        session_store: Option<(SessionCache, SessionKey)>,
        preroll: Vec<u8>,
    ) -> Self {
        let resumption = session_store.and_then(|(cache, cache_key)| {
            let resumption_master = established.resumption_master?;
            let cipher_suite = established.cipher_suite?;
            Some(ResumptionContext {
                resumption_master,
                hash: established.hash,
                cipher_suite,
                cache,
                cache_key,
            })
        });
        Self {
            socket,
            protectors: established.protectors,
            alpn: established.alpn,
            preroll,
            preroll_offset: 0,
            plaintext: Vec::new(),
            consumed: 0,
            peer_closed: false,
            header_scratch: [0u8; RECORD_HEADER_LEN],
            payload_scratch: Vec::new(),
            post_handshake_buf: Vec::new(),
            state: ReadState::default(),
            resumption,
            client_ap_secret: established.client_ap_secret,
            server_ap_secret: established.server_ap_secret,
            cipher_suite: established.cipher_suite,
            max_write_plaintext: established.max_write_plaintext.clamp(1, MAX_PLAINTEXT_LEN),
            write_buf: Vec::new(),
            write_offset: 0,
            pending_plaintext_len: 0,
        }
    }

    /// The ALPN protocol the server selected, if any.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// Which version's protectors the connection carries.
    #[must_use]
    pub const fn protectors_kind(&self) -> ProtectorsKind {
        match self.protectors {
            Protectors::Tls13 { .. } => ProtectorsKind::Tls13,
            Protectors::Tls12 { .. } => ProtectorsKind::Tls12,
        }
    }

    /// Drain any buffered ciphertext from `write_buf` to the underlying socket.
    fn poll_flush_write_buf(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.write_offset < self.write_buf.len() {
            let remaining = &self.write_buf[self.write_offset..];
            match std::pin::Pin::new(&mut self.socket).poll_write(cx, remaining) {
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "underlying transport wrote zero bytes",
                    )));
                }
                std::task::Poll::Ready(Ok(n)) => {
                    self.write_offset += n;
                }
                std::task::Poll::Ready(Err(error)) => {
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
            }
        }
        self.write_buf.clear();
        self.write_offset = 0;
        std::task::Poll::Ready(Ok(()))
    }

    /// Send a close_notify and shut the transport down.
    ///
    /// # Errors
    /// A record-protection or transport write failure.
    pub async fn close(&mut self) -> Result<(), OwnedTlsError>
    where
        S: AsyncWrite + Unpin,
    {
        std::future::poll_fn(|cx| self.poll_flush_write_buf(cx))
            .await
            .map_err(|error| OwnedTlsError::Transport {
                reason: error.to_string(),
            })?;
        self.pending_plaintext_len = 0;
        let alert = [1u8, 0]; // warning-level close_notify
        let next_seq;
        let record = match &self.protectors {
            Protectors::Tls13 {
                write, write_seq, ..
            } => {
                next_seq = write_seq
                    .checked_add(1)
                    .ok_or_else(|| OwnedTlsError::Transport {
                        reason: "TLS 1.3 write sequence number exhausted".into(),
                    })?;
                write
                    .seal(*write_seq, CONTENT_ALERT, &alert)
                    .map_err(record_error)?
            }
            Protectors::Tls12 {
                write, write_seq, ..
            } => {
                next_seq = write_seq
                    .checked_add(1)
                    .ok_or_else(|| OwnedTlsError::Transport {
                        reason: "TLS 1.2 write sequence number exhausted".into(),
                    })?;
                write
                    .seal(*write_seq, CONTENT_ALERT, &alert)
                    .map_err(record_error)?
            }
        };
        match &mut self.protectors {
            Protectors::Tls13 { write_seq, .. } | Protectors::Tls12 { write_seq, .. } => {
                *write_seq = next_seq;
            }
        }
        self.socket
            .write_all(&record)
            .await
            .map_err(|error| OwnedTlsError::Transport {
                reason: error.to_string(),
            })?;
        self.socket
            .flush()
            .await
            .map_err(|error| OwnedTlsError::Transport {
                reason: error.to_string(),
            })?;
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for OwnedTlsStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        // Drain any partially-written encrypted record from a prior poll before
        // sealing new plaintext. If an application-data record was sealed on a
        // previous poll that returned Pending, complete that poll_write once the
        // underlying socket finishes accepting the record.
        match this.poll_flush_write_buf(cx) {
            std::task::Poll::Ready(Ok(())) => {
                if this.pending_plaintext_len > 0 {
                    let committed = std::mem::replace(&mut this.pending_plaintext_len, 0);
                    if buf.len() < committed {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "retried write buffer ({} bytes) is smaller than previously committed plaintext ({committed} bytes)",
                                buf.len()
                            ),
                        )));
                    }
                    return std::task::Poll::Ready(Ok(committed));
                }
            }
            std::task::Poll::Ready(Err(error)) => {
                this.pending_plaintext_len = 0;
                return std::task::Poll::Ready(Err(error));
            }
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }

        // Fragment at the negotiated record size limit (at most 2^14 bytes per
        // RFC 8446 §5.1 / RFC 5246 §6.2.1 / RFC 8449) so callers can pass
        // arbitrarily large buffers.
        let chunk = &buf[..buf.len().min(this.max_write_plaintext)];
        let next_seq;
        let record = match &this.protectors {
            Protectors::Tls13 {
                write, write_seq, ..
            } => {
                next_seq = write_seq.checked_add(1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "TLS 1.3 write sequence number exhausted",
                    )
                })?;
                write
                    .seal(*write_seq, CONTENT_APPLICATION_DATA, chunk)
                    .map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                    })?
            }
            Protectors::Tls12 {
                write, write_seq, ..
            } => {
                next_seq = write_seq.checked_add(1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "TLS 1.2 write sequence number exhausted",
                    )
                })?;
                write
                    .seal(*write_seq, CONTENT_APPLICATION_DATA, chunk)
                    .map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                    })?
            }
        };
        match &mut this.protectors {
            Protectors::Tls13 { write_seq, .. } | Protectors::Tls12 { write_seq, .. } => {
                *write_seq = next_seq;
            }
        }
        this.write_buf.extend_from_slice(&record);
        this.pending_plaintext_len = chunk.len();

        // Flush the sealed record to the underlying socket. Only return Ready
        // once the entire TLS record is written so callers that do not issue an
        // explicit `flush()` after `write_all()` never leave a partial TLS
        // record stranded in `write_buf`.
        match this.poll_flush_write_buf(cx) {
            std::task::Poll::Ready(Ok(())) => {
                let committed = std::mem::replace(&mut this.pending_plaintext_len, 0);
                std::task::Poll::Ready(Ok(committed))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Err(error)) => {
                this.pending_plaintext_len = 0;
                std::task::Poll::Ready(Err(error))
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        match this.poll_flush_write_buf(cx) {
            std::task::Poll::Ready(Ok(())) => {
                this.pending_plaintext_len = 0;
                std::pin::Pin::new(&mut this.socket).poll_flush(cx)
            }
            std::task::Poll::Ready(Err(error)) => {
                this.pending_plaintext_len = 0;
                std::task::Poll::Ready(Err(error))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        match this.poll_flush_write_buf(cx) {
            std::task::Poll::Ready(Ok(())) => {
                this.pending_plaintext_len = 0;
                std::pin::Pin::new(&mut this.socket).poll_shutdown(cx)
            }
            std::task::Poll::Ready(Err(error)) => {
                this.pending_plaintext_len = 0;
                std::task::Poll::Ready(Err(error))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// The read state: filling the 5-byte record header, then the payload.
#[derive(Debug)]
enum ReadState {
    NeedHeader {
        filled: usize,
    },
    NeedPayload {
        header: [u8; RECORD_HEADER_LEN],
        filled: usize,
    },
}

impl Default for ReadState {
    fn default() -> Self {
        Self::NeedHeader { filled: 0 }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for OwnedTlsStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if out.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        if this.consumed < this.plaintext.len() {
            let remaining_plaintext = &this.plaintext[this.consumed..];
            let take = remaining_plaintext.len().min(out.remaining());
            out.put_slice(&remaining_plaintext[..take]);
            this.consumed += take;
            if this.consumed == this.plaintext.len() {
                this.plaintext.clear();
                this.consumed = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        if this.peer_closed {
            return std::task::Poll::Ready(Ok(()));
        }

        // One record per poll: read the header, then the payload, then open.
        loop {
            if this.pending_plaintext_len == 0
                && !this.write_buf.is_empty()
                && let std::task::Poll::Ready(Err(error)) = this.poll_flush_write_buf(cx)
            {
                return std::task::Poll::Ready(Err(error));
            }
            match this.state {
                ReadState::NeedHeader { filled } => {
                    let mut buf = ReadBuf::new(&mut this.header_scratch[filled..]);
                    match poll_read_wire(
                        &mut this.socket,
                        &mut this.preroll,
                        &mut this.preroll_offset,
                        cx,
                        &mut buf,
                    ) {
                        std::task::Poll::Ready(Ok(())) => {
                            let filled_now = buf.filled().len();
                            if filled_now == 0 {
                                if filled == 0 && this.post_handshake_buf.is_empty() {
                                    this.peer_closed = true;
                                    return std::task::Poll::Ready(Ok(()));
                                }
                                return std::task::Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "peer closed connection mid-record",
                                )));
                            }
                            let filled = filled + filled_now;
                            if filled < RECORD_HEADER_LEN {
                                this.state = ReadState::NeedHeader { filled };
                                continue;
                            }
                            let complete = this.header_scratch;
                            let payload_len =
                                u16::from_be_bytes([complete[3], complete[4]]) as usize;
                            if payload_len > MAX_CIPHERTEXT_LEN {
                                return std::task::Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "record exceeds the limit",
                                )));
                            }
                            this.state = ReadState::NeedPayload {
                                header: complete,
                                filled: 0,
                            };
                            this.payload_scratch.clear();
                            this.payload_scratch.resize(payload_len, 0);
                        }
                        std::task::Poll::Ready(Err(error)) => {
                            return std::task::Poll::Ready(Err(error));
                        }
                        std::task::Poll::Pending => {
                            this.state = ReadState::NeedHeader { filled };
                            return std::task::Poll::Pending;
                        }
                    }
                }
                ReadState::NeedPayload { header, filled } => {
                    let payload_len = this.payload_scratch.len();
                    if filled < payload_len {
                        let mut buf = ReadBuf::new(&mut this.payload_scratch[filled..]);
                        match poll_read_wire(
                            &mut this.socket,
                            &mut this.preroll,
                            &mut this.preroll_offset,
                            cx,
                            &mut buf,
                        ) {
                            std::task::Poll::Ready(Ok(())) => {
                                let filled_now = buf.filled().len();
                                if filled_now == 0 {
                                    return std::task::Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "peer closed connection mid-record payload",
                                    )));
                                }
                                let filled = filled + filled_now;
                                if filled < payload_len {
                                    this.state = ReadState::NeedPayload { header, filled };
                                    continue;
                                }
                            }
                            std::task::Poll::Ready(Err(error)) => {
                                return std::task::Poll::Ready(Err(error));
                            }
                            std::task::Poll::Pending => {
                                this.state = ReadState::NeedPayload { header, filled };
                                return std::task::Poll::Pending;
                            }
                        }
                    }
                    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + payload_len);
                    record.extend_from_slice(&header);
                    record.extend_from_slice(&this.payload_scratch);
                    this.state = ReadState::NeedHeader { filled: 0 };
                    let (content_type, plaintext) = this
                        .open_post_handshake(record.as_slice())
                        .map_err(|error| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                        })?;
                    match content_type {
                        CONTENT_APPLICATION_DATA => {
                            if plaintext.is_empty() {
                                continue;
                            }
                            let take = plaintext.len().min(out.remaining());
                            out.put_slice(&plaintext[..take]);
                            if take < plaintext.len() {
                                this.plaintext = plaintext;
                                this.consumed = take;
                            }
                            return std::task::Poll::Ready(Ok(()));
                        }
                        CONTENT_ALERT => {
                            match plaintext.as_slice() {
                                // close_notify (warning or fatal level)
                                [1 | 2, 0] => {
                                    this.peer_closed = true;
                                    return std::task::Poll::Ready(Ok(()));
                                }
                                // RFC 8446 §6.1: user_canceled warning alert is
                                // commonly sent right before close_notify; ignore it.
                                [1, 90] => {
                                    continue;
                                }
                                [level, description] => {
                                    return std::task::Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        OwnedTlsError::Alert {
                                            level: *level,
                                            description: *description,
                                        }
                                        .to_string(),
                                    )));
                                }
                                _ => {
                                    return std::task::Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "malformed alert record",
                                    )));
                                }
                            }
                        }
                        other => {
                            return std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("unexpected post-handshake content type {other:#04x}"),
                            )));
                        }
                    }
                }
            }
        }
    }
}

impl<S> OwnedTlsStream<S> {
    /// Open one post-establishment record and classify its inner content.
    fn open_post_handshake(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>), OwnedTlsError> {
        let advanced;
        let (inner, payload) = match &self.protectors {
            Protectors::Tls13 { read, read_seq, .. } => {
                let next_seq = read_seq
                    .checked_add(1)
                    .ok_or_else(|| OwnedTlsError::Transport {
                        reason: "TLS 1.3 read sequence number exhausted".into(),
                    })?;
                let (inner, payload) = read.open(*read_seq, record).map_err(record_error)?;
                advanced = next_seq;
                (inner, payload)
            }
            Protectors::Tls12 { read, read_seq, .. } => {
                let next_seq = read_seq
                    .checked_add(1)
                    .ok_or_else(|| OwnedTlsError::Transport {
                        reason: "TLS 1.2 read sequence number exhausted".into(),
                    })?;
                let (inner, payload) = read.open(*read_seq, record).map_err(record_error)?;
                advanced = next_seq;
                (inner, payload)
            }
        };
        match &mut self.protectors {
            Protectors::Tls13 { read_seq, .. } | Protectors::Tls12 { read_seq, .. } => {
                *read_seq = advanced;
            }
        }
        // RFC 8446 §5.1: handshake messages MUST NOT be interleaved with other
        // record types.
        if inner != CONTENT_HANDSHAKE && !self.post_handshake_buf.is_empty() {
            return Err(OwnedTlsError::Handshake(
                HandshakeError::ProtocolViolation {
                    reason: "post-handshake message was interrupted by another record type".into(),
                },
            ));
        }
        if inner == CONTENT_HANDSHAKE {
            if matches!(self.protectors, Protectors::Tls12 { .. }) {
                return Err(OwnedTlsError::Handshake(HandshakeError::ProtocolViolation {
                    reason: "post-handshake handshake messages (renegotiation) are not permitted in TLS 1.2".into(),
                }));
            }
            if payload.is_empty() {
                return Err(OwnedTlsError::Handshake(
                    HandshakeError::ProtocolViolation {
                        reason: "zero-length post-handshake handshake fragment (RFC 8446 §5.1)"
                            .into(),
                    },
                ));
            }
            self.post_handshake_buf.extend_from_slice(&payload);
            if self.post_handshake_buf.len() > MAX_FLIGHT_BYTES {
                return Err(OwnedTlsError::Handshake(
                    HandshakeError::FlightBufferExceeded {
                        len: self.post_handshake_buf.len(),
                        max: MAX_FLIGHT_BYTES,
                    },
                ));
            }
            while let Some((kind, message)) = take_post_handshake_vec(&mut self.post_handshake_buf)
            {
                match kind {
                    NEW_SESSION_TICKET => {
                        if let Some(ctx) = &self.resumption
                            && let Some(parsed) = parse_new_session_ticket(&message)
                            && let Ok(psk) = ctx.resumption_master.hkdf_expand_label(
                                "resumption",
                                &parsed.nonce,
                                ctx.hash.output_len(),
                            )
                        {
                            ctx.cache.insert(
                                ctx.cache_key.clone(),
                                ResumptionTicket {
                                    ticket: parsed.ticket,
                                    psk,
                                    hash: ctx.hash,
                                    cipher_suite: ctx.cipher_suite,
                                    ticket_age_add: parsed.age_add,
                                    lifetime_secs: parsed.lifetime_secs,
                                    received_at: std::time::Instant::now(),
                                },
                            );
                        }
                    }
                    KEY_UPDATE => {
                        if !self.post_handshake_buf.is_empty() {
                            return Err(OwnedTlsError::Handshake(
                                HandshakeError::ProtocolViolation {
                                    reason: "KeyUpdate was followed by trailing bytes in the same record before key rotation (RFC 8446 §5.1)".into(),
                                },
                            ));
                        }
                        self.handle_key_update(&message)?;
                    }
                    other => {
                        return Err(OwnedTlsError::UnsupportedPostHandshake { got: other });
                    }
                }
            }
            return Ok((CONTENT_APPLICATION_DATA, Vec::new()));
        }
        Ok((inner, payload))
    }

    /// Process a TLS 1.3 `KeyUpdate` message (RFC 8446 §4.6.3).
    fn handle_key_update(&mut self, message: &[u8]) -> Result<(), OwnedTlsError> {
        let &[request_update] = message else {
            return Err(OwnedTlsError::Handshake(
                HandshakeError::ProtocolViolation {
                    reason: "KeyUpdate payload must be exactly 1 byte".into(),
                },
            ));
        };
        if request_update != 0 && request_update != 1 {
            return Err(OwnedTlsError::Handshake(
                HandshakeError::ProtocolViolation {
                    reason: format!("invalid KeyUpdate request_update value {request_update}"),
                },
            ));
        }
        let suite = self.cipher_suite.ok_or_else(|| {
            OwnedTlsError::Handshake(HandshakeError::ProtocolViolation {
                reason: "KeyUpdate received without a TLS 1.3 cipher suite".into(),
            })
        })?;
        let (algorithm, _, key_len) = suite_params(suite).ok_or_else(|| {
            OwnedTlsError::Handshake(HandshakeError::NegotiationFailed {
                reason: format!("unsupported TLS 1.3 cipher suite {suite:#06x} in KeyUpdate"),
            })
        })?;
        let server_ap = self.server_ap_secret.as_ref().ok_or_else(|| {
            OwnedTlsError::Handshake(HandshakeError::ProtocolViolation {
                reason: "KeyUpdate received without server application traffic secret".into(),
            })
        })?;
        let next_server_ap = server_ap
            .next_traffic_secret()
            .map_err(HandshakeError::from)?;
        let read_keys = next_server_ap
            .traffic_keys(key_len)
            .map_err(HandshakeError::from)?;
        let new_read = RecordUnprotector13::new(algorithm, &read_keys.key, read_keys.iv)
            .map_err(record_error)?;
        self.server_ap_secret = Some(next_server_ap);
        match &mut self.protectors {
            Protectors::Tls13 { read, read_seq, .. } => {
                *read = new_read;
                *read_seq = 0;
            }
            Protectors::Tls12 { .. } => {
                return Err(OwnedTlsError::Handshake(
                    HandshakeError::ProtocolViolation {
                        reason: "KeyUpdate is not valid in TLS 1.2".into(),
                    },
                ));
            }
        }

        if request_update == 1 {
            let client_ap = self.client_ap_secret.as_ref().ok_or_else(|| {
                OwnedTlsError::Handshake(HandshakeError::ProtocolViolation {
                    reason: "KeyUpdate response requires client application traffic secret".into(),
                })
            })?;
            let response_msg = [KEY_UPDATE, 0x00, 0x00, 0x01, 0x00];
            let record = match &self.protectors {
                Protectors::Tls13 {
                    write, write_seq, ..
                } => write
                    .seal(*write_seq, CONTENT_HANDSHAKE, &response_msg)
                    .map_err(record_error)?,
                Protectors::Tls12 { .. } => unreachable!(),
            };
            self.write_buf.extend_from_slice(&record);

            let next_client_ap = client_ap
                .next_traffic_secret()
                .map_err(HandshakeError::from)?;
            let write_keys = next_client_ap
                .traffic_keys(key_len)
                .map_err(HandshakeError::from)?;
            let new_write = RecordProtector13::new(algorithm, &write_keys.key, write_keys.iv)
                .map_err(record_error)?;
            self.client_ap_secret = Some(next_client_ap);
            if let Protectors::Tls13 {
                write, write_seq, ..
            } = &mut self.protectors
            {
                *write = new_write;
                *write_seq = 0;
            }
        }
        Ok(())
    }
}

/// Read wire bytes from `preroll` first, then from `socket`.
fn poll_read_wire<S: AsyncRead + Unpin>(
    socket: &mut S,
    preroll: &mut Vec<u8>,
    preroll_offset: &mut usize,
    cx: &mut std::task::Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> std::task::Poll<std::io::Result<()>> {
    if *preroll_offset < preroll.len() {
        let available = &preroll[*preroll_offset..];
        let take = available.len().min(buf.remaining());
        buf.put_slice(&available[..take]);
        *preroll_offset += take;
        if *preroll_offset == preroll.len() {
            *preroll = Vec::new();
            *preroll_offset = 0;
        }
        return std::task::Poll::Ready(Ok(()));
    }
    std::pin::Pin::new(socket).poll_read(cx, buf)
}

/// A record-layer failure outside the handshake: a connection killer with
/// no recovery.
fn record_error(error: crate::record::RecordError) -> OwnedTlsError {
    OwnedTlsError::Transport {
        reason: error.to_string(),
    }
}

fn take_post_handshake_vec(buffer: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    if buffer.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, buffer[1], buffer[2], buffer[3]]) as usize;
    if buffer.len() < 4 + len {
        return None;
    }
    let kind = buffer[0];
    let message: Vec<u8> = buffer.drain(..4 + len).collect();
    Some((kind, message[4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::{ClientHello, GoIdentity, KeyShareEntry};
    use crate::key_exchange::ClientKeyShare;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use test_support::tls::identity;

    struct AcceptAny;

    impl ServerCertVerifier for AcceptAny {
        fn verify_chain(
            &mut self,
            _server_name: &str,
            _end_entity: &[u8],
            _intermediates: &[Vec<u8>],
        ) -> Result<(), String> {
            Ok(())
        }
    }

    /// The full driver path: owned handshake + owned AsyncRead/AsyncWrite
    /// against a rustls TLS 1.3 or TLS 1.2 server, HTTP request/response in
    /// both directions.
    #[tokio::test]
    async fn the_driver_completes_handshake_and_application_data_against_rustls() {
        for (suite, versions) in [
            (
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
                &[&rustls::version::TLS13][..],
            ),
            (
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                &[&rustls::version::TLS12][..],
            ),
        ] {
            let identity = identity(&["localhost"], &[b"http/1.1"]);
            let mut provider = rustls::crypto::aws_lc_rs::default_provider();
            provider.cipher_suites = vec![suite];
            let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(versions)
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![identity.certificate.clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key.clone()),
                    ),
                )
                .expect("server certificate");
            server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let address = listener.local_addr().expect("addr");
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut connection =
                    rustls::ServerConnection::new(Arc::new(server_config)).expect("server");
                let mut buffer = [0u8; 16_384];
                let mut responded = false;
                loop {
                    while connection.wants_write() {
                        let written = connection
                            .write_tls(&mut &mut buffer[..])
                            .expect("write_tls");
                        if written == 0 {
                            break;
                        }
                        socket.write_all(&buffer[..written]).await.expect("write");
                    }
                    if responded {
                        break;
                    }
                    let read = socket.read(&mut buffer).await.expect("read");
                    if read == 0 {
                        break;
                    }
                    connection.read_tls(&mut &buffer[..read]).expect("read_tls");
                    connection.process_new_packets().expect("process");
                    let mut plaintext = [0u8; 1024];
                    if let Ok(size) = connection.reader().read(&mut plaintext)
                        && size > 0
                    {
                        connection
                            .writer()
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                            .expect("respond");
                        responded = true;
                    }
                }
            });

            let shares = ClientKeyShare::generate(&[0x11ec, 0x001d]).expect("shares");
            let entries = shares
                .iter()
                .map(|share| KeyShareEntry {
                    group: share.group,
                    share: share.share.clone(),
                })
                .collect();
            let mut random = [0u8; 32];
            aws_lc_rs::rand::fill(&mut random).expect("random");
            let hello = ClientHello::go_identity(GoIdentity {
                server_name: "localhost",
                alpn: &[b"http/1.1"],
                random,
                session_id: &[0x42; 32],
                key_shares: entries,
                cipher_suites: None,
                kx_groups: None,
            });
            let socket = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            let mut stream = OwnedTlsConnector
                .connect(socket, OwnedConnectParams { hello, shares }, AcceptAny)
                .await
                .expect("owned handshake");
            assert_eq!(stream.alpn(), Some(b"http/1.1".as_slice()));

            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write request");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("read response");
            assert!(
                response.starts_with(b"HTTP/1.1 200 OK"),
                "the server answered over the owned stream: {:?}",
                String::from_utf8_lossy(&response)
            );
            drop(stream);
            server.await.expect("server task");
        }
    }

    #[tokio::test]
    async fn the_driver_caches_new_session_ticket_and_resumes_over_psk() {
        use crate::hello::{BlueprintBuildParams, ClientHelloBlueprint, PskIdentity};
        use crate::session::{SessionCache, SessionKey};
        use std::io::Read as _;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let identity = test_support::tls::identity(&["localhost"], &[b"http/1.1"]);
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key.clone()),
                ),
            )
            .expect("server certificate");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_config = Arc::new(server_config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut connection =
                    rustls::ServerConnection::new(Arc::clone(&server_config)).expect("server");
                let mut buffer = [0u8; 16_384];
                let mut responded = false;
                loop {
                    while connection.wants_write() {
                        let written = connection
                            .write_tls(&mut &mut buffer[..])
                            .expect("write_tls");
                        if written == 0 {
                            break;
                        }
                        socket.write_all(&buffer[..written]).await.expect("write");
                    }
                    if responded {
                        break;
                    }
                    let read = socket.read(&mut buffer).await.expect("read");
                    if read == 0 {
                        break;
                    }
                    connection.read_tls(&mut &buffer[..read]).expect("read_tls");
                    connection.process_new_packets().expect("process");
                    let mut plaintext = [0u8; 1024];
                    if let Ok(size) = connection.reader().read(&mut plaintext)
                        && size > 0
                    {
                        connection
                            .writer()
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .expect("respond");
                        responded = true;
                    }
                }
            }
        });

        let cache = SessionCache::new();
        let key = SessionKey {
            server_name: "localhost".into(),
            profile_name: "go-standard".into(),
            alpn: vec![b"http/1.1".to_vec()],
        };
        let mut bp = ClientHelloBlueprint::go_standard();
        bp.alpn = vec![b"http/1.1".to_vec()];

        // 1. Initial full handshake receives NewSessionTicket and caches it.
        {
            let shares = ClientKeyShare::generate(&bp.key_share_groups).expect("shares");
            let entries = shares
                .iter()
                .map(|s| KeyShareEntry {
                    group: s.group,
                    share: s.share.clone(),
                })
                .collect();
            let mut random = [0u8; 32];
            aws_lc_rs::rand::fill(&mut random).expect("random");
            let hello = bp
                .build(BlueprintBuildParams {
                    server_name: "localhost",
                    random,
                    session_id: &[0x11; 32],
                    key_shares: entries,
                    grease_seed: [0; 8],
                    permutation_seed: [0; 32],
                })
                .expect("build");
            let socket = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect 1");
            let mut stream = OwnedTlsConnector
                .connect_with_session(
                    socket,
                    OwnedConnectParams { hello, shares },
                    AcceptAny,
                    None,
                    Some((cache.clone(), key.clone())),
                )
                .await
                .expect("handshake 1");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write 1");
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.expect("read 1");
            assert!(resp.starts_with(b"HTTP/1.1 200 OK"));
        }

        // 2. Second connection pops the ticket and performs PSK resumption.
        let ticket = cache
            .take(&key)
            .expect("ticket was cached from connection 1");
        {
            let shares = ClientKeyShare::generate(&bp.key_share_groups).expect("shares");
            let entries = shares
                .iter()
                .map(|s| KeyShareEntry {
                    group: s.group,
                    share: s.share.clone(),
                })
                .collect();
            let mut random = [0u8; 32];
            aws_lc_rs::rand::fill(&mut random).expect("random");
            let mut hello = bp
                .build(BlueprintBuildParams {
                    server_name: "localhost",
                    random,
                    session_id: &[0x22; 32],
                    key_shares: entries,
                    grease_seed: [0; 8],
                    permutation_seed: [0; 32],
                })
                .expect("build 2");
            let age_ms = ticket.obfuscated_age_ms(std::time::Instant::now());
            hello
                .attach_psk_and_sign(
                    PskIdentity {
                        identity: ticket.ticket,
                        obfuscated_ticket_age: age_ms,
                    },
                    &ticket.psk,
                    ticket.hash,
                )
                .expect("attach psk");
            let socket = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect 2");
            let mut stream = OwnedTlsConnector
                .connect_with_session(
                    socket,
                    OwnedConnectParams { hello, shares },
                    AcceptAny,
                    Some(ticket.psk),
                    Some((cache.clone(), key.clone())),
                )
                .await
                .expect("resumed PSK handshake 2");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write 2");
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.expect("read 2");
            assert!(resp.starts_with(b"HTTP/1.1 200 OK"));
        }

        server.await.expect("server task");
    }

    /// A socket wrapper that forces small partial writes and periodic
    /// `Poll::Pending` responses on `AsyncWrite` to exercise record buffering.
    struct TrickleSocket<S> {
        inner: S,
        max_write: usize,
        polls: usize,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for TrickleSocket<S> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for TrickleSocket<S> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            self.polls += 1;
            if self.polls.is_multiple_of(3) {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            let cap = buf.len().min(self.max_write);
            std::pin::Pin::new(&mut self.inner).poll_write(cx, &buf[..cap])
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn the_driver_fragments_large_writes_and_handles_partial_socket_writes() {
        use crate::hello::{BlueprintBuildParams, ClientHelloBlueprint, KeyShareEntry};

        let identity = test_support::tls::identity(&["localhost"], &[b"http/1.1"]);
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key.clone()),
                ),
            )
            .expect("server certificate");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_config = Arc::new(server_config);

        let payload_len = MAX_PLAINTEXT_LEN * 3 + 777;
        let expected_payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let expected_on_server = expected_payload.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut connection =
                rustls::ServerConnection::new(Arc::clone(&server_config)).expect("server");
            let mut received = Vec::new();
            let mut buffer = [0u8; 16_384];
            loop {
                while connection.wants_write() {
                    let written = connection
                        .write_tls(&mut &mut buffer[..])
                        .expect("write_tls");
                    if written == 0 {
                        break;
                    }
                    socket.write_all(&buffer[..written]).await.expect("write");
                }
                if received.len() >= expected_on_server.len() {
                    connection.writer().write_all(b"OK").expect("respond");
                    while connection.wants_write() {
                        let written = connection
                            .write_tls(&mut &mut buffer[..])
                            .expect("write_tls");
                        if written == 0 {
                            break;
                        }
                        socket.write_all(&buffer[..written]).await.expect("write");
                    }
                    break;
                }
                let read = socket.read(&mut buffer).await.expect("read");
                if read == 0 {
                    break;
                }
                let mut slice = &buffer[..read];
                while !slice.is_empty() {
                    let consumed = connection.read_tls(&mut slice).expect("read_tls");
                    if consumed == 0 {
                        break;
                    }
                    connection.process_new_packets().expect("process");
                    let mut chunk = [0u8; 16_384];
                    while let Ok(size) = connection.reader().read(&mut chunk) {
                        if size == 0 {
                            break;
                        }
                        received.extend_from_slice(&chunk[..size]);
                    }
                }
            }
            assert_eq!(received, expected_on_server);
        });

        let mut bp = ClientHelloBlueprint::go_standard();
        bp.alpn = vec![b"http/1.1".to_vec()];
        let shares = ClientKeyShare::generate(&bp.key_share_groups).expect("shares");
        let entries = shares
            .iter()
            .map(|s| KeyShareEntry {
                group: s.group,
                share: s.share.clone(),
            })
            .collect();
        let mut random = [0u8; 32];
        aws_lc_rs::rand::fill(&mut random).expect("random");
        let hello = bp
            .build(BlueprintBuildParams {
                server_name: "localhost",
                random,
                session_id: &[0x33; 32],
                key_shares: entries,
                grease_seed: [0; 8],
                permutation_seed: [0; 32],
            })
            .expect("build");

        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let trickle = TrickleSocket {
            inner: tcp,
            max_write: 137,
            polls: 0,
        };
        let mut stream = OwnedTlsConnector
            .connect(trickle, OwnedConnectParams { hello, shares }, AcceptAny)
            .await
            .expect("handshake");

        stream
            .write_all(&expected_payload)
            .await
            .expect("large write_all across records");
        stream.flush().await.expect("flush");

        let mut ack = [0u8; 2];
        stream.read_exact(&mut ack).await.expect("read ack");
        assert_eq!(&ack, b"OK");
        server.await.expect("server task");
    }

    struct ScriptedReadSocket {
        steps: std::collections::VecDeque<Option<Vec<u8>>>,
        written: Vec<u8>,
        write_pending_once: bool,
        max_write: usize,
    }

    impl ScriptedReadSocket {
        fn new(steps: Vec<Option<Vec<u8>>>) -> Self {
            Self {
                steps: steps.into(),
                written: Vec::new(),
                write_pending_once: false,
                max_write: usize::MAX,
            }
        }
    }

    impl AsyncRead for ScriptedReadSocket {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            while let Some(front) = self.steps.pop_front() {
                match front {
                    None => {
                        cx.waker().wake_by_ref();
                        return std::task::Poll::Pending;
                    }
                    Some(mut chunk) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        let take = chunk.len().min(buf.remaining());
                        buf.put_slice(&chunk[..take]);
                        if take < chunk.len() {
                            self.steps.push_front(Some(chunk.split_off(take)));
                        }
                        return std::task::Poll::Ready(Ok(()));
                    }
                }
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedReadSocket {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            if self.write_pending_once {
                self.write_pending_once = false;
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            let take = buf.len().min(self.max_write);
            self.written.extend_from_slice(&buf[..take]);
            std::task::Poll::Ready(Ok(take))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn synthetic_tls13_pair() -> (
        Established,
        RecordProtector13,
        RecordUnprotector13,
        Secret,
        Secret,
    ) {
        let client_ap = Secret::extract(&[0u8; 32], &[0x33; 32], Hash::Sha256);
        let server_ap = Secret::extract(&[0u8; 32], &[0x44; 32], Hash::Sha256);
        let client_keys = client_ap.traffic_keys(16).expect("client keys");
        let server_keys = server_ap.traffic_keys(16).expect("server keys");
        let client_write = RecordProtector13::new(
            &aws_lc_rs::aead::AES_128_GCM,
            &client_keys.key,
            client_keys.iv,
        )
        .expect("client write");
        let server_read = RecordUnprotector13::new(
            &aws_lc_rs::aead::AES_128_GCM,
            &client_keys.key,
            client_keys.iv,
        )
        .expect("server read");
        let server_write = RecordProtector13::new(
            &aws_lc_rs::aead::AES_128_GCM,
            &server_keys.key,
            server_keys.iv,
        )
        .expect("server write");
        let client_read = RecordUnprotector13::new(
            &aws_lc_rs::aead::AES_128_GCM,
            &server_keys.key,
            server_keys.iv,
        )
        .expect("client read");

        let established = Established {
            alpn: Some(b"http/1.1".to_vec()),
            protectors: Protectors::Tls13 {
                write: client_write,
                read: client_read,
                write_seq: 0,
                read_seq: 0,
            },
            resumption_master: Some(Secret::extract(&[0u8; 32], &[0x55; 32], Hash::Sha256)),
            client_ap_secret: Some(client_ap.clone()),
            server_ap_secret: Some(server_ap.clone()),
            hash: Hash::Sha256,
            cipher_suite: Some(0x1301),
            max_write_plaintext: MAX_PLAINTEXT_LEN,
        };
        (established, server_write, server_read, client_ap, server_ap)
    }

    #[tokio::test]
    async fn the_driver_survives_single_byte_headers_pending_polls_and_partial_payloads() {
        let (established, server_write, _, _, _) = synthetic_tls13_pair();
        let empty_rec = server_write
            .seal(0, CONTENT_APPLICATION_DATA, &[])
            .expect("empty");
        let app_rec = server_write
            .seal(1, CONTENT_APPLICATION_DATA, b"hello after pending")
            .expect("app");
        let user_canceled = server_write
            .seal(2, CONTENT_ALERT, &[1, 90])
            .expect("user_canceled");
        let close_notify = server_write
            .seal(3, CONTENT_ALERT, &[1, 0])
            .expect("close_notify");

        // Feed byte-by-byte with a `Poll::Pending` between EVERY byte so
        // `NeedHeader { filled: 1..=4 }` (including the exact `filled: 4` panic
        // trigger) and `NeedPayload { filled: .. }` all yield across polls.
        let mut wire = Vec::new();
        wire.extend_from_slice(&empty_rec);
        wire.extend_from_slice(&app_rec);
        wire.extend_from_slice(&user_canceled);
        wire.extend_from_slice(&close_notify);
        let mut steps = Vec::with_capacity(wire.len() * 2);
        for byte in wire {
            steps.push(Some(vec![byte]));
            steps.push(None);
        }

        let mut stream = OwnedTlsStream::new(ScriptedReadSocket::new(steps), established, None);

        // Zero-length destination reads must be no-ops.
        let n0 = stream.read(&mut []).await.expect("zero-len read");
        assert_eq!(n0, 0);

        // Drain 3 bytes at a time until clean close_notify EOF.
        let mut got = Vec::new();
        let mut small = [0u8; 3];
        loop {
            let n = stream.read(&mut small).await.expect("chunked read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&small[..n]);
        }
        assert_eq!(&got, b"hello after pending");
    }

    #[tokio::test]
    async fn the_driver_rejects_mid_record_eof_with_unexpected_eof() {
        // 1) Truncated inside NeedHeader (filled = 4).
        let (established, _, _, _, _) = synthetic_tls13_pair();
        let mut header_eof = OwnedTlsStream::new(
            ScriptedReadSocket::new(vec![Some(vec![0x17, 0x03, 0x03, 0x00])]),
            established,
            None,
        );
        let err = header_eof
            .read(&mut [0u8; 16])
            .await
            .expect_err("truncated header must error");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        // 2) Truncated inside NeedPayload.
        let (established, _, _, _, _) = synthetic_tls13_pair();
        let mut payload_eof = OwnedTlsStream::new(
            ScriptedReadSocket::new(vec![
                Some(vec![0x17, 0x03, 0x03, 0x00, 0x20]),
                None,
                Some(vec![0xaa; 7]),
            ]),
            established,
            None,
        );
        let err = payload_eof
            .read(&mut [0u8; 16])
            .await
            .expect_err("truncated payload must error");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn the_driver_drains_preroll_coalesced_ticket_and_application_data() {
        let (established, server_write, _, _, _) = synthetic_tls13_pair();

        // Build a synthetic NewSessionTicket: lifetime(4)=600, age_add(4)=1,
        // nonce_len(1)=2, nonce=[0xaa, 0xbb], ticket_len(2)=4, ticket="TKT1", ext_len(2)=0.
        let mut nst_body = Vec::new();
        nst_body.extend_from_slice(&600u32.to_be_bytes());
        nst_body.extend_from_slice(&1u32.to_be_bytes());
        nst_body.push(2);
        nst_body.extend_from_slice(&[0xaa, 0xbb]);
        nst_body.extend_from_slice(&4u16.to_be_bytes());
        nst_body.extend_from_slice(b"TKT1");
        nst_body.extend_from_slice(&0u16.to_be_bytes());
        let mut nst_msg = Vec::with_capacity(4 + nst_body.len());
        nst_msg.push(NEW_SESSION_TICKET);
        nst_msg.extend_from_slice(&(nst_body.len() as u32).to_be_bytes()[1..4]);
        nst_msg.extend_from_slice(&nst_body);

        let mut preroll = Vec::new();
        preroll.extend_from_slice(
            &server_write
                .seal(0, CONTENT_HANDSHAKE, &nst_msg)
                .expect("nst"),
        );
        preroll.extend_from_slice(
            &server_write
                .seal(1, CONTENT_APPLICATION_DATA, b"coalesced body")
                .expect("app"),
        );
        preroll.extend_from_slice(&server_write.seal(2, CONTENT_ALERT, &[1, 0]).expect("eof"));

        let cache = SessionCache::new();
        let key = SessionKey {
            server_name: "example.test".into(),
            profile_name: "go".into(),
            alpn: vec![b"http/1.1".to_vec()],
        };
        let mut stream = OwnedTlsStream::new_with_preroll(
            ScriptedReadSocket::new(Vec::new()),
            established,
            Some((cache.clone(), key.clone())),
            preroll,
        );

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.expect("read preroll");
        assert_eq!(&body, b"coalesced body");
        let cached = cache.take(&key).expect("ticket from preroll cached");
        assert_eq!(&cached.ticket, b"TKT1");
    }

    #[tokio::test]
    async fn the_driver_handles_tls13_key_update_from_rustls_and_acknowledges_request_update_one() {
        // Part A: live rustls server triggering KeyUpdate mid-stream.
        let identity = identity(&["localhost"], &[b"http/1.1"]);
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key.clone()),
                ),
            )
            .expect("cert");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut conn = rustls::ServerConnection::new(Arc::new(server_config)).expect("server");
            let mut buf = [0u8; 4096];
            let mut received = Vec::new();
            let mut updated = false;
            loop {
                while conn.wants_write() {
                    let n = conn.write_tls(&mut &mut buf[..]).expect("write_tls");
                    if n == 0 {
                        break;
                    }
                    sock.write_all(&buf[..n]).await.expect("sock write");
                }
                if received.starts_with(b"before update") && !updated {
                    conn.refresh_traffic_keys().expect("refresh server keys");
                    conn.writer()
                        .write_all(b"after server key update")
                        .expect("write post-update");
                    updated = true;
                    continue;
                }
                if updated && received.ends_with(b"client still alive") {
                    break;
                }
                let n = sock.read(&mut buf).await.expect("sock read");
                if n == 0 {
                    break;
                }
                conn.read_tls(&mut &buf[..n]).expect("read_tls");
                conn.process_new_packets().expect("process");
                let mut plain = [0u8; 256];
                while let Ok(r) = conn.reader().read(&mut plain) {
                    if r == 0 {
                        break;
                    }
                    received.extend_from_slice(&plain[..r]);
                }
            }
        });

        let hello = ClientHello::go_identity(GoIdentity {
            server_name: "localhost",
            alpn: &[b"http/1.1"],
            random: [0x21; 32],
            session_id: &[0x22; 32],
            key_shares: Vec::new(),
            cipher_suites: None,
            kx_groups: None,
        });
        let shares = ClientKeyShare::generate(&[0x001d, 0x0017]).expect("shares");
        let entries = shares
            .iter()
            .map(|s| KeyShareEntry {
                group: s.group,
                share: s.share.clone(),
            })
            .collect();
        let mut hello = hello;
        for ext in &mut hello.extensions {
            if let crate::hello::ExtensionBody::KeyShare { shares } = &mut ext.body {
                *shares = entries;
                break;
            }
        }
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut stream = OwnedTlsConnector
            .connect(tcp, OwnedConnectParams { hello, shares }, AcceptAny)
            .await
            .expect("connect tls");
        stream.write_all(b"before update").await.expect("write 1");
        stream.flush().await.expect("flush 1");
        let mut reply = [0u8; 23];
        stream
            .read_exact(&mut reply)
            .await
            .expect("read post-update");
        assert_eq!(&reply, b"after server key update");
        stream
            .write_all(b"client still alive")
            .await
            .expect("write 2");
        stream.flush().await.expect("flush 2");
        server.await.expect("server done");

        // Part B: split read-only reader receives KeyUpdate(request_update=1)
        // and must automatically flush KeyUpdate(0) without waiting for poll_write.
        let (established, server_write0, server_read0, client_ap, server_ap) =
            synthetic_tls13_pair();
        let (client_io, mut server_io) = tokio::io::duplex(8192);
        let tls_stream = OwnedTlsStream::new(client_io, established, None);
        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        let ku_req = [KEY_UPDATE, 0x00, 0x00, 0x01, 0x01];
        server_io
            .write_all(
                &server_write0
                    .seal(0, CONTENT_HANDSHAKE, &ku_req)
                    .expect("seal ku"),
            )
            .await
            .expect("send ku");
        let next_server_ap = server_ap.next_traffic_secret().expect("next server ap");
        let next_server_keys = next_server_ap.traffic_keys(16).expect("server keys 1");
        let server_write1 = RecordProtector13::new(
            &aws_lc_rs::aead::AES_128_GCM,
            &next_server_keys.key,
            next_server_keys.iv,
        )
        .expect("server write1");
        server_io
            .write_all(
                &server_write1
                    .seal(0, CONTENT_APPLICATION_DATA, b"post-update from server")
                    .expect("seal app"),
            )
            .await
            .expect("send app");

        // Poll ONLY `reader` — `writer` is never touched yet!
        let mut got = [0u8; 23];
        reader
            .read_exact(&mut got)
            .await
            .expect("read after key update");
        assert_eq!(&got, b"post-update from server");

        // Server must already see the client's KeyUpdate(0) sealed with old key seq 0.
        let mut hdr = [0u8; RECORD_HEADER_LEN];
        server_io.read_exact(&mut hdr).await.expect("ku hdr");
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut rec = Vec::with_capacity(RECORD_HEADER_LEN + len);
        rec.extend_from_slice(&hdr);
        rec.resize(RECORD_HEADER_LEN + len, 0);
        server_io
            .read_exact(&mut rec[RECORD_HEADER_LEN..])
            .await
            .expect("ku body");
        let (ct, body) = server_read0.open(0, &rec).expect("open client ku(0)");
        assert_eq!(ct, CONTENT_HANDSHAKE);
        assert_eq!(body, vec![KEY_UPDATE, 0x00, 0x00, 0x01, 0x00]);

        // Subsequent writes must use the rotated client key (`client_ap.next_traffic_secret()`).
        writer
            .write_all(b"post-update from client")
            .await
            .expect("write rotated");
        let mut hdr = [0u8; RECORD_HEADER_LEN];
        server_io.read_exact(&mut hdr).await.expect("app hdr");
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut rec = Vec::with_capacity(RECORD_HEADER_LEN + len);
        rec.extend_from_slice(&hdr);
        rec.resize(RECORD_HEADER_LEN + len, 0);
        server_io
            .read_exact(&mut rec[RECORD_HEADER_LEN..])
            .await
            .expect("app body");
        let next_client_ap = client_ap.next_traffic_secret().expect("next client ap");
        let next_client_keys = next_client_ap.traffic_keys(16).expect("client keys 1");
        let server_read1 = RecordUnprotector13::new(
            &aws_lc_rs::aead::AES_128_GCM,
            &next_client_keys.key,
            next_client_keys.iv,
        )
        .expect("server read1");
        let (ct, body) = server_read1.open(0, &rec).expect("open rotated write");
        assert_eq!(ct, CONTENT_APPLICATION_DATA);
        assert_eq!(&body, b"post-update from client");
    }

    #[tokio::test]
    async fn the_driver_flushes_write_all_without_explicit_flush_and_guards_short_retry() {
        // Part A: `write_all` over TrickleSocket WITHOUT calling `.flush()`.
        let identity = identity(&["localhost"], &[b"http/1.1"]);
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key.clone()),
                ),
            )
            .expect("cert");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_config = Arc::new(server_config);

        let expected: Vec<u8> = (0..(MAX_PLAINTEXT_LEN + 321))
            .map(|i| (i % 199) as u8)
            .collect();
        let expected_srv = expected.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut conn = rustls::ServerConnection::new(server_config).expect("server");
            let mut got = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                while conn.wants_write() {
                    let n = conn.write_tls(&mut &mut buf[..]).expect("write_tls");
                    if n == 0 {
                        break;
                    }
                    sock.write_all(&buf[..n]).await.expect("sock write");
                }
                if got.len() >= expected_srv.len() {
                    conn.writer().write_all(b"OK").expect("ack");
                    while conn.wants_write() {
                        let n = conn.write_tls(&mut &mut buf[..]).expect("write_tls");
                        if n == 0 {
                            break;
                        }
                        sock.write_all(&buf[..n]).await.expect("sock write");
                    }
                    break;
                }
                let n = sock.read(&mut buf).await.expect("sock read");
                if n == 0 {
                    break;
                }
                let mut slice = &buf[..n];
                while !slice.is_empty() {
                    let consumed = conn.read_tls(&mut slice).expect("read_tls");
                    if consumed == 0 {
                        break;
                    }
                    conn.process_new_packets().expect("process");
                    let mut p = [0u8; 8192];
                    while let Ok(r) = conn.reader().read(&mut p) {
                        if r == 0 {
                            break;
                        }
                        got.extend_from_slice(&p[..r]);
                    }
                }
            }
            assert_eq!(got, expected_srv);
        });

        let bp = crate::hello::ClientHelloBlueprint::go_standard();
        let shares = ClientKeyShare::generate(&bp.key_share_groups).expect("shares");
        let entries = shares
            .iter()
            .map(|s| KeyShareEntry {
                group: s.group,
                share: s.share.clone(),
            })
            .collect();
        let hello = bp
            .build(crate::hello::BlueprintBuildParams {
                server_name: "localhost",
                random: [0x44; 32],
                session_id: &[0x55; 32],
                key_shares: entries,
                grease_seed: [0; 8],
                permutation_seed: [0; 32],
            })
            .expect("build");
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let trickle = TrickleSocket {
            inner: tcp,
            max_write: 7,
            polls: 0,
        };
        let mut stream = OwnedTlsConnector
            .connect(trickle, OwnedConnectParams { hello, shares }, AcceptAny)
            .await
            .expect("handshake");

        // Deliberately do NOT call `stream.flush().await`.
        stream.write_all(&expected).await.expect("write_all");
        let mut ack = [0u8; 2];
        stream.read_exact(&mut ack).await.expect("read ack");
        assert_eq!(&ack, b"OK");
        server.await.expect("server");

        // Part B: cancelled poll_write retried with smaller buffer errors cleanly.
        let (established, _, _, _, _) = synthetic_tls13_pair();
        let mut sock = ScriptedReadSocket::new(Vec::new());
        sock.max_write = 3;
        sock.write_pending_once = false;
        // Inject Pending after the first 3 bytes via custom wrapper inline.
        struct SplitPendingWrite {
            step: usize,
            written: Vec<u8>,
        }
        impl AsyncRead for SplitPendingWrite {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for SplitPendingWrite {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<Result<usize, std::io::Error>> {
                self.step += 1;
                if self.step == 1 {
                    let take = buf.len().min(4);
                    self.written.extend_from_slice(&buf[..take]);
                    std::task::Poll::Ready(Ok(take))
                } else if self.step == 2 {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    self.written.extend_from_slice(buf);
                    std::task::Poll::Ready(Ok(buf.len()))
                }
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), std::io::Error>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), std::io::Error>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let mut stream = OwnedTlsStream::new(
            SplitPendingWrite {
                step: 0,
                written: Vec::new(),
            },
            established,
            None,
        );
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(matches!(
            std::pin::Pin::new(&mut stream).poll_write(&mut cx, &[0xaa; 20]),
            std::task::Poll::Pending
        ));
        let err = match std::pin::Pin::new(&mut stream).poll_write(&mut cx, &[0xbb; 4]) {
            std::task::Poll::Ready(Err(e)) => e,
            other => panic!("expected InvalidInput error on short retry, got {other:?}"),
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn the_driver_verifies_ip_literal_san_without_sending_sni() {
        let identity = identity(&["127.0.0.1"], &[b"http/1.1"]);
        let anchor_der = identity.certificate.as_ref().to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server_cfg = identity.server.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut conn = rustls::ServerConnection::new(server_cfg).expect("server");
            let mut buf = [0u8; 4096];
            let mut seen_ping = Vec::new();
            let mut replied = false;
            loop {
                while conn.wants_write() {
                    let n = conn.write_tls(&mut &mut buf[..]).expect("write_tls");
                    if n == 0 {
                        break;
                    }
                    sock.write_all(&buf[..n]).await.expect("sock write");
                }
                if !replied && seen_ping == b"ip-ping" {
                    assert!(
                        conn.server_name().is_none(),
                        "wire ClientHello must omit SNI when targeting an IP literal"
                    );
                    conn.writer().write_all(b"ip-pong").expect("write pong");
                    replied = true;
                    continue;
                }
                if replied {
                    break;
                }
                let n = sock.read(&mut buf).await.expect("sock read");
                if n == 0 {
                    break;
                }
                conn.read_tls(&mut &buf[..n]).expect("read_tls");
                conn.process_new_packets().expect("process");
                let mut plain = [0u8; 256];
                while let Ok(r) = conn.reader().read(&mut plain) {
                    if r == 0 {
                        break;
                    }
                    seen_ping.extend_from_slice(&plain[..r]);
                }
            }
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let bp = crate::hello::ClientHelloBlueprint::chrome_current();
        let shares = ClientKeyShare::generate(&bp.key_share_groups).expect("shares");
        let entries = shares
            .iter()
            .map(|s| KeyShareEntry {
                group: s.group,
                share: s.share.clone(),
            })
            .collect();
        let mut random = [0u8; 32];
        let mut session_id = [0u8; 32];
        let mut grease_seed = [0u8; 8];
        let mut permutation_seed = [0u8; 32];
        crate::hello::fill_random(&mut random).expect("rng");
        crate::hello::fill_random(&mut session_id).expect("rng");
        crate::hello::fill_random(&mut grease_seed).expect("rng");
        crate::hello::fill_random(&mut permutation_seed).expect("rng");
        let hello = bp
            .build(crate::hello::BlueprintBuildParams {
                server_name: "127.0.0.1",
                random,
                session_id: &session_id,
                key_shares: entries,
                grease_seed,
                permutation_seed,
            })
            .expect("build");

        let mut tls = OwnedTlsConnector
            .connect_for_server(
                tcp,
                OwnedConnectParams { hello, shares },
                crate::verifier::Verifier::Pinned(anchor_der),
                Some("127.0.0.1"),
                None,
                None,
            )
            .await
            .expect("ip-san TLS handshake must succeed");
        tls.write_all(b"ip-ping").await.expect("write");
        tls.flush().await.expect("flush");
        let mut reply = [0u8; 7];
        tls.read_exact(&mut reply).await.expect("read");
        assert_eq!(&reply, b"ip-pong");
        server.await.expect("server");
    }
}
