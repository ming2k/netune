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
//! NewSessionTicket is parsed and dropped (session resumption is a
//! documented non-goal until an ADR ratifies it), a key_update is refused,
//! and a peer close_notify reads as end-of-stream. Everything else is an
//! error.

use thiserror::Error;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::handshake::{
    ClientHandshake, Established, HandshakeError, HandshakeProgress, KEY_UPDATE,
    NEW_SESSION_TICKET, Protectors, ServerCertVerifier,
};
use crate::hello::ClientHello;
use crate::key_exchange::ClientKeyShare;
use crate::key_schedule::{Hash, Secret};
use crate::record::{
    CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE, MAX_CIPHERTEXT_LEN,
    MAX_PLAINTEXT_LEN, RECORD_HEADER_LEN,
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
        mut socket: S,
        params: OwnedConnectParams,
        verifier: impl ServerCertVerifier,
        offered_psk: Option<Vec<u8>>,
        session_store: Option<(SessionCache, SessionKey)>,
    ) -> Result<OwnedTlsStream<S>, OwnedTlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut machine =
            ClientHandshake::start_with_psk(params.hello, params.shares, verifier, offered_psk)
                .map_err(OwnedTlsError::from)?;
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
        Ok(OwnedTlsStream::new(socket, established, session_store))
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
    /// Where the read state machine stands.
    state: ReadState,
    /// Optional TLS 1.3 session resumption context for caching incoming
    /// `NewSessionTicket` messages.
    resumption: Option<ResumptionContext>,
    /// Encrypted record bytes queued for the underlying socket across partial
    /// writes or `Poll::Pending`.
    write_buf: Vec<u8>,
    /// Offset into `write_buf` already accepted by `socket`.
    write_offset: usize,
}

impl<S> OwnedTlsStream<S> {
    /// Wrap the established connection.
    fn new(
        socket: S,
        established: Established,
        session_store: Option<(SessionCache, SessionKey)>,
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
            plaintext: Vec::new(),
            consumed: 0,
            peer_closed: false,
            header_scratch: [0u8; RECORD_HEADER_LEN],
            payload_scratch: Vec::new(),
            state: ReadState::default(),
            resumption,
            write_buf: Vec::new(),
            write_offset: 0,
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
        let alert = [1u8, 0]; // warning-level close_notify
        let record = match &self.protectors {
            Protectors::Tls13 {
                write, write_seq, ..
            } => write
                .seal(*write_seq, CONTENT_ALERT, &alert)
                .map_err(record_error)?,
            Protectors::Tls12 {
                write, write_seq, ..
            } => write
                .seal(*write_seq, CONTENT_ALERT, &alert)
                .map_err(record_error)?,
        };
        match &mut self.protectors {
            Protectors::Tls13 { write_seq, .. } | Protectors::Tls12 { write_seq, .. } => {
                *write_seq += 1;
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
        // sealing new plaintext.
        match this.poll_flush_write_buf(cx) {
            std::task::Poll::Ready(Ok(())) => {}
            std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }

        // Fragment at the RFC 8446 §5.1 / RFC 5246 §6.2.1 2^14-byte plaintext
        // limit so callers (e.g. `write_all`) can pass arbitrarily large buffers.
        let chunk = &buf[..buf.len().min(MAX_PLAINTEXT_LEN)];
        let record = match &this.protectors {
            Protectors::Tls13 {
                write, write_seq, ..
            } => write
                .seal(*write_seq, CONTENT_APPLICATION_DATA, chunk)
                .map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                })?,
            Protectors::Tls12 {
                write, write_seq, ..
            } => write
                .seal(*write_seq, CONTENT_APPLICATION_DATA, chunk)
                .map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                })?,
        };
        match &mut this.protectors {
            Protectors::Tls13 { write_seq, .. } | Protectors::Tls12 { write_seq, .. } => {
                *write_seq += 1;
            }
        }
        this.write_buf = record;
        this.write_offset = 0;

        // Best-effort immediate flush: if the socket accepts part of the record
        // or returns Pending, the remainder stays buffered in `write_buf` and
        // `chunk.len()` is already committed to the TLS stream.
        match this.poll_flush_write_buf(cx) {
            std::task::Poll::Ready(Ok(())) | std::task::Poll::Pending => {
                std::task::Poll::Ready(Ok(chunk.len()))
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        match this.poll_flush_write_buf(cx) {
            std::task::Poll::Ready(Ok(())) => std::pin::Pin::new(&mut this.socket).poll_flush(cx),
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
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
                std::pin::Pin::new(&mut this.socket).poll_shutdown(cx)
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
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

impl<S: AsyncRead + Unpin> AsyncRead for OwnedTlsStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.consumed < this.plaintext.len() {
            let available = this.plaintext[this.consumed..].to_vec();
            let take = available.len().min(out.remaining());
            out.put_slice(&available[..take]);
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
            match this.state {
                ReadState::NeedHeader { filled } => {
                    let mut header = [0u8; RECORD_HEADER_LEN];
                    header[..filled].copy_from_slice(&this.header_scratch[..filled]);
                    let mut buf = ReadBuf::new(&mut header);
                    match std::pin::Pin::new(&mut this.socket).poll_read(cx, &mut buf) {
                        std::task::Poll::Ready(Ok(())) => {
                            let filled_now = buf.filled().len();
                            if filled_now == 0 {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            let filled = filled + filled_now;
                            if filled < RECORD_HEADER_LEN {
                                this.header_scratch[..filled]
                                    .copy_from_slice(&buf.filled()[..filled]);
                                this.state = ReadState::NeedHeader { filled };
                                continue;
                            }
                            let mut complete = [0u8; RECORD_HEADER_LEN];
                            complete.copy_from_slice(buf.filled());
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
                            this.payload_scratch = vec![0u8; payload_len];
                        }
                        std::task::Poll::Ready(Err(error)) => {
                            return std::task::Poll::Ready(Err(error));
                        }
                        std::task::Poll::Pending => {
                            this.header_scratch[..filled].copy_from_slice(&buf.filled()[..filled]);
                            this.state = ReadState::NeedHeader { filled };
                            return std::task::Poll::Pending;
                        }
                    }
                }
                ReadState::NeedPayload { header, filled } => {
                    let mut buf = ReadBuf::new(&mut this.payload_scratch[filled..]);
                    match std::pin::Pin::new(&mut this.socket).poll_read(cx, &mut buf) {
                        std::task::Poll::Ready(Ok(())) => {
                            let filled_now = buf.filled().len();
                            if filled_now == 0 {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            let filled = filled + filled_now;
                            let payload_len = this.payload_scratch.len();
                            if filled < payload_len {
                                this.state = ReadState::NeedPayload { header, filled };
                                continue;
                            }
                            let mut record = Vec::with_capacity(RECORD_HEADER_LEN + payload_len);
                            record.extend_from_slice(&header);
                            record.extend_from_slice(&this.payload_scratch);
                            let (content_type, plaintext) = this
                                .open_post_handshake(record.as_slice())
                                .map_err(|error| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        error.to_string(),
                                    )
                                })?;
                            match content_type {
                                CONTENT_APPLICATION_DATA => {
                                    if plaintext.is_empty() {
                                        this.state = ReadState::NeedHeader { filled: 0 };
                                        continue;
                                    }
                                    this.plaintext = plaintext.clone();
                                    this.consumed = 0;
                                    let take = plaintext.len().min(out.remaining());
                                    out.put_slice(&this.plaintext[..take]);
                                    this.consumed = take;
                                    if this.consumed == this.plaintext.len() {
                                        this.plaintext.clear();
                                        this.consumed = 0;
                                    }
                                    this.state = ReadState::NeedHeader { filled: 0 };
                                    return std::task::Poll::Ready(Ok(()));
                                }
                                CONTENT_ALERT => {
                                    if plaintext == [1u8, 0] {
                                        this.peer_closed = true;
                                        this.state = ReadState::NeedHeader { filled: 0 };
                                        return std::task::Poll::Ready(Ok(()));
                                    }
                                    return std::task::Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        OwnedTlsError::Alert {
                                            level: plaintext.first().copied().unwrap_or(0),
                                            description: plaintext.get(1).copied().unwrap_or(0),
                                        }
                                        .to_string(),
                                    )));
                                }
                                _ => {
                                    this.state = ReadState::NeedHeader { filled: 0 };
                                    continue;
                                }
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
                let (inner, payload) = read.open(*read_seq, record).map_err(record_error)?;
                advanced = read_seq + 1;
                (inner, payload)
            }
            Protectors::Tls12 { read, read_seq, .. } => {
                let (inner, payload) = read.open(*read_seq, record).map_err(record_error)?;
                advanced = read_seq + 1;
                (inner, payload)
            }
        };
        match &mut self.protectors {
            Protectors::Tls13 { read_seq, .. } | Protectors::Tls12 { read_seq, .. } => {
                *read_seq = advanced;
            }
        }
        if inner == CONTENT_HANDSHAKE {
            // Post-handshake messages: cache NewSessionTicket when a session
            // store is wired; refuse key_update or unknown messages.
            let mut rest = payload.as_slice();
            while let Some((kind, message)) = take_post_handshake_message(&mut rest) {
                if kind == NEW_SESSION_TICKET {
                    if let Some(ctx) = &self.resumption
                        && let Some(parsed) = parse_new_session_ticket(message)
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
                    continue;
                }
                return Err(OwnedTlsError::UnsupportedPostHandshake { got: KEY_UPDATE });
            }
            return Ok((CONTENT_APPLICATION_DATA, Vec::new()));
        }
        Ok((inner, payload))
    }
}

/// Split one complete handshake message from the front; `None` while fewer
/// than the declared bytes remain.
/// A record-layer failure outside the handshake: a connection killer with
/// no recovery.
fn record_error(error: crate::record::RecordError) -> OwnedTlsError {
    OwnedTlsError::Transport {
        reason: error.to_string(),
    }
}

fn take_post_handshake_message<'a>(buffer: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    if buffer.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, buffer[1], buffer[2], buffer[3]]) as usize;
    if buffer.len() < 4 + len {
        return None;
    }
    let (message, rest) = buffer.split_at(4 + len);
    *buffer = rest;
    Some((message[0], &message[4..]))
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
}
