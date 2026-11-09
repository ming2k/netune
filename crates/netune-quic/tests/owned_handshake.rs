// SPDX-License-Identifier: MIT

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Handshake integration: the owned wire/crypto/TLS layers drive a real QUIC
//! handshake against a `quinn` server. `quinn` is a dev-only oracle.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use netune_quic::crypto::{
    CryptoError, TlsSession, initial_keys, long_header_info, protect_long, protect_short,
    unprotect_long, unprotect_short,
};
use netune_quic::wire::frame::Frame;
use netune_quic::wire::packet::{LongPacket, LongType, ShortPacket, VERSION_1};
use netune_quic::wire::transport_parameters::TransportParameters;
use netune_quic::wire::varint;
use tokio::net::UdpSocket;

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn server_endpoint() -> (quinn::Endpoint, SocketAddr) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("cert");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("server crypto"),
    ));
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = socket.local_addr().expect("addr");
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("endpoint");
    (endpoint, addr)
}

fn client_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

fn random_cid(len: usize) -> Vec<u8> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut cid = vec![0u8; len];
    provider
        .secure_random
        .fill(&mut cid)
        .expect("secure random");
    cid
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Initial = 0,
    Handshake = 1,
    OneRtt = 2,
}

struct Space {
    keys: Option<rustls::quic::Keys>,
    next_pn: u64,
    received: BTreeSet<u64>,
    crypto_send: Vec<u8>,
    crypto_sent: usize,
    crypto_recv: BTreeMap<u64, Vec<u8>>,
    crypto_read: u64,
}

impl Space {
    fn new(keys: Option<rustls::quic::Keys>) -> Self {
        Self {
            keys,
            next_pn: 0,
            received: BTreeSet::new(),
            crypto_send: Vec::new(),
            crypto_sent: 0,
            crypto_recv: BTreeMap::new(),
            crypto_read: 0,
        }
    }
}

struct OwnedClient {
    socket: UdpSocket,
    server: SocketAddr,
    original_dcid: Vec<u8>,
    scid: Vec<u8>,
    peer_cid: Vec<u8>,
    tls: TlsSession,
    spaces: [Space; 3],
    tls_send_level: Level,
    tls_read_level: Level,
    handshake_done: bool,
    stream_data: BTreeMap<u64, Vec<u8>>,
    stream_fin: BTreeSet<u64>,
}

impl OwnedClient {
    async fn new(server: SocketAddr) -> Result<Self, String> {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let original_dcid = random_cid(8);
        let scid = random_cid(8);
        let tls = TlsSession::client(
            client_config(),
            rustls::pki_types::ServerName::try_from("localhost").expect("name"),
            client_transport_parameters(&scid),
        )
        .map_err(|error| error.to_string())?;
        let initial = initial_keys(&original_dcid, rustls::Side::Client)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            socket,
            server,
            original_dcid,
            scid: scid.clone(),
            peer_cid: scid,
            tls,
            spaces: [
                Space::new(Some(initial)),
                Space::new(None),
                Space::new(None),
            ],
            tls_send_level: Level::Initial,
            tls_read_level: Level::Initial,
            handshake_done: false,
            stream_data: BTreeMap::new(),
            stream_fin: BTreeSet::new(),
        })
    }

    async fn run(&mut self) -> Result<(), String> {
        self.drain_tls()?;
        self.send_pending().await?;
        let mut buffer = vec![0u8; 64 * 1024];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !self.handshake_done {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err("handshake timed out".to_string());
            }
            let received = tokio::time::timeout(remaining, self.socket.recv_from(&mut buffer))
                .await
                .map_err(|_| "handshake timed out".to_string())?
                .map_err(|error| error.to_string())?;
            self.process_datagram(&buffer[..received.0]).await?;
            self.send_pending().await?;
        }
        Ok(())
    }

    fn drain_tls(&mut self) -> Result<(), String> {
        loop {
            let level = self.tls_send_level;
            let mut data = Vec::new();
            let change = self.tls.write_handshake(&mut data);
            if !data.is_empty() {
                self.space(level).crypto_send.extend_from_slice(&data);
            }
            let advanced = !data.is_empty();
            if let Some(change) = change {
                match change {
                    rustls::quic::KeyChange::Handshake { keys } => {
                        self.spaces[Level::Handshake as usize].keys = Some(keys);
                        self.tls_send_level = Level::Handshake;
                        self.tls_read_level = Level::Handshake;
                    }
                    rustls::quic::KeyChange::OneRtt { keys, .. } => {
                        self.spaces[Level::OneRtt as usize].keys = Some(keys);
                        self.tls_send_level = Level::OneRtt;
                        self.tls_read_level = Level::OneRtt;
                    }
                }
                continue;
            }
            if !advanced {
                break;
            }
        }
        Ok(())
    }

    fn space(&mut self, level: Level) -> &mut Space {
        &mut self.spaces[level as usize]
    }

    async fn send_pending(&mut self) -> Result<(), String> {
        for level in [Level::Initial, Level::Handshake, Level::OneRtt] {
            loop {
                let (offset, chunk) = {
                    let space = self.space(level);
                    if space.crypto_sent >= space.crypto_send.len() {
                        break;
                    }
                    let offset = space.crypto_sent;
                    let end = (offset + 1000).min(space.crypto_send.len());
                    let chunk = space.crypto_send[offset..end].to_vec();
                    space.crypto_sent = end;
                    (offset, chunk)
                };
                let mut payload = BytesMut::new();
                Frame::Crypto {
                    offset: offset as u64,
                    data: Bytes::from(chunk),
                }
                .encode(&mut payload)
                .map_err(|error| error.to_string())?;
                self.send_level(level, payload.freeze()).await?;
            }
            let ack = self.ack_frame(level);
            if let Some(ack) = ack {
                let mut payload = BytesMut::new();
                ack.encode(&mut payload)
                    .map_err(|error| error.to_string())?;
                self.send_level(level, payload.freeze()).await?;
            }
        }
        Ok(())
    }

    async fn write_stream(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<(), String> {
        let mut payload = BytesMut::new();
        Frame::Stream {
            stream_id,
            offset: 0,
            fin,
            data: Bytes::copy_from_slice(data),
        }
        .encode(&mut payload)
        .map_err(|error| error.to_string())?;
        self.send_level(Level::OneRtt, payload.freeze()).await
    }

    async fn recv_stream(&mut self, stream_id: u64, timeout: Duration) -> Result<Vec<u8>, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.stream_fin.contains(&stream_id) {
                return Ok(self.stream_data.remove(&stream_id).unwrap_or_default());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err("stream timed out".to_string());
            }
            let mut buffer = vec![0u8; 64 * 1024];
            let received = tokio::time::timeout(remaining, self.socket.recv_from(&mut buffer))
                .await
                .map_err(|_| "stream timed out".to_string())?
                .map_err(|error| error.to_string())?;
            self.process_datagram(&buffer[..received.0]).await?;
            self.send_pending().await?;
        }
    }

    fn ack_frame(&mut self, level: Level) -> Option<Frame> {
        let space = self.space(level);
        let largest = *space.received.last()?;
        let contiguous = space.received.iter().copied().eq(0..=largest);
        Some(Frame::Ack(netune_quic::wire::frame::AckFrame {
            largest_acknowledged: largest,
            ack_delay: 0,
            first_ack_range: if contiguous { largest } else { 0 },
            ranges: Vec::new(),
            ecn: None,
        }))
    }

    async fn send_level(&mut self, level: Level, payload: Bytes) -> Result<(), String> {
        let packet = match level {
            Level::Initial | Level::Handshake => {
                let ty = if level == Level::Initial {
                    LongType::Initial
                } else {
                    LongType::Handshake
                };
                let packet = LongPacket {
                    ty,
                    version: VERSION_1,
                    destination_connection_id: if level == Level::Initial {
                        self.original_dcid.clone()
                    } else {
                        self.peer_cid.clone()
                    },
                    source_connection_id: self.scid.clone(),
                    token: Vec::new(),
                    packet_number: self.space(level).next_pn,
                    packet_number_len: 4,
                    payload,
                };
                self.space(level).next_pn += 1;
                let protected = protect_long(&packet, &self.keys(level)?.local)
                    .map_err(|error| error.to_string())?;
                if level == Level::Initial && protected.len() < 1200 {
                    let mut padded = packet;
                    padded.payload = Bytes::from({
                        let mut data = padded.payload.to_vec();
                        data.resize(data.len() + (1200 - protected.len()), 0);
                        data
                    });
                    protect_long(&padded, &self.keys(level)?.local)
                        .map_err(|error| error.to_string())?
                } else {
                    protected
                }
            }
            Level::OneRtt => {
                let packet = ShortPacket {
                    spin: false,
                    key_phase: false,
                    destination_connection_id: self.peer_cid.clone(),
                    packet_number: self.space(level).next_pn,
                    packet_number_len: 4,
                    payload,
                };
                self.space(level).next_pn += 1;
                protect_short(&packet, &self.keys(level)?.local)
                    .map_err(|error| error.to_string())?
            }
        };
        self.socket
            .send_to(&packet, self.server)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn keys(&self, level: Level) -> Result<&rustls::quic::Keys, String> {
        self.spaces[level as usize]
            .keys
            .as_ref()
            .ok_or_else(|| format!("missing {level:?} keys"))
    }

    async fn process_datagram(&mut self, datagram: &[u8]) -> Result<(), String> {
        let mut cursor = datagram;
        while !cursor.is_empty() {
            let first = cursor[0];
            if first & 0x80 == 0 {
                let keys = match self.spaces[Level::OneRtt as usize].keys.as_ref() {
                    Some(keys) => keys,
                    None => return Err("short packet before 1-RTT keys".to_string()),
                };
                let mut packet = cursor.to_vec();
                let (pn, _pn_len, payload) =
                    unprotect_short(&mut packet, self.peer_cid.len(), 0, &keys.remote)
                        .map_err(|error| error.to_string())?;
                self.record(Level::OneRtt, pn);
                self.process_frames(Level::OneRtt, &payload)?;
                cursor = &[];
            } else {
                let (_, packet_end) =
                    long_header_info(cursor).map_err(|error| error.to_string())?;
                let mut packet_bytes = cursor[..packet_end].to_vec();
                let ty = LongType::from_bits(first);
                let level = match ty {
                    LongType::Initial => Level::Initial,
                    LongType::Handshake => Level::Handshake,
                    _ => return Err("unsupported long packet".to_string()),
                };
                let keys = &self.keys(level)?.remote;
                let (pn, _pn_len, payload) = unprotect_long(&mut packet_bytes, 0, keys)
                    .map_err(|error| error.to_string())?;
                if level == Level::Initial
                    && let Some(server_scid) = server_scid(cursor, packet_end)
                {
                    self.peer_cid = server_scid;
                }
                self.record(level, pn);
                self.process_frames(level, &payload)?;
                cursor = &cursor[packet_end..];
            }
        }
        Ok(())
    }

    fn record(&mut self, level: Level, pn: u64) {
        self.space(level).received.insert(pn);
    }

    fn process_frames(&mut self, level: Level, payload: &[u8]) -> Result<(), String> {
        let mut cursor = payload;
        while !cursor.is_empty() {
            let frame = Frame::decode(&mut cursor).map_err(|error| error.to_string())?;
            match frame {
                Frame::Crypto { offset, data } => {
                    self.insert_crypto(level, offset, &data)?;
                }
                Frame::ConnectionCloseTransport { reason, .. }
                | Frame::ConnectionCloseApplication { reason, .. } => {
                    return Err(format!("peer closed: {}", String::from_utf8_lossy(&reason)));
                }
                Frame::HandshakeDone => self.handshake_done = true,
                Frame::Ack(_)
                | Frame::Padding { .. }
                | Frame::Ping
                | Frame::MaxData(_)
                | Frame::MaxStreamData { .. }
                | Frame::MaxStreams { .. }
                | Frame::DataBlocked(_)
                | Frame::StreamDataBlocked { .. }
                | Frame::StreamsBlocked { .. }
                | Frame::NewConnectionId { .. }
                | Frame::RetireConnectionId(_)
                | Frame::PathChallenge(_)
                | Frame::PathResponse(_)
                | Frame::NewToken { .. }
                | Frame::ResetStream { .. }
                | Frame::StopSending { .. }
                | Frame::Datagram { .. } => {}
                Frame::Stream {
                    stream_id,
                    offset,
                    fin,
                    data,
                } => {
                    let entry = self.stream_data.entry(stream_id).or_default();
                    let offset =
                        usize::try_from(offset).map_err(|_| "stream offset".to_string())?;
                    if offset == entry.len() {
                        entry.extend_from_slice(&data);
                    } else if offset < entry.len() && offset + data.len() > entry.len() {
                        entry.extend_from_slice(&data[entry.len() - offset..]);
                    }
                    if fin {
                        self.stream_fin.insert(stream_id);
                    }
                }
            }
        }
        self.feed_tls()
    }

    fn insert_crypto(&mut self, level: Level, offset: u64, data: &[u8]) -> Result<(), String> {
        let space = self.space(level);
        if offset < space.crypto_read {
            let skip = (space.crypto_read - offset) as usize;
            if skip >= data.len() {
                return Ok(());
            }
            space
                .crypto_recv
                .insert(space.crypto_read, data[skip..].to_vec());
        } else {
            space.crypto_recv.insert(offset, data.to_vec());
        }
        Ok(())
    }

    fn feed_tls(&mut self) -> Result<(), String> {
        loop {
            let mut fed = false;
            for level in [Level::Initial, Level::Handshake, Level::OneRtt] {
                if level as usize > self.tls_read_level as usize {
                    continue;
                }
                loop {
                    let data = {
                        let space = self.space(level);
                        match space.crypto_recv.remove(&space.crypto_read) {
                            Some(data) => data,
                            None => break,
                        }
                    };
                    self.tls
                        .read_handshake(&data)
                        .map_err(|error| error.to_string())?;
                    self.space(level).crypto_read += data.len() as u64;
                    self.drain_tls()?;
                    fed = true;
                }
            }
            if !fed {
                break;
            }
        }
        Ok(())
    }
}

fn client_transport_parameters(scid: &[u8]) -> Vec<u8> {
    TransportParameters {
        initial_max_data: Some(1 << 20),
        initial_max_stream_data_bidi_local: Some(1 << 18),
        initial_max_stream_data_bidi_remote: Some(1 << 18),
        initial_max_stream_data_uni: Some(1 << 18),
        initial_max_streams_bidi: Some(100),
        initial_max_streams_uni: Some(100),
        active_connection_id_limit: Some(2),
        initial_source_connection_id: Some(scid.to_vec()),
        ..TransportParameters::default()
    }
    .encode()
    .expect("transport parameters")
    .to_vec()
}

fn server_scid(datagram: &[u8], packet_end: usize) -> Option<Vec<u8>> {
    // Parse the long header far enough to read the server's Source Connection
    // ID. This is only used by the test harness; the real core parses it once.
    let mut cursor = &datagram[..packet_end];
    if cursor.len() < 1 + 4 + 1 {
        return None;
    }
    cursor = &cursor[5..];
    let dcid_len = cursor[0] as usize;
    if cursor.len() < 1 + dcid_len + 1 {
        return None;
    }
    cursor = &cursor[1 + dcid_len..];
    let scid_len = cursor[0] as usize;
    if cursor.len() < 1 + scid_len {
        return None;
    }
    Some(cursor[1..1 + scid_len].to_vec())
}

#[tokio::test]
async fn owned_client_handshakes_with_quinn_server() {
    let (server, addr) = server_endpoint();
    let (established_tx, established_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        if let Some(connecting) = server.accept().await
            && let Ok(connection) = connecting.await
        {
            let _ = established_tx.send(());
            if let Ok((mut send, mut recv)) = connection.accept_bi().await
                && let Ok(data) = recv.read_to_end(1024).await
            {
                assert_eq!(data, b"hello");
                let _ = send.write_all(b"world").await;
                let _ = send.finish();
            }
            let _ = connection.closed().await;
        }
    });

    let mut client = OwnedClient::new(addr).await.expect("client");
    client.run().await.expect("handshake");
    tokio::time::timeout(Duration::from_secs(2), established_rx)
        .await
        .expect("server established")
        .expect("established signal");
    client
        .write_stream(0, b"hello", true)
        .await
        .expect("write stream");
    let response = client
        .recv_stream(0, Duration::from_secs(2))
        .await
        .expect("stream response");
    assert_eq!(response, b"world");
    server_task.abort();
}

fn _assert_crypto_error_is_display(error: CryptoError) -> String {
    error.to_string()
}

fn _assert_varint(value: u64) -> usize {
    varint::encoded_len(value)
}
