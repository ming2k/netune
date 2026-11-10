// SPDX-License-Identifier: MIT

//! Sans-IO owned QUIC connection core.
//!
//! This is the production core behind the async endpoint. It owns the QUIC
//! packet spaces, TLS handshake wiring, stream state and flow-control windows.
//! It never opens a socket; `endpoint` feeds it datagrams and sends the bytes
//! it emits.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use rustls::pki_types::ServerName;
use rustls::quic::{DirectionalKeys, KeyChange, Keys, PacketKey, Secrets};
use rustls::{ClientConfig, Side};

use crate::crypto::{
    TlsSession, decode_retry, initial_keys_for_version, long_header_info, protect_long,
    protect_short, unprotect_long, unprotect_short_with,
};
use crate::error::QuicError;
use crate::profile::CongestionAlgorithm;

use super::congestion::{Congestion, CongestionControllerFactory};
use super::session::SessionCache;
use crate::wire::frame::{AckFrame, AckRange, Frame};
use crate::wire::packet::{LongPacket, LongType, ShortPacket, VersionNegotiation};
use crate::wire::transport_parameters::TransportParameters;

/// The three QUIC packet-number spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    Initial = 0,
    Handshake = 1,
    OneRtt = 2,
}

const LEVELS: [Level; 3] = [Level::Initial, Level::Handshake, Level::OneRtt];
const MAX_STREAM_BUFFER: usize = 16 * 1024 * 1024;
const MAX_DATAGRAM: usize = 1200;
/// Payload budget for one packet: the QUIC header and AEAD tag are reserved
/// before any frame is admitted. A sender that ignores this budget fragments a
/// datagram at the IP layer or gets `EMSGSIZE` from the UDP stack.
const PACKET_BUDGET: usize = MAX_DATAGRAM - 64;
const MAX_STREAM_FRAME: usize = 1000;

fn frame_len(frame: &Frame) -> Result<usize, QuicError> {
    frame
        .encoded_len()
        .map_err(|error| QuicError::Protocol(error.to_string()))
}

/// Result of a stream read.
pub(crate) enum ReadResult {
    Data(Bytes),
    Fin,
    Pending,
}

struct Space {
    keys: Option<Keys>,
    next_pn: u64,
    received: BTreeSet<u64>,
    ack_pending: bool,
    crypto_send: Vec<u8>,
    crypto_sent: usize,
    crypto_recv: BTreeMap<u64, Vec<u8>>,
    crypto_read: u64,
}

impl Space {
    fn new(keys: Option<Keys>) -> Self {
        Self {
            keys,
            next_pn: 0,
            received: BTreeSet::new(),
            ack_pending: false,
            crypto_send: Vec::new(),
            crypto_sent: 0,
            crypto_recv: BTreeMap::new(),
            crypto_read: 0,
        }
    }
}

struct SendState {
    data: Vec<u8>,
    sent: u64,
    fin: bool,
    fin_sent: bool,
    reset: Option<u64>,
    max_data: u64,
}

struct RecvState {
    chunks: BTreeMap<u64, Bytes>,
    read: u64,
    fin: Option<u64>,
    max_data: u64,
    window: u64,
    consumed: u64,
    stopped: bool,
}

struct Stream {
    send: Option<SendState>,
    recv: Option<RecvState>,
}

struct OneRttKeys {
    secrets: Secrets,
    key_phase: bool,
    next_local: Option<Box<dyn PacketKey>>,
    next_remote: Option<Box<dyn PacketKey>>,
    previous_remote: Option<Box<dyn PacketKey>>,
}

struct SentPacket {
    level: Level,
    packet_number: u64,
    time: Instant,
    size: u64,
    frames: Vec<Frame>,
}

/// Client-side knobs that are not part of the QUIC wire parameters.
pub(crate) struct ClientOptions {
    pub version: u32,
    pub supported_versions: Vec<u32>,
    pub congestion: CongestionAlgorithm,
    pub congestion_factory: Option<std::sync::Arc<dyn CongestionControllerFactory>>,
    pub early_data: bool,
    pub keep_alive: Option<Duration>,
    pub session_cache: Option<std::sync::Arc<SessionCache>>,
    pub session_key: String,
}

/// The owned QUIC connection state.
pub(crate) struct Core {
    side: Side,
    tls: TlsSession,
    spaces: [Space; 3],
    original_dcid: Vec<u8>,
    local_cid: Vec<u8>,
    peer_cid: Vec<u8>,
    local_tp: TransportParameters,
    peer_tp: Option<TransportParameters>,
    streams: HashMap<u64, Stream>,
    accept_bi: VecDeque<u64>,
    accept_uni: VecDeque<u64>,
    next_bidi: u64,
    next_uni: u64,
    opened_bidi: u64,
    opened_uni: u64,
    peer_max_bidi: u64,
    peer_max_uni: u64,
    send_max_data: u64,
    send_data: u64,
    recv_data: u64,
    local_max_data: u64,
    recv_consumed: u64,
    send_level: Level,
    read_level: Level,
    established: bool,
    handshake_done: bool,
    server: bool,
    outgoing: Vec<Vec<u8>>,
    control_frames: Vec<Frame>,
    closed: Option<(u64, String)>,
    last_activity: Instant,
    last_keep_alive: Instant,
    ack_eliciting_since_receive: bool,
    sent: Vec<SentPacket>,
    retransmit: [Vec<Frame>; 3],
    srtt: Option<Duration>,
    rttvar: Duration,
    pto: Duration,
    peer_max_datagram: Option<u64>,
    send_datagrams: VecDeque<Bytes>,
    recv_datagrams: VecDeque<Bytes>,
    congestion: Congestion,
    bytes_in_flight: u64,
    peer_opened_bidi: u64,
    peer_opened_uni: u64,
    peer_reset_token: Option<[u8; 16]>,
    one_rtt: Option<OneRttKeys>,
    one_rtt_packets: u64,
    client_config: Option<std::sync::Arc<ClientConfig>>,
    server_name: Option<ServerName<'static>>,
    client_tp: TransportParameters,
    initial_token: Vec<u8>,
    initial_odcid: Vec<u8>,
    retried: bool,
    retry_source_cid: Option<Vec<u8>>,
    version: u32,
    supported_versions: Vec<u32>,
    migration_disabled: bool,
    path_challenge: Option<[u8; 8]>,
    path_validated: bool,
    early_keys: Option<DirectionalKeys>,
    early_frames: Vec<Frame>,
    early_data_accepted: bool,
    early_data_available: bool,
    keep_alive: Option<Duration>,
    session_cache: Option<std::sync::Arc<SessionCache>>,
    session_key: String,
}

impl Core {
    /// Create a client core. The first ClientHello is queued by `poll_transmit`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn client(
        client_config: std::sync::Arc<ClientConfig>,
        server_name: ServerName<'static>,
        original_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        local_tp: TransportParameters,
        options: ClientOptions,
    ) -> Result<Self, QuicError> {
        if options.keep_alive == Some(Duration::ZERO) {
            return Err(QuicError::Config(
                "keep_alive must be greater than zero".to_string(),
            ));
        }
        let initial = initial_keys_for_version(&original_dcid, Side::Client, options.version)?;
        let local_max_data = local_tp.initial_max_data.unwrap_or(0);
        let client_tp = local_tp.clone();
        let migration_disabled = local_tp.disable_active_migration;
        let initial_odcid = original_dcid.clone();
        let encoded_tp = local_tp
            .encode()
            .map_err(|error| QuicError::Protocol(error.to_string()))?
            .to_vec();
        let tls = TlsSession::client_with_version(
            client_config.clone(),
            server_name.clone(),
            encoded_tp,
            options.version,
        )?;
        let early_keys = if options.early_data {
            tls.zero_rtt_keys()
        } else {
            None
        };
        let cached = options
            .session_cache
            .as_ref()
            .and_then(|cache| cache.get(&options.session_key));
        let early_data_available = early_keys.is_some() && cached.is_some();
        let mut core = Self {
            side: Side::Client,
            tls,
            spaces: [
                Space::new(Some(initial)),
                Space::new(None),
                Space::new(None),
            ],
            original_dcid,
            local_cid,
            peer_cid: Vec::new(),
            local_tp,
            peer_tp: None,
            streams: HashMap::new(),
            accept_bi: VecDeque::new(),
            accept_uni: VecDeque::new(),
            next_bidi: 0,
            next_uni: 2,
            opened_bidi: 0,
            opened_uni: 0,
            peer_max_bidi: 0,
            peer_max_uni: 0,
            send_max_data: 0,
            send_data: 0,
            recv_data: 0,
            local_max_data,
            recv_consumed: 0,
            send_level: Level::Initial,
            read_level: Level::Initial,
            established: false,
            handshake_done: false,
            server: false,
            outgoing: Vec::new(),
            control_frames: Vec::new(),
            closed: None,
            last_activity: Instant::now(),
            last_keep_alive: Instant::now(),
            ack_eliciting_since_receive: false,
            sent: Vec::new(),
            retransmit: [Vec::new(), Vec::new(), Vec::new()],
            srtt: None,
            rttvar: Duration::ZERO,
            pto: Duration::from_secs(1),
            peer_max_datagram: None,
            send_datagrams: VecDeque::new(),
            recv_datagrams: VecDeque::new(),
            congestion: Congestion::new_with_factory(
                options.congestion,
                options.congestion_factory.as_ref(),
                Instant::now(),
            ),
            bytes_in_flight: 0,
            peer_opened_bidi: 0,
            peer_opened_uni: 0,
            peer_reset_token: None,
            one_rtt: None,
            one_rtt_packets: 0,
            client_config: Some(client_config),
            server_name: Some(server_name),
            client_tp,
            initial_token: Vec::new(),
            initial_odcid,
            retried: false,
            retry_source_cid: None,
            version: options.version,
            supported_versions: options.supported_versions,
            migration_disabled,
            path_challenge: None,
            path_validated: false,
            early_keys,
            early_frames: Vec::new(),
            early_data_accepted: false,
            early_data_available,
            keep_alive: options.keep_alive,
            session_cache: options.session_cache,
            session_key: options.session_key,
        };
        if let Some(parameters) = cached {
            core.apply_peer_parameters(parameters);
        }
        core.drain_tls()?;
        Ok(core)
    }

    /// Create a server core for an accepted Initial packet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn server(
        tls: TlsSession,
        original_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        local_tp: TransportParameters,
        version: u32,
        congestion: CongestionAlgorithm,
        congestion_factory: Option<std::sync::Arc<dyn CongestionControllerFactory>>,
        keep_alive: Option<Duration>,
    ) -> Result<Self, QuicError> {
        let initial = initial_keys_for_version(&original_dcid, Side::Server, version)?;
        let local_max_data = local_tp.initial_max_data.unwrap_or(0);
        let initial_odcid = original_dcid.clone();
        let migration_disabled = local_tp.disable_active_migration;
        Ok(Self {
            side: Side::Server,
            tls,
            spaces: [
                Space::new(Some(initial)),
                Space::new(None),
                Space::new(None),
            ],
            original_dcid,
            local_cid,
            peer_cid: Vec::new(),
            local_tp,
            peer_tp: None,
            streams: HashMap::new(),
            accept_bi: VecDeque::new(),
            accept_uni: VecDeque::new(),
            next_bidi: 1,
            next_uni: 3,
            opened_bidi: 0,
            opened_uni: 0,
            peer_max_bidi: 0,
            peer_max_uni: 0,
            send_max_data: 0,
            send_data: 0,
            recv_data: 0,
            local_max_data,
            recv_consumed: 0,
            send_level: Level::Initial,
            read_level: Level::Initial,
            established: false,
            handshake_done: false,
            server: true,
            outgoing: Vec::new(),
            control_frames: Vec::new(),
            closed: None,
            last_activity: Instant::now(),
            last_keep_alive: Instant::now(),
            ack_eliciting_since_receive: false,
            sent: Vec::new(),
            retransmit: [Vec::new(), Vec::new(), Vec::new()],
            srtt: None,
            rttvar: Duration::ZERO,
            pto: Duration::from_secs(1),
            peer_max_datagram: None,
            send_datagrams: VecDeque::new(),
            recv_datagrams: VecDeque::new(),
            congestion: Congestion::new_with_factory(
                congestion,
                congestion_factory.as_ref(),
                Instant::now(),
            ),
            bytes_in_flight: 0,
            peer_opened_bidi: 0,
            peer_opened_uni: 0,
            peer_reset_token: None,
            one_rtt: None,
            one_rtt_packets: 0,
            client_config: None,
            server_name: None,
            client_tp: TransportParameters::default(),
            initial_token: Vec::new(),
            initial_odcid,
            retried: false,
            retry_source_cid: None,
            version,
            supported_versions: vec![version],
            migration_disabled,
            path_challenge: None,
            path_validated: false,
            early_keys: None,
            early_frames: Vec::new(),
            early_data_accepted: false,
            early_data_available: false,
            keep_alive,
            session_cache: None,
            session_key: String::new(),
        })
    }

    pub(crate) fn is_established(&self) -> bool {
        self.established
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    pub(crate) fn take_outgoing(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outgoing)
    }

    pub(crate) fn close(&mut self, code: u64, reason: &str) {
        if self.closed.is_some() {
            return;
        }
        // A CONNECTION_CLOSE frame must fit one packet. Keep a UTF-8 boundary
        // so a caller-supplied reason cannot make the close frame unsendable.
        let mut end = reason.len().min(512);
        while end > 0 && !reason.is_char_boundary(end) {
            end -= 1;
        }
        self.closed = Some((code, reason[..end].to_string()));
        self.control_frames.push(Frame::ConnectionCloseApplication {
            error_code: code,
            reason: Bytes::copy_from_slice(&reason.as_bytes()[..end]),
        });
    }

    pub(crate) fn migration_disabled(&self) -> bool {
        self.migration_disabled
    }

    pub(crate) fn begin_path_validation(&mut self, challenge: [u8; 8]) {
        self.path_challenge = Some(challenge);
        self.path_validated = false;
        self.control_frames.push(Frame::PathChallenge(challenge));
    }

    pub(crate) fn path_validated(&self) -> bool {
        self.path_validated
    }

    pub(crate) fn early_data_available(&self) -> bool {
        self.early_data_available && self.early_keys.is_some() && !self.established
    }

    pub(crate) fn early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    pub(crate) fn max_datagram_size(&self) -> Option<usize> {
        self.peer_max_datagram.map(|frame_max| {
            // `max_datagram_frame_size` bounds the whole DATAGRAM frame, so the
            // application payload must leave room for the frame type and the
            // length varint. Solve p + 1 + varint_len(p) <= frame_max.
            let frame_max = usize::try_from(frame_max)
                .unwrap_or(usize::MAX)
                .min(PACKET_BUDGET);
            let mut payload = frame_max.saturating_sub(2);
            for _ in 0..3 {
                let overhead = 1 + crate::wire::varint::encoded_len(payload as u64);
                let next = frame_max.saturating_sub(overhead);
                if next >= payload {
                    break;
                }
                payload = next;
            }
            payload
        })
    }

    pub(crate) fn send_datagram(&mut self, data: Bytes) -> Result<(), QuicError> {
        let Some(maximum) = self.max_datagram_size() else {
            return Err(QuicError::DatagramsNotSupported);
        };
        if data.len() > maximum {
            return Err(QuicError::DatagramTooLarge {
                max: maximum,
                size: data.len(),
            });
        }
        self.send_datagrams.push_back(data);
        Ok(())
    }

    pub(crate) fn recv_datagram(&mut self) -> Option<Bytes> {
        self.recv_datagrams.pop_front()
    }

    /// The negotiated idle timeout, lifted to at least three times the current
    /// PTO (RFC 9000 Section 10.1). `None` means neither endpoint advertised one.
    fn effective_idle_timeout(&self) -> Option<Duration> {
        let local = self.local_tp.max_idle_timeout.filter(|value| *value > 0);
        let peer = self
            .peer_tp
            .as_ref()
            .and_then(|parameters| parameters.max_idle_timeout)
            .filter(|value| *value > 0);
        let advertised = match (local, peer) {
            (Some(local), Some(peer)) => Some(local.min(peer)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        }?;
        Some(Duration::from_millis(advertised).max(self.pto.saturating_mul(3)))
    }

    pub(crate) fn handle_timeout(&mut self) -> Result<(), QuicError> {
        let now = Instant::now();
        if let Some(idle) = self.effective_idle_timeout()
            && now.saturating_duration_since(self.last_activity) >= idle
        {
            // RFC 9000 Section 10.1: silently discard the connection state; an
            // idle close does not send CONNECTION_CLOSE, and nothing queued
            // before the timeout may leak out afterwards.
            self.closed = Some((0, "idle timeout".to_string()));
            self.control_frames.clear();
            self.send_datagrams.clear();
            self.retransmit = [Vec::new(), Vec::new(), Vec::new()];
            return Ok(());
        }
        if let Some(interval) = self.keep_alive
            && self.established
            && self.spaces[Level::OneRtt as usize].keys.is_some()
        {
            // A keep-alive must fire before the negotiated idle timer, or the
            // connection would be torn down by the timeout it exists to avoid.
            let interval = self
                .effective_idle_timeout()
                .map_or(interval, |idle| interval.min(idle / 2));
            if now.saturating_duration_since(self.last_keep_alive) >= interval {
                // A PING keeps the NAT mapping and the peer's idle timer alive. It
                // is a retransmittable control frame, so it takes the normal send
                // path; `last_keep_alive` is separate from the idle timer so a
                // busy sender does not queue one PING per timer tick.
                self.last_keep_alive = now;
                self.retransmit[Level::OneRtt as usize].push(Frame::Ping);
            }
        }
        let Some(earliest) = self.sent.iter().map(|packet| packet.time).min() else {
            return Ok(());
        };
        if now.saturating_duration_since(earliest) < self.pto {
            return Ok(());
        }
        self.congestion.on_pto(now);
        self.bytes_in_flight = 0;
        let packets = std::mem::take(&mut self.sent);
        for packet in packets {
            for frame in packet.frames {
                if matches!(frame, Frame::Ack(_) | Frame::Padding { .. }) {
                    continue;
                }
                self.retransmit[packet.level as usize].push(frame);
            }
        }
        self.pto = self.pto.saturating_mul(2).min(Duration::from_secs(60));
        Ok(())
    }

    pub(crate) fn rtt(&self) -> Option<Duration> {
        self.srtt
    }

    pub(crate) fn peer_certificates(
        &self,
    ) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        self.tls.peer_certificates()
    }

    fn handle_version_negotiation(&mut self, bytes: &[u8]) -> Result<(), QuicError> {
        let mut cursor = bytes;
        let negotiation = VersionNegotiation::decode(&mut cursor)
            .map_err(|error| QuicError::Protocol(error.to_string()))?;
        if !cursor.is_empty() {
            return Err(QuicError::Protocol(
                "trailing bytes after Version Negotiation".to_string(),
            ));
        }
        if negotiation.destination_connection_id != self.local_cid {
            return Err(QuicError::Protocol(
                "Version Negotiation destination CID mismatch".to_string(),
            ));
        }
        if negotiation.versions.contains(&self.version) {
            return Ok(());
        }
        let Some(version) = self
            .supported_versions
            .iter()
            .copied()
            .find(|version| *version != self.version && negotiation.versions.contains(version))
        else {
            return Err(QuicError::Protocol(
                "no mutually supported QUIC version".to_string(),
            ));
        };
        self.reset_for_version(version)
    }

    fn reset_for_version(&mut self, version: u32) -> Result<(), QuicError> {
        let config = self
            .client_config
            .clone()
            .ok_or_else(|| QuicError::Protocol("missing client TLS config".to_string()))?;
        let server_name = self
            .server_name
            .clone()
            .ok_or_else(|| QuicError::Protocol("missing server name".to_string()))?;
        let encoded_tp = self
            .client_tp
            .encode()
            .map_err(|error| QuicError::Protocol(error.to_string()))?
            .to_vec();
        self.version = version;
        self.tls = TlsSession::client_with_version(config, server_name, encoded_tp, version)?;
        self.early_keys = self.tls.zero_rtt_keys();
        self.early_data_available = self.early_keys.is_some() && self.peer_tp.is_some();
        self.early_frames.clear();
        self.send_data = 0;
        for stream in self.streams.values_mut() {
            if let Some(send) = stream.send.as_mut() {
                send.sent = 0;
                send.fin_sent = false;
            }
        }
        self.spaces = [
            Space::new(Some(initial_keys_for_version(
                &self.original_dcid,
                Side::Client,
                version,
            )?)),
            Space::new(None),
            Space::new(None),
        ];
        self.sent.clear();
        self.retransmit = [Vec::new(), Vec::new(), Vec::new()];
        self.one_rtt = None;
        self.one_rtt_packets = 0;
        self.send_level = Level::Initial;
        self.read_level = Level::Initial;
        self.established = false;
        self.handshake_done = false;
        self.peer_cid.clear();
        self.srtt = None;
        self.rttvar = Duration::ZERO;
        self.pto = Duration::from_secs(1);
        self.bytes_in_flight = 0;
        self.drain_tls()?;
        Ok(())
    }

    fn handle_retry(&mut self, bytes: &[u8]) -> Result<(), QuicError> {
        if self.server || self.retried {
            return Err(QuicError::Protocol("unexpected Retry packet".to_string()));
        }
        let packet = decode_retry(bytes, &self.initial_odcid)
            .map_err(|error| QuicError::Protocol(error.to_string()))?;
        if packet.version != self.version {
            return Err(QuicError::Protocol("Retry version mismatch".to_string()));
        }
        if packet.destination_connection_id != self.local_cid {
            return Err(QuicError::Protocol(
                "Retry destination CID does not match the local CID".to_string(),
            ));
        }
        let retry_source = packet.source_connection_id.clone();
        if retry_source.is_empty() {
            return Err(QuicError::Protocol("Retry source CID is empty".to_string()));
        }
        let config = self
            .client_config
            .clone()
            .ok_or_else(|| QuicError::Protocol("missing client TLS config".to_string()))?;
        let server_name = self
            .server_name
            .clone()
            .ok_or_else(|| QuicError::Protocol("missing server name".to_string()))?;
        let encoded_tp = self
            .client_tp
            .encode()
            .map_err(|error| QuicError::Protocol(error.to_string()))?
            .to_vec();
        self.tls = TlsSession::client_with_version(config, server_name, encoded_tp, self.version)?;
        self.early_keys = self.tls.zero_rtt_keys();
        self.early_data_available = self.early_keys.is_some() && self.peer_tp.is_some();
        self.early_frames.clear();
        self.send_data = 0;
        for stream in self.streams.values_mut() {
            if let Some(send) = stream.send.as_mut() {
                send.sent = 0;
                send.fin_sent = false;
            }
        }
        self.original_dcid = retry_source.clone();
        self.initial_token = packet.token;
        self.retried = true;
        self.retry_source_cid = Some(retry_source.clone());
        self.spaces = [
            Space::new(Some(initial_keys_for_version(
                &retry_source,
                Side::Client,
                self.version,
            )?)),
            Space::new(None),
            Space::new(None),
        ];
        self.sent.clear();
        self.retransmit = [Vec::new(), Vec::new(), Vec::new()];
        self.one_rtt = None;
        self.one_rtt_packets = 0;
        self.send_level = Level::Initial;
        self.read_level = Level::Initial;
        self.established = false;
        self.handshake_done = false;
        self.peer_cid.clear();
        self.srtt = None;
        self.rttvar = Duration::ZERO;
        self.pto = Duration::from_secs(1);
        self.bytes_in_flight = 0;
        self.drain_tls()?;
        Ok(())
    }

    fn commit_key_update(&mut self, phase: bool) -> Result<(), QuicError> {
        self.ensure_next_one_rtt();
        let Some(mut state) = self.one_rtt.take() else {
            return Err(QuicError::Protocol("missing 1-RTT key state".to_string()));
        };
        let keys = self.spaces[Level::OneRtt as usize]
            .keys
            .as_mut()
            .ok_or_else(|| QuicError::Protocol("missing 1-RTT keys".to_string()))?;
        let next_local = state.next_local.take().ok_or_else(|| {
            QuicError::Protocol("next local packet key is unavailable".to_string())
        })?;
        let next_remote = state.next_remote.take().ok_or_else(|| {
            QuicError::Protocol("next remote packet key is unavailable".to_string())
        })?;
        let previous = std::mem::replace(&mut keys.remote.packet, next_remote);
        keys.local.packet = next_local;
        state.previous_remote = Some(previous);
        state.key_phase = phase;
        self.one_rtt = Some(state);
        Ok(())
    }

    pub(crate) fn initiate_key_update(&mut self) -> Result<(), QuicError> {
        self.ensure_next_one_rtt();
        let Some(mut state) = self.one_rtt.take() else {
            return Err(QuicError::Protocol(
                "1-RTT keys are not available".to_string(),
            ));
        };
        let keys = self.spaces[Level::OneRtt as usize]
            .keys
            .as_mut()
            .ok_or_else(|| QuicError::Protocol("missing 1-RTT keys".to_string()))?;
        let next_local = state.next_local.take().ok_or_else(|| {
            QuicError::Protocol("next local packet key is unavailable".to_string())
        })?;
        let next_remote = state.next_remote.take().ok_or_else(|| {
            QuicError::Protocol("next remote packet key is unavailable".to_string())
        })?;
        let previous = std::mem::replace(&mut keys.remote.packet, next_remote);
        keys.local.packet = next_local;
        state.previous_remote = Some(previous);
        state.key_phase = !state.key_phase;
        self.one_rtt = Some(state);
        Ok(())
    }

    fn ensure_next_one_rtt(&mut self) {
        if let Some(state) = &mut self.one_rtt
            && state.next_local.is_none()
        {
            let next = state.secrets.next_packet_keys();
            state.next_local = Some(next.local);
            state.next_remote = Some(next.remote);
        }
    }

    fn handle_ack(&mut self, level: Level, ack: AckFrame) {
        let acked = acknowledged_packets(&ack);
        let now = Instant::now();
        if let Some(packet) = self.sent.iter().find(|packet| {
            packet.level == level && packet.packet_number == ack.largest_acknowledged
        }) {
            let sample = now.saturating_duration_since(packet.time);
            match self.srtt {
                None => {
                    self.srtt = Some(sample);
                    self.rttvar = sample / 2;
                }
                Some(srtt) => {
                    let difference = srtt.abs_diff(sample);
                    self.rttvar = (self.rttvar * 3 + difference) / 4;
                    self.srtt = Some((srtt * 7 + sample) / 8);
                }
            }
            self.pto = self
                .srtt
                .unwrap_or(Duration::from_secs(1))
                .saturating_add(4 * self.rttvar)
                .max(Duration::from_millis(1));
        }
        let mut acked_bytes = 0u64;
        let mut lost = Vec::new();
        let loss_delay = self
            .srtt
            .unwrap_or(Duration::from_millis(100))
            .saturating_mul(9)
            / 8;
        self.sent.retain(|packet| {
            if packet.level != level {
                return true;
            }
            if acked.contains(&packet.packet_number) {
                acked_bytes = acked_bytes.saturating_add(packet.size);
                return false;
            }
            if packet.packet_number < ack.largest_acknowledged
                && now.saturating_duration_since(packet.time) > loss_delay
            {
                lost.push((packet.size, packet.frames.clone()));
                return false;
            }
            true
        });
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        if !lost.is_empty() {
            let lost_bytes = lost.iter().map(|(size, _)| *size).sum();
            self.congestion.on_loss(now, lost_bytes);
            for (size, frames) in lost {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(size);
                for frame in frames {
                    if !matches!(frame, Frame::Ack(_) | Frame::Padding { .. }) {
                        self.retransmit[level as usize].push(frame);
                    }
                }
            }
        } else if acked_bytes > 0 {
            self.congestion.on_ack(acked_bytes, now, self.srtt);
        }
    }

    pub(crate) fn receive(&mut self, datagram: &[u8]) -> Result<(), QuicError> {
        if self.closed.is_some() {
            return Err(QuicError::Closed("connection is closed".to_string()));
        }
        let mut cursor = datagram;
        while !cursor.is_empty() {
            let first = cursor[0];
            if first & 0x80 == 0 {
                let dcid_len = self.local_cid.len();
                let largest = self.largest(Level::OneRtt);
                let mut decrypted = None;
                let mut used_next = false;
                {
                    let keys = self.spaces[Level::OneRtt as usize]
                        .keys
                        .as_ref()
                        .ok_or_else(|| {
                            QuicError::Protocol("short packet before 1-RTT keys".to_string())
                        })?;
                    let header = keys.remote.header.as_ref();
                    if let Some(value) = try_short(
                        cursor,
                        dcid_len,
                        largest,
                        header,
                        keys.remote.packet.as_ref(),
                    ) {
                        decrypted = Some(value);
                    }
                    if decrypted.is_none()
                        && let Some(state) = &self.one_rtt
                        && let Some(previous) = &state.previous_remote
                        && let Some(value) =
                            try_short(cursor, dcid_len, largest, header, previous.as_ref())
                    {
                        decrypted = Some(value);
                    }
                }
                if decrypted.is_none() {
                    self.ensure_next_one_rtt();
                    if let Some(keys) = self.spaces[Level::OneRtt as usize].keys.as_ref()
                        && let Some(state) = &self.one_rtt
                        && let Some(next) = &state.next_remote
                        && let Some(value) = try_short(
                            cursor,
                            dcid_len,
                            largest,
                            keys.remote.header.as_ref(),
                            next.as_ref(),
                        )
                    {
                        decrypted = Some(value);
                        used_next = true;
                    }
                }
                let Some((pn, _pn_len, phase, payload)) = decrypted else {
                    if cursor.len() >= 16
                        && self.peer_reset_token
                            == Some(cursor[cursor.len() - 16..].try_into().unwrap_or([0; 16]))
                    {
                        self.closed = Some((0, "stateless reset".to_string()));
                        return Err(QuicError::Closed("stateless reset".to_string()));
                    }
                    return Err(QuicError::Protocol(
                        "short packet could not be decrypted".to_string(),
                    ));
                };
                if used_next {
                    self.commit_key_update(phase)?;
                }
                let ack_eliciting = self.process_frames(Level::OneRtt, &payload)?;
                self.record(Level::OneRtt, pn, ack_eliciting);
                cursor = &[];
            } else {
                if cursor.len() >= 5 {
                    let version = u32::from_be_bytes([cursor[1], cursor[2], cursor[3], cursor[4]]);
                    if version == 0 {
                        if !self.server {
                            self.handle_version_negotiation(cursor)?;
                        }
                        cursor = &[];
                        continue;
                    }
                }
                let ty = LongType::from_bits_for(
                    u32::from_be_bytes([
                        cursor.get(1).copied().unwrap_or(0),
                        cursor.get(2).copied().unwrap_or(0),
                        cursor.get(3).copied().unwrap_or(0),
                        cursor.get(4).copied().unwrap_or(0),
                    ]),
                    first,
                );
                if ty == LongType::Retry {
                    if !self.server {
                        self.handle_retry(cursor)?;
                    }
                    cursor = &[];
                    continue;
                }
                if ty == LongType::ZeroRtt {
                    if !self.server {
                        return Err(QuicError::Protocol(
                            "client received a 0-RTT packet".to_string(),
                        ));
                    }
                    let (_, packet_end) = long_header_info(cursor)?;
                    let Some(keys) = &self.early_keys else {
                        cursor = &cursor[packet_end..];
                        continue;
                    };
                    let mut packet = cursor[..packet_end].to_vec();
                    let (pn, _pn_len, payload) =
                        unprotect_long(&mut packet, self.largest(Level::OneRtt), keys)?;
                    self.process_early_frames(&payload)?;
                    self.record(Level::OneRtt, pn, true);
                    cursor = &cursor[packet_end..];
                    continue;
                }
                let (_, packet_end) = long_header_info(cursor)?;
                let mut packet = cursor[..packet_end].to_vec();
                let level = match ty {
                    LongType::Initial => Level::Initial,
                    LongType::Handshake => Level::Handshake,
                    _ => {
                        return Err(QuicError::Protocol(
                            "unsupported long packet type".to_string(),
                        ));
                    }
                };
                let keys = self.spaces[level as usize]
                    .keys
                    .as_ref()
                    .ok_or_else(|| QuicError::Protocol("missing packet keys".to_string()))?;
                let (pn, _pn_len, payload) =
                    unprotect_long(&mut packet, self.largest(level), &keys.remote)?;
                if level == Level::Initial && self.peer_cid.is_empty() {
                    self.peer_cid = parse_scid(cursor, packet_end).unwrap_or_default();
                }
                let ack_eliciting = self.process_frames(level, &payload)?;
                self.record(level, pn, ack_eliciting);
                cursor = &cursor[packet_end..];
            }
        }
        // RFC 9000 Section 10.1: the idle timer restarts only after a packet
        // from the peer has been received and processed successfully.
        self.last_activity = Instant::now();
        self.last_keep_alive = self.last_activity;
        self.ack_eliciting_since_receive = false;
        self.update_established()?;
        Ok(())
    }

    /// Build and queue one datagram if there is anything to send.
    pub(crate) fn poll_transmit(&mut self) -> Result<(), QuicError> {
        if self.closed.is_some() && self.control_frames.is_empty() {
            return Ok(());
        }
        for level in LEVELS {
            if self.spaces[level as usize].keys.is_none() {
                continue;
            }
            let mut frames = Vec::new();
            let mut budget = PACKET_BUDGET;
            if self.spaces[level as usize].ack_pending {
                let ack = self.ack_frame(level);
                let len = frame_len(&ack)?;
                if len <= budget {
                    budget -= len;
                    frames.push(ack);
                    self.spaces[level as usize].ack_pending = false;
                }
            }
            let crypto_pending = self.spaces[level as usize].crypto_sent
                < self.spaces[level as usize].crypto_send.len();
            if crypto_pending {
                let space = &mut self.spaces[level as usize];
                let start = space.crypto_sent;
                let end = (start + 1000).min(space.crypto_send.len());
                let data = Bytes::copy_from_slice(&space.crypto_send[start..end]);
                let frame = Frame::Crypto {
                    offset: start as u64,
                    data,
                };
                let len = frame_len(&frame)?;
                if len <= budget {
                    budget -= len;
                    space.crypto_sent = end;
                    frames.push(frame);
                }
            }
            Self::take_fitting(
                &mut self.retransmit[level as usize],
                &mut frames,
                &mut budget,
            )?;
            if level == Level::OneRtt {
                let available = self
                    .congestion
                    .window()
                    .saturating_sub(self.bytes_in_flight);
                let mut data_budget = usize::try_from(available)
                    .unwrap_or(usize::MAX)
                    .min(MAX_DATAGRAM)
                    .saturating_sub(64)
                    .min(budget);
                if data_budget > 0 {
                    Self::take_fitting(&mut self.control_frames, &mut frames, &mut data_budget)?;
                    self.append_stream_frames(&mut frames, &mut data_budget)?;
                    if let Some(data) = self.send_datagrams.front() {
                        let frame = Frame::Datagram { data: data.clone() };
                        let len = frame_len(&frame)?;
                        if len <= data_budget {
                            self.send_datagrams.pop_front();
                            frames.push(frame);
                        }
                    }
                }
            }
            if frames.is_empty() {
                continue;
            }
            self.queue_packet(level, frames)?;
        }
        if self.early_data_available && self.early_keys.is_some() && !self.established {
            let available = self
                .congestion
                .window()
                .saturating_sub(self.bytes_in_flight);
            let mut budget = usize::try_from(available)
                .unwrap_or(usize::MAX)
                .min(MAX_DATAGRAM)
                .saturating_sub(64)
                .min(PACKET_BUDGET);
            let mut frames = Vec::new();
            self.append_stream_frames(&mut frames, &mut budget)?;
            if let Some(data) = self.send_datagrams.front() {
                let frame = Frame::Datagram { data: data.clone() };
                let len = frame_len(&frame)?;
                if len <= budget {
                    self.send_datagrams.pop_front();
                    frames.push(frame);
                }
            }
            if !frames.is_empty() {
                self.queue_zero_rtt(frames)?;
            }
        }
        Ok(())
    }

    pub(crate) fn open_bi(&mut self) -> Result<u64, QuicError> {
        if self.opened_bidi >= self.peer_max_bidi {
            return Err(QuicError::Stream(
                "peer bidirectional stream limit".to_string(),
            ));
        }
        let id = self.next_bidi;
        self.next_bidi += 4;
        self.opened_bidi += 1;
        let window = self.peer_stream_window(true);
        self.streams.insert(
            id,
            Stream {
                send: Some(SendState {
                    data: Vec::new(),
                    sent: 0,
                    fin: false,
                    fin_sent: false,
                    reset: None,
                    max_data: window,
                }),
                recv: Some(RecvState {
                    chunks: BTreeMap::new(),
                    read: 0,
                    fin: None,
                    max_data: self.local_stream_window(true),
                    window: self.local_stream_window(true),
                    consumed: 0,
                    stopped: false,
                }),
            },
        );
        Ok(id)
    }

    pub(crate) fn open_uni(&mut self) -> Result<u64, QuicError> {
        if self.opened_uni >= self.peer_max_uni {
            return Err(QuicError::Stream(
                "peer unidirectional stream limit".to_string(),
            ));
        }
        let id = self.next_uni;
        self.next_uni += 4;
        self.opened_uni += 1;
        let window = self.peer_stream_window(false);
        self.streams.insert(
            id,
            Stream {
                send: Some(SendState {
                    data: Vec::new(),
                    sent: 0,
                    fin: false,
                    fin_sent: false,
                    reset: None,
                    max_data: window,
                }),
                recv: None,
            },
        );
        Ok(id)
    }

    pub(crate) fn write(&mut self, id: u64, data: &[u8]) -> Result<(), QuicError> {
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or_else(|| QuicError::Stream("unknown stream".to_string()))?;
        let send = stream
            .send
            .as_mut()
            .ok_or_else(|| QuicError::Stream("stream is receive-only".to_string()))?;
        if send.data.len() + data.len() > MAX_STREAM_BUFFER {
            return Err(QuicError::Stream("stream send buffer exceeded".to_string()));
        }
        send.data.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn finish(&mut self, id: u64) -> Result<(), QuicError> {
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or_else(|| QuicError::Stream("unknown stream".to_string()))?;
        let send = stream
            .send
            .as_mut()
            .ok_or_else(|| QuicError::Stream("stream is receive-only".to_string()))?;
        send.fin = true;
        Ok(())
    }

    pub(crate) fn read(&mut self, id: u64, max: usize) -> Result<ReadResult, QuicError> {
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or_else(|| QuicError::Stream("unknown stream".to_string()))?;
        let recv = stream
            .recv
            .as_mut()
            .ok_or_else(|| QuicError::Stream("stream is send-only".to_string()))?;
        let mut data = BytesMut::new();
        while data.len() < max {
            let Some(chunk) = recv.chunks.remove(&recv.read) else {
                break;
            };
            let take = (max - data.len()).min(chunk.len());
            data.extend_from_slice(&chunk[..take]);
            recv.read += take as u64;
            if take < chunk.len() {
                recv.chunks.insert(recv.read, chunk.slice(take..));
                break;
            }
        }
        if !data.is_empty() {
            recv.consumed += data.len() as u64;
            self.recv_consumed = self.recv_consumed.saturating_add(data.len() as u64);
            if recv.consumed.saturating_add(recv.window / 2) > recv.max_data {
                recv.max_data = recv.consumed.saturating_add(recv.window);
                self.control_frames.push(Frame::MaxStreamData {
                    stream_id: id,
                    maximum: recv.max_data,
                });
            }
            let initial = self.local_tp.initial_max_data.unwrap_or(0);
            if self.recv_consumed.saturating_add(initial / 2) > self.local_max_data {
                self.local_max_data = self.recv_consumed.saturating_add(initial);
                self.control_frames
                    .push(Frame::MaxData(self.local_max_data));
            }
            return Ok(ReadResult::Data(data.freeze()));
        }
        if recv.fin == Some(recv.read) {
            return Ok(ReadResult::Fin);
        }
        Ok(ReadResult::Pending)
    }

    pub(crate) fn stop_sending(&mut self, id: u64, code: u64) {
        self.control_frames.push(Frame::StopSending {
            stream_id: id,
            error_code: code,
        });
        if let Some(stream) = self.streams.get_mut(&id)
            && let Some(recv) = stream.recv.as_mut()
        {
            recv.stopped = true;
        }
    }

    pub(crate) fn reset(&mut self, id: u64, code: u64) {
        let final_size = self
            .streams
            .get(&id)
            .and_then(|stream| stream.send.as_ref())
            .map(|send| send.data.len() as u64)
            .unwrap_or(0);
        self.control_frames.push(Frame::ResetStream {
            stream_id: id,
            error_code: code,
            final_size,
        });
        if let Some(stream) = self.streams.get_mut(&id)
            && let Some(send) = stream.send.as_mut()
        {
            send.reset = Some(code);
        }
    }

    pub(crate) fn accept_bi(&mut self) -> Option<u64> {
        self.accept_bi.pop_front()
    }

    pub(crate) fn accept_uni(&mut self) -> Option<u64> {
        self.accept_uni.pop_front()
    }

    fn apply_peer_parameters(&mut self, parameters: TransportParameters) {
        self.peer_max_bidi = parameters.initial_max_streams_bidi.unwrap_or(0);
        self.peer_max_uni = parameters.initial_max_streams_uni.unwrap_or(0);
        self.send_max_data = parameters.initial_max_data.unwrap_or(0);
        self.peer_max_datagram = parameters.max_datagram_frame_size;
        self.peer_reset_token = parameters.stateless_reset_token;
        self.peer_tp = Some(parameters);
    }

    fn drain_tls(&mut self) -> Result<(), QuicError> {
        loop {
            let level = self.send_level;
            let mut data = Vec::new();
            let change = self.tls.write_handshake(&mut data);
            if !data.is_empty() {
                self.spaces[level as usize]
                    .crypto_send
                    .extend_from_slice(&data);
            }
            let advanced = !data.is_empty();
            if let Some(change) = change {
                match change {
                    KeyChange::Handshake { keys } => {
                        self.spaces[Level::Handshake as usize].keys = Some(keys);
                        self.send_level = Level::Handshake;
                        self.read_level = Level::Handshake;
                    }
                    KeyChange::OneRtt { keys, next } => {
                        self.spaces[Level::OneRtt as usize].keys = Some(keys);
                        self.one_rtt = Some(OneRttKeys {
                            secrets: next,
                            key_phase: false,
                            next_local: None,
                            next_remote: None,
                            previous_remote: None,
                        });
                        self.send_level = Level::OneRtt;
                        self.read_level = Level::OneRtt;
                    }
                }
                continue;
            }
            if !advanced {
                break;
            }
        }
        if let Some(peer) = self.tls.peer_transport_parameters() {
            let parameters = TransportParameters::decode(&peer)
                .map_err(|error| QuicError::Protocol(error.to_string()))?;
            if self.server && self.early_keys.is_none() {
                self.early_keys = self.tls.zero_rtt_keys();
            }
            let cacheable = !self.tls.is_handshaking();
            self.apply_peer_parameters(parameters.clone());
            if cacheable && let Some(cache) = &self.session_cache {
                cache.insert(&self.session_key, parameters.clone());
            }
        }
        Ok(())
    }

    fn process_early_frames(&mut self, payload: &[u8]) -> Result<(), QuicError> {
        let mut cursor = payload;
        while !cursor.is_empty() {
            let frame = Frame::decode(&mut cursor)
                .map_err(|error| QuicError::Protocol(error.to_string()))?;
            match frame {
                Frame::Stream {
                    stream_id,
                    offset,
                    fin,
                    data,
                } => self.handle_stream(stream_id, offset, fin, &data)?,
                Frame::Datagram { data } => {
                    if self.recv_datagrams.len() < 64 {
                        self.recv_datagrams.push_back(data);
                    }
                }
                Frame::Ping | Frame::Padding { .. } => {}
                Frame::MaxData(maximum) => self.send_max_data = self.send_max_data.max(maximum),
                Frame::MaxStreamData { stream_id, maximum } => {
                    if let Some(send) = self
                        .streams
                        .get_mut(&stream_id)
                        .and_then(|stream| stream.send.as_mut())
                    {
                        send.max_data = send.max_data.max(maximum);
                    }
                }
                Frame::MaxStreams { bidi, maximum } => {
                    if bidi {
                        self.peer_max_bidi = self.peer_max_bidi.max(maximum);
                    } else {
                        self.peer_max_uni = self.peer_max_uni.max(maximum);
                    }
                }
                Frame::DataBlocked(_)
                | Frame::StreamDataBlocked { .. }
                | Frame::StreamsBlocked { .. } => {}
                _ => {
                    return Err(QuicError::Protocol(
                        "frame is not allowed in a 0-RTT packet".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn process_frames(&mut self, level: Level, payload: &[u8]) -> Result<bool, QuicError> {
        let mut cursor = payload;
        let mut ack_eliciting = false;
        while !cursor.is_empty() {
            let frame = Frame::decode(&mut cursor)
                .map_err(|error| QuicError::Protocol(error.to_string()))?;
            ack_eliciting |= !matches!(frame, Frame::Ack(_) | Frame::Padding { .. });
            match frame {
                Frame::Crypto { offset, data } => {
                    self.insert_crypto(level, offset, &data)?;
                }
                Frame::ConnectionCloseTransport { reason, .. }
                | Frame::ConnectionCloseApplication { reason, .. } => {
                    self.closed = Some((
                        0,
                        format!("peer closed: {}", String::from_utf8_lossy(&reason)),
                    ));
                }
                Frame::HandshakeDone => self.handshake_done = true,
                Frame::Stream {
                    stream_id,
                    offset,
                    fin,
                    data,
                } => self.handle_stream(stream_id, offset, fin, &data)?,
                Frame::MaxData(maximum) => self.send_max_data = self.send_max_data.max(maximum),
                Frame::MaxStreamData { stream_id, maximum } => {
                    if let Some(send) = self
                        .streams
                        .get_mut(&stream_id)
                        .and_then(|stream| stream.send.as_mut())
                    {
                        send.max_data = send.max_data.max(maximum);
                    }
                }
                Frame::MaxStreams { bidi, maximum } => {
                    if bidi {
                        self.peer_max_bidi = self.peer_max_bidi.max(maximum);
                    } else {
                        self.peer_max_uni = self.peer_max_uni.max(maximum);
                    }
                }
                Frame::StopSending {
                    stream_id,
                    error_code,
                } => {
                    self.reset(stream_id, error_code);
                }
                Frame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                } => {
                    if let Some(stream) = self.streams.get_mut(&stream_id)
                        && let Some(recv) = stream.recv.as_mut()
                    {
                        recv.fin = Some(final_size);
                        recv.consumed = final_size;
                        let _ = error_code;
                    }
                }
                Frame::Ack(ack) => self.handle_ack(level, ack),
                Frame::Padding { .. }
                | Frame::Ping
                | Frame::DataBlocked(_)
                | Frame::StreamDataBlocked { .. }
                | Frame::StreamsBlocked { .. }
                | Frame::NewConnectionId { .. }
                | Frame::RetireConnectionId(_)
                | Frame::NewToken { .. } => {}
                Frame::PathChallenge(data) => {
                    self.control_frames.push(Frame::PathResponse(data));
                }
                Frame::PathResponse(data) => {
                    if self.path_challenge == Some(data) {
                        self.path_challenge = None;
                        self.path_validated = true;
                    }
                }
                Frame::Datagram { data } => {
                    if self.recv_datagrams.len() < 64 {
                        self.recv_datagrams.push_back(data);
                    }
                }
            }
        }
        self.feed_tls()?;
        Ok(ack_eliciting)
    }

    fn handle_stream(
        &mut self,
        id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), QuicError> {
        if !self.streams.contains_key(&id) {
            if self.is_local_stream(id) {
                return Err(QuicError::Protocol(
                    "peer referenced a local-only stream".to_string(),
                ));
            }
            let bidi = id & 0x2 == 0;
            let limit = if bidi {
                self.local_tp.initial_max_streams_bidi.unwrap_or(0)
            } else {
                self.local_tp.initial_max_streams_uni.unwrap_or(0)
            };
            let opened = if bidi {
                &mut self.peer_opened_bidi
            } else {
                &mut self.peer_opened_uni
            };
            if *opened >= limit {
                return Err(QuicError::Protocol(
                    "peer exceeded the stream limit".to_string(),
                ));
            }
            *opened += 1;
            let stream = Stream {
                send: if bidi {
                    Some(SendState {
                        data: Vec::new(),
                        sent: 0,
                        fin: false,
                        fin_sent: false,
                        reset: None,
                        max_data: self.peer_stream_window(true),
                    })
                } else {
                    None
                },
                recv: Some(RecvState {
                    chunks: BTreeMap::new(),
                    read: 0,
                    fin: None,
                    max_data: self.local_stream_window(bidi),
                    window: self.local_stream_window(bidi),
                    consumed: 0,
                    stopped: false,
                }),
            };
            self.streams.insert(id, stream);
            if bidi {
                self.accept_bi.push_back(id);
            } else {
                self.accept_uni.push_back(id);
            }
        }
        let Some(stream) = self.streams.get_mut(&id) else {
            return Err(QuicError::Protocol("stream disappeared".to_string()));
        };
        let recv = stream
            .recv
            .as_mut()
            .ok_or_else(|| QuicError::Protocol("STREAM on a send-only stream".to_string()))?;
        if offset + data.len() as u64 > recv.max_data {
            return Err(QuicError::Protocol(
                "STREAM exceeds the receive window".to_string(),
            ));
        }
        if recv.fin.is_some_and(|end| offset + data.len() as u64 > end) {
            return Err(QuicError::Protocol(
                "STREAM exceeds its final size".to_string(),
            ));
        }
        if !data.is_empty() {
            let limit = self.local_max_data;
            if self.recv_data.saturating_add(data.len() as u64) > limit {
                return Err(QuicError::Protocol(
                    "connection receive window exceeded".to_string(),
                ));
            }
            self.recv_data = self.recv_data.saturating_add(data.len() as u64);
            recv.chunks.insert(offset, Bytes::copy_from_slice(data));
        }
        if fin {
            recv.fin = Some(offset + data.len() as u64);
        }
        Ok(())
    }

    fn insert_crypto(&mut self, level: Level, offset: u64, data: &[u8]) -> Result<(), QuicError> {
        let space = &mut self.spaces[level as usize];
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

    fn feed_tls(&mut self) -> Result<(), QuicError> {
        loop {
            let mut fed = false;
            for level in LEVELS {
                if level as usize > self.read_level as usize {
                    continue;
                }
                loop {
                    let data = {
                        let space = &mut self.spaces[level as usize];
                        match space.crypto_recv.remove(&space.crypto_read) {
                            Some(data) => data,
                            None => break,
                        }
                    };
                    self.tls.read_handshake(&data)?;
                    self.spaces[level as usize].crypto_read += data.len() as u64;
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

    fn validate_retry_parameters(&mut self) -> Result<(), QuicError> {
        if !self.retried {
            return Ok(());
        }
        let peer = self
            .tls
            .peer_transport_parameters()
            .ok_or_else(|| QuicError::Protocol("missing peer transport parameters".to_string()))?;
        let parameters = TransportParameters::decode(&peer)
            .map_err(|error| QuicError::Protocol(error.to_string()))?;
        if parameters.retry_source_connection_id.as_deref() != self.retry_source_cid.as_deref() {
            return Err(QuicError::Protocol(
                "Retry source CID transport parameter is invalid".to_string(),
            ));
        }
        if parameters.original_destination_connection_id.as_deref()
            != Some(self.initial_odcid.as_slice())
        {
            return Err(QuicError::Protocol(
                "original destination CID transport parameter is invalid".to_string(),
            ));
        }
        Ok(())
    }

    fn update_established(&mut self) -> Result<(), QuicError> {
        if !self.established
            && self.spaces[Level::OneRtt as usize].keys.is_some()
            && !self.tls.is_handshaking()
        {
            if !self.server {
                self.validate_retry_parameters()?;
            }
            self.established = true;
            self.early_data_accepted = self.tls.is_early_data_accepted();
            if !self.server && !self.early_data_accepted && !self.early_frames.is_empty() {
                self.retransmit[Level::OneRtt as usize].append(&mut self.early_frames);
            } else {
                self.early_frames.clear();
            }
            self.early_keys = None;
            if self.server && !self.handshake_done {
                self.control_frames.push(Frame::HandshakeDone);
                self.handshake_done = true;
            }
        }
        Ok(())
    }

    fn queue_zero_rtt(&mut self, frames: Vec<Frame>) -> Result<(), QuicError> {
        let keys = self
            .early_keys
            .as_ref()
            .ok_or_else(|| QuicError::Protocol("missing 0-RTT keys".to_string()))?;
        let packet_number = self.spaces[Level::OneRtt as usize].next_pn;
        let mut payload = BytesMut::new();
        for frame in &frames {
            frame
                .encode(&mut payload)
                .map_err(|error| QuicError::Protocol(error.to_string()))?;
        }
        let packet = LongPacket {
            ty: LongType::ZeroRtt,
            version: self.version,
            destination_connection_id: self.original_dcid.clone(),
            source_connection_id: self.local_cid.clone(),
            token: Vec::new(),
            packet_number,
            packet_number_len: 4,
            payload: payload.freeze(),
        };
        let protected = protect_long(&packet, keys)?;
        if protected.len() > MAX_DATAGRAM {
            return Err(QuicError::Protocol(format!(
                "0-RTT packet of {} bytes exceeds the {} byte datagram limit",
                protected.len(),
                MAX_DATAGRAM
            )));
        }
        self.spaces[Level::OneRtt as usize].next_pn += 1;
        self.early_frames.extend(frames);
        self.outgoing.push(protected.to_vec());
        Ok(())
    }

    fn queue_packet(&mut self, level: Level, frames: Vec<Frame>) -> Result<(), QuicError> {
        let packet_number = self.spaces[level as usize].next_pn;
        let mut frames = frames;
        let mut payload = BytesMut::new();
        for frame in &frames {
            frame
                .encode(&mut payload)
                .map_err(|error| QuicError::Protocol(error.to_string()))?;
        }

        let mut protected = self.protect(level, packet_number, payload.freeze())?;
        if protected.len() > MAX_DATAGRAM {
            return Err(QuicError::Protocol(format!(
                "packet of {} bytes exceeds the {} byte datagram limit",
                protected.len(),
                MAX_DATAGRAM
            )));
        }
        if level == Level::Initial && protected.len() < MAX_DATAGRAM {
            // PADDING changes the long-header length field, which is itself a
            // varint: adding one byte of padding can grow the header by one
            // byte. Iterate to land exactly on the 1200-byte Initial floor.
            let mut padding = MAX_DATAGRAM - protected.len();
            for _ in 0..8 {
                if padding == 0 {
                    break;
                }
                frames.push(Frame::Padding { len: padding });
                let mut payload = BytesMut::new();
                for frame in &frames {
                    frame
                        .encode(&mut payload)
                        .map_err(|error| QuicError::Protocol(error.to_string()))?;
                }
                frames.pop();
                protected = self.protect(level, packet_number, payload.freeze())?;
                match protected.len().cmp(&MAX_DATAGRAM) {
                    std::cmp::Ordering::Equal => break,
                    std::cmp::Ordering::Less => {
                        padding += MAX_DATAGRAM - protected.len();
                    }
                    std::cmp::Ordering::Greater => {
                        let excess = protected.len() - MAX_DATAGRAM;
                        padding = padding.saturating_sub(excess);
                    }
                }
            }
            if protected.len() != MAX_DATAGRAM {
                return Err(QuicError::Protocol(format!(
                    "Initial datagram is {} bytes, expected {}",
                    protected.len(),
                    MAX_DATAGRAM
                )));
            }
        }
        if protected.len() > MAX_DATAGRAM {
            return Err(QuicError::Protocol(format!(
                "packet of {} bytes exceeds the {} byte datagram limit",
                protected.len(),
                MAX_DATAGRAM
            )));
        }

        self.spaces[level as usize].next_pn += 1;
        if level == Level::OneRtt {
            self.one_rtt_packets = self.one_rtt_packets.saturating_add(1);
            if self.one_rtt_packets >= 1_000_000 {
                self.one_rtt_packets = 0;
                let _ = self.initiate_key_update();
            }
        }
        let ack_eliciting = frames.iter().any(|frame| {
            !matches!(
                frame,
                Frame::Ack(_)
                    | Frame::Padding { .. }
                    | Frame::ConnectionCloseApplication { .. }
                    | Frame::ConnectionCloseTransport { .. }
            )
        });
        if ack_eliciting {
            // RFC 9000 Section 10.1: sending an ack-eliciting packet restarts
            // the idle timer only when none has been sent since the last
            // successfully processed packet from the peer.
            if !self.ack_eliciting_since_receive {
                self.last_activity = Instant::now();
                self.ack_eliciting_since_receive = true;
            }
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(protected.len() as u64);
            self.sent.push(SentPacket {
                level,
                packet_number,
                time: Instant::now(),
                size: protected.len() as u64,
                frames,
            });
        }
        self.outgoing.push(protected.to_vec());
        Ok(())
    }

    fn protect(
        &self,
        level: Level,
        packet_number: u64,
        payload: Bytes,
    ) -> Result<Bytes, QuicError> {
        let keys = self.spaces[level as usize]
            .keys
            .as_ref()
            .ok_or_else(|| QuicError::Protocol("missing send keys".to_string()))?;
        match level {
            Level::Initial | Level::Handshake => {
                let ty = if level == Level::Initial {
                    LongType::Initial
                } else {
                    LongType::Handshake
                };
                let dcid = if self.server {
                    if self.peer_cid.is_empty() {
                        self.original_dcid.clone()
                    } else {
                        self.peer_cid.clone()
                    }
                } else if level == Level::Initial || self.peer_cid.is_empty() {
                    self.original_dcid.clone()
                } else {
                    self.peer_cid.clone()
                };
                let packet = LongPacket {
                    ty,
                    version: self.version,
                    destination_connection_id: dcid,
                    source_connection_id: self.local_cid.clone(),
                    token: if level == Level::Initial {
                        self.initial_token.clone()
                    } else {
                        Vec::new()
                    },
                    packet_number,
                    packet_number_len: 4,
                    payload,
                };
                Ok(protect_long(&packet, &keys.local)?)
            }
            Level::OneRtt => {
                let packet = ShortPacket {
                    spin: false,
                    key_phase: self.one_rtt.as_ref().is_some_and(|state| state.key_phase),
                    destination_connection_id: self.peer_cid.clone(),
                    packet_number,
                    packet_number_len: 4,
                    payload,
                };
                Ok(protect_short(&packet, &keys.local)?)
            }
        }
    }

    fn append_stream_frames(
        &mut self,
        frames: &mut Vec<Frame>,
        budget: &mut usize,
    ) -> Result<(), QuicError> {
        let send_max_data = self.send_max_data;
        let mut ids: Vec<u64> = self.streams.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            let mut frame = None;
            if let Some(stream) = self.streams.get_mut(&id)
                && let Some(send) = stream.send.as_mut()
            {
                let available = send.data.len() as u64 - send.sent;
                if available > 0 {
                    let window = send
                        .max_data
                        .saturating_sub(send.sent)
                        .min(send_max_data.saturating_sub(self.send_data))
                        .min(MAX_STREAM_FRAME as u64)
                        .min(available);
                    if window > 0 {
                        let start = send.sent as usize;
                        let end = start + window as usize;
                        let data = Bytes::copy_from_slice(&send.data[start..end]);
                        let fin = send.fin && end == send.data.len();
                        let candidate = Frame::Stream {
                            stream_id: id,
                            offset: start as u64,
                            fin,
                            data,
                        };
                        let len = frame_len(&candidate)?;
                        if len > *budget {
                            break;
                        }
                        *budget -= len;
                        send.fin_sent |= fin;
                        send.sent += window;
                        self.send_data += window;
                        frame = Some(candidate);
                    }
                } else if send.fin && !send.fin_sent {
                    let candidate = Frame::Stream {
                        stream_id: id,
                        offset: send.sent,
                        fin: true,
                        data: Bytes::new(),
                    };
                    let len = frame_len(&candidate)?;
                    if len > *budget {
                        break;
                    }
                    *budget -= len;
                    send.fin_sent = true;
                    frame = Some(candidate);
                }
            }
            if let Some(frame) = frame {
                frames.push(frame);
            }
        }
        Ok(())
    }

    fn take_fitting(
        queue: &mut Vec<Frame>,
        frames: &mut Vec<Frame>,
        budget: &mut usize,
    ) -> Result<(), QuicError> {
        let mut count = 0;
        for frame in queue.iter() {
            let len = frame_len(frame)?;
            if len > *budget {
                break;
            }
            *budget -= len;
            frames.push(frame.clone());
            count += 1;
        }
        queue.drain(..count);
        Ok(())
    }

    fn ack_frame(&self, level: Level) -> Frame {
        let space = &self.spaces[level as usize];
        let largest = *space.received.last().unwrap_or(&0);
        let contiguous = space.received.iter().copied().eq(0..=largest);
        Frame::Ack(AckFrame {
            largest_acknowledged: largest,
            ack_delay: 0,
            first_ack_range: if contiguous { largest } else { 0 },
            ranges: Vec::<AckRange>::new(),
            ecn: None,
        })
    }

    fn record(&mut self, level: Level, pn: u64, ack_eliciting: bool) {
        let space = &mut self.spaces[level as usize];
        space.received.insert(pn);
        if ack_eliciting {
            space.ack_pending = true;
        }
    }

    fn largest(&self, level: Level) -> u64 {
        *self.spaces[level as usize].received.last().unwrap_or(&0)
    }

    fn is_local_stream(&self, id: u64) -> bool {
        let initiator = id & 0x1;
        match self.side {
            Side::Client => initiator == 0,
            Side::Server => initiator == 1,
        }
    }

    fn peer_stream_window(&self, bidi: bool) -> u64 {
        let Some(parameters) = &self.peer_tp else {
            return 1 << 20;
        };
        if bidi {
            parameters
                .initial_max_stream_data_bidi_local
                .unwrap_or(1 << 20)
        } else {
            parameters.initial_max_stream_data_uni.unwrap_or(1 << 20)
        }
    }

    fn local_stream_window(&self, bidi: bool) -> u64 {
        if bidi {
            self.local_tp
                .initial_max_stream_data_bidi_remote
                .unwrap_or(1 << 20)
        } else {
            self.local_tp.initial_max_stream_data_uni.unwrap_or(1 << 20)
        }
    }
}

fn try_short(
    packet: &[u8],
    dcid_len: usize,
    largest: u64,
    header: &dyn rustls::quic::HeaderProtectionKey,
    key: &dyn PacketKey,
) -> Option<(u64, u8, bool, Bytes)> {
    let mut packet = packet.to_vec();
    unprotect_short_with(&mut packet, dcid_len, largest, header, key).ok()
}

fn acknowledged_packets(ack: &AckFrame) -> BTreeSet<u64> {
    let mut acked = BTreeSet::new();
    let mut lowest = ack.largest_acknowledged.saturating_sub(ack.first_ack_range);
    for packet in lowest..=ack.largest_acknowledged {
        acked.insert(packet);
    }
    for range in &ack.ranges {
        let Some(largest) = lowest.checked_sub(range.gap + 2) else {
            break;
        };
        lowest = largest.saturating_sub(range.range);
        for packet in lowest..=largest {
            acked.insert(packet);
        }
    }
    acked
}

fn parse_scid(datagram: &[u8], packet_end: usize) -> Option<Vec<u8>> {
    let mut cursor = &datagram[..packet_end];
    if cursor.len() < 6 {
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

/// The amount of time until the next recovery timer is due.
pub(crate) const TIMER_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct AcceptAny;

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    fn core() -> Core {
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        Core::client(
            std::sync::Arc::new(tls),
            ServerName::try_from("localhost").expect("name"),
            vec![1; 8],
            vec![2; 8],
            TransportParameters::default(),
            ClientOptions {
                version: crate::wire::packet::VERSION_1,
                supported_versions: vec![crate::wire::packet::VERSION_1],
                congestion: CongestionAlgorithm::NewReno,
                congestion_factory: None,
                early_data: false,
                keep_alive: None,
                session_cache: None,
                session_key: "localhost".to_string(),
            },
        )
        .expect("core")
    }

    fn frame_bytes(frame: Frame) -> Bytes {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).expect("encode");
        bytes.freeze()
    }

    #[test]
    fn datagram_payload_accounts_for_the_frame_overhead() {
        let mut core = core();
        core.peer_max_datagram = Some(64);
        assert_eq!(core.max_datagram_size(), Some(62));
        core.send_datagram(Bytes::from(vec![0; 62]))
            .expect("payload fits");
        assert!(matches!(
            core.send_datagram(Bytes::from(vec![0; 63])),
            Err(QuicError::DatagramTooLarge { .. })
        ));
    }

    #[test]
    fn a_close_reason_cannot_make_the_close_frame_unsendable() {
        let mut core = core();
        core.close(1, &"x".repeat(4096));
        let frame = core
            .control_frames
            .iter()
            .find(|frame| matches!(frame, Frame::ConnectionCloseApplication { .. }))
            .expect("close frame");
        assert!(frame_len(frame).expect("frame length") <= PACKET_BUDGET);
    }

    #[test]
    fn idle_timeout_closes_the_connection_silently() {
        let mut core = core();
        core.local_tp.max_idle_timeout = Some(100);
        core.peer_tp = Some(TransportParameters {
            max_idle_timeout: Some(100),
            ..TransportParameters::default()
        });
        core.pto = Duration::from_millis(10);
        core.last_activity = Instant::now() - Duration::from_millis(200);
        core.handle_timeout().expect("timeout");
        assert!(core.is_closed());
        assert!(core.control_frames.is_empty(), "idle close is silent");
    }

    #[test]
    fn keep_alive_queues_a_ping_before_the_idle_timeout() {
        let mut core = core();
        core.spaces[Level::OneRtt as usize].keys = Some(
            initial_keys_for_version(&[0; 8], Side::Client, crate::wire::packet::VERSION_1)
                .expect("keys"),
        );
        core.established = true;
        core.keep_alive = Some(Duration::from_millis(50));
        core.pto = Duration::from_millis(10);
        core.last_keep_alive = Instant::now() - Duration::from_millis(100);
        core.handle_timeout().expect("timeout");
        assert_eq!(
            core.retransmit[Level::OneRtt as usize]
                .iter()
                .filter(|frame| matches!(frame, Frame::Ping))
                .count(),
            1
        );
        core.handle_timeout().expect("second timeout");
        assert_eq!(
            core.retransmit[Level::OneRtt as usize]
                .iter()
                .filter(|frame| matches!(frame, Frame::Ping))
                .count(),
            1,
            "a keep-alive timer must not queue one PING per tick"
        );
    }

    #[test]
    fn keep_alive_does_not_fire_before_its_interval() {
        let mut core = core();
        core.spaces[Level::OneRtt as usize].keys = Some(
            initial_keys_for_version(&[0; 8], Side::Client, crate::wire::packet::VERSION_1)
                .expect("keys"),
        );
        core.established = true;
        core.keep_alive = Some(Duration::from_secs(10));
        core.last_keep_alive = Instant::now();
        core.handle_timeout().expect("timeout");
        assert!(
            !core.retransmit[Level::OneRtt as usize]
                .iter()
                .any(|frame| matches!(frame, Frame::Ping))
        );
    }

    #[test]
    fn path_challenge_validation_tracks_response() {
        let mut core = core();
        core.begin_path_validation([7; 8]);
        assert!(core.control_frames.iter().any(|frame| {
            matches!(frame, Frame::PathChallenge(challenge) if *challenge == [7; 8])
        }));
        core.process_frames(Level::OneRtt, &frame_bytes(Frame::PathResponse([7; 8])))
            .expect("path response");
        assert!(core.path_validated());
    }

    #[test]
    fn path_challenge_is_answered() {
        let mut core = core();
        core.process_frames(Level::OneRtt, &frame_bytes(Frame::PathChallenge([9; 8])))
            .expect("path challenge");
        assert!(core.control_frames.iter().any(|frame| {
            matches!(frame, Frame::PathResponse(challenge) if *challenge == [9; 8])
        }));
    }
}
