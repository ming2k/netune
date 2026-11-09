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
use rustls::Side;
use rustls::quic::{KeyChange, Keys};

use crate::crypto::{
    TlsSession, initial_keys, long_header_info, protect_long, protect_short, unprotect_long,
    unprotect_short,
};
use crate::error::QuicError;
use crate::wire::frame::{AckFrame, AckRange, Frame};
use crate::wire::packet::{LongPacket, LongType, ShortPacket, VERSION_1};
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
const MAX_STREAM_FRAME: usize = 1000;

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
    reset: Option<u64>,
    max_data: u64,
}

struct RecvState {
    chunks: BTreeMap<u64, Bytes>,
    read: u64,
    fin: Option<u64>,
    max_data: u64,
    consumed: u64,
    stopped: bool,
}

struct Stream {
    send: Option<SendState>,
    recv: Option<RecvState>,
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
    send_level: Level,
    read_level: Level,
    established: bool,
    handshake_done: bool,
    server: bool,
    outgoing: Vec<Vec<u8>>,
    control_frames: Vec<Frame>,
    closed: Option<(u64, String)>,
    last_activity: Instant,
}

impl Core {
    /// Create a client core. The first ClientHello is queued by `poll_transmit`.
    pub(crate) fn client(
        tls: TlsSession,
        original_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        local_tp: TransportParameters,
    ) -> Result<Self, QuicError> {
        let initial = initial_keys(&original_dcid, Side::Client)?;
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
            next_uni: 0,
            opened_bidi: 0,
            opened_uni: 0,
            peer_max_bidi: 0,
            peer_max_uni: 0,
            send_max_data: 0,
            send_data: 0,
            recv_data: 0,
            send_level: Level::Initial,
            read_level: Level::Initial,
            established: false,
            handshake_done: false,
            server: false,
            outgoing: Vec::new(),
            control_frames: Vec::new(),
            closed: None,
            last_activity: Instant::now(),
        };
        core.drain_tls()?;
        Ok(core)
    }

    /// Create a server core for an accepted Initial packet.
    pub(crate) fn server(
        tls: TlsSession,
        original_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        local_tp: TransportParameters,
    ) -> Result<Self, QuicError> {
        let initial = initial_keys(&original_dcid, Side::Server)?;
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
            next_bidi: 0,
            next_uni: 0,
            opened_bidi: 0,
            opened_uni: 0,
            peer_max_bidi: 0,
            peer_max_uni: 0,
            send_max_data: 0,
            send_data: 0,
            recv_data: 0,
            send_level: Level::Initial,
            read_level: Level::Initial,
            established: false,
            handshake_done: false,
            server: true,
            outgoing: Vec::new(),
            control_frames: Vec::new(),
            closed: None,
            last_activity: Instant::now(),
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
        self.closed = Some((code, reason.to_string()));
        self.control_frames.push(Frame::ConnectionCloseApplication {
            error_code: code,
            reason: Bytes::copy_from_slice(reason.as_bytes()),
        });
    }

    pub(crate) fn handle_timeout(&mut self) -> Result<(), QuicError> {
        // The first production milestone has no retransmission timer yet. ACKs
        // are generated immediately, which is sufficient for a lossless path;
        // recovery is the next ADR-0028 gate.
        let _ = self.last_activity;
        Ok(())
    }

    pub(crate) fn receive(&mut self, datagram: &[u8]) -> Result<(), QuicError> {
        if self.closed.is_some() {
            return Err(QuicError::Closed("connection is closed".to_string()));
        }
        self.last_activity = Instant::now();
        let mut cursor = datagram;
        while !cursor.is_empty() {
            let first = cursor[0];
            if first & 0x80 == 0 {
                let keys = self.spaces[Level::OneRtt as usize]
                    .keys
                    .as_ref()
                    .ok_or_else(|| {
                        QuicError::Protocol("short packet before 1-RTT keys".to_string())
                    })?;
                let dcid_len = self.local_cid.len();
                let mut packet = cursor.to_vec();
                let (pn, _pn_len, payload) = unprotect_short(
                    &mut packet,
                    dcid_len,
                    self.largest(Level::OneRtt),
                    &keys.remote,
                )?;
                self.record(Level::OneRtt, pn);
                self.process_frames(Level::OneRtt, &payload)?;
                cursor = &[];
            } else {
                let (_, packet_end) = long_header_info(cursor)?;
                let mut packet = cursor[..packet_end].to_vec();
                let ty = LongType::from_bits(first);
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
                self.record(level, pn);
                self.process_frames(level, &payload)?;
                cursor = &cursor[packet_end..];
            }
        }
        self.update_established();
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
            let mut payload = BytesMut::new();
            if self.spaces[level as usize].ack_pending {
                let ack = self.ack_frame(level);
                ack.encode(&mut payload)
                    .map_err(|error| QuicError::Protocol(error.to_string()))?;
                self.spaces[level as usize].ack_pending = false;
            }
            let crypto_pending = self.spaces[level as usize].crypto_sent
                < self.spaces[level as usize].crypto_send.len();
            if crypto_pending {
                let space = &mut self.spaces[level as usize];
                let start = space.crypto_sent;
                let end = (start + 1000).min(space.crypto_send.len());
                let data = Bytes::copy_from_slice(&space.crypto_send[start..end]);
                space.crypto_sent = end;
                Frame::Crypto {
                    offset: start as u64,
                    data,
                }
                .encode(&mut payload)
                .map_err(|error| QuicError::Protocol(error.to_string()))?;
            }
            if level == Level::OneRtt {
                self.append_stream_frames(&mut payload)?;
                for frame in self.control_frames.drain(..) {
                    frame
                        .encode(&mut payload)
                        .map_err(|error| QuicError::Protocol(error.to_string()))?;
                }
            }
            if payload.is_empty() {
                continue;
            }
            self.queue_packet(level, payload.freeze())?;
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
                    reset: None,
                    max_data: window,
                }),
                recv: Some(RecvState {
                    chunks: BTreeMap::new(),
                    read: 0,
                    fin: None,
                    max_data: self.local_stream_window(true),
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
            self.recv_data += data.len() as u64;
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
        self.control_frames.push(Frame::ResetStream {
            stream_id: id,
            error_code: code,
            final_size: 0,
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
                    KeyChange::OneRtt { keys, .. } => {
                        self.spaces[Level::OneRtt as usize].keys = Some(keys);
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
            self.peer_max_bidi = parameters.initial_max_streams_bidi.unwrap_or(0);
            self.peer_max_uni = parameters.initial_max_streams_uni.unwrap_or(0);
            self.send_max_data = parameters.initial_max_data.unwrap_or(0);
            self.peer_tp = Some(parameters);
        }
        Ok(())
    }

    fn process_frames(&mut self, level: Level, payload: &[u8]) -> Result<(), QuicError> {
        let mut cursor = payload;
        while !cursor.is_empty() {
            let frame = Frame::decode(&mut cursor)
                .map_err(|error| QuicError::Protocol(error.to_string()))?;
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
                Frame::Ack(_)
                | Frame::Padding { .. }
                | Frame::Ping
                | Frame::DataBlocked(_)
                | Frame::StreamDataBlocked { .. }
                | Frame::StreamsBlocked { .. }
                | Frame::NewConnectionId { .. }
                | Frame::RetireConnectionId(_)
                | Frame::PathChallenge(_)
                | Frame::PathResponse(_)
                | Frame::NewToken { .. }
                | Frame::Datagram { .. } => {}
            }
        }
        self.feed_tls()
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
            let stream = Stream {
                send: if bidi {
                    Some(SendState {
                        data: Vec::new(),
                        sent: 0,
                        fin: false,
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
                    self.tls
                        .read_handshake(&data)
                        .map_err(|error| QuicError::Protocol(error.to_string()))?;
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

    fn update_established(&mut self) {
        if !self.established
            && self.spaces[Level::OneRtt as usize].keys.is_some()
            && !self.tls.is_handshaking()
        {
            self.established = true;
            if self.server && !self.handshake_done {
                self.control_frames.push(Frame::HandshakeDone);
                self.handshake_done = true;
            }
        }
    }

    fn queue_packet(&mut self, level: Level, payload: Bytes) -> Result<(), QuicError> {
        let packet = match level {
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
                    version: VERSION_1,
                    destination_connection_id: dcid,
                    source_connection_id: self.local_cid.clone(),
                    token: Vec::new(),
                    packet_number: self.spaces[level as usize].next_pn,
                    packet_number_len: 4,
                    payload,
                };
                self.spaces[level as usize].next_pn += 1;
                let keys = self.spaces[level as usize]
                    .keys
                    .as_ref()
                    .ok_or_else(|| QuicError::Protocol("missing send keys".to_string()))?;
                let protected = protect_long(&packet, &keys.local)?;
                if level == Level::Initial && protected.len() < MAX_DATAGRAM {
                    let mut padded = packet;
                    let mut data = padded.payload.to_vec();
                    data.resize(data.len() + (MAX_DATAGRAM - protected.len()), 0);
                    padded.payload = Bytes::from(data);
                    protect_long(&padded, &keys.local)?
                } else {
                    protected
                }
            }
            Level::OneRtt => {
                let packet = ShortPacket {
                    spin: false,
                    key_phase: false,
                    destination_connection_id: self.peer_cid.clone(),
                    packet_number: self.spaces[level as usize].next_pn,
                    packet_number_len: 4,
                    payload,
                };
                self.spaces[level as usize].next_pn += 1;
                let keys = self.spaces[level as usize]
                    .keys
                    .as_ref()
                    .ok_or_else(|| QuicError::Protocol("missing send keys".to_string()))?;
                protect_short(&packet, &keys.local)?
            }
        };
        self.outgoing.push(packet.to_vec());
        Ok(())
    }

    fn append_stream_frames(&mut self, payload: &mut BytesMut) -> Result<(), QuicError> {
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
                        send.sent += window;
                        self.send_data += window;
                        frame = Some(Frame::Stream {
                            stream_id: id,
                            offset: start as u64,
                            fin,
                            data,
                        });
                    }
                }
            }
            if let Some(frame) = frame {
                frame
                    .encode(payload)
                    .map_err(|error| QuicError::Protocol(error.to_string()))?;
            }
        }
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

    fn record(&mut self, level: Level, pn: u64) {
        let space = &mut self.spaces[level as usize];
        space.received.insert(pn);
        space.ack_pending = true;
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
