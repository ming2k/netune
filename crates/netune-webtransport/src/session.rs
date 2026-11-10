// SPDX-License-Identifier: MIT

//! WebTransport session runtime over the owned H3/QUIC stack.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use netune_http3::{
    Capsule, ExtendedConnectProtocol, H3Client, H3ExtensionStream, H3ResponseStream,
    H3ServerConnection, H3ServerStream, H3SettingsProfile,
};
use netune_quic::owned::{Connection as QuicConnection, RecvStream, SendStream};

use crate::{
    ControlCapsule, SETTINGS_WT_ENABLED, SETTINGS_WT_INITIAL_MAX_DATA,
    SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, SETTINGS_WT_INITIAL_MAX_STREAMS_UNI, SessionId,
    WT_STREAM_SIGNAL, WT_UNI_STREAM_TYPE, WebTransportError, WebTransportSettings,
    encode_bidi_header, encode_uni_header,
};

/// A reliable bidirectional WebTransport stream (header already consumed).
pub struct WebTransportBidi {
    pub send: WebTransportSendStream,
    pub recv: WebTransportRecvStream,
}

#[derive(Debug)]
struct FlowState {
    send_max_data: u64,
    sent_data: u64,
    send_max_uni: u64,
    send_max_bidi: u64,
    opened_uni: u64,
    opened_bidi: u64,
    recv_max_data: u64,
    recv_data: u64,
    recv_max_uni: u64,
    recv_max_bidi: u64,
    accepted_uni: u64,
    accepted_bidi: u64,
    closed: bool,
}

/// A send half of a reliable WebTransport stream.
pub struct WebTransportSendStream {
    inner: SendStream,
    flow: Arc<Mutex<FlowState>>,
    /// Bytes of the WT stream header already written before the application
    /// payload. Reliable reset sizes include this prefix.
    header_len: u64,
    reset: bool,
}

impl WebTransportSendStream {
    pub fn id(&self) -> u64 {
        self.inner.id()
    }
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), WebTransportError> {
        if self.reset {
            return Err(WebTransportError::SessionClosed(
                "stream was reset".to_string(),
            ));
        }
        {
            let mut flow = self.flow.lock().unwrap_or_else(|e| e.into_inner());
            if flow.closed {
                return Err(WebTransportError::SessionClosed("session closed".into()));
            }
            if flow.sent_data + data.len() as u64 > flow.send_max_data {
                return Err(WebTransportError::FlowControl(
                    "WT_MAX_DATA exceeded".into(),
                ));
            }
            flow.sent_data += data.len() as u64;
        }
        self.inner.write_all(data).await.map_err(quic_error)
    }
    pub async fn finish(&mut self) -> Result<(), WebTransportError> {
        if self.reset {
            return Err(WebTransportError::SessionClosed(
                "stream was reset".to_string(),
            ));
        }
        self.inner.finish().await.map_err(quic_error)
    }
    pub fn reset(&mut self, code: u64) {
        self.reset = true;
        self.inner.reset(code);
    }

    /// Reset the WT stream after reliably delivering `payload_reliable_size`
    /// application bytes. The WT stream header is included automatically.
    pub fn reset_reliable(
        &mut self,
        code: u64,
        payload_reliable_size: u64,
    ) -> Result<(), WebTransportError> {
        let result = self
            .inner
            .reset_at(code, self.header_len.saturating_add(payload_reliable_size))
            .map_err(quic_error);
        if result.is_ok() {
            self.reset = true;
        }
        result
    }
}

/// A receive half of a reliable WebTransport stream.
pub struct WebTransportRecvStream {
    inner: RecvStream,
    flow: Arc<Mutex<FlowState>>,
}

impl WebTransportRecvStream {
    pub fn id(&self) -> u64 {
        self.inner.id()
    }
    pub async fn read(&mut self, max: usize) -> Result<Option<Bytes>, WebTransportError> {
        let data = self.inner.read(max).await.map_err(quic_error)?;
        if let Some(data) = &data {
            let mut flow = self.flow.lock().unwrap_or_else(|e| e.into_inner());
            if flow.recv_data + data.len() as u64 > flow.recv_max_data {
                return Err(WebTransportError::FlowControl(
                    "WT_MAX_DATA exceeded".into(),
                ));
            }
            flow.recv_data += data.len() as u64;
        }
        Ok(data)
    }
    pub fn stop(&mut self, code: u64) {
        self.inner.stop(code);
    }
}

/// A WebTransport client endpoint over one H3 connection.
type Routes = Arc<Mutex<HashMap<u64, tokio::sync::mpsc::UnboundedSender<H3ExtensionStream>>>>;
type Pending = Arc<Mutex<HashMap<u64, VecDeque<H3ExtensionStream>>>>;

pub struct WebTransportClient {
    h3: H3Client,
    settings: WebTransportSettings,
    peer: WebTransportSettings,
    routes: Routes,
    pending: Pending,
    router: tokio::task::JoinHandle<()>,
}

impl WebTransportClient {
    pub async fn connect(
        connector: &netune_quic::QuicConnector,
        target: std::net::SocketAddr,
        server_name: &str,
        settings: WebTransportSettings,
    ) -> Result<Self, WebTransportError> {
        if !settings.enabled {
            return Err(WebTransportError::Settings(
                "WebTransport client must enable WT".to_string(),
            ));
        }
        let h3 = H3Client::connect_with_settings(
            connector,
            target,
            server_name,
            None,
            h3_profile(settings),
        )
        .await
        .map_err(http3_error)?;
        h3.wait_settings().await;
        if !h3
            .quic_connection()
            .is_some_and(netune_quic::owned::Connection::peer_reset_stream_at)
        {
            return Err(WebTransportError::Settings(
                "peer did not advertise reset_stream_at".to_string(),
            ));
        }
        let enabled = h3.peer_setting(SETTINGS_WT_ENABLED).unwrap_or(0);
        if enabled != 1 {
            return Err(WebTransportError::Settings(
                "peer did not enable WebTransport over HTTP/3".to_string(),
            ));
        }
        if h3.peer_setting(0x33).unwrap_or(0) != 1 || h3.peer_setting(0x08).unwrap_or(0) != 1 {
            return Err(WebTransportError::Settings(
                "peer lacks H3 datagram or extended CONNECT support".to_string(),
            ));
        }
        let peer = peer_settings(&h3)?;
        let events = h3.enable_stream_extension(vec![WT_UNI_STREAM_TYPE], WT_STREAM_SIGNAL);
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let router = spawn_router(events, routes.clone(), pending.clone());
        Ok(Self {
            h3,
            settings,
            peer,
            routes,
            pending,
            router,
        })
    }

    pub async fn connect_session(
        &mut self,
        uri: &str,
    ) -> Result<WebTransportSession, WebTransportError> {
        let response = self
            .h3
            .connect_extended("webtransport-h3", uri)
            .await
            .map_err(http3_error)?;
        let id = SessionId::new(response.id())?;
        let events = self.register_session(id)?;
        Ok(WebTransportSession {
            id,
            transport: SessionTransport::Client(Box::new(response)),
            events,
            pending: VecDeque::new(),
            settings: self.settings,
            peer: self.peer,
            flow: initial_flow(self.settings, self.peer),
        })
    }

    fn register_session(
        &self,
        id: SessionId,
    ) -> Result<tokio::sync::mpsc::UnboundedReceiver<H3ExtensionStream>, WebTransportError> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.get(), tx.clone());
        if let Some(mut pending) = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id.get())
        {
            while let Some(event) = pending.pop_front() {
                let _ = tx.send(event);
            }
        }
        Ok(rx)
    }
}

impl Drop for WebTransportClient {
    fn drop(&mut self) {
        self.router.abort();
    }
}

/// A WebTransport server endpoint over one H3 connection.
pub struct WebTransportServer {
    h3: H3ServerConnection,
    settings: WebTransportSettings,
    peer: WebTransportSettings,
    routes: Routes,
    pending: Pending,
    router: tokio::task::JoinHandle<()>,
}

impl WebTransportServer {
    pub async fn new(
        connection: QuicConnection,
        settings: WebTransportSettings,
    ) -> Result<Self, WebTransportError> {
        if !settings.enabled {
            return Err(WebTransportError::Settings(
                "WebTransport server must enable WT".to_string(),
            ));
        }
        let peer_reset_stream_at = connection.peer_reset_stream_at();
        let h3 = H3ServerConnection::new(connection, &h3_profile(settings))
            .await
            .map_err(http3_error)?;
        h3.wait_settings().await;
        if !peer_reset_stream_at {
            return Err(WebTransportError::Settings(
                "peer did not advertise reset_stream_at".to_string(),
            ));
        }
        if h3.peer_setting(SETTINGS_WT_ENABLED).unwrap_or(0) != 1 {
            return Err(WebTransportError::Settings(
                "peer did not enable WebTransport over HTTP/3".to_string(),
            ));
        }
        let peer = peer_settings(&h3)?;
        let events = h3.enable_stream_extension(vec![WT_UNI_STREAM_TYPE], WT_STREAM_SIGNAL);
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let router = spawn_router(events, routes.clone(), pending.clone());
        Ok(Self {
            h3,
            settings,
            peer,
            routes,
            pending,
            router,
        })
    }

    /// Send an H3 GOAWAY. Existing sessions may finish; new sessions are
    /// refused by the client's H3 stack.
    pub async fn shutdown(&mut self) -> Result<(), WebTransportError> {
        self.h3.shutdown().await.map_err(http3_error)
    }

    pub async fn accept(&mut self) -> Result<Option<WebTransportSession>, WebTransportError> {
        loop {
            let Some(request) = self.h3.accept().await.map_err(http3_error)? else {
                return Ok(None);
            };
            let (request, mut stream) = request.into_parts();
            let protocol = request
                .extensions()
                .get::<ExtendedConnectProtocol>()
                .map(|p| p.0.as_str());
            if protocol != Some("webtransport-h3") {
                let response = http::Response::builder()
                    .status(405)
                    .body(())
                    .map_err(|error| WebTransportError::Http(error.to_string()))?;
                let _ = stream.send_response(response).await;
                continue;
            }
            let response = http::Response::builder()
                .status(200)
                .body(())
                .map_err(|error| WebTransportError::Http(error.to_string()))?;
            stream.send_response(response).await.map_err(http3_error)?;
            let id = SessionId::new(stream.id())?;
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            self.routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id.get(), tx.clone());
            if let Some(mut pending) = self
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id.get())
            {
                while let Some(event) = pending.pop_front() {
                    let _ = tx.send(event);
                }
            }
            return Ok(Some(WebTransportSession {
                id,
                transport: SessionTransport::Server(Box::new(stream)),
                events: rx,
                pending: VecDeque::new(),
                settings: self.settings,
                peer: self.peer,
                flow: initial_flow(self.settings, self.peer),
            }));
        }
    }
}

impl Drop for WebTransportServer {
    fn drop(&mut self) {
        self.router.abort();
    }
}

fn spawn_router(
    mut events: tokio::sync::mpsc::UnboundedReceiver<H3ExtensionStream>,
    routes: Routes,
    pending: Pending,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            let session_id = match &event {
                H3ExtensionStream::Uni { session_id, .. }
                | H3ExtensionStream::Bidi { session_id, .. } => *session_id,
            };
            let sender = routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&session_id)
                .cloned();
            if let Some(sender) = sender {
                let _ = sender.send(event);
            } else {
                let mut pending = pending.lock().unwrap_or_else(|e| e.into_inner());
                let queue = pending.entry(session_id).or_default();
                if queue.len() < 32 {
                    queue.push_back(event);
                }
            }
        }
    })
}

enum SessionTransport {
    Client(Box<H3ResponseStream>),
    Server(Box<H3ServerStream>),
}

/// One established WebTransport session.
pub struct WebTransportSession {
    id: SessionId,
    transport: SessionTransport,
    events: tokio::sync::mpsc::UnboundedReceiver<H3ExtensionStream>,
    pending: VecDeque<H3ExtensionStream>,
    settings: WebTransportSettings,
    peer: WebTransportSettings,
    flow: Arc<Mutex<FlowState>>,
}

impl WebTransportSession {
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn settings(&self) -> WebTransportSettings {
        self.settings
    }

    pub fn peer_settings(&self) -> WebTransportSettings {
        self.peer
    }

    pub fn quic(&self) -> &QuicConnection {
        match &self.transport {
            SessionTransport::Client(stream) => stream.quic_connection(),
            SessionTransport::Server(stream) => stream.quic_connection(),
        }
    }

    pub async fn open_bidi(&self) -> Result<WebTransportBidi, WebTransportError> {
        {
            let mut flow = self.flow.lock().unwrap_or_else(|e| e.into_inner());
            if flow.closed {
                return Err(WebTransportError::SessionClosed("session closed".into()));
            }
            if flow.opened_bidi >= flow.send_max_bidi {
                return Err(WebTransportError::FlowControl(
                    "WT_MAX_STREAMS(bidi) exceeded".into(),
                ));
            }
            flow.opened_bidi += 1;
        }
        let (mut send, recv) = self.quic().open_bi().await.map_err(quic_error)?;
        let mut header = bytes::BytesMut::new();
        encode_bidi_header(self.id, &mut header)?;
        send.write_all(&header).await.map_err(quic_error)?;
        Ok(WebTransportBidi {
            send: WebTransportSendStream {
                inner: send,
                flow: self.flow.clone(),
                header_len: header.len() as u64,
                reset: false,
            },
            recv: WebTransportRecvStream {
                inner: recv,
                flow: self.flow.clone(),
            },
        })
    }

    pub async fn open_uni(&self) -> Result<WebTransportSendStream, WebTransportError> {
        {
            let mut flow = self.flow.lock().unwrap_or_else(|e| e.into_inner());
            if flow.closed {
                return Err(WebTransportError::SessionClosed("session closed".into()));
            }
            if flow.opened_uni >= flow.send_max_uni {
                return Err(WebTransportError::FlowControl(
                    "WT_MAX_STREAMS(uni) exceeded".into(),
                ));
            }
            flow.opened_uni += 1;
        }
        let mut send = self.quic().open_uni().await.map_err(quic_error)?;
        let mut header = bytes::BytesMut::new();
        encode_uni_header(self.id, &mut header)?;
        send.write_all(&header).await.map_err(quic_error)?;
        Ok(WebTransportSendStream {
            inner: send,
            flow: self.flow.clone(),
            header_len: header.len() as u64,
            reset: false,
        })
    }

    pub async fn accept_bidi(&mut self) -> Result<WebTransportBidi, WebTransportError> {
        loop {
            match self.next_event().await? {
                H3ExtensionStream::Bidi {
                    session_id,
                    send,
                    recv,
                } if session_id == self.id.get() => {
                    {
                        let mut flow = self.flow.lock().unwrap_or_else(|e| e.into_inner());
                        if flow.accepted_bidi >= flow.recv_max_bidi {
                            return Err(WebTransportError::FlowControl(
                                "incoming WT_MAX_STREAMS(bidi) exceeded".into(),
                            ));
                        }
                        flow.accepted_bidi += 1;
                    }
                    return Ok(WebTransportBidi {
                        send: WebTransportSendStream {
                            inner: send,
                            flow: self.flow.clone(),
                            header_len: 0,
                            reset: false,
                        },
                        recv: WebTransportRecvStream {
                            inner: recv,
                            flow: self.flow.clone(),
                        },
                    });
                }
                event => self.pending.push_back(event),
            }
        }
    }

    pub async fn accept_uni(&mut self) -> Result<WebTransportRecvStream, WebTransportError> {
        loop {
            match self.next_event().await? {
                H3ExtensionStream::Uni {
                    stream_type,
                    session_id,
                    recv,
                } if stream_type == WT_UNI_STREAM_TYPE && session_id == self.id.get() => {
                    {
                        let mut flow = self.flow.lock().unwrap_or_else(|e| e.into_inner());
                        if flow.accepted_uni >= flow.recv_max_uni {
                            return Err(WebTransportError::FlowControl(
                                "incoming WT_MAX_STREAMS(uni) exceeded".into(),
                            ));
                        }
                        flow.accepted_uni += 1;
                    }
                    return Ok(WebTransportRecvStream {
                        inner: recv,
                        flow: self.flow.clone(),
                    });
                }
                event => self.pending.push_back(event),
            }
        }
    }

    async fn next_event(&mut self) -> Result<H3ExtensionStream, WebTransportError> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(event);
        }
        self.events
            .recv()
            .await
            .ok_or_else(|| WebTransportError::SessionClosed("stream router stopped".to_string()))
    }

    pub async fn send_datagram(&mut self, data: &[u8]) -> Result<(), WebTransportError> {
        match &mut self.transport {
            SessionTransport::Client(stream) => {
                stream.send_datagram(data).await.map_err(http3_error)
            }
            SessionTransport::Server(stream) => {
                stream.send_datagram(data).await.map_err(http3_error)
            }
        }
    }

    pub async fn next_datagram(&mut self) -> Result<Bytes, WebTransportError> {
        match &mut self.transport {
            SessionTransport::Client(stream) => stream.next_datagram().await.ok_or_else(|| {
                WebTransportError::SessionClosed("datagram router stopped".to_string())
            }),
            SessionTransport::Server(stream) => stream.next_datagram().await.ok_or_else(|| {
                WebTransportError::SessionClosed("datagram router stopped".to_string())
            }),
        }
    }

    pub async fn send_control(
        &mut self,
        capsule: &ControlCapsule,
    ) -> Result<(), WebTransportError> {
        let capsule = capsule.to_capsule()?;
        self.send_capsule(&capsule).await
    }

    pub async fn send_capsule(&mut self, capsule: &Capsule) -> Result<(), WebTransportError> {
        match &mut self.transport {
            SessionTransport::Client(stream) => {
                stream.send_capsule(capsule).await.map_err(http3_error)
            }
            SessionTransport::Server(stream) => {
                stream.send_capsule(capsule).await.map_err(http3_error)
            }
        }
    }

    pub async fn next_control(&mut self) -> Result<Option<ControlCapsule>, WebTransportError> {
        let capsule = match &mut self.transport {
            SessionTransport::Client(stream) => stream.next_capsule().await.map_err(http3_error)?,
            SessionTransport::Server(stream) => stream.next_capsule().await.map_err(http3_error)?,
        };
        let Some(capsule) = capsule else {
            return Ok(None);
        };
        let parsed = ControlCapsule::from_capsule(&capsule)?;
        if let Some(control) = &parsed {
            let mut flow = self.flow.lock().unwrap_or_else(|e| e.into_inner());
            match control {
                ControlCapsule::MaxData(maximum) => {
                    if *maximum <= flow.send_max_data {
                        return Err(WebTransportError::FlowControl(
                            "WT_MAX_DATA did not increase".into(),
                        ));
                    }
                    flow.send_max_data = *maximum;
                }
                ControlCapsule::MaxStreams {
                    bidi: true,
                    maximum,
                } => {
                    if *maximum <= flow.send_max_bidi {
                        return Err(WebTransportError::FlowControl(
                            "WT_MAX_STREAMS(bidi) did not increase".into(),
                        ));
                    }
                    flow.send_max_bidi = *maximum;
                }
                ControlCapsule::MaxStreams {
                    bidi: false,
                    maximum,
                } => {
                    if *maximum <= flow.send_max_uni {
                        return Err(WebTransportError::FlowControl(
                            "WT_MAX_STREAMS(uni) did not increase".into(),
                        ));
                    }
                    flow.send_max_uni = *maximum;
                }
                ControlCapsule::Close { .. } => flow.closed = true,
                _ => {}
            }
        }
        Ok(parsed)
    }

    pub async fn close(&mut self, code: u32, message: &str) -> Result<(), WebTransportError> {
        self.flow.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        self.send_control(&ControlCapsule::Close {
            code,
            message: message.to_string(),
        })
        .await?;
        match &mut self.transport {
            SessionTransport::Client(stream) => stream.finish().await.map_err(http3_error),
            SessionTransport::Server(stream) => stream.finish().await.map_err(http3_error),
        }
    }

    pub async fn drain(&mut self) -> Result<(), WebTransportError> {
        self.send_control(&ControlCapsule::Drain).await
    }
}

trait PeerSettingsSource {
    fn peer_setting(&self, id: u64) -> Option<u64>;
}

impl PeerSettingsSource for H3Client {
    fn peer_setting(&self, id: u64) -> Option<u64> {
        H3Client::peer_setting(self, id)
    }
}

impl PeerSettingsSource for H3ServerConnection {
    fn peer_setting(&self, id: u64) -> Option<u64> {
        H3ServerConnection::peer_setting(self, id)
    }
}

fn peer_settings<T: PeerSettingsSource>(h3: &T) -> Result<WebTransportSettings, WebTransportError> {
    let mut extra = Vec::new();
    for id in [
        SETTINGS_WT_ENABLED,
        SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
        SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI,
        SETTINGS_WT_INITIAL_MAX_DATA,
    ] {
        if let Some(value) = h3.peer_setting(id) {
            extra.push((id, value));
        }
    }
    WebTransportSettings::from_extra(&extra)
        .map_err(|error| WebTransportError::Settings(error.to_string()))
}

fn initial_flow(local: WebTransportSettings, peer: WebTransportSettings) -> Arc<Mutex<FlowState>> {
    Arc::new(Mutex::new(FlowState {
        send_max_data: peer.initial_max_data,
        sent_data: 0,
        send_max_uni: peer.initial_max_streams_uni,
        send_max_bidi: peer.initial_max_streams_bidi,
        opened_uni: 0,
        opened_bidi: 0,
        recv_max_data: local.initial_max_data,
        recv_data: 0,
        recv_max_uni: local.initial_max_streams_uni,
        recv_max_bidi: local.initial_max_streams_bidi,
        accepted_uni: 0,
        accepted_bidi: 0,
        closed: false,
    }))
}

fn h3_profile(settings: WebTransportSettings) -> H3SettingsProfile {
    let mut profile = H3SettingsProfile::default()
        .with_extended_connect()
        .with_datagrams();
    profile.extra_settings = settings.extra_settings();
    profile
}

fn http3_error(error: netune_http3::H3Error) -> WebTransportError {
    WebTransportError::Http3(error.to_string())
}

fn quic_error(error: netune_quic::QuicError) -> WebTransportError {
    WebTransportError::Quic(error.to_string())
}
