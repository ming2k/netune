// SPDX-License-Identifier: MIT

//! WebTransport session runtime over the owned H3/QUIC stack.

use std::collections::VecDeque;

use bytes::Bytes;
use netune_http3::{
    Capsule, ExtendedConnectProtocol, H3Client, H3ExtensionStream, H3ResponseStream,
    H3ServerConnection, H3ServerStream, H3SettingsProfile,
};
use netune_quic::owned::{Connection as QuicConnection, RecvStream, SendStream};

use crate::{
    ControlCapsule, SETTINGS_WT_ENABLED, SessionId, WT_STREAM_SIGNAL, WT_UNI_STREAM_TYPE,
    WebTransportError, WebTransportSettings, encode_bidi_header, encode_uni_header,
};

/// A reliable bidirectional WebTransport stream (header already consumed).
pub struct WebTransportBidi {
    pub send: SendStream,
    pub recv: RecvStream,
}

/// A WebTransport client endpoint over one H3 connection.
pub struct WebTransportClient {
    h3: H3Client,
    settings: WebTransportSettings,
    events: Option<tokio::sync::mpsc::UnboundedReceiver<H3ExtensionStream>>,
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
        let events = h3.enable_stream_extension(vec![WT_UNI_STREAM_TYPE], WT_STREAM_SIGNAL);
        Ok(Self {
            h3,
            settings,
            events: Some(events),
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
        let events = self.events.take().ok_or_else(|| {
            WebTransportError::Settings(
                "one WebTransport session per client connection in draft-17 profile".to_string(),
            )
        })?;
        Ok(WebTransportSession {
            id,
            transport: SessionTransport::Client(Box::new(response)),
            events,
            pending: VecDeque::new(),
            settings: self.settings,
        })
    }
}

/// A WebTransport server endpoint over one H3 connection.
pub struct WebTransportServer {
    h3: H3ServerConnection,
    settings: WebTransportSettings,
    events: Option<tokio::sync::mpsc::UnboundedReceiver<H3ExtensionStream>>,
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
        let h3 = H3ServerConnection::new(connection, &h3_profile(settings))
            .await
            .map_err(http3_error)?;
        h3.wait_settings().await;
        if h3.peer_setting(SETTINGS_WT_ENABLED).unwrap_or(0) != 1 {
            return Err(WebTransportError::Settings(
                "peer did not enable WebTransport over HTTP/3".to_string(),
            ));
        }
        let events = h3.enable_stream_extension(vec![WT_UNI_STREAM_TYPE], WT_STREAM_SIGNAL);
        Ok(Self {
            h3,
            settings,
            events: Some(events),
        })
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
            let events = self.events.take().ok_or_else(|| {
                WebTransportError::Settings(
                    "one WebTransport session per server connection in draft-17 profile"
                        .to_string(),
                )
            })?;
            return Ok(Some(WebTransportSession {
                id,
                transport: SessionTransport::Server(Box::new(stream)),
                events,
                pending: VecDeque::new(),
                settings: self.settings,
            }));
        }
    }
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
}

impl WebTransportSession {
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn settings(&self) -> WebTransportSettings {
        self.settings
    }

    pub fn quic(&self) -> &QuicConnection {
        match &self.transport {
            SessionTransport::Client(stream) => stream.quic_connection(),
            SessionTransport::Server(stream) => stream.quic_connection(),
        }
    }

    pub async fn open_bidi(&self) -> Result<WebTransportBidi, WebTransportError> {
        let (mut send, recv) = self.quic().open_bi().await.map_err(quic_error)?;
        let mut header = bytes::BytesMut::new();
        encode_bidi_header(self.id, &mut header)?;
        send.write_all(&header).await.map_err(quic_error)?;
        Ok(WebTransportBidi { send, recv })
    }

    pub async fn open_uni(&self) -> Result<SendStream, WebTransportError> {
        let mut send = self.quic().open_uni().await.map_err(quic_error)?;
        let mut header = bytes::BytesMut::new();
        encode_uni_header(self.id, &mut header)?;
        send.write_all(&header).await.map_err(quic_error)?;
        Ok(send)
    }

    pub async fn accept_bidi(&mut self) -> Result<WebTransportBidi, WebTransportError> {
        loop {
            match self.next_event().await? {
                H3ExtensionStream::Bidi {
                    session_id,
                    send,
                    recv,
                } if session_id == self.id.get() => {
                    return Ok(WebTransportBidi { send, recv });
                }
                event => self.pending.push_back(event),
            }
        }
    }

    pub async fn accept_uni(&mut self) -> Result<RecvStream, WebTransportError> {
        loop {
            match self.next_event().await? {
                H3ExtensionStream::Uni {
                    stream_type,
                    session_id,
                    recv,
                } if stream_type == WT_UNI_STREAM_TYPE && session_id == self.id.get() => {
                    return Ok(recv);
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
        ControlCapsule::from_capsule(&capsule)
    }

    pub async fn close(&mut self, code: u32, message: &str) -> Result<(), WebTransportError> {
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
