// SPDX-License-Identifier: MIT

//! Async owned QUIC endpoint and connection handles (ADR-0028).
//!
//! UDP I/O is the only place in the owned engine that owns a socket. Each
//! connection runs a driver task over a sans-IO `Core`; public handles are
//! cheap clones that talk to the driver through the core mutex and a notify.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use bytes::Bytes;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, broadcast, mpsc, watch};

use crate::crypto::TlsSession;
use crate::error::QuicError;
use crate::owned::congestion::CongestionControllerFactory;
use crate::socket::{QuicUdpSocket, recv_from as udp_recv_from, send_to as udp_send_to};
use crate::wire::transport_parameters::TransportParameters;

use super::core::{Core, ReadResult, TIMER_INTERVAL};

type IncomingDatagram = (Vec<u8>, SocketAddr);

/// A client configuration for the owned endpoint.
#[derive(Clone)]
pub struct ClientConfigOwned {
    pub tls: Arc<ClientConfig>,
    pub transport: TransportParameters,
    /// Preferred QUIC version first; later entries are Version Negotiation fallbacks.
    pub versions: Vec<u32>,
    pub congestion: crate::profile::CongestionAlgorithm,
    /// Overrides the profile's built-in controller when present.
    pub congestion_factory: Option<Arc<dyn CongestionControllerFactory>>,
    /// Enable 0-RTT when a resumed TLS session offers early keys.
    pub enable_early_data: bool,
    /// Send a PING after this much receive inactivity.
    pub keep_alive: Option<std::time::Duration>,
    /// QUIC transport parameters remembered from prior authenticated sessions.
    pub session_cache: Option<Arc<super::session::SessionCache>>,
}

/// A server configuration for the owned endpoint.
#[derive(Clone)]
pub struct ServerConfigOwned {
    pub tls: Arc<ServerConfig>,
    pub transport: TransportParameters,
    /// Require a Retry token before allocating connection state.
    pub retry: bool,
    pub congestion: crate::profile::CongestionAlgorithm,
    /// Accept 0-RTT tickets using a stateful, single-use resumption cache.
    pub enable_early_data: bool,
}

fn prepare_server_config(mut config: ServerConfigOwned) -> ServerConfigOwned {
    if config.enable_early_data {
        let mut tls = (*config.tls).clone();
        tls.max_early_data_size = u32::MAX;
        tls.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);
        config.tls = Arc::new(tls);
    }
    config
}

/// A bound owned QUIC endpoint.
///
/// The endpoint owns the UDP demultiplexer: accepted connections need it alive
/// to keep receiving datagrams. Dropping the endpoint keeps already-accepted
/// connections alive and stops the demultiplexer when the last one ends;
/// [`Endpoint::close`] closes them eagerly and wakes pending waiters.
pub struct Endpoint {
    inner: Arc<EndpointInner>,
    driver: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

struct EndpointInner {
    udp: Arc<dyn QuicUdpSocket>,
    local: SocketAddr,
    routes: StdMutex<HashMap<Vec<u8>, mpsc::Sender<IncomingDatagram>>>,
    accept_tx: mpsc::Sender<Connection>,
    accept_rx: Mutex<mpsc::Receiver<Connection>>,
    server: Option<ServerConfigOwned>,
    reset_key: [u8; 32],
    retry_key: [u8; 32],
    cid_len: usize,
    closed: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    driver_stop: Arc<Notify>,
    close_tx: broadcast::Sender<()>,
    _close_guard: broadcast::Receiver<()>,
}

impl Endpoint {
    /// Bind a client endpoint on an ephemeral local port.
    pub async fn client() -> Result<Self, QuicError> {
        Self::bind("0.0.0.0:0", None).await
    }

    /// Bind a server endpoint.
    pub async fn server(address: &str, config: ServerConfigOwned) -> Result<Self, QuicError> {
        Self::bind(address, Some(prepare_server_config(config))).await
    }

    /// Bind a server endpoint over an abstract socket stack.
    ///
    /// The caller owns binding, socket configuration and ingress admission for
    /// the supplied socket. The endpoint drives exactly one socket for its
    /// lifetime; a caller that needs a new socket per connection builds a new
    /// endpoint.
    pub async fn server_with_socket(
        udp: Arc<dyn QuicUdpSocket>,
        config: ServerConfigOwned,
    ) -> Result<Self, QuicError> {
        Self::from_socket(udp, Some(prepare_server_config(config))).await
    }

    /// Bind a client endpoint over an already-configured tokio UDP socket.
    pub async fn client_with_udp(udp: UdpSocket) -> Result<Self, QuicError> {
        Self::client_with_socket(Arc::new(udp)).await
    }

    /// Bind a client endpoint over an abstract socket stack.
    ///
    /// The caller owns socket configuration and egress confinement: this is the
    /// seam for obfuscation and port-hopping wrappers, and it must be used only
    /// after the same checks [`crate::QuicConnector`] performs before it
    /// creates a socket.
    pub async fn client_with_socket(udp: Arc<dyn QuicUdpSocket>) -> Result<Self, QuicError> {
        Self::from_socket(udp, None).await
    }

    async fn bind(address: &str, server: Option<ServerConfigOwned>) -> Result<Self, QuicError> {
        let udp = UdpSocket::bind(address).await.map_err(QuicError::Socket)?;
        Self::from_socket(Arc::new(udp), server).await
    }

    async fn from_socket(
        udp: Arc<dyn QuicUdpSocket>,
        server: Option<ServerConfigOwned>,
    ) -> Result<Self, QuicError> {
        let local = udp.local_addr().map_err(QuicError::Socket)?;
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let reset_key = random_bytes::<32>()?;
        let retry_key = random_bytes::<32>()?;
        let (close_tx, close_guard) = broadcast::channel(1);
        let inner = Arc::new(EndpointInner {
            udp,
            local,
            routes: StdMutex::new(HashMap::new()),
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
            server,
            reset_key,
            retry_key,
            cid_len: 8,
            closed: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(AtomicUsize::new(0)),
            driver_stop: Arc::new(Notify::new()),
            close_tx,
            _close_guard: close_guard,
        });
        let driver = tokio::spawn(endpoint_driver(inner.clone()));
        Ok(Self {
            inner,
            driver: StdMutex::new(Some(driver)),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local
    }

    /// Connect to a server. Resolves once the QUIC handshake is established.
    pub async fn connect(
        &self,
        target: SocketAddr,
        server_name: &str,
        config: ClientConfigOwned,
    ) -> Result<Connection, QuicError> {
        let connection = self.connect_early(target, server_name, config).await?;
        connection.wait_established().await?;
        Ok(connection)
    }

    /// Start a connection without waiting for the handshake.
    ///
    /// When a resumed session and cached transport parameters are available,
    /// the returned connection can open streams and emit 0-RTT data immediately.
    pub async fn connect_early(
        &self,
        target: SocketAddr,
        server_name: &str,
        config: ClientConfigOwned,
    ) -> Result<Connection, QuicError> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(QuicError::Closed("endpoint closed".to_string()));
        }
        let local_cid = random_cid(8)?;
        let original_dcid = random_cid(8)?;
        let mut local_tp = config.transport;
        local_tp.initial_source_connection_id = Some(local_cid.clone());
        let session_key = server_name.to_string();
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|error| QuicError::Config(error.to_string()))?;
        let versions = if config.versions.is_empty() {
            vec![crate::wire::packet::VERSION_1]
        } else {
            config.versions.clone()
        };
        let version = versions[0];
        let core = Core::client(
            config.tls,
            server_name,
            original_dcid,
            local_cid.clone(),
            local_tp,
            super::core::ClientOptions {
                version,
                supported_versions: versions,
                congestion: config.congestion,
                congestion_factory: config.congestion_factory,
                early_data: config.enable_early_data,
                keep_alive: config.keep_alive,
                session_cache: config.session_cache,
                session_key,
            },
        )?;
        let (connection, outgoing) = spawn_connection(
            self.inner.clone(),
            target,
            core,
            None,
            vec![local_cid.clone()],
        )
        .await?;
        if let Some(sender) = connection.inner.incoming.clone() {
            self.inner
                .routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(local_cid, sender);
        }
        send_outgoing(&self.inner.udp, target, outgoing).await;
        Ok(connection)
    }

    /// Accept the next established server connection.
    pub async fn accept(&self) -> Result<Connection, QuicError> {
        let mut rx = self.inner.accept_rx.lock().await;
        let mut close_rx = self.inner.close_tx.subscribe();
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(QuicError::Closed("endpoint closed".to_string()));
        }
        tokio::select! {
            connection = rx.recv() => {
                connection.ok_or_else(|| QuicError::Closed("endpoint closed".to_string()))
            }
            _ = close_rx.recv() => {
                Err(QuicError::Closed("endpoint closed".to_string()))
            }
        }
    }

    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        let _ = self.inner.close_tx.send(());
        self.inner.driver_stop.notify_one();
        if let Some(driver) = self.driver.lock().unwrap_or_else(|e| e.into_inner()).take() {
            driver.abort();
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        self.inner.driver_stop.notify_one();
        if self.inner.connections.load(Ordering::SeqCst) == 0
            && let Some(driver) = self.driver.lock().unwrap_or_else(|e| e.into_inner()).take()
        {
            driver.abort();
        }
    }
}

async fn endpoint_driver(inner: Arc<EndpointInner>) {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        if inner.closed.load(Ordering::SeqCst) && inner.connections.load(Ordering::SeqCst) == 0 {
            break;
        }
        let received = tokio::select! {
            received = udp_recv_from(&*inner.udp, &mut buffer) => match received {
                Ok(received) => received,
                Err(_) => {
                    inner.closed.store(true, Ordering::SeqCst);
                    let _ = inner.close_tx.send(());
                    break;
                }
            },
            _ = inner.driver_stop.notified() => continue,
        };
        let datagram = buffer[..received.0].to_vec();
        let Some(dcid) = parse_dcid(&datagram, &inner.routes, inner.cid_len) else {
            if inner.server.is_some()
                && datagram.len() >= 21
                && datagram[0] & 0x80 == 0
                && datagram.len() > 1 + inner.cid_len
            {
                send_stateless_reset(&inner, received.1, &datagram[1..1 + inner.cid_len]).await;
            }
            continue;
        };
        let route = inner
            .routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&dcid)
            .cloned();
        if let Some(route) = route {
            let _ = route.send((datagram, received.1)).await;
            continue;
        }
        if inner.server.is_some()
            && datagram.len() >= 1200
            && datagram[0] & 0x80 != 0
            && let Some((version, dcid, scid)) = parse_long_cids(&datagram)
            && !matches!(
                version,
                crate::wire::packet::VERSION_1 | crate::wire::packet::VERSION_2
            )
        {
            let negotiation = crate::wire::packet::VersionNegotiation {
                destination_connection_id: scid,
                source_connection_id: dcid,
                versions: vec![
                    crate::wire::packet::VERSION_1,
                    crate::wire::packet::VERSION_2,
                ],
            };
            if let Ok(packet) = negotiation.encode() {
                let _ = udp_send_to(&*inner.udp, &packet, received.1).await;
            }
            continue;
        }
        if let Some(server) = &inner.server
            && let Some(initial) = parse_initial(&datagram)
        {
            let (version, client_dcid, client_scid, token) = initial;
            let (original_dcid, local_cid) = if server.retry {
                if let Some(validated) = validate_retry_token(&inner.retry_key, received.1, &token)
                {
                    validated
                } else {
                    let Ok(retry_scid) = random_cid(8) else {
                        continue;
                    };
                    let token =
                        issue_retry_token(&inner.retry_key, received.1, &client_dcid, &retry_scid);
                    if let Ok(packet) = crate::crypto::encode_retry(
                        version,
                        client_scid.clone(),
                        retry_scid,
                        token,
                        &client_dcid,
                    ) {
                        let _ = udp_send_to(&*inner.udp, &packet, received.1).await;
                    }
                    continue;
                }
            } else {
                (client_dcid.clone(), client_scid)
            };
            let mut local_tp = server.transport.clone();
            local_tp.initial_source_connection_id = Some(local_cid.clone());
            local_tp.original_destination_connection_id = Some(original_dcid.clone());
            if server.retry {
                local_tp.retry_source_connection_id = Some(local_cid.clone());
            }
            local_tp.stateless_reset_token = Some(reset_token(&inner.reset_key, &local_cid));
            let tls = match TlsSession::server_with_version(
                server.tls.clone(),
                local_tp
                    .encode()
                    .map(|parameters| parameters.to_vec())
                    .unwrap_or_default(),
                version,
            ) {
                Ok(tls) => tls,
                Err(_) => continue,
            };
            let core = match Core::server(
                tls,
                client_dcid.clone(),
                local_cid.clone(),
                local_tp,
                version,
                server.congestion,
            ) {
                Ok(core) => core,
                Err(_) => continue,
            };
            let (connection, outgoing) = match spawn_connection(
                inner.clone(),
                received.1,
                core,
                Some(datagram),
                vec![client_dcid.clone(), local_cid.clone()],
            )
            .await
            {
                Ok(value) => value,
                Err(_) => continue,
            };
            {
                let mut routes = inner.routes.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(sender) = connection.inner.incoming.clone() {
                    routes.insert(client_dcid, sender.clone());
                    routes.insert(local_cid, sender);
                }
            }
            send_outgoing(&inner.udp, received.1, outgoing).await;
            let accept = inner.accept_tx.clone();
            tokio::spawn(async move {
                let mut established = connection.inner.established.subscribe();
                let mut closed = connection.inner.closed.subscribe();
                if !*established.borrow() {
                    tokio::select! {
                        _ = established.changed() => {}
                        _ = closed.changed() => {}
                    }
                }
                if *established.borrow() && closed.borrow().is_none() {
                    let _ = accept.send(connection).await;
                }
            });
        }
    }
}

struct ConnectionInner {
    core: StdMutex<Core>,
    notify: Notify,
    readable: Notify,
    established: watch::Sender<bool>,
    closed: watch::Sender<Option<Arc<QuicError>>>,
    close_rx: broadcast::Receiver<()>,
    endpoint: Arc<EndpointInner>,
    route_keys: Vec<Vec<u8>>,
    incoming: Option<mpsc::Sender<IncomingDatagram>>,
    udp: Arc<dyn QuicUdpSocket>,
    peer: StdMutex<SocketAddr>,
    candidate: StdMutex<Option<SocketAddr>>,
    local: SocketAddr,
    driver: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

fn remove_routes(inner: &ConnectionInner) {
    let mut routes = inner
        .endpoint
        .routes
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for key in &inner.route_keys {
        routes.remove(key);
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        remove_routes(self);
        let remaining = self
            .endpoint
            .connections
            .fetch_sub(1, Ordering::SeqCst)
            .saturating_sub(1);
        if self.endpoint.closed.load(Ordering::SeqCst) && remaining == 0 {
            self.endpoint.driver_stop.notify_one();
        }
    }
}

/// An established or handshaking owned QUIC connection.
#[derive(Clone)]
pub struct Connection {
    inner: Arc<ConnectionInner>,
}

impl Connection {
    pub fn remote_address(&self) -> SocketAddr {
        *self.inner.peer.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn local_address(&self) -> SocketAddr {
        self.inner.local
    }

    pub fn rtt(&self) -> Option<std::time::Duration> {
        self.inner
            .core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rtt()
    }

    /// The peer's certificate chain, when the handshake presented one.
    pub fn peer_certificates(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        self.inner
            .core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peer_certificates()
    }

    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner
            .core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .max_datagram_size()
    }

    pub async fn send_datagram(&self, data: Bytes) -> Result<(), QuicError> {
        {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.send_datagram(data)?;
        }
        self.inner.notify.notify_one();
        Ok(())
    }

    pub async fn recv_datagram(&self) -> Result<Bytes, QuicError> {
        loop {
            let notified = self.inner.readable.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let datagram = {
                let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
                core.recv_datagram()
            };
            if let Some(datagram) = datagram {
                return Ok(datagram);
            }
            notified.await;
        }
    }

    pub fn early_data_available(&self) -> bool {
        self.inner
            .core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .early_data_available()
    }

    pub fn early_data_accepted(&self) -> bool {
        self.inner
            .core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .early_data_accepted()
    }

    /// Wait for the handshake, surfacing a failure instead of waiting forever.
    pub async fn wait_established(&self) -> Result<(), QuicError> {
        let mut established = self.inner.established.subscribe();
        let mut closed = self.inner.closed.subscribe();
        let mut close_rx = self.inner.close_rx.resubscribe();
        loop {
            if *established.borrow() {
                return Ok(());
            }
            if let Some(error) = closed.borrow().as_ref() {
                return Err(clone_error(error));
            }
            tokio::select! {
                changed = established.changed() => {
                    if changed.is_err() {
                        return Err(QuicError::Closed(
                            "connection task ended before the handshake completed".to_string(),
                        ));
                    }
                }
                changed = closed.changed() => {
                    if changed.is_err() {
                        return Err(QuicError::Closed(
                            "connection task ended before the handshake completed".to_string(),
                        ));
                    }
                }
                _ = close_rx.recv() => {
                    return Err(QuicError::Closed("endpoint closed".to_string()));
                }
            }
        }
    }

    pub fn is_established(&self) -> bool {
        self.inner
            .core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_established()
    }

    /// Whether the connection has closed, locally or by peer.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.borrow().is_some()
            || self
                .inner
                .core
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_closed()
    }

    pub async fn closed(&self) {
        let mut closed = self.inner.closed.subscribe();
        let mut close_rx = self.inner.close_rx.resubscribe();
        if closed.borrow().is_some() {
            return;
        }
        tokio::select! {
            _ = closed.changed() => {}
            _ = close_rx.recv() => {}
        }
    }

    /// Initiate a 1-RTT key update (RFC 9001 Section 6).
    pub fn initiate_key_update(&self) -> Result<(), QuicError> {
        {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.initiate_key_update()?;
        }
        self.inner.notify.notify_one();
        Ok(())
    }

    /// Close the connection. The reason is a short diagnostic and is truncated
    /// to keep the CONNECTION_CLOSE frame inside one packet.
    pub fn close(&self, code: u64, reason: &str) {
        {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.close(code, reason);
        }
        self.inner.notify.notify_one();
    }

    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), QuicError> {
        let id = {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.open_bi()?
        };
        self.inner.notify.notify_one();
        Ok((
            SendStream {
                inner: self.inner.clone(),
                id,
            },
            RecvStream {
                inner: self.inner.clone(),
                id,
            },
        ))
    }

    pub async fn open_uni(&self) -> Result<SendStream, QuicError> {
        let id = {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.open_uni()?
        };
        self.inner.notify.notify_one();
        Ok(SendStream {
            inner: self.inner.clone(),
            id,
        })
    }

    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), QuicError> {
        loop {
            let notified = self.inner.readable.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let id = {
                let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
                core.accept_bi()
            };
            if let Some(id) = id {
                return Ok((
                    SendStream {
                        inner: self.inner.clone(),
                        id,
                    },
                    RecvStream {
                        inner: self.inner.clone(),
                        id,
                    },
                ));
            }
            notified.await;
        }
    }

    pub async fn accept_uni(&self) -> Result<RecvStream, QuicError> {
        loop {
            let notified = self.inner.readable.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let id = {
                let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
                core.accept_uni()
            };
            if let Some(id) = id {
                return Ok(RecvStream {
                    inner: self.inner.clone(),
                    id,
                });
            }
            notified.await;
        }
    }
}

/// A send half of an owned QUIC stream.
pub struct SendStream {
    inner: Arc<ConnectionInner>,
    id: u64,
}

impl SendStream {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), QuicError> {
        {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.write(self.id, data)?;
        }
        self.inner.notify.notify_one();
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<(), QuicError> {
        {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.finish(self.id)?;
        }
        self.inner.notify.notify_one();
        Ok(())
    }

    pub fn reset(&mut self, code: u64) {
        {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.reset(self.id, code);
        }
        self.inner.notify.notify_one();
    }
}

/// A receive half of an owned QUIC stream.
pub struct RecvStream {
    inner: Arc<ConnectionInner>,
    id: u64,
}

impl RecvStream {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn read(&mut self, max: usize) -> Result<Option<Bytes>, QuicError> {
        loop {
            let notified = self.inner.readable.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let result = {
                let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
                core.read(self.id, max)?
            };
            match result {
                ReadResult::Data(data) => return Ok(Some(data)),
                ReadResult::Fin => return Ok(None),
                ReadResult::Pending => notified.await,
            }
        }
    }

    pub fn stop(&mut self, code: u64) {
        {
            let mut core = self.inner.core.lock().unwrap_or_else(|e| e.into_inner());
            core.stop_sending(self.id, code);
        }
        self.inner.notify.notify_one();
    }
}

fn clone_error(error: &QuicError) -> QuicError {
    match error {
        QuicError::Dns { host, detail } => QuicError::Dns {
            host: host.clone(),
            detail: detail.clone(),
        },
        QuicError::Socket(error) => {
            QuicError::Socket(std::io::Error::new(error.kind(), error.to_string()))
        }
        QuicError::Connect(message) => QuicError::Connect(message.clone()),
        QuicError::Timeout => QuicError::Timeout,
        QuicError::Stream(message) => QuicError::Stream(message.clone()),
        QuicError::DatagramTooLarge { max, size } => QuicError::DatagramTooLarge {
            max: *max,
            size: *size,
        },
        QuicError::DatagramsNotSupported => QuicError::DatagramsNotSupported,
        QuicError::Tls(message) => QuicError::Tls(message.clone()),
        QuicError::Config(message) => QuicError::Config(message.clone()),
        QuicError::Protocol(message) => QuicError::Protocol(message.clone()),
        QuicError::Closed(message) => QuicError::Closed(message.clone()),
    }
}

async fn spawn_connection(
    endpoint: Arc<EndpointInner>,
    peer: SocketAddr,
    core: Core,
    first: Option<Vec<u8>>,
    route_keys: Vec<Vec<u8>>,
) -> Result<(Connection, Vec<Vec<u8>>), QuicError> {
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<IncomingDatagram>(64);
    let (established_tx, _) = watch::channel(false);
    let (closed_tx, _) = watch::channel(None);
    endpoint.connections.fetch_add(1, Ordering::SeqCst);
    let inner = Arc::new(ConnectionInner {
        core: StdMutex::new(core),
        notify: Notify::new(),
        readable: Notify::new(),
        established: established_tx,
        closed: closed_tx,
        close_rx: endpoint.close_tx.subscribe(),
        endpoint: endpoint.clone(),
        route_keys,
        incoming: Some(incoming_tx.clone()),
        udp: endpoint.udp.clone(),
        peer: StdMutex::new(peer),
        candidate: StdMutex::new(None),
        local: endpoint.local,
        driver: StdMutex::new(None),
    });
    let connection = Connection {
        inner: inner.clone(),
    };
    let outgoing = {
        let mut core = inner.core.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(first) = first {
            core.receive(&first)?;
        }
        core.poll_transmit()?;
        core.take_outgoing()
    };
    let driver_inner = inner.clone();
    let driver = tokio::spawn(async move {
        let mut timer = tokio::time::interval(TIMER_INTERVAL);
        let mut close_rx = driver_inner.close_rx.resubscribe();
        loop {
            let mut outgoing: Vec<Vec<u8>> = Vec::new();
            let mut close_error: Option<QuicError> = None;
            if let Some(error) = close_error {
                remove_routes(&driver_inner);
                let _ = driver_inner.closed.send(Some(Arc::new(error)));
                break;
            }
            tokio::select! {
                Some((datagram, source)) = incoming_rx.recv() => {
                    let current = *driver_inner.peer.lock().unwrap_or_else(|e| e.into_inner());
                    let mut core = driver_inner.core.lock().unwrap_or_else(|e| e.into_inner());
                    if source != current {
                        if core.migration_disabled() {
                            continue;
                        }
                        let known_candidate = *driver_inner
                            .candidate
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if known_candidate != Some(source) {
                            let Ok(challenge) = random_bytes::<8>() else {
                                continue;
                            };
                            core.begin_path_validation(challenge);
                            *driver_inner
                                .candidate
                                .lock()
                                .unwrap_or_else(|e| e.into_inner()) = Some(source);
                        }
                    }
                    if let Err(error) = core.receive(&datagram) {
                        close_error = Some(error);
                    } else {
                        if core.path_validated() {
                            let candidate = *driver_inner
                                .candidate
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if let Some(candidate) = candidate {
                                *driver_inner
                                    .peer
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner()) = candidate;
                                *driver_inner
                                    .candidate
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner()) = None;
                            }
                        }
                        let _ = core.poll_transmit();
                        outgoing = core.take_outgoing();
                        if core.is_closed() {
                            close_error = Some(QuicError::Closed(
                                "connection closed".to_string(),
                            ));
                        }
                        driver_inner.readable.notify_waiters();
                        driver_inner.readable.notify_one();
                    }
                }
                _ = driver_inner.notify.notified() => {
                    let mut core = driver_inner.core.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = core.poll_transmit();
                    outgoing = core.take_outgoing();
                    if core.is_closed() {
                        close_error = Some(QuicError::Closed(
                            "connection closed".to_string(),
                        ));
                    }
                }
                _ = close_rx.recv() => {
                    close_error = Some(QuicError::Closed("endpoint closed".to_string()));
                }
                _ = timer.tick() => {
                    let mut core = driver_inner.core.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = core.handle_timeout();
                    let _ = core.poll_transmit();
                    outgoing = core.take_outgoing();
                    if core.is_closed() {
                        close_error = Some(QuicError::Closed(
                            "connection closed".to_string(),
                        ));
                    }
                }
            }
            let target = *driver_inner
                .candidate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .unwrap_or(&*driver_inner.peer.lock().unwrap_or_else(|e| e.into_inner()));
            for datagram in outgoing {
                if let Err(error) = udp_send_to(&*driver_inner.udp, &datagram, target).await {
                    close_error = Some(QuicError::Socket(error));
                    break;
                }
            }
            let established = driver_inner
                .core
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_established();
            if established && !*driver_inner.established.borrow() {
                let _ = driver_inner.established.send(true);
            }
            if close_error.is_none()
                && driver_inner
                    .core
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_closed()
            {
                close_error = Some(QuicError::Closed("connection closed".to_string()));
            }
            if let Some(error) = close_error {
                remove_routes(&driver_inner);
                let _ = driver_inner.closed.send(Some(Arc::new(error)));
                break;
            }
        }
    });
    *inner.driver.lock().unwrap_or_else(|e| e.into_inner()) = Some(driver);
    Ok((connection, outgoing))
}

async fn send_outgoing(udp: &Arc<dyn QuicUdpSocket>, peer: SocketAddr, outgoing: Vec<Vec<u8>>) {
    for datagram in outgoing {
        let _ = udp_send_to(&**udp, &datagram, peer).await;
    }
}

fn parse_dcid(
    datagram: &[u8],
    routes: &StdMutex<HashMap<Vec<u8>, mpsc::Sender<IncomingDatagram>>>,
    cid_len: usize,
) -> Option<Vec<u8>> {
    if datagram.len() < 5 {
        return None;
    }
    if datagram[0] & 0x80 != 0 {
        let dcid_len = *datagram.get(5)? as usize;
        if datagram.len() < 6 + dcid_len {
            return None;
        }
        return Some(datagram[6..6 + dcid_len].to_vec());
    }
    if datagram.len() <= 1 + cid_len {
        return None;
    }
    let candidate = datagram[1..1 + cid_len].to_vec();
    let routes = routes.lock().unwrap_or_else(|e| e.into_inner());
    routes.contains_key(&candidate).then_some(candidate)
}

fn parse_long_cids(datagram: &[u8]) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    if datagram.len() < 6 || datagram[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
    let mut cursor = &datagram[5..];
    let dcid_len = usize::from(*cursor.first()?);
    if dcid_len > 20 || cursor.len() < 1 + dcid_len + 1 {
        return None;
    }
    let dcid = cursor[1..1 + dcid_len].to_vec();
    cursor = &cursor[1 + dcid_len..];
    let scid_len = usize::from(*cursor.first()?);
    if scid_len > 20 || cursor.len() < 1 + scid_len {
        return None;
    }
    let scid = cursor[1..1 + scid_len].to_vec();
    Some((version, dcid, scid))
}

type InitialHeader = (u32, Vec<u8>, Vec<u8>, Vec<u8>);

fn parse_initial(datagram: &[u8]) -> Option<InitialHeader> {
    if datagram.len() < 6 || datagram[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
    let ty = (datagram[0] & 0x30) >> 4;
    let initial_type = match version {
        crate::wire::packet::VERSION_1 => 0,
        crate::wire::packet::VERSION_2 => 1,
        _ => return None,
    };
    if ty != initial_type {
        return None;
    }
    let mut cursor = &datagram[5..];
    let dcid_len = usize::from(*cursor.first()?);
    if dcid_len > 20 || cursor.len() < 1 + dcid_len + 1 {
        return None;
    }
    let dcid = cursor[1..1 + dcid_len].to_vec();
    cursor = &cursor[1 + dcid_len..];
    let scid_len = usize::from(*cursor.first()?);
    if scid_len > 20 || cursor.len() < 1 + scid_len + 1 {
        return None;
    }
    let scid = cursor[1..1 + scid_len].to_vec();
    cursor = &cursor[1 + scid_len..];
    let token_len = usize::try_from(crate::wire::varint::decode(&mut cursor).ok()?).ok()?;
    if cursor.len() < token_len {
        return None;
    }
    let token = cursor[..token_len].to_vec();
    Some((version, dcid, scid, token))
}

fn ip_octets(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(ip) => ip.octets(),
    }
}

fn issue_retry_token(
    key: &[u8; 32],
    peer: SocketAddr,
    original_dcid: &[u8],
    retry_scid: &[u8],
) -> Vec<u8> {
    use aws_lc_rs::hmac;
    let mut payload = Vec::new();
    payload.push(1u8);
    payload.extend_from_slice(&ip_octets(peer.ip()));
    payload.extend_from_slice(&peer.port().to_be_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    payload.extend_from_slice(&now.to_be_bytes());
    payload.push(original_dcid.len() as u8);
    payload.extend_from_slice(original_dcid);
    payload.push(retry_scid.len() as u8);
    payload.extend_from_slice(retry_scid);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&hmac_key, &payload);
    payload.extend_from_slice(&tag.as_ref()[..16]);
    payload
}

fn validate_retry_token(
    key: &[u8; 32],
    peer: SocketAddr,
    token: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    use aws_lc_rs::hmac;
    if token.len() < 1 + 16 + 2 + 8 + 1 + 1 + 16 || token[0] != 1 {
        return None;
    }
    let payload_len = token.len() - 16;
    let (payload, tag) = token.split_at(payload_len);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let expected = hmac::sign(&hmac_key, payload);
    if aws_lc_rs::constant_time::verify_slices_are_equal(&expected.as_ref()[..16], tag).is_err() {
        return None;
    }
    let mut cursor = &payload[1..];
    let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&cursor[..16]).ok()?);
    cursor = &cursor[16..];
    let port = u16::from_be_bytes([cursor[0], cursor[1]]);
    cursor = &cursor[2..];
    let timestamp = u64::from_be_bytes(<[u8; 8]>::try_from(&cursor[..8]).ok()?);
    cursor = &cursor[8..];
    let expected = std::net::Ipv6Addr::from(ip_octets(peer.ip()));
    if ip != expected || port != peer.port() {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(timestamp) > 60 || timestamp > now.saturating_add(5) {
        return None;
    }
    let odcid_len = usize::from(*cursor.first()?);
    if cursor.len() < 1 + odcid_len + 1 {
        return None;
    }
    let odcid = cursor[1..1 + odcid_len].to_vec();
    cursor = &cursor[1 + odcid_len..];
    let scid_len = usize::from(*cursor.first()?);
    if cursor.len() < 1 + scid_len {
        return None;
    }
    let retry_scid = cursor[1..1 + scid_len].to_vec();
    Some((odcid, retry_scid))
}

async fn send_stateless_reset(
    inner: &EndpointInner,
    peer: SocketAddr,
    destination_connection_id: &[u8],
) {
    let len = 64usize;
    let mut reset = vec![0u8; len];
    if random_bytes_into(&mut reset).is_err() {
        return;
    }
    reset[0] = 0x40 | (reset[0] & 0x3f);
    let token = reset_token(&inner.reset_key, destination_connection_id);
    reset[len - 16..].copy_from_slice(&token);
    let _ = udp_send_to(&*inner.udp, &reset, peer).await;
}

fn reset_token(key: &[u8; 32], connection_id: &[u8]) -> [u8; 16] {
    use aws_lc_rs::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, connection_id);
    let mut token = [0u8; 16];
    token.copy_from_slice(&tag.as_ref()[..16]);
    token
}

fn random_bytes<const N: usize>() -> Result<[u8; N], QuicError> {
    let mut bytes = [0u8; N];
    random_bytes_into(&mut bytes)?;
    Ok(bytes)
}

fn random_bytes_into(bytes: &mut [u8]) -> Result<(), QuicError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .secure_random
        .fill(bytes)
        .map_err(|_| QuicError::Config("secure random is unavailable".to_string()))
}

fn random_cid(len: usize) -> Result<Vec<u8>, QuicError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut cid = vec![0u8; len];
    provider
        .secure_random
        .fill(&mut cid)
        .map_err(|_| QuicError::Config("secure random is unavailable".to_string()))?;
    Ok(cid)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn client_config() -> std::sync::Arc<rustls::ClientConfig> {
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h3".to_vec()];
        std::sync::Arc::new(config)
    }

    #[tokio::test]
    async fn a_closed_connection_removes_its_endpoint_route() {
        let endpoint = Endpoint::client().await.expect("endpoint");
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("sink");
        let connection = endpoint
            .connect_early(
                sink.local_addr().expect("sink address"),
                "localhost",
                ClientConfigOwned {
                    tls: client_config(),
                    transport: TransportParameters {
                        max_idle_timeout: Some(1_000),
                        ..TransportParameters::default()
                    },
                    versions: vec![crate::wire::packet::VERSION_1],
                    congestion: crate::profile::CongestionAlgorithm::NewReno,
                    congestion_factory: None,
                    keep_alive: None,
                    enable_early_data: false,
                    session_cache: None,
                },
            )
            .await
            .expect("connect early");
        assert_eq!(
            endpoint
                .inner
                .routes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            1
        );
        connection.close(0, "done");
        connection.closed().await;
        for _ in 0..50 {
            if endpoint
                .inner
                .routes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the closed connection left its route behind");
    }
}
