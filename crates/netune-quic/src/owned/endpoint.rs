// SPDX-License-Identifier: MIT

//! Async owned QUIC endpoint and connection handles (ADR-0028).
//!
//! UDP I/O is the only place in the owned engine that owns a socket. Each
//! connection runs a driver task over a sans-IO `Core`; public handles are
//! cheap clones that talk to the driver through the core mutex and a notify.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use bytes::Bytes;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, mpsc, watch};

use crate::crypto::TlsSession;
use crate::error::QuicError;
use crate::wire::transport_parameters::TransportParameters;

use super::core::{Core, ReadResult, TIMER_INTERVAL};

/// A client configuration for the owned endpoint.
#[derive(Clone)]
pub struct ClientConfigOwned {
    pub tls: Arc<ClientConfig>,
    pub transport: TransportParameters,
}

/// A server configuration for the owned endpoint.
#[derive(Clone)]
pub struct ServerConfigOwned {
    pub tls: Arc<ServerConfig>,
    pub transport: TransportParameters,
}

/// A bound owned QUIC endpoint.
pub struct Endpoint {
    inner: Arc<EndpointInner>,
    driver: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

struct EndpointInner {
    udp: Arc<UdpSocket>,
    local: SocketAddr,
    routes: StdMutex<HashMap<Vec<u8>, mpsc::Sender<Vec<u8>>>>,
    accept_tx: mpsc::Sender<Connection>,
    accept_rx: Mutex<mpsc::Receiver<Connection>>,
    server: Option<ServerConfigOwned>,
    closed: AtomicBool,
}

impl Endpoint {
    /// Bind a client endpoint on an ephemeral local port.
    pub async fn client() -> Result<Self, QuicError> {
        Self::bind("0.0.0.0:0", None).await
    }

    /// Bind a server endpoint.
    pub async fn server(address: &str, config: ServerConfigOwned) -> Result<Self, QuicError> {
        Self::bind(address, Some(config)).await
    }

    /// Bind a client endpoint over an already-configured tokio UDP socket.
    pub async fn client_with_udp(udp: UdpSocket) -> Result<Self, QuicError> {
        Self::from_udp(udp, None).await
    }

    async fn bind(address: &str, server: Option<ServerConfigOwned>) -> Result<Self, QuicError> {
        let udp = UdpSocket::bind(address).await.map_err(QuicError::Socket)?;
        Self::from_udp(udp, server).await
    }

    async fn from_udp(
        udp: UdpSocket,
        server: Option<ServerConfigOwned>,
    ) -> Result<Self, QuicError> {
        let local = udp.local_addr().map_err(QuicError::Socket)?;
        let udp = Arc::new(udp);
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let inner = Arc::new(EndpointInner {
            udp: udp.clone(),
            local,
            routes: StdMutex::new(HashMap::new()),
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
            server,
            closed: AtomicBool::new(false),
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
        let local_cid = random_cid(8)?;
        let original_dcid = random_cid(8)?;
        let mut local_tp = config.transport;
        local_tp.initial_source_connection_id = Some(local_cid.clone());
        let tls = TlsSession::client(
            config.tls,
            rustls::pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|error| QuicError::Config(error.to_string()))?,
            local_tp
                .encode()
                .map_err(|error| QuicError::Config(error.to_string()))?
                .to_vec(),
        )?;
        let core = Core::client(tls, original_dcid, local_cid.clone(), local_tp)?;
        let (connection, outgoing) =
            spawn_connection(self.inner.clone(), target, core, None).await?;
        if let Some(sender) = connection.inner.incoming.clone() {
            self.inner
                .routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(local_cid, sender);
        }
        send_outgoing(&self.inner.udp, target, outgoing).await;
        let mut established = connection.inner.established.subscribe();
        if !*established.borrow() {
            established
                .changed()
                .await
                .map_err(|_| QuicError::Closed("connection driver stopped".to_string()))?;
        }
        Ok(connection)
    }

    /// Accept the next established server connection.
    pub async fn accept(&self) -> Result<Connection, QuicError> {
        let mut rx = self.inner.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| QuicError::Closed("endpoint closed".to_string()))
    }

    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        if let Some(driver) = self.driver.lock().unwrap_or_else(|e| e.into_inner()).take() {
            driver.abort();
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        if let Some(driver) = self.driver.lock().unwrap_or_else(|e| e.into_inner()).take() {
            driver.abort();
        }
    }
}

async fn endpoint_driver(inner: Arc<EndpointInner>) {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        if inner.closed.load(Ordering::SeqCst) {
            break;
        }
        let received = match inner.udp.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(_) => break,
        };
        let datagram = buffer[..received.0].to_vec();
        let Some(dcid) = parse_dcid(&datagram, &inner.routes) else {
            continue;
        };
        let route = inner
            .routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&dcid)
            .cloned();
        if let Some(route) = route {
            let _ = route.send(datagram).await;
            continue;
        }
        if let Some(server) = &inner.server
            && is_initial(&datagram)
        {
            let Ok(local_cid) = random_cid(8) else {
                continue;
            };
            let mut local_tp = server.transport.clone();
            local_tp.initial_source_connection_id = Some(local_cid.clone());
            local_tp.original_destination_connection_id = Some(dcid.clone());
            let tls = match TlsSession::server(
                server.tls.clone(),
                local_tp
                    .encode()
                    .map(|parameters| parameters.to_vec())
                    .unwrap_or_default(),
            ) {
                Ok(tls) => tls,
                Err(_) => continue,
            };
            let core = match Core::server(tls, dcid.clone(), local_cid.clone(), local_tp) {
                Ok(core) => core,
                Err(_) => continue,
            };
            let (connection, outgoing) =
                match spawn_connection(inner.clone(), received.1, core, Some(datagram)).await {
                    Ok(value) => value,
                    Err(_) => continue,
                };
            {
                let mut routes = inner.routes.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(sender) = connection.inner.incoming.clone() {
                    routes.insert(dcid.clone(), sender.clone());
                    routes.insert(local_cid, sender);
                }
            }
            send_outgoing(&inner.udp, received.1, outgoing).await;
            let accept = inner.accept_tx.clone();
            tokio::spawn(async move {
                let mut established = connection.inner.established.subscribe();
                if !*established.borrow() && established.changed().await.is_ok() {
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
    incoming: Option<mpsc::Sender<Vec<u8>>>,
    udp: Arc<UdpSocket>,
    peer: SocketAddr,
    local: SocketAddr,
    driver: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

/// An established or handshaking owned QUIC connection.
#[derive(Clone)]
pub struct Connection {
    inner: Arc<ConnectionInner>,
}

impl Connection {
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.peer
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

    pub fn is_established(&self) -> bool {
        self.inner
            .core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_established()
    }

    pub async fn closed(&self) {
        let mut closed = self.inner.closed.subscribe();
        if closed.borrow().is_some() {
            return;
        }
        let _ = closed.changed().await;
    }

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

async fn spawn_connection(
    endpoint: Arc<EndpointInner>,
    peer: SocketAddr,
    core: Core,
    first: Option<Vec<u8>>,
) -> Result<(Connection, Vec<Vec<u8>>), QuicError> {
    let (incoming_tx, mut incoming_rx) = mpsc::channel(64);
    let (established_tx, _) = watch::channel(false);
    let (closed_tx, _) = watch::channel(None);
    let inner = Arc::new(ConnectionInner {
        core: StdMutex::new(core),
        notify: Notify::new(),
        readable: Notify::new(),
        established: established_tx,
        closed: closed_tx,
        incoming: Some(incoming_tx.clone()),
        udp: endpoint.udp.clone(),
        peer,
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
        loop {
            let mut outgoing: Vec<Vec<u8>> = Vec::new();
            let mut closed = false;
            tokio::select! {
                Some(datagram) = incoming_rx.recv() => {
                    let mut core = driver_inner.core.lock().unwrap_or_else(|e| e.into_inner());
                    if core.receive(&datagram).is_err() {
                        closed |= true;
                    } else {
                        let _ = core.poll_transmit();
                        outgoing = core.take_outgoing();
                        closed |= core.is_closed();
                        driver_inner.readable.notify_waiters();
                        driver_inner.readable.notify_one();
                    }
                }
                _ = driver_inner.notify.notified() => {
                    let mut core = driver_inner.core.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = core.poll_transmit();
                    outgoing = core.take_outgoing();
                    closed |= core.is_closed();
                }
                _ = timer.tick() => {
                    let mut core = driver_inner.core.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = core.handle_timeout();
                    let _ = core.poll_transmit();
                    outgoing = core.take_outgoing();
                    closed |= core.is_closed();
                }
            }
            for datagram in outgoing {
                if driver_inner
                    .udp
                    .send_to(&datagram, driver_inner.peer)
                    .await
                    .is_err()
                {
                    closed |= true;
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
            if closed {
                let _ = driver_inner.closed.send(Some(Arc::new(QuicError::Closed(
                    "connection closed".to_string(),
                ))));
                break;
            }
        }
    });
    *inner.driver.lock().unwrap_or_else(|e| e.into_inner()) = Some(driver);
    Ok((connection, outgoing))
}

async fn send_outgoing(udp: &UdpSocket, peer: SocketAddr, outgoing: Vec<Vec<u8>>) {
    for datagram in outgoing {
        let _ = udp.send_to(&datagram, peer).await;
    }
}

fn parse_dcid(
    datagram: &[u8],
    routes: &StdMutex<HashMap<Vec<u8>, mpsc::Sender<Vec<u8>>>>,
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
    let routes = routes.lock().unwrap_or_else(|e| e.into_inner());
    routes
        .keys()
        .filter(|cid| datagram.get(1..1 + cid.len()) == Some(cid.as_slice()))
        .max_by_key(|cid| cid.len())
        .cloned()
}

fn is_initial(datagram: &[u8]) -> bool {
    datagram.len() >= 6
        && datagram[0] & 0x80 != 0
        && datagram[1..5] == [0, 0, 0, 1]
        && datagram[0] & 0x30 == 0
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
