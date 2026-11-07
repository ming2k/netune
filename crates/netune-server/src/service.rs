//! The listener: accept, admit, trace, dispatch, drain.
//!
//! This module is the only place in the workspace that owns a listening socket, and it owns exactly
//! one (`[INV-SERVER-01]`). Everything it does per connection is ordered, and the order is the design:
//!
//! ```text
//! accept ─► permit ─► trace origin ─► protocol? ─► serve ─► drain ─► release
//! ```
//!
//! 1. **Permit before work.** A connection that cannot be admitted is closed before a trace ring is
//!    allocated or a byte is read (`[INV-SERVER-05]`). Shedding is explicit and immediate; queueing
//!    without limit turns a burst into an OOM.
//! 2. **Trace origin at accept.** The earliest fact a server can know is the kernel handover, so that
//!    is offset 0 of an ingress trace (`[INV-SERVER-02]`). Every later span is a derivation from it.
//! 3. **Protocol decided once, from the first bytes.** HTTP/1.1 or prior-knowledge HTTP/2; ALPN
//!    decides for TLS. Never both on one socket, because an in-place upgrade is a request-smuggling
//!    surface and a second parser.
//! 4. **Drain, then close.** On shutdown the listener stops accepting, in-flight exchanges finish up
//!    to a deadline, and only then are sockets closed (`[INV-SERVER-06]`).
//!
//! # Concurrency model
//!
//! One spawned task per connection, taken from the caller's runtime; inside HTTP/1.1 that task serves
//! one exchange at a time, and inside HTTP/2 it multiplexes streams over one writer. There is no
//! thread pool and no per-request spawn at this layer: a task that lives for the connection is what
//! makes the trace ring, the codec buffer and the permit share one lifetime, and it is what makes a
//! drain possible at all.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use netune_trace::{EventLog, Recorder};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::config::{ServerConfig, TraceObserver};
use crate::handler::Handler;

/// One finished connection's ingress trace.
///
/// The unit the transport hands over: a connection may have served several exchanges, and each
/// exchange is visible in the log as its own run of events — tagged with its stream identity when the
/// protocol multiplexed them. Derive with [`netune_trace::derive_ingress_exchanges`] for the
/// per-exchange view.
#[derive(Debug, Clone)]
pub struct IngressTrace {
    /// The peer this connection belonged to.
    pub peer: SocketAddr,
    /// The local address it arrived on, which names the listener when several are bound.
    pub local: SocketAddr,
    /// How many exchanges the connection completed.
    pub exchanges: u32,
    /// The protocol that was served, for an operator that has to tell them apart.
    pub protocol: ServedProtocol,
    /// The recorded events.
    pub log: EventLog,
}

/// Which protocol a connection was served with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServedProtocol {
    /// HTTP/1.1.
    Http1,
    /// HTTP/2.
    Http2,
}

impl ServedProtocol {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Http1 => "http/1.1",
            Self::Http2 => "h2",
        }
    }
}

/// Why a server could not be bound.
#[derive(Debug)]
pub enum BindError {
    /// The address could not be bound.
    Bind(std::io::Error),
    /// The configuration is not usable.
    Invalid(&'static str),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(error) => write!(f, "could not bind the listener: {error}"),
            Self::Invalid(what) => write!(f, "invalid server configuration: {what}"),
        }
    }
}

impl std::error::Error for BindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

/// A bound, not-yet-serving listener.
///
/// Binding is separated from serving so a caller can learn the actual port (`:0`) and build a shutdown
/// channel before the loop starts — the shape a test needs and a binary needs in the same way.
pub struct Server {
    listener: TcpListener,
    config: ServerConfig,
    handler: Arc<dyn Handler>,
    permits: Arc<Semaphore>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("local_addr", &self.local_addr())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Bind `address` and prepare to serve `handler`.
    ///
    /// # Errors
    ///
    /// [`BindError::Invalid`] when the configuration cannot be honoured (a zero connection cap, zero
    /// codec bounds, a timeout of zero), and [`BindError::Bind`] when the address is unavailable.
    /// Configuration is validated *before* binding so a bad config never leaves a port held.
    pub async fn bind(
        address: impl AsRef<str>,
        config: ServerConfig,
        handler: Arc<dyn Handler>,
    ) -> Result<Self, BindError> {
        config.validate()?;
        let listener = TcpListener::bind(address.as_ref())
            .await
            .map_err(BindError::Bind)?;
        let permits = Arc::new(Semaphore::new(config.max_connections));
        Ok(Self {
            listener,
            config,
            handler,
            permits,
        })
    }

    /// The address actually bound, with the kernel-assigned port when `:0` was requested.
    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// The configuration in force.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Serve until `shutdown` resolves, then drain.
    ///
    /// # Drain semantics
    ///
    /// When `shutdown` resolves the listener is dropped, so no further connection is accepted and the
    /// port is released. In-flight connections are then awaited as a group with `drain_timeout` as
    /// the overall deadline; a connection still running at the deadline is aborted. The function
    /// returns only after every connection task has ended, so a caller that awaits it knows the
    /// socket is quiet.
    ///
    /// # Panics
    ///
    /// Does not panic: a failing `accept` is treated as a per-connection error and the loop
    /// continues, because taking the port down because one peer reset is worse than the alternative.
    pub async fn serve<S>(self, shutdown: S)
    where
        S: std::future::Future<Output = ()>,
    {
        let Self {
            listener,
            config,
            handler,
            permits,
        } = self;
        let config = Arc::new(config);

        let mut connections: JoinSet<()> = JoinSet::new();
        // The drain signal every connection watches. Flipped once, after the listener stops
        // accepting, so a connection that is idle in a read learns about the drain immediately.
        let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                // Biased so a shutdown is honoured before a new connection under load: a server that
                // keeps admitting while draining never finishes.
                biased;

                () = &mut shutdown => break,
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else {
                        // A failed `accept` is almost always a per-connection error (the peer reset
                        // before we got to it), not a listener failure. Keep serving rather than
                        // taking the port down.
                        continue;
                    };
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        // No permit: shed now, explicitly. The client learns immediately, which is
                        // what makes a retry possible.
                        drop(stream);
                        let _ = peer;
                        continue;
                    };
                    let handler = Arc::clone(&handler);
                    let config = Arc::clone(&config);
                    let drain = drain_rx.clone();
                    connections.spawn(async move {
                        run_connection(stream, peer, config, handler, permit, drain).await;
                    });
                }
                // Reap finished connections so the set does not grow without bound on a long-lived
                // listener.
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        // The listener is dropped here, before draining: the port must stop accepting even while old
        // connections finish.
        drop(listener);
        // Tell every in-flight connection at once, so each can finish its own streams rather than
        // being aborted when the drain deadline expires.
        let _ = drain_tx.send(true);

        let deadline = tokio::time::Instant::now() + config.drain_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                connections.shutdown().await;
                return;
            }
            tokio::select! {
                joined = connections.join_next() => {
                    if joined.is_none() {
                        return;
                    }
                }
                () = tokio::time::sleep(remaining) => {
                    connections.shutdown().await;
                    return;
                }
            }
        }
    }
}

/// Serve one accepted connection until it closes or the listener is draining.
///
/// `drain` resolves when the listener stops accepting. Passing it down is what makes
/// `[INV-SERVER-06]` true for HTTP/2 as well as HTTP/1.1: a session that was never told to drain
/// would be aborted by the drain deadline instead of finishing its streams.
async fn run_connection(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ServerConfig>,
    handler: Arc<dyn Handler>,
    permit: OwnedSemaphorePermit,
    #[cfg_attr(not(feature = "http2"), allow(unused_variables))]
    drain: tokio::sync::watch::Receiver<bool>,
) {
    // The accept is the trace origin: `Recorder::start_ingress` writes `IngressDispatch` at offset 0,
    // which is what every ingress derivation anchors on (`[INV-SERVER-02]`).
    let recorder = Arc::new(Mutex::new(Recorder::start_ingress(config.trace_capacity)));
    let local = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

    #[cfg(feature = "tls")]
    if config.tls.is_some() {
        run_tls_connection(stream, peer, local, config, handler, recorder, drain).await;
        drop(permit);
        return;
    }

    // Protocol selection from the first bytes. Reading is bounded by the head timeout because a peer
    // that opens a connection and says nothing must not hold a permit for the connection's lifetime.
    let mut probe = [0u8; 24];
    let peek = tokio::time::timeout(config.head_timeout, stream.peek(&mut probe)).await;
    let protocol = match peek {
        Ok(Ok(read)) if read >= 5 && &probe[..5] == b"PRI *" => ServedProtocol::Http2,
        Ok(Ok(_)) | Ok(Err(_)) => ServedProtocol::Http1,
        // A peer that never sends anything gets no protocol and no trace beyond the accept: the
        // connection is closed, which is the whole point of the head bound.
        Err(_) => {
            let mut recorder = recorder.lock().unwrap_or_else(|error| error.into_inner());
            recorder.mark(
                netune_trace::EventKind::Error,
                crate::h1::ERROR_HEAD_TIMEOUT,
                0,
            );
            hand_over(&config, peer, local, ServedProtocol::Http1, 0, &recorder);
            drop(permit);
            return;
        }
    };

    let (exchanges, protocol) = serve_selected(
        stream,
        protocol,
        Arc::clone(&config),
        handler,
        Arc::clone(&recorder),
        false,
        drain,
    )
    .await;

    {
        let recorder = recorder.lock().unwrap_or_else(|error| error.into_inner());
        hand_over(&config, peer, local, protocol, exchanges, &recorder);
    }
    drop(permit);
}

/// Serve a connection whose protocol a TLS handshake decided.
///
/// The handshake is part of the trace (`IngressTlsEnd`), because it is the one cost a TLS listener pays
/// that a plaintext one does not — and the reason a fronting terminator was rejected: whoever performs
/// the handshake owns its measurement.
#[cfg(feature = "tls")]
async fn run_tls_connection(
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    config: Arc<ServerConfig>,
    handler: Arc<dyn Handler>,
    recorder: Arc<Mutex<Recorder>>,
    #[cfg_attr(not(feature = "http2"), allow(unused_variables))]
    drain: tokio::sync::watch::Receiver<bool>,
) {
    let Some(tls) = config.tls.as_ref() else {
        return;
    };
    let selected = tls.select.clone();
    let negotiated =
        match crate::tls::accept(stream, config.head_timeout, move |name| selected(name)).await {
            Ok(negotiated) => negotiated,
            Err(error) => {
                let mut recorder = recorder.lock().unwrap_or_else(|error| error.into_inner());
                recorder.mark(
                    netune_trace::EventKind::Error,
                    crate::h1::ERROR_TLS_HANDSHAKE,
                    0,
                );
                let _ = error.reason();
                hand_over(&config, peer, local, ServedProtocol::Http1, 0, &recorder);
                return;
            }
        };

    let (mut stream, negotiated) = negotiated;
    {
        // The handshake's end is a recorded fact, so a derivation can separate "the TLS identity cost
        // this" from "the client was slow to speak".
        let mut recorder = recorder.lock().unwrap_or_else(|error| error.into_inner());
        recorder.mark(
            netune_trace::EventKind::IngressTlsEnd,
            u32::from(negotiated == crate::tls::Negotiated::Http2),
            0,
        );
    }

    let protocol = match negotiated {
        crate::tls::Negotiated::Http2 => ServedProtocol::Http2,
        crate::tls::Negotiated::Http1 => ServedProtocol::Http1,
    };

    let serves = match protocol {
        ServedProtocol::Http2 => config.protocols.http2,
        ServedProtocol::Http1 => config.protocols.http1,
    };
    if !serves {
        // A negotiated protocol the listener does not serve is refused inside the session, so the peer
        // sees a status line rather than a truncated TLS record.
        crate::tls::write_refusal(
            &mut stream,
            "505 HTTP Version Not Supported",
            config.write_timeout,
        )
        .await;
        let recorder = recorder.lock().unwrap_or_else(|error| error.into_inner());
        hand_over(&config, peer, local, protocol, 0, &recorder);
        return;
    }

    // An HTTP/2 connection over TLS has *not* read the preface: ALPN decided, and the bytes are still
    // in the stream.
    let (exchanges, protocol) = serve_selected(
        stream,
        protocol,
        Arc::clone(&config),
        handler,
        Arc::clone(&recorder),
        false,
        drain,
    )
    .await;

    let recorder = recorder.lock().unwrap_or_else(|error| error.into_inner());
    hand_over(&config, peer, local, protocol, exchanges, &recorder);
}

/// Dispatch a connection whose protocol is already known.
#[allow(clippy::too_many_arguments)]
async fn serve_selected<S>(
    stream: S,
    protocol: ServedProtocol,
    config: Arc<ServerConfig>,
    handler: Arc<dyn Handler>,
    recorder: Arc<Mutex<Recorder>>,
    #[cfg_attr(not(feature = "http2"), allow(unused_variables))] preface_already_read: bool,
    #[cfg_attr(not(feature = "http2"), allow(unused_variables))]
    drain: tokio::sync::watch::Receiver<bool>,
) -> (u32, ServedProtocol)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    match protocol {
        // A protocol the listener does not offer is *refused*, whichever one it is. Checking only the
        // HTTP/2 side would let an `HTTP2`-only listener serve HTTP/1.1 requests it never advertised —
        // the downgrade `[INV-SERVER-09]` forbids, through the door nobody looked at.
        ServedProtocol::Http1 if !config.protocols.http1 => {
            let mut stream = stream;
            let _ = write_within(
                &mut stream,
                b"HTTP/1.1 505 HTTP Version Not Supported\r\nconnection: close\r\n\r\n",
                config.write_timeout,
            )
            .await;
            (0, ServedProtocol::Http1)
        }
        #[cfg(feature = "http2")]
        ServedProtocol::Http2 if config.protocols.http2 => {
            let end = crate::h2::serve_http2(
                stream,
                Arc::clone(&config),
                handler,
                Arc::clone(&recorder),
                preface_already_read,
                wait_for_drain(drain),
            )
            .await;
            let exchanges = exchange_count(&recorder);
            let _ = end;
            (exchanges, ServedProtocol::Http2)
        }
        ServedProtocol::Http2 => {
            // HTTP/2 was asked for but is not enabled on this listener: refuse rather than silently
            // downgrading, because a downgrade is a protocol confusion a client cannot detect.
            let mut stream = stream;
            let _ = write_within(
                &mut stream,
                b"HTTP/1.1 505 HTTP Version Not Supported\r\nconnection: close\r\n\r\n",
                config.write_timeout,
            )
            .await;
            (0, ServedProtocol::Http2)
        }
        ServedProtocol::Http1 => {
            let exchanges =
                crate::h1::serve_http1(stream, Arc::clone(&config), handler, Arc::clone(&recorder))
                    .await;
            (exchanges, ServedProtocol::Http1)
        }
    }
}

/// Deliver the finished trace to the configured observer.
///
/// Before the permit is released: the observer runs on this connection's task, so the recorder is
/// quiescent and the ring is complete.
fn hand_over(
    config: &ServerConfig,
    peer: SocketAddr,
    local: SocketAddr,
    protocol: ServedProtocol,
    exchanges: u32,
    recorder: &Recorder,
) {
    if let Some(observer) = &config.trace_sink {
        observer.connection_finished(IngressTrace {
            peer,
            local,
            exchanges,
            protocol,
            log: recorder.log().clone(),
        });
    }
}

/// How many exchanges a connection's recorder witnessed.
#[cfg(feature = "http2")]
fn exchange_count(recorder: &Arc<Mutex<Recorder>>) -> u32 {
    let recorder = recorder.lock().unwrap_or_else(|error| error.into_inner());
    netune_trace::exchange_count(recorder.log()) as u32
}

/// Resolve when the listener starts draining.
#[cfg(feature = "http2")]
///
/// A watch channel rather than a shared flag: a flag would have to be polled, and a connection that
/// is idle in a read would never poll it — which is exactly the connection a drain most needs to
/// reach.
async fn wait_for_drain(mut drain: tokio::sync::watch::Receiver<bool>) {
    // The sender is dropped when the listener ends; either fact means "stop accepting".
    while drain.changed().await.is_ok() {
        if *drain.borrow() {
            return;
        }
    }
}

/// Write under a deadline, ignoring failures. For a refusal on a connection that is about to close.
async fn write_within<S>(
    stream: &mut S,
    bytes: &[u8],
    timeout: std::time::Duration,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, stream.write_all(bytes)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the peer did not accept the write within the configured bound",
        )),
    }
}

/// A trace observer that keeps nothing, for a server that wants the connection lifecycle but not the
/// records. Present so a caller can name the choice rather than leaving the field `None` and
/// wondering whether tracing is off by accident.
#[derive(Debug, Default, Clone, Copy)]
pub struct DiscardingObserver;

impl TraceObserver for DiscardingObserver {
    fn connection_finished(&self, _trace: IngressTrace) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_cap_configuration_is_refused_before_binding() {
        let config = ServerConfig::for_tests().with_max_connections(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_discarding_observer_compiles_as_a_trace_sink() {
        let observer: Arc<dyn TraceObserver> = Arc::new(DiscardingObserver);
        observer.connection_finished(IngressTrace {
            peer: SocketAddr::from(([127, 0, 0, 1], 1)),
            local: SocketAddr::from(([127, 0, 0, 1], 2)),
            exchanges: 0,
            protocol: ServedProtocol::Http1,
            log: EventLog::with_capacity(1),
        });
    }
}
