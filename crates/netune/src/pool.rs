//! Connection pool: keep-alive reuse we own and can therefore attribute.
//!
//! The pool's whole reason to exist is a metric: a request that finds a pooled
//! connection has no DNS/TCP/TLS phases, and the trace says so
//! ([`netune_trace::EventKind::ConnectReused`]) instead of charging the peer for
//! a handshake that never happened. Reuse is also where the previous client's
//! behaviour was least visible — a 90 s idle eviction silently moved hundreds of
//! milliseconds into TTFT.
//!
//! HTTP/1.1 and HTTP/2 are pooled as different payloads because "reuse" means
//! different things: an HTTP/1.1 socket is bytes at a message boundary, while an
//! HTTP/2 connection carries negotiated SETTINGS and HPACK state that a second
//! handshake cannot recreate on the same socket. A pool that stored only the
//! byte stream would either re-handshake an already-negotiated connection or
//! lose the compression tables.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::runtime::Id as RuntimeId;

use bytes::BytesMut;
use netune_trace::ConnectionIdentity;

use crate::connect::Transport;
#[cfg(feature = "http2")]
use netune_http2::H2ClientConnection;

/// Pool policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// Idle connections retained per authority.
    pub max_idle_per_authority: usize,
    /// How long an idle connection may be reused.
    pub idle_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_authority: 4,
            // Long enough that human-paced agent turns (read, think, send) keep
            // their connection, short enough that a dead one is not reused.
            //
            // The previous 300 s was measured against the wrong party: a
            // long-horizon agent waits minutes between turns, and mainstream
            // LLM relays/gateways close idle keep-alive sockets on their own
            // schedule — commonly 30–60 s, and not necessarily announced with a
            // `close_notify`. Every such socket stayed "fresh" here, was handed
            // out, and surfaced to the user as a provider failure. Retaining a
            // connection is only worth anything if it is still alive, so the
            // bound now sits inside the shortest idle cull observed from the
            // peers this client actually talks to.
            idle_timeout: Duration::from_secs(20),
        }
    }
}

/// Which protocol an idle connection speaks.
///
/// A caller selecting from the pool has to say which protocols it can drive: an
/// HTTP/2 connection cannot be handed to the HTTP/1.1 writer, and a request that
/// mandates HTTP/2 cannot use a keep-alive socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Http1,
    #[cfg(feature = "http2")]
    Http2,
}

/// An idle HTTP/1.1 keep-alive socket.
pub struct Http1Idle {
    pub stream: Box<dyn Transport>,
    /// Bytes the peer sent after the last response, to be parsed as the next one.
    pub buffered: BytesMut,
    pub local_port: Option<u16>,
    /// Duplicate socket handle for `TCP_INFO` sampling on the next use.
    pub socket: Option<std::net::TcpStream>,
    /// How long it sat idle.
    pub age: Duration,
}

/// An established HTTP/2 connection with no stream in flight.
#[cfg(feature = "http2")]
pub struct Http2Idle {
    pub connection: Box<H2ClientConnection<Box<dyn Transport>>>,
    pub local_port: Option<u16>,
    /// Duplicate socket handle for `TCP_INFO` sampling on the next use.
    pub socket: Option<std::net::TcpStream>,
    /// How long it sat idle.
    pub age: Duration,
}

/// A connection taken from the pool.
pub enum IdleConnection {
    Http1(Http1Idle),
    #[cfg(feature = "http2")]
    Http2(Http2Idle),
}

enum Idle {
    Http1 {
        stream: Box<dyn Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
        since: Instant,
        runtime: Option<RuntimeId>,
    },
    #[cfg(feature = "http2")]
    Http2 {
        // Boxed: a negotiated connection carries SETTINGS and both HPACK tables,
        // so it dwarfs the HTTP/1.1 socket variant and would otherwise inflate
        // every entry in the idle map.
        connection: Box<H2ClientConnection<Box<dyn Transport>>>,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
        since: Instant,
        runtime: Option<RuntimeId>,
    },
}

impl Idle {
    const fn protocol(&self) -> Protocol {
        match self {
            Self::Http1 { .. } => Protocol::Http1,
            #[cfg(feature = "http2")]
            Self::Http2 { .. } => Protocol::Http2,
        }
    }

    const fn since(&self) -> Instant {
        match self {
            Self::Http1 { since, .. } => *since,
            #[cfg(feature = "http2")]
            Self::Http2 { since, .. } => *since,
        }
    }

    const fn runtime(&self) -> Option<RuntimeId> {
        match self {
            Self::Http1 { runtime, .. } => *runtime,
            #[cfg(feature = "http2")]
            Self::Http2 { runtime, .. } => *runtime,
        }
    }

    fn into_connection(self, age: Duration) -> IdleConnection {
        match self {
            Self::Http1 {
                stream,
                buffered,
                local_port,
                socket,
                ..
            } => IdleConnection::Http1(Http1Idle {
                stream,
                buffered,
                local_port,
                socket,
                age,
            }),
            #[cfg(feature = "http2")]
            Self::Http2 {
                connection,
                local_port,
                socket,
                ..
            } => IdleConnection::Http2(Http2Idle {
                connection,
                local_port,
                socket,
                age,
            }),
        }
    }
}

/// The id of the runtime the caller is currently running on, if any.
///
/// `None` outside a runtime: a connection released from synchronous context
/// carries no affinity claim, and `take` treats `None == None` as a match so a
/// pool driven entirely from synchronous code keeps working.
fn current_runtime_id() -> Option<RuntimeId> {
    tokio::runtime::Handle::try_current()
        .ok()
        .map(|handle| handle.id())
}

/// The only key a pooled connection may be stored under.
///
/// The authority is the socket address; the identity is every property fixed at
/// connection establishment. A pool lookup that does not carry the whole
/// identity cannot typecheck, which is what makes `[INV-CUSTOM-04]` structural
/// rather than a convention.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub authority: String,
    pub identity: ConnectionIdentity,
}

impl PoolKey {
    pub fn new(authority: impl Into<String>, identity: ConnectionIdentity) -> Self {
        Self {
            authority: authority.into(),
            identity,
        }
    }
}

#[derive(Default)]
struct PoolInner {
    config: PoolConfig,
    idle: Mutex<HashMap<PoolKey, Vec<Idle>>>,
}

/// A shared, cloneable connection pool.
#[derive(Clone, Default)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

impl Pool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                config,
                idle: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn config(&self) -> PoolConfig {
        self.inner.config
    }

    /// Take the newest live idle connection for `key`, whatever its protocol.
    pub fn take(&self, key: &PoolKey) -> Option<IdleConnection> {
        self.take_matching(key, |_| true)
    }

    /// Take the newest live idle connection whose protocol `accept` approves.
    ///
    /// A candidate the caller cannot drive is left in place for a request that
    /// can; only expired entries and sockets registered with another runtime are
    /// discarded.
    pub(crate) fn take_matching(
        &self,
        key: &PoolKey,
        accept: impl Fn(Protocol) -> bool,
    ) -> Option<IdleConnection> {
        let current = current_runtime_id();
        let mut idle = self.inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        let entries = idle.get_mut(key)?;
        let now = Instant::now();
        for index in (0..entries.len()).rev() {
            let age = now.saturating_duration_since(entries[index].since());
            // An idle socket past the keep-alive window, or one dialled by
            // another (possibly dead) runtime, cannot be reused: its I/O
            // registration belongs to that reactor. Drop it and keep looking.
            if age > self.inner.config.idle_timeout || entries[index].runtime() != current {
                entries.remove(index);
                continue;
            }
            if !accept(entries[index].protocol()) {
                continue;
            }
            let entry = entries.remove(index);
            return Some(entry.into_connection(age));
        }
        None
    }

    /// Return an HTTP/1.1 keep-alive socket to the pool.
    pub fn put(
        &self,
        key: &PoolKey,
        stream: Box<dyn Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
    ) {
        self.put_http1(key, stream, buffered, local_port, socket);
    }

    /// Return an HTTP/1.1 keep-alive socket to the pool.
    pub fn put_http1(
        &self,
        key: &PoolKey,
        stream: Box<dyn Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
    ) {
        self.put_entry(
            key,
            Idle::Http1 {
                stream,
                buffered,
                local_port,
                socket,
                since: Instant::now(),
                runtime: current_runtime_id(),
            },
        );
    }

    /// Return an established HTTP/2 connection with no stream in flight.
    ///
    /// The connection must have finished its exchange and must not have received
    /// a `GOAWAY`; the caller decides that before calling this.
    #[cfg(feature = "http2")]
    pub fn put_http2(
        &self,
        key: &PoolKey,
        connection: H2ClientConnection<Box<dyn Transport>>,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
    ) {
        self.put_entry(
            key,
            Idle::Http2 {
                connection: Box::new(connection),
                local_port,
                socket,
                since: Instant::now(),
                runtime: current_runtime_id(),
            },
        );
    }

    fn put_entry(&self, key: &PoolKey, entry: Idle) {
        if self.inner.config.max_idle_per_authority == 0 {
            return;
        }
        let mut idle = self.inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        let entries = idle.entry(key.clone()).or_default();
        while entries.len() >= self.inner.config.max_idle_per_authority {
            entries.remove(0);
        }
        entries.push(entry);
    }

    /// Number of idle connections retained for `key` (tests, diagnostics).
    pub fn idle_count(&self, key: &PoolKey) -> usize {
        let idle = self.inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.get(key).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests;
