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

#[derive(Default)]
struct PoolInner {
    config: PoolConfig,
    idle: Mutex<HashMap<String, Vec<Idle>>>,
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

    /// Take the newest live idle connection for `authority`, whatever its protocol.
    pub fn take(&self, authority: &str) -> Option<IdleConnection> {
        self.take_matching(authority, |_| true)
    }

    /// Take the newest live idle connection whose protocol `accept` approves.
    ///
    /// A candidate the caller cannot drive is left in place for a request that
    /// can; only expired entries and sockets registered with another runtime are
    /// discarded.
    pub(crate) fn take_matching(
        &self,
        authority: &str,
        accept: impl Fn(Protocol) -> bool,
    ) -> Option<IdleConnection> {
        let current = current_runtime_id();
        let mut idle = self.inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        let entries = idle.get_mut(authority)?;
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
        authority: &str,
        stream: Box<dyn Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
    ) {
        self.put_http1(authority, stream, buffered, local_port, socket);
    }

    /// Return an HTTP/1.1 keep-alive socket to the pool.
    pub fn put_http1(
        &self,
        authority: &str,
        stream: Box<dyn Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
    ) {
        self.put_entry(
            authority,
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
        authority: &str,
        connection: H2ClientConnection<Box<dyn Transport>>,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
    ) {
        self.put_entry(
            authority,
            Idle::Http2 {
                connection: Box::new(connection),
                local_port,
                socket,
                since: Instant::now(),
                runtime: current_runtime_id(),
            },
        );
    }

    fn put_entry(&self, authority: &str, entry: Idle) {
        if self.inner.config.max_idle_per_authority == 0 {
            return;
        }
        let mut idle = self.inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        let entries = idle.entry(authority.to_string()).or_default();
        while entries.len() >= self.inner.config.max_idle_per_authority {
            entries.remove(0);
        }
        entries.push(entry);
    }

    /// Number of idle connections retained for `authority` (tests, diagnostics).
    pub fn idle_count(&self, authority: &str) -> usize {
        let idle = self.inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.get(authority).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A transport that never carries data: the pool only needs the type.
    #[derive(Debug)]
    struct Dummy;

    impl AsyncRead for Dummy {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Dummy {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn idle_stream() -> Box<dyn Transport> {
        Box::new(Dummy)
    }

    fn take_http1(pool: &Pool, authority: &str) -> Http1Idle {
        match pool.take(authority) {
            Some(IdleConnection::Http1(idle)) => idle,
            #[cfg(feature = "http2")]
            Some(IdleConnection::Http2(_)) => panic!("expected an HTTP/1.1 connection"),
            None => panic!("expected an idle connection"),
        }
    }

    fn pool(max_idle: usize, idle_timeout: Duration) -> Pool {
        Pool::new(PoolConfig {
            max_idle_per_authority: max_idle,
            idle_timeout,
        })
    }

    #[test]
    fn an_empty_pool_has_nothing_to_reuse() {
        let pool = pool(2, Duration::from_secs(60));
        assert!(pool.take("example:443").is_none());
        assert_eq!(pool.idle_count("example:443"), 0);
    }

    #[test]
    fn a_returned_connection_is_reused_with_its_buffered_bytes() {
        let pool = pool(2, Duration::from_secs(60));
        let mut buffered = BytesMut::new();
        buffered.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        pool.put("example:443", idle_stream(), buffered, Some(51_234), None);

        let idle = take_http1(&pool, "example:443");
        assert_eq!(idle.local_port, Some(51_234));
        assert_eq!(&idle.buffered[..], b"HTTP/1.1 200 OK\r\n");
        assert_eq!(pool.idle_count("example:443"), 0, "take removes it");
    }

    #[test]
    fn authorities_do_not_share_connections() {
        let pool = pool(2, Duration::from_secs(60));
        pool.put("a:443", idle_stream(), BytesMut::new(), None, None);
        assert!(pool.take("b:443").is_none());
        assert!(pool.take("a:443").is_some());
    }

    #[test]
    fn the_idle_cap_evicts_the_oldest() {
        let pool = pool(2, Duration::from_secs(60));
        for port in 1..=5u16 {
            pool.put(
                "example:443",
                idle_stream(),
                BytesMut::new(),
                Some(port),
                None,
            );
        }
        assert_eq!(pool.idle_count("example:443"), 2);
        assert_eq!(take_http1(&pool, "example:443").local_port, Some(5));
        assert_eq!(take_http1(&pool, "example:443").local_port, Some(4));
        assert!(pool.take("example:443").is_none());
    }

    #[test]
    fn a_stale_connection_is_discarded_rather_than_reused() {
        let pool = pool(2, Duration::from_millis(1));
        pool.put("example:443", idle_stream(), BytesMut::new(), None, None);
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            pool.take("example:443").is_none(),
            "an expired connection must not be handed out"
        );
    }

    #[test]
    fn a_candidate_the_caller_cannot_drive_is_left_in_place() {
        let pool = pool(2, Duration::from_secs(60));
        pool.put("example:443", idle_stream(), BytesMut::new(), None, None);
        assert!(
            pool.take_matching("example:443", |protocol| protocol != Protocol::Http1)
                .is_none(),
            "an HTTP/1.1 socket must not be handed to a caller that wants HTTP/2"
        );
        assert_eq!(
            pool.idle_count("example:443"),
            1,
            "the rejected candidate must remain available to a compatible request"
        );
    }

    /// Same authority, same pool, two runtimes: the second runtime must not
    /// receive the first one's socket, whose I/O registration died with it.
    #[test]
    fn a_connection_is_never_handed_to_a_different_runtime() {
        let pool = pool(2, Duration::from_secs(60));
        let first = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("first runtime");
        first.block_on(async {
            pool.put("example:443", idle_stream(), BytesMut::new(), None, None);
            assert_eq!(pool.idle_count("example:443"), 1);
        });

        let second = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("second runtime");
        let taken = second.block_on(async { pool.take("example:443").is_some() });
        assert!(!taken, "a foreign runtime must not inherit this socket");
        assert_eq!(
            pool.idle_count("example:443"),
            0,
            "the discarded candidate must leave the pool"
        );
    }

    #[test]
    fn a_zero_cap_disables_pooling() {
        let pool = pool(0, Duration::from_secs(60));
        pool.put("example:443", idle_stream(), BytesMut::new(), None, None);
        assert_eq!(pool.idle_count("example:443"), 0);
    }
}
