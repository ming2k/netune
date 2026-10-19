//! Connection pool: keep-alive reuse we own and can therefore attribute.
//!
//! The pool's whole reason to exist is a metric: a request that finds a pooled
//! connection has no DNS/TCP/TLS phases, and the trace says so
//! ([`netune_trace::EventKind::ConnectReused`]) instead of charging the peer for
//! a handshake that never happened. Reuse is also where the previous client's
//! behaviour was least visible — a 90 s idle eviction silently moved hundreds of
//! milliseconds into TTFT.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;

use crate::connect::Transport;

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

/// A connection taken from the pool, with whatever bytes it already buffered.
pub struct IdleConnection {
    pub stream: Box<dyn Transport>,
    pub buffered: BytesMut,
    pub local_port: Option<u16>,
    /// Duplicate socket handle for `TCP_INFO` sampling on the next use.
    pub socket: Option<std::net::TcpStream>,
    /// How long it sat idle.
    pub age: Duration,
}

struct Idle {
    stream: Box<dyn Transport>,
    buffered: BytesMut,
    local_port: Option<u16>,
    socket: Option<std::net::TcpStream>,
    since: Instant,
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

    /// Take a live idle connection for `authority`, if one is fresh enough.
    pub fn take(&self, authority: &str) -> Option<IdleConnection> {
        let mut idle = self.inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        let entries = idle.get_mut(authority)?;
        let now = Instant::now();
        while let Some(candidate) = entries.pop() {
            let age = now.saturating_duration_since(candidate.since);
            if age <= self.inner.config.idle_timeout {
                return Some(IdleConnection {
                    stream: candidate.stream,
                    buffered: candidate.buffered,
                    local_port: candidate.local_port,
                    socket: candidate.socket,
                    age,
                });
            }
            // Stale: drop it and try the next candidate.
        }
        None
    }

    /// Return a connection to the pool.
    pub fn put(
        &self,
        authority: &str,
        stream: Box<dyn Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
    ) {
        if self.inner.config.max_idle_per_authority == 0 {
            return;
        }
        let mut idle = self.inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        let entries = idle.entry(authority.to_string()).or_default();
        while entries.len() >= self.inner.config.max_idle_per_authority {
            entries.remove(0);
        }
        entries.push(Idle {
            stream,
            buffered,
            local_port,
            socket,
            since: Instant::now(),
        });
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

        let idle = pool.take("example:443").expect("reused");
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
        assert_eq!(
            pool.take("example:443").map(|i| i.local_port),
            Some(Some(5))
        );
        assert_eq!(
            pool.take("example:443").map(|i| i.local_port),
            Some(Some(4))
        );
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
    fn a_zero_cap_disables_pooling() {
        let pool = pool(0, Duration::from_secs(60));
        pool.put("example:443", idle_stream(), BytesMut::new(), None, None);
        assert_eq!(pool.idle_count("example:443"), 0);
    }
}
