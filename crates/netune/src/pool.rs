//! Connection pool: keep-alive reuse, multiplexed session sharing, and
//! deterministic lifecycle governance.
//!
//! The pool's whole reason to exist is a metric: a request that finds a pooled
//! connection has no DNS/TCP/TLS phases, and the trace says so
//! ([`netune_trace::EventKind::ConnectReused`]) instead of charging the peer for
//! a handshake that never happened.
//!
//! HTTP/1.1 keep-alive connections remain exclusively owned while in flight
//! because HTTP/1.1 is byte-ordered on one socket at a time. Multiplexed
//! protocols (HTTP/2 and HTTP/3) stay shared inside the pool so concurrent
//! requests share a single handshake and socket up to the peer's advertised
//! stream limit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use netune_trace::ConnectionIdentity;
use tokio::runtime::Id as RuntimeId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use crate::connect::Transport;
use crate::error::NetError;
#[cfg(feature = "http2")]
use netune_http2::{H2ClientSession, H2StreamPermit};
#[cfg(feature = "http3")]
use netune_http3::H3Session;

const MIN_REAPER_INTERVAL: Duration = Duration::from_millis(50);
const MAX_REAPER_INTERVAL: Duration = Duration::from_secs(5);

/// Pool policy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// Idle connections retained per authority key.
    pub max_idle_per_authority: usize,
    /// Global cap on idle connections retained across all keys (`0` disables pooling).
    pub max_idle_total: usize,
    /// Maximum concurrent in-flight exchanges per authority (`None` = unlimited).
    pub max_in_flight_per_authority: Option<usize>,
    /// Global cap on concurrent in-flight exchanges across every authority.
    ///
    /// A per-authority limit alone lets an attacker spread work over many
    /// authorities. The global ceiling is the actual memory/file-descriptor
    /// bound. `None` is an explicit opt-out, not the default.
    pub max_in_flight_total: Option<usize>,
    /// How long an idle connection may be reused.
    pub idle_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_authority: 4,
            max_idle_total: 64,
            max_in_flight_per_authority: Some(64),
            max_in_flight_total: Some(512),
            // Long enough that human-paced agent turns (read, think, send) keep
            // their connection, short enough that a dead one is not reused.
            //
            // The previous 300 s was measured against the wrong party: a
            // long-horizon agent waits minutes between turns, and mainstream
            // LLM relays/gateways close idle keep-alive sockets on their own
            // schedule — commonly 30–60 s, and not necessarily announced with a
            // `close_notify`. Retaining a connection is only worth anything if
            // it is still alive, so the bound sits inside the shortest idle
            // cull observed from peers.
            idle_timeout: Duration::from_secs(20),
        }
    }
}

impl PoolConfig {
    /// Set the per-authority idle connection cap.
    #[must_use]
    pub fn with_max_idle_per_authority(mut self, cap: usize) -> Self {
        self.max_idle_per_authority = cap;
        self
    }

    /// Set the global idle connection cap (`0` disables pooling).
    #[must_use]
    pub fn with_max_idle_total(mut self, cap: usize) -> Self {
        self.max_idle_total = cap;
        self
    }

    /// Set the per-authority concurrent in-flight limit.
    #[must_use]
    pub fn with_max_in_flight_per_authority(mut self, cap: Option<usize>) -> Self {
        self.max_in_flight_per_authority = cap;
        self
    }

    /// Set the global concurrent in-flight limit.
    #[must_use]
    pub fn with_max_in_flight_total(mut self, cap: Option<usize>) -> Self {
        self.max_in_flight_total = cap;
        self
    }

    /// Set how long an idle connection may be reused.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }
}

/// Which idle single-owner protocol a pooled socket speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Http1,
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

/// A connection taken from the pool.
pub enum IdleConnection {
    /// An idle HTTP/1.1 keep-alive connection.
    Http1(Http1Idle),
}

enum Idle {
    Http1 {
        stream: Box<dyn Transport>,
        buffered: BytesMut,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
        since: Instant,
        seq: u64,
        runtime: Option<RuntimeId>,
    },
}

impl Idle {
    const fn protocol(&self) -> Protocol {
        match self {
            Self::Http1 { .. } => Protocol::Http1,
        }
    }

    const fn since(&self) -> Instant {
        match self {
            Self::Http1 { since, .. } => *since,
        }
    }

    const fn seq(&self) -> u64 {
        match self {
            Self::Http1 { seq, .. } => *seq,
        }
    }

    const fn runtime(&self) -> Option<RuntimeId> {
        match self {
            Self::Http1 { runtime, .. } => *runtime,
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
        }
    }
}

#[cfg(feature = "http2")]
struct SharedH2Entry {
    session: H2ClientSession,
    local_port: Option<u16>,
    socket: Option<std::net::TcpStream>,
    seq: u64,
    runtime: Option<RuntimeId>,
}

/// Stream permit checked out on an active shared HTTP/2 session.
#[cfg(feature = "http2")]
pub(crate) struct CheckedOutHttp2 {
    pub session: H2ClientSession,
    pub permit: H2StreamPermit,
    pub local_port: Option<u16>,
    pub socket: Option<std::net::TcpStream>,
    pub age: Duration,
}

#[cfg(feature = "http3")]
struct SharedH3Entry {
    session: H3Session,
    local_port: Option<u16>,
    seq: u64,
    runtime: Option<RuntimeId>,
}

/// Checked-out shared HTTP/3 session handle.
#[cfg(feature = "http3")]
pub(crate) struct CheckedOutHttp3 {
    pub session: H3Session,
    pub local_port: Option<u16>,
    pub age: Duration,
}

/// Concurrency slot held for the lifetime of an in-flight exchange.
#[derive(Debug)]
pub(crate) struct PoolInFlightPermit {
    _per_authority: Option<OwnedSemaphorePermit>,
    _global: Option<OwnedSemaphorePermit>,
}

struct DialFlight {
    done_tx: watch::Sender<bool>,
}

/// Singleflight leader guard: waking followers on drop even if cancelled.
pub(crate) struct DialLeaderGuard {
    inner: Arc<PoolInner>,
    key: PoolKey,
    flight: Arc<DialFlight>,
}

impl Drop for DialLeaderGuard {
    fn drop(&mut self) {
        {
            let mut flights = self
                .inner
                .dial_flights
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if flights
                .get(&self.key)
                .is_some_and(|existing| Arc::ptr_eq(existing, &self.flight))
            {
                flights.remove(&self.key);
            }
        }
        let _ = self.flight.done_tx.send(true);
    }
}

/// Singleflight follower handle waiting for an in-flight cold dial to finish.
pub(crate) struct DialWaiter {
    done_rx: watch::Receiver<bool>,
}

impl DialWaiter {
    pub(crate) async fn wait(mut self) {
        let _ = self.done_rx.wait_for(|done| *done).await;
    }
}

/// Whether the caller should open a cold multiplexed connection or wait for an
/// active cold dial to register one.
pub(crate) enum DialDecision {
    Lead(Box<DialLeaderGuard>),
    Wait(DialWaiter),
}

/// The id of the runtime the caller is currently running on, if any.
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
    /// Authority (`host:port`) of the peer.
    pub authority: String,
    /// Connection-fixed TLS/wire/route identity.
    pub identity: ConnectionIdentity,
}

impl PoolKey {
    /// Construct a [`PoolKey`] from `authority` and `identity`.
    pub fn new(authority: impl Into<String>, identity: ConnectionIdentity) -> Self {
        Self {
            authority: authority.into(),
            identity,
        }
    }
}

#[derive(Default)]
struct PoolState {
    idle: HashMap<PoolKey, Vec<Idle>>,
    #[cfg(feature = "http2")]
    shared_h2: HashMap<PoolKey, Vec<SharedH2Entry>>,
    #[cfg(feature = "http3")]
    shared_h3: HashMap<PoolKey, Vec<SharedH3Entry>>,
    next_seq: u64,
}

impl PoolState {
    fn bump_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    fn count_h1(entries: &[Idle], now: Instant, idle_timeout: Duration) -> usize {
        entries
            .iter()
            .filter(|entry| now.saturating_duration_since(entry.since()) <= idle_timeout)
            .count()
    }

    #[cfg(feature = "http2")]
    fn count_h2(entries: &[SharedH2Entry], idle_timeout: Duration) -> usize {
        entries
            .iter()
            .filter(|entry| {
                entry.session.is_usable()
                    && entry
                        .session
                        .idle_duration()
                        .is_some_and(|age| age <= idle_timeout)
            })
            .count()
    }

    #[cfg(feature = "http3")]
    fn count_h3(entries: &[SharedH3Entry], idle_timeout: Duration) -> usize {
        entries
            .iter()
            .filter(|entry| {
                entry.session.is_usable()
                    && entry
                        .session
                        .idle_duration()
                        .is_some_and(|age| age <= idle_timeout)
            })
            .count()
    }

    fn idle_count_for_key(&self, key: &PoolKey, now: Instant, idle_timeout: Duration) -> usize {
        let h1 = self
            .idle
            .get(key)
            .map_or(0, |entries| Self::count_h1(entries, now, idle_timeout));
        #[cfg(feature = "http2")]
        let h2 = self
            .shared_h2
            .get(key)
            .map_or(0, |entries| Self::count_h2(entries, idle_timeout));
        #[cfg(not(feature = "http2"))]
        let h2 = 0;
        #[cfg(feature = "http3")]
        let h3 = self
            .shared_h3
            .get(key)
            .map_or(0, |entries| Self::count_h3(entries, idle_timeout));
        #[cfg(not(feature = "http3"))]
        let h3 = 0;
        h1 + h2 + h3
    }

    fn total_idle_count(&self, now: Instant, idle_timeout: Duration) -> usize {
        let h1: usize = self
            .idle
            .values()
            .map(|entries| Self::count_h1(entries, now, idle_timeout))
            .sum();
        #[cfg(feature = "http2")]
        let h2: usize = self
            .shared_h2
            .values()
            .map(|entries| Self::count_h2(entries, idle_timeout))
            .sum();
        #[cfg(not(feature = "http2"))]
        let h2 = 0;
        #[cfg(feature = "http3")]
        let h3: usize = self
            .shared_h3
            .values()
            .map(|entries| Self::count_h3(entries, idle_timeout))
            .sum();
        #[cfg(not(feature = "http3"))]
        let h3 = 0;
        h1 + h2 + h3
    }

    fn reap(&mut self, now: Instant, idle_timeout: Duration) -> usize {
        let mut evicted = 0;

        self.idle.retain(|_, entries| {
            let before = entries.len();
            entries.retain(|entry| now.saturating_duration_since(entry.since()) <= idle_timeout);
            evicted += before - entries.len();
            !entries.is_empty()
        });

        #[cfg(feature = "http2")]
        self.shared_h2.retain(|_, entries| {
            let before = entries.len();
            entries.retain(|entry| {
                entry.session.is_usable()
                    && entry
                        .session
                        .idle_duration()
                        .is_none_or(|age| age <= idle_timeout)
            });
            evicted += before - entries.len();
            !entries.is_empty()
        });

        #[cfg(feature = "http3")]
        self.shared_h3.retain(|_, entries| {
            let before = entries.len();
            entries.retain(|entry| {
                entry.session.is_usable()
                    && entry
                        .session
                        .idle_duration()
                        .is_none_or(|age| age <= idle_timeout)
            });
            evicted += before - entries.len();
            !entries.is_empty()
        });

        evicted
    }

    fn evict_oldest_matching(&mut self, key_filter: Option<&PoolKey>, now: Instant) -> bool {
        use std::cmp::Reverse;

        enum Victim {
            Http1(PoolKey, usize),
            #[cfg(feature = "http2")]
            Http2(PoolKey, usize),
            #[cfg(feature = "http3")]
            Http3(PoolKey, usize),
        }

        let mut oldest: Option<((Duration, Reverse<u64>), Victim)> = None;
        let matches = |k: &PoolKey| key_filter.is_none_or(|target| target == k);

        for (key, entries) in self.idle.iter().filter(|(k, _)| matches(k)) {
            for (index, entry) in entries.iter().enumerate() {
                let rank = (
                    now.saturating_duration_since(entry.since()),
                    Reverse(entry.seq()),
                );
                if oldest.as_ref().is_none_or(|(best, _)| rank > *best) {
                    oldest = Some((rank, Victim::Http1(key.clone(), index)));
                }
            }
        }

        #[cfg(feature = "http2")]
        for (key, entries) in self.shared_h2.iter().filter(|(k, _)| matches(k)) {
            for (index, entry) in entries.iter().enumerate() {
                let Some(age) = entry.session.idle_duration() else {
                    continue;
                };
                let rank = (age, Reverse(entry.seq));
                if oldest.as_ref().is_none_or(|(best, _)| rank > *best) {
                    oldest = Some((rank, Victim::Http2(key.clone(), index)));
                }
            }
        }

        #[cfg(feature = "http3")]
        for (key, entries) in self.shared_h3.iter().filter(|(k, _)| matches(k)) {
            for (index, entry) in entries.iter().enumerate() {
                let Some(age) = entry.session.idle_duration() else {
                    continue;
                };
                let rank = (age, Reverse(entry.seq));
                if oldest.as_ref().is_none_or(|(best, _)| rank > *best) {
                    oldest = Some((rank, Victim::Http3(key.clone(), index)));
                }
            }
        }

        match oldest {
            Some((_, Victim::Http1(key, index))) => {
                remove_at(&mut self.idle, &key, index);
                true
            }
            #[cfg(feature = "http2")]
            Some((_, Victim::Http2(key, index))) => {
                remove_at(&mut self.shared_h2, &key, index);
                true
            }
            #[cfg(feature = "http3")]
            Some((_, Victim::Http3(key, index))) => {
                remove_at(&mut self.shared_h3, &key, index);
                true
            }
            None => false,
        }
    }

    fn enforce_caps(&mut self, key: &PoolKey, config: PoolConfig, now: Instant) {
        self.reap(now, config.idle_timeout);
        while self.idle_count_for_key(key, now, config.idle_timeout) > config.max_idle_per_authority
        {
            if !self.evict_oldest_matching(Some(key), now) {
                break;
            }
        }
        while self.total_idle_count(now, config.idle_timeout) > config.max_idle_total {
            if !self.evict_oldest_matching(None, now) {
                break;
            }
        }
    }
}

fn remove_at<T>(map: &mut HashMap<PoolKey, Vec<T>>, key: &PoolKey, index: usize) {
    if let Some(entries) = map.get_mut(key) {
        entries.remove(index);
        if entries.is_empty() {
            map.remove(key);
        }
    }
}

#[derive(Default)]
struct PoolInner {
    config: PoolConfig,
    state: Mutex<PoolState>,
    in_flight: Mutex<HashMap<String, Arc<Semaphore>>>,
    /// Created once from `max_in_flight_total`; `None` means the caller
    /// explicitly opted out of the global bound.
    global_in_flight: Option<Arc<Semaphore>>,
    dial_flights: Mutex<HashMap<PoolKey, Arc<DialFlight>>>,
    reaper_started: AtomicBool,
}

struct ReaperResetGuard {
    weak: Weak<PoolInner>,
}

impl Drop for ReaperResetGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.weak.upgrade() {
            inner.reaper_started.store(false, Ordering::Release);
        }
    }
}

/// A shared, cloneable connection pool.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new(PoolConfig::default())
    }
}

impl Pool {
    /// Create a pool governed by `config`.
    pub fn new(config: PoolConfig) -> Self {
        let global_in_flight = config
            .max_in_flight_total
            .map(|limit| Arc::new(Semaphore::new(limit)));
        Self {
            inner: Arc::new(PoolInner {
                config,
                global_in_flight,
                ..PoolInner::default()
            }),
        }
    }

    /// Return this pool's configuration.
    pub fn config(&self) -> PoolConfig {
        self.inner.config
    }

    pub(crate) fn pooling_enabled(&self) -> bool {
        self.inner.config.max_idle_per_authority > 0 && self.inner.config.max_idle_total > 0
    }

    /// Acquire one in-flight exchange slot for `authority`, waiting if
    /// `max_in_flight_per_authority` is saturated.
    pub(crate) async fn acquire_in_flight(
        &self,
        authority: &str,
    ) -> Result<Option<PoolInFlightPermit>, NetError> {
        let global =
            match self.inner.config.max_in_flight_total {
                Some(0) => {
                    return Err(NetError::Protocol(
                        "pool max_in_flight_total cannot be 0".into(),
                    ));
                }
                Some(_) => {
                    let Some(semaphore) = self.inner.global_in_flight.as_ref() else {
                        return Err(NetError::Protocol(
                            "global in-flight limiter was not initialized".into(),
                        ));
                    };
                    Some(Arc::clone(semaphore).acquire_owned().await.map_err(|_| {
                        NetError::Protocol("global in-flight limiter closed".into())
                    })?)
                }
                None => None,
            };
        let per_authority =
            match self.inner.config.max_in_flight_per_authority {
                Some(0) => {
                    return Err(NetError::Protocol(
                        "pool max_in_flight_per_authority cannot be 0".into(),
                    ));
                }
                Some(limit) => {
                    let semaphore = {
                        let mut map = self
                            .inner
                            .in_flight
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        Arc::clone(
                            map.entry(authority.to_owned())
                                .or_insert_with(|| Arc::new(Semaphore::new(limit))),
                        )
                    };
                    Some(semaphore.acquire_owned().await.map_err(|_| {
                        NetError::Protocol("in-flight limiter semaphore closed".into())
                    })?)
                }
                None => None,
            };
        if global.is_none() && per_authority.is_none() {
            return Ok(None);
        }
        Ok(Some(PoolInFlightPermit {
            _per_authority: per_authority,
            _global: global,
        }))
    }

    /// Coordinate concurrent cold dials on the same [`PoolKey`] so requests
    /// coalesce onto a single multiplexed session instead of dialing N sockets.
    pub(crate) fn begin_or_join_dial(&self, key: &PoolKey) -> DialDecision {
        let mut flights = self
            .inner
            .dial_flights
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(flight) = flights.get(key) {
            return DialDecision::Wait(DialWaiter {
                done_rx: flight.done_tx.subscribe(),
            });
        }
        let (done_tx, _done_rx) = watch::channel(false);
        let flight = Arc::new(DialFlight { done_tx });
        flights.insert(key.clone(), Arc::clone(&flight));
        DialDecision::Lead(Box::new(DialLeaderGuard {
            inner: Arc::clone(&self.inner),
            key: key.clone(),
            flight,
        }))
    }

    /// Take the newest live idle connection for `key`, whatever its protocol.
    pub fn take(&self, key: &PoolKey) -> Option<IdleConnection> {
        self.take_matching(key, |_| true)
    }

    /// Take the newest live idle HTTP/1.1 connection whose protocol `accept` approves.
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
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let entries = state.idle.get_mut(key)?;
        let now = Instant::now();
        let mut taken = None;
        for index in (0..entries.len()).rev() {
            let age = now.saturating_duration_since(entries[index].since());
            if age > self.inner.config.idle_timeout || entries[index].runtime() != current {
                entries.remove(index);
                continue;
            }
            if !accept(entries[index].protocol()) {
                continue;
            }
            let entry = entries.remove(index);
            taken = Some(entry.into_connection(age));
            break;
        }
        if entries.is_empty() {
            state.idle.remove(key);
        }
        taken
    }

    /// Checkout a stream permit from a live shared HTTP/2 session for `key`.
    #[cfg(feature = "http2")]
    pub(crate) fn checkout_http2(&self, key: &PoolKey) -> Option<CheckedOutHttp2> {
        let current = current_runtime_id();
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let entries = state.shared_h2.get_mut(key)?;
        let mut selected = None;

        for index in (0..entries.len()).rev() {
            let entry = &entries[index];
            let idle_age = entry.session.idle_duration();
            let expired = idle_age.is_some_and(|age| age > self.inner.config.idle_timeout);
            if !entry.session.is_usable() || entry.runtime != current || expired {
                entries.remove(index);
                continue;
            }
            if let Some(permit) = entry.session.try_reserve_stream() {
                selected = Some(CheckedOutHttp2 {
                    session: entry.session.clone(),
                    permit,
                    local_port: entry.local_port,
                    socket: entry.socket.as_ref().and_then(crate::tcp_info::duplicate),
                    age: idle_age.unwrap_or(Duration::ZERO),
                });
                break;
            }
        }

        if entries.is_empty() {
            state.shared_h2.remove(key);
        }
        selected
    }

    /// Whether a live, non-expired HTTP/2 session already exists for `key` on
    /// the current runtime.
    #[cfg(feature = "http2")]
    pub(crate) fn has_live_http2(&self, key: &PoolKey) -> bool {
        let current = current_runtime_id();
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entries) = state.shared_h2.get_mut(key) else {
            return false;
        };
        entries.retain(|entry| {
            entry.session.is_usable()
                && entry.runtime == current
                && entry
                    .session
                    .idle_duration()
                    .is_none_or(|age| age <= self.inner.config.idle_timeout)
        });
        let has_live = !entries.is_empty();
        if !has_live {
            state.shared_h2.remove(key);
        }
        has_live
    }

    /// Register a newly negotiated shared HTTP/2 session in the pool.
    #[cfg(feature = "http2")]
    pub(crate) fn register_http2(
        &self,
        key: &PoolKey,
        session: H2ClientSession,
        local_port: Option<u16>,
        socket: Option<std::net::TcpStream>,
    ) {
        if !self.pooling_enabled() {
            return;
        }
        self.ensure_reaper();
        let now = Instant::now();
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let seq = state.bump_seq();
        state
            .shared_h2
            .entry(key.clone())
            .or_default()
            .push(SharedH2Entry {
                session,
                local_port,
                socket,
                seq,
                runtime: current_runtime_id(),
            });
        state.enforce_caps(key, self.inner.config, now);
    }

    /// Checkout a handle to a live shared HTTP/3 session for `key`.
    #[cfg(feature = "http3")]
    pub(crate) fn checkout_http3(&self, key: &PoolKey) -> Option<CheckedOutHttp3> {
        let current = current_runtime_id();
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let entries = state.shared_h3.get_mut(key)?;
        let mut selected = None;

        for index in (0..entries.len()).rev() {
            let entry = &entries[index];
            let idle_age = entry.session.idle_duration();
            let expired = idle_age.is_some_and(|age| age > self.inner.config.idle_timeout);
            if !entry.session.is_usable() || entry.runtime != current || expired {
                entries.remove(index);
                continue;
            }
            selected = Some(CheckedOutHttp3 {
                session: entry.session.clone(),
                local_port: entry.local_port,
                age: idle_age.unwrap_or(Duration::ZERO),
            });
            break;
        }

        if entries.is_empty() {
            state.shared_h3.remove(key);
        }
        selected
    }

    /// Whether a live, non-expired HTTP/3 session already exists for `key` on
    /// the current runtime.
    #[cfg(feature = "http3")]
    pub(crate) fn has_live_http3(&self, key: &PoolKey) -> bool {
        let current = current_runtime_id();
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entries) = state.shared_h3.get_mut(key) else {
            return false;
        };
        entries.retain(|entry| {
            entry.session.is_usable()
                && entry.runtime == current
                && entry
                    .session
                    .idle_duration()
                    .is_none_or(|age| age <= self.inner.config.idle_timeout)
        });
        let has_live = !entries.is_empty();
        if !has_live {
            state.shared_h3.remove(key);
        }
        has_live
    }

    /// Register a newly negotiated shared HTTP/3 session in the pool.
    #[cfg(feature = "http3")]
    pub(crate) fn register_http3(&self, key: &PoolKey, session: H3Session) {
        if !self.pooling_enabled() {
            return;
        }
        self.ensure_reaper();
        let now = Instant::now();
        let local_port = session.local_port();
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let seq = state.bump_seq();
        state
            .shared_h3
            .entry(key.clone())
            .or_default()
            .push(SharedH3Entry {
                session,
                local_port,
                seq,
                runtime: current_runtime_id(),
            });
        state.enforce_caps(key, self.inner.config, now);
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
        if !self.pooling_enabled() {
            return;
        }
        self.ensure_reaper();
        let now = Instant::now();
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let seq = state.bump_seq();
        state
            .idle
            .entry(key.clone())
            .or_default()
            .push(Idle::Http1 {
                stream,
                buffered,
                local_port,
                socket,
                since: now,
                seq,
                runtime: current_runtime_id(),
            });
        state.enforce_caps(key, self.inner.config, now);
    }

    /// Synchronously evict all expired idle connections, dead shared sessions,
    /// and unreferenced per-authority limiters.
    pub fn reap(&self) -> usize {
        reap_inner(&self.inner)
    }

    /// Immediately evict every pooled HTTP/1.1, HTTP/2, and HTTP/3 connection
    /// without disturbing already checked-out in-flight streams
    /// (`[INV-TRANSPORT-15]`).
    ///
    /// Returns the number of pooled connection entries removed. Callers use
    /// this on transport-level retry backoff or after a suspected network
    /// change so the next attempt dials fresh sockets instead of inheriting
    /// half-open pooled sessions.
    pub fn clear(&self) -> usize {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut evicted = 0usize;
        for entries in state.idle.values() {
            evicted += entries.len();
        }
        state.idle.clear();
        #[cfg(feature = "http2")]
        {
            for entries in state.shared_h2.values() {
                evicted += entries.len();
            }
            state.shared_h2.clear();
        }
        #[cfg(feature = "http3")]
        {
            for entries in state.shared_h3.values() {
                evicted += entries.len();
            }
            state.shared_h3.clear();
        }
        evicted
    }

    /// Number of idle connections retained for `key` (tests, diagnostics).
    pub fn idle_count(&self, key: &PoolKey) -> usize {
        let now = Instant::now();
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.idle_count_for_key(key, now, self.inner.config.idle_timeout)
    }

    /// Total idle connections retained across all keys.
    pub fn total_idle_count(&self) -> usize {
        let now = Instant::now();
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.total_idle_count(now, self.inner.config.idle_timeout)
    }

    fn ensure_reaper(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.inner.reaper_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(&self.inner);
        let interval =
            (self.inner.config.idle_timeout / 2).clamp(MIN_REAPER_INTERVAL, MAX_REAPER_INTERVAL);
        handle.spawn(async move {
            let _reset = ReaperResetGuard { weak: weak.clone() };
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                reap_inner(&inner);
            }
        });
    }
}

fn reap_inner(inner: &PoolInner) -> usize {
    let now = Instant::now();
    let evicted = {
        let mut state = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.reap(now, inner.config.idle_timeout)
    };
    if let Some(limit) = inner.config.max_in_flight_per_authority {
        let mut map = inner.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, semaphore| {
            !(Arc::strong_count(semaphore) == 1 && semaphore.available_permits() == limit)
        });
    }
    evicted
}

#[cfg(test)]
mod tests;
