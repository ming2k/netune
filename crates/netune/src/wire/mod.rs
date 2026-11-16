//! The real transport: connections that are dialled, pooled and spoken to.
//!
//! [`Wire`] is the [`RoundTrip`] that touches the network. It owns exactly the
//! decisions that need a connection in hand — which pooled connection may
//! serve a request, whether a pooled one is still alive, which protocol the
//! connection speaks, and whether a request that died on a reused connection
//! may be sent again — and delegates the speaking to one module per protocol.
//!
//! # Replay is a safety decision, not a convenience
//!
//! A pooled socket can be closed by the peer while it sits idle, and virtually
//! every peer does so without notice. Two mechanisms absorb that, in order:
//!
//! 1. **Probe before use.** A connection taken from the pool is polled once.
//!    An idle HTTP/1.1 socket that is readable has either been closed or
//!    carries bytes nobody asked for; both make it unusable, and it is
//!    discarded *before* any request byte is written, so nothing is replayed
//!    at all.
//! 2. **Replay only what is safe.** If the socket dies in the window between
//!    the probe and the response head, the request may already have reached
//!    the origin. It is sent again only when a second copy cannot hurt: the
//!    peer said it did not process it ([`NetError::RetryableProtocol`]), or
//!    the request is idempotent or carries an idempotency key
//!    ([`Request::is_replay_safe`]). Any other request fails with a retryable
//!    error and the decision goes to the caller, who knows what a duplicate
//!    would cost ([`INV-TRANSPORT-06`]).

mod h1;
#[cfg(feature = "http2")]
mod h2;
#[cfg(feature = "http3")]
mod h3;

use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use netune_trace::{
    ConnectionInfo, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EventKind, TraceCollector,
};
use tokio::io::{AsyncRead, ReadBuf};

use crate::connect::{Connector, Established, Transport};
use crate::error::NetError;
use crate::exchange::{Attempt, BoxFuture, Exchange, Request, RoundTrip};
use crate::pool::{
    DialDecision, DialLeaderGuard, Http1Idle, IdleConnection, Pool, PoolInFlightPermit, PoolKey,
    Protocol,
};
use crate::profile::Http2Mode;

/// A [`RoundTrip`] over real connections: a [`Connector`] to open them and a
/// [`Pool`] to keep them.
pub struct Wire<C: Connector> {
    connector: C,
    pool: Pool,
    #[cfg(feature = "http3")]
    quic: netune_quic::QuicConnector,
}

impl<C: Connector> Wire<C> {
    /// Construct a real network [`RoundTrip`] over `connector` and `pool`.
    pub fn new(connector: C, pool: Pool) -> Self {
        Self {
            connector,
            pool,
            #[cfg(feature = "http3")]
            quic: netune_quic::QuicConnector::default(),
        }
    }

    /// Supply a customized QUIC connector used for `HttpProtocol::Http3` targets.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn with_quic(mut self, quic: netune_quic::QuicConnector) -> Self {
        self.quic = quic;
        self
    }

    /// The pool this transport keeps its connections in.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// The connector this transport dials with.
    pub fn connector(&self) -> &C {
        &self.connector
    }

    /// The QUIC connector used for HTTP/3 requests.
    #[cfg(feature = "http3")]
    pub fn quic(&self) -> &netune_quic::QuicConnector {
        &self.quic
    }

    /// Take an idle HTTP/1.1 connection, discarding any that died while idle.
    fn checkout_http1(&self, attempt: Attempt<'_>, key: &PoolKey) -> Option<Http1Idle> {
        loop {
            let candidate = self
                .pool
                .take_matching(key, |protocol| protocol == Protocol::Http1)?;
            match candidate {
                IdleConnection::Http1(mut idle) => {
                    if idle.buffered.is_empty() && is_quiet(&mut idle.stream) {
                        return Some(idle);
                    }
                    let age_ms = idle.age.as_millis() as u32;
                    record_stale(
                        attempt.recorder,
                        age_ms,
                        "pooled socket was closed by the peer while idle; it was discarded before use",
                        "probe",
                    );
                }
            }
        }
    }

    async fn exchange(
        &self,
        attempt: Attempt<'_>,
        request: &Request,
    ) -> Result<Exchange, NetError> {
        let key = attempt.plan.pool_key();
        let mut in_flight = self
            .pool
            .acquire_in_flight(&attempt.plan.target.authority)
            .await?;

        #[cfg(feature = "http3")]
        if attempt.plan.is_http3() {
            return self
                .exchange_http3(attempt, request, &key, &mut in_flight)
                .await;
        }

        let mode = attempt.plan.http2_mode();
        let mut coalesce_budget = mode != Http2Mode::Off && self.pool.pooling_enabled();

        loop {
            #[cfg(feature = "http2")]
            if mode != Http2Mode::Off
                && let Some(h2) = self.pool.checkout_http2(&key)
            {
                let age_ms = h2.age.as_millis() as u32;
                attempt.recorder.mark(EventKind::ConnectReused, age_ms, 0);
                let info = ConnectionInfo {
                    reused: true,
                    local_port: h2.local_port,
                    age_ns: u64::try_from(h2.age.as_nanos()).ok(),
                };
                match h2::exchange_on_session(
                    &h2.session,
                    h2.permit,
                    h2.socket,
                    info,
                    attempt,
                    request,
                    &mut in_flight,
                )
                .await
                {
                    Ok(exchange) => return Ok(exchange),
                    Err(error) if may_replay(&error, request) => {
                        record_stale(
                            attempt.recorder,
                            age_ms,
                            "pooled HTTP/2 session died before a response head; the attempt reconnected",
                            error.class(),
                        );
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }

            if mode != Http2Mode::Force
                && let Some(idle) = self.checkout_http1(attempt, &key)
            {
                let age_ms = idle.age.as_millis() as u32;
                attempt.recorder.mark(EventKind::ConnectReused, age_ms, 0);
                let connection = h1::Connection {
                    stream: idle.stream,
                    buffered: idle.buffered,
                    local_port: idle.local_port,
                    socket: idle.socket,
                    info: ConnectionInfo {
                        reused: true,
                        local_port: idle.local_port,
                        age_ns: u64::try_from(idle.age.as_nanos()).ok(),
                    },
                };
                match h1::exchange(
                    &self.pool,
                    key.clone(),
                    connection,
                    attempt,
                    request,
                    &mut in_flight,
                )
                .await
                {
                    Ok(exchange) => return Ok(exchange),
                    Err(error) if may_replay(&error, request) => {
                        record_stale(
                            attempt.recorder,
                            age_ms,
                            "pooled socket died before a response head; the attempt reconnected",
                            error.class(),
                        );
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }

            let dial_guard = if coalesce_budget {
                match self.pool.begin_or_join_dial(&key) {
                    DialDecision::Lead(guard) => Some(guard),
                    DialDecision::Wait(waiter) => {
                        coalesce_budget = false;
                        waiter.wait().await;
                        continue;
                    }
                }
            } else {
                None
            };

            return self
                .dial_and_exchange(attempt, request, &key, dial_guard, &mut in_flight)
                .await;
        }
    }

    #[cfg(feature = "http3")]
    async fn exchange_http3(
        &self,
        attempt: Attempt<'_>,
        request: &Request,
        key: &PoolKey,
        in_flight: &mut Option<PoolInFlightPermit>,
    ) -> Result<Exchange, NetError> {
        if self.connector.route_shape().is_some() {
            return Err(NetError::Protocol(
                "HTTP/3 over a TCP proxy connector is not supported".into(),
            ));
        }
        let mut coalesce_budget = self.pool.pooling_enabled();
        loop {
            if let Some(h3) = self.pool.checkout_http3(key) {
                let age_ms = h3.age.as_millis() as u32;
                attempt.recorder.mark(EventKind::ConnectReused, age_ms, 0);
                let info = ConnectionInfo {
                    reused: true,
                    local_port: h3.local_port,
                    age_ns: u64::try_from(h3.age.as_nanos()).ok(),
                };
                match h3::exchange_on_session(&h3.session, info, attempt, request, in_flight).await
                {
                    Ok(exchange) => return Ok(exchange),
                    Err(error) if may_replay(&error, request) => {
                        record_stale(
                            attempt.recorder,
                            age_ms,
                            "pooled HTTP/3 session died before a response head; the attempt reconnected",
                            error.class(),
                        );
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }

            let dial_guard = if coalesce_budget {
                match self.pool.begin_or_join_dial(key) {
                    DialDecision::Lead(guard) => Some(guard),
                    DialDecision::Wait(waiter) => {
                        coalesce_budget = false;
                        waiter.wait().await;
                        continue;
                    }
                }
            } else {
                None
            };

            let session =
                h3::dial_and_handshake(&self.quic, self.connector.egress_confinement(), attempt)
                    .await?;
            let info = ConnectionInfo {
                reused: false,
                local_port: session.local_port(),
                age_ns: None,
            };
            self.pool.register_http3(key, session.clone());
            drop(dial_guard);
            return h3::exchange_on_session(&session, info, attempt, request, in_flight).await;
        }
    }

    async fn dial_and_exchange(
        &self,
        attempt: Attempt<'_>,
        request: &Request,
        key: &PoolKey,
        dial_guard: Option<Box<DialLeaderGuard>>,
        in_flight: &mut Option<PoolInFlightPermit>,
    ) -> Result<Exchange, NetError> {
        let plan = attempt.plan;
        let recorder = attempt.recorder;
        let established = self.connector.connect(&plan.target, recorder).await?;
        let info = ConnectionInfo {
            reused: false,
            local_port: established.local_port,
            age_ns: None,
        };

        if speaks_http2(plan.http2_mode(), &established) {
            // Without the `http2` feature this fails closed instead of falling
            // back to HTTP/1.1: a caller that mandated HTTP/2 must not be
            // handed a downgraded request.
            #[cfg(not(feature = "http2"))]
            {
                drop(dial_guard);
                return Err(NetError::Protocol(
                    "HTTP/2 was requested but the `http2` feature is not compiled in".into(),
                ));
            }
            #[cfg(feature = "http2")]
            {
                let session = h2::handshake(established.stream, attempt).await?;
                let permit = session.try_reserve_stream().ok_or_else(|| {
                    NetError::Protocol("fresh HTTP/2 session rejected its initial stream".into())
                })?;
                let socket = established
                    .socket
                    .as_ref()
                    .and_then(crate::tcp_info::duplicate);
                self.pool.register_http2(
                    key,
                    session.clone(),
                    established.local_port,
                    established.socket,
                );
                // Release singleflight followers now so concurrent requests share
                // this session immediately instead of waiting on our response head.
                drop(dial_guard);
                return h2::exchange_on_session(
                    &session, permit, socket, info, attempt, request, in_flight,
                )
                .await;
            }
        }

        drop(dial_guard);
        let connection = h1::Connection {
            stream: established.stream,
            buffered: BytesMut::new(),
            local_port: established.local_port,
            socket: established.socket,
            info,
        };
        h1::exchange(
            &self.pool,
            key.clone(),
            connection,
            attempt,
            request,
            in_flight,
        )
        .await
    }

    async fn warm(&self, attempt: Attempt<'_>) -> Result<bool, NetError> {
        let plan = attempt.plan;
        let key = plan.pool_key();

        #[cfg(feature = "http3")]
        if plan.is_http3() {
            if self.connector.route_shape().is_some() {
                return Err(NetError::Protocol(
                    "HTTP/3 over a TCP proxy connector is not supported".into(),
                ));
            }
            if self.pool.has_live_http3(&key) || self.pool.idle_count(&key) > 0 {
                return Ok(false);
            }
            let session =
                h3::dial_and_handshake(&self.quic, self.connector.egress_confinement(), attempt)
                    .await?;
            self.pool.register_http3(&key, session);
            return Ok(true);
        }

        #[cfg(feature = "http2")]
        let has_h2 = self.pool.has_live_http2(&key);
        #[cfg(not(feature = "http2"))]
        let has_h2 = false;
        if has_h2 || self.pool.idle_count(&key) > 0 {
            return Ok(false);
        }
        let established = self
            .connector
            .connect(&plan.target, attempt.recorder)
            .await?;
        // Warm the connection in the protocol the next request will actually
        // use; pooling a negotiated HTTP/2 socket as if it were HTTP/1.1 would
        // hand it to the wrong writer.
        if speaks_http2(plan.http2_mode(), &established) {
            #[cfg(not(feature = "http2"))]
            return Err(NetError::Protocol(
                "HTTP/2 was requested but the `http2` feature is not compiled in".into(),
            ));
            #[cfg(feature = "http2")]
            {
                let session = h2::handshake(established.stream, attempt).await?;
                self.pool
                    .register_http2(&key, session, established.local_port, established.socket);
                return Ok(true);
            }
        }
        let mut stream = established.stream;
        // The dial tap belongs to this warm-up, not to whichever attempt takes
        // the connection later.
        let _ = stream.swap_tap(netune_trace::SocketTap::Off);
        self.pool.put_http1(
            &key,
            stream,
            BytesMut::new(),
            established.local_port,
            established.socket,
        );
        Ok(true)
    }
}

impl<C: Connector + 'static> RoundTrip for Wire<C> {
    fn round_trip<'a>(
        &'a self,
        attempt: Attempt<'a>,
        request: &'a Request,
    ) -> BoxFuture<'a, Result<Exchange, NetError>> {
        Box::pin(self.exchange(attempt, request))
    }

    fn open_stream<'a>(
        &'a self,
        attempt: Attempt<'a>,
    ) -> BoxFuture<'a, Result<Established, NetError>> {
        Box::pin(
            self.connector
                .connect(&attempt.plan.target, attempt.recorder),
        )
    }

    fn prewarm<'a>(&'a self, attempt: Attempt<'a>) -> BoxFuture<'a, Result<bool, NetError>> {
        Box::pin(self.warm(attempt))
    }

    fn socket_shape(&self) -> Option<String> {
        self.connector.socket_shape()
    }

    fn route_shape(&self) -> Option<String> {
        self.connector.route_shape()
    }
}

/// Whether a freshly established connection carries HTTP/2 for this plan:
/// prior knowledge, or a negotiated `h2` when the plan allows the upgrade.
fn speaks_http2(mode: Http2Mode, established: &Established) -> bool {
    match mode {
        Http2Mode::Force => true,
        Http2Mode::Negotiate => established.alpn == Some(netune_trace::Alpn::H2),
        // A peer that negotiated `h2` against a client that never offered to
        // speak it cannot be served by the HTTP/1.1 writer either; without the
        // codec compiled in that is a refusal, with it the client's policy
        // said HTTP/1.1 and the profile's ALPN list is what kept `h2` out.
        Http2Mode::Off => {
            cfg!(not(feature = "http2")) && established.alpn == Some(netune_trace::Alpn::H2)
        }
    }
}

/// Whether a request that failed on a reused connection may be sent again.
fn may_replay(error: &NetError, request: &Request) -> bool {
    if !request.body.can_replay() {
        return false;
    }
    match error {
        // The peer said it did not process the stream.
        NetError::RetryableProtocol(_) => true,
        _ => error.is_stale_connection() && request.is_replay_safe(),
    }
}

/// Record that a pooled connection was found dead and abandoned.
fn record_stale(recorder: &TraceCollector, age_ms: u32, message: &str, class: &str) {
    recorder.record_note(
        DiagnosticRecord::new(DiagnosticCode::EGRESS_POOL_STALE)
            .with_phase(DiagnosticPhase::Pool)
            .with_message(message)
            .with_field("error_class", class),
    );
    recorder.mark(EventKind::ConnectStaleDiscarded, age_ms, 0);
}

/// Split a request head into its target `:authority` and lowercased regular
/// headers (RFC 9113 §8.3.1 / RFC 9114 §4.3.1), promoting any caller `Host`
/// header to `:authority` so the wire request carries one authority identity.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) fn request_parts(
    head: &netune_http1::RequestHead,
    fallback_authority: &str,
) -> (String, Vec<(String, String)>) {
    let mut authority: Option<String> = None;
    let mut headers = Vec::new();
    match &head.raw_headers {
        Some(raw) => {
            for (name, value) in raw {
                if name.eq_ignore_ascii_case("host") {
                    authority.get_or_insert_with(|| value.clone());
                } else {
                    headers.push((name.to_ascii_lowercase(), value.clone()));
                }
            }
        }
        None => {
            for (name, value) in head.headers.iter() {
                if name == http::header::HOST {
                    if let Ok(value) = value.to_str() {
                        authority.get_or_insert_with(|| value.to_string());
                    }
                } else {
                    headers.push((
                        name.as_str().to_string(),
                        value.to_str().unwrap_or_default().to_string(),
                    ));
                }
            }
        }
    }
    (
        authority.unwrap_or_else(|| fallback_authority.to_string()),
        headers,
    )
}

/// Whether an idle stream has nothing to say: not closed, not failed, and no
/// unsolicited bytes.
///
/// One non-blocking poll with a waker that goes nowhere. `Pending` is the only
/// healthy answer for an idle HTTP/1.1 connection; end-of-stream, an error or
/// data all mean the next request must not be written to it. A TLS layer
/// absorbs its own post-handshake records (tickets, key updates) inside this
/// poll and still answers `Pending`.
fn is_quiet(stream: &mut Box<dyn Transport>) -> bool {
    let mut context = Context::from_waker(Waker::noop());
    let mut byte = [0u8; 1];
    let mut buffer = ReadBuf::new(&mut byte);
    matches!(
        Pin::new(stream).poll_read(&mut context, &mut buffer),
        Poll::Pending
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::RequestBody;
    use http::Method;
    use netune_http1::RequestHead;
    use tokio::io::AsyncWriteExt;

    fn boxed(stream: tokio::io::DuplexStream) -> Box<dyn Transport> {
        Box::new(stream)
    }

    #[tokio::test]
    async fn an_idle_stream_is_quiet_until_the_peer_closes_or_speaks() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut ours = boxed(ours);
        assert!(is_quiet(&mut ours), "an open, silent stream is reusable");

        theirs.write_all(b"x").await.expect("write");
        assert!(!is_quiet(&mut ours), "unsolicited bytes poison the stream");

        let (ours, theirs) = tokio::io::duplex(64);
        let mut ours = boxed(ours);
        drop(theirs);
        assert!(!is_quiet(&mut ours), "a closed stream is not reusable");
    }

    #[test]
    fn inv_transport_06_a_bare_post_is_not_replayed_on_a_stale_socket() {
        let stale = || NetError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        let get = Request::new(RequestHead::new(Method::GET, "/"), RequestBody::Empty);
        let post = Request::new(RequestHead::new(Method::POST, "/"), "body");
        assert!(may_replay(&stale(), &get));
        assert!(!may_replay(&stale(), &post));
        // The peer's own word that it did not process the request overrides
        // the method.
        assert!(may_replay(
            &NetError::RetryableProtocol("refused".into()),
            &post
        ));
        // A failure that is not a dead-socket signature is never replayed.
        assert!(!may_replay(&NetError::Protocol("broken".into()), &get));
        let timeout = NetError::Timeout {
            phase: DiagnosticPhase::Response,
            waiting_for: "response head",
            limit: std::time::Duration::from_secs(1),
        };
        assert!(!may_replay(&timeout, &get));
    }
}
