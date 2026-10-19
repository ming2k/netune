//! WebSocket session policy: client-initiated heartbeat liveness.
//!
//! A WebSocket connection is dedicated and stateful (`INV-WS-05`), so unlike
//! the keep-alive pool it cannot rely on a fresh dial to absorb a silently
//! culled socket ([ADR-0005]). The client must *prove* liveness: send a ping
//! every `ping_interval`, and declare the session dead if no pong arrives
//! within `pong_timeout`.
//!
//! Deliberately out of scope, by the same replay-safety principle that keeps
//! retry policy out of `Client` ([INV-TRANSPORT-01]): automatic reconnection.
//! A WebSocket session's identity *is* its connection; silently re-dialing
//! would silently drop in-flight messages. Reconnection is the harness's
//! policy, layered above the `NetError` this module reports.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, sleep};

use bytes::Bytes;
use netune_ws::Message;

use crate::error::NetError;
use crate::ws::WsStream;

/// Client-side heartbeat policy for a WebSocket session.
#[derive(Debug, Clone)]
pub struct WsSessionConfig {
    /// Send an unsolicited ping when this long has passed since the last
    /// inbound frame or pong. `Zero` disables client-initiated pings
    /// (server-initiated pings are still auto-ponged by [`WsStream`]).
    ///
    /// Default 20 s: aligned with the pool's idle bound, sized against the
    /// 30–60 s silent cull window middleboxes actually apply ([ADR-0005]).
    pub ping_interval: Duration,
    /// A session with an outstanding ping that has not been answered within
    /// this duration is declared dead. Default 10 s.
    pub pong_timeout: Duration,
}

impl Default for WsSessionConfig {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(20),
            pong_timeout: Duration::from_secs(10),
        }
    }
}

/// A WebSocket session with client-driven liveness enforcement.
///
/// Wraps a [`WsStream`] and drives the heartbeat inside [`WsSession::next`],
/// so a caller's receive loop never needs its own timer machinery. Any inbound
/// frame (pong, ping, text, binary) refreshes the liveness clock; a ping sent
/// with no matching pong within `pong_timeout` fails the session with
/// `NetError::Protocol`.
pub struct WsSession<S> {
    stream: WsStream<S>,
    config: WsSessionConfig,
    /// Last moment a frame of any kind arrived from the peer.
    last_inbound: Instant,
    /// When the currently outstanding ping was sent, if one is outstanding.
    ping_in_flight: Option<Instant>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsSession<S> {
    /// Wrap a stream in session policy. Handshake completeness is the caller's
    /// concern: pass the `WsStream` returned by `Client::connect_ws`.
    pub fn new(stream: WsStream<S>, config: WsSessionConfig) -> Self {
        Self {
            stream,
            config,
            last_inbound: Instant::now(),
            ping_in_flight: None,
        }
    }

    /// Send a message through the underlying stream, bypassing heartbeat
    /// timing (outbound data is itself evidence of a live endpoint, but the
    /// ping clock is driven by *inbound* traffic, so an outbound-only caller
    /// still gets probes answered).
    pub async fn send(&mut self, message: Message) -> Result<(), NetError> {
        self.stream.send(message).await
    }

    /// Receive the next message, sending heartbeat pings and enforcing the
    /// pong deadline as needed.
    ///
    /// Returns `Ok(None)` only after a clean close handshake. A pong deadline
    /// violation is `NetError::Protocol` — terminal, non-retryable here, by
    /// design.
    pub async fn next(&mut self) -> Result<Option<Message>, NetError> {
        loop {
            // A dead session: the outstanding ping aged out without an answer.
            if let Some(sent) = self.ping_in_flight
                && sent.elapsed() >= self.config.pong_timeout
            {
                return Err(NetError::Protocol(format!(
                    "WebSocket pong deadline exceeded: no pong within {:?}",
                    self.config.pong_timeout
                )));
            }

            // Decide the next action's deadline: answer the outstanding ping's
            // fate, or fall due for a fresh probe.
            let idle_for = self.last_inbound.elapsed();
            let deadline = if let Some(sent) = self.ping_in_flight {
                // Pong may still arrive; wake exactly at the deadline.
                self.config.pong_timeout.saturating_sub(sent.elapsed())
            } else if self.config.ping_interval.is_zero() {
                // Heartbeat disabled: no timer of our own to wake for.
                return self.next_message().await;
            } else {
                self.config.ping_interval.saturating_sub(idle_for)
            };

            // An interval that has already elapsed probes immediately.
            if self.ping_in_flight.is_none()
                && !self.config.ping_interval.is_zero()
                && idle_for >= self.config.ping_interval
            {
                self.stream.send_ping(Bytes::new()).await?;
                self.ping_in_flight = Some(Instant::now());
                continue;
            }

            tokio::select! {
                message = self.stream.receive() => {
                    let message = message?;
                    // Any inbound frame proves the wire is alive.
                    self.last_inbound = Instant::now();

                    // Deadline check *before* delivery: a peer-initiated pong
                    // may arrive as a message, but if our probe has already
                    // aged out unanswered, the session is dead and the error
                    // wins over message delivery.
                    if let Some(sent) = self.ping_in_flight
                        && sent.elapsed() >= self.config.pong_timeout
                    {
                        return Err(NetError::Protocol(format!(
                            "WebSocket pong deadline exceeded: no pong within {:?}",
                            self.config.pong_timeout
                        )));
                    }

                    // A pong discharges the outstanding probe only if its
                    // payload matches what we sent; a peer-initiated pong is
                    // liveness evidence but not an answer to our question.
                    if let Some(Message::Pong(payload)) = &message
                        && self
                            .stream
                            .outstanding_ping_matches(payload)
                    {
                        self.ping_in_flight = None;
                    }
                    if message.is_some() {
                        return Ok(message);
                    }
                    // Clean close: propagate.
                    return Ok(None);
                }
                _ = sleep(deadline) => {
                    // Loop: either probe now or answer the pong verdict.
                    continue;
                }
            }
        }
    }

    /// Send a UTF-8 text message through the session.
    pub async fn send_text(&mut self, text: impl Into<String>) -> Result<(), NetError> {
        self.stream.send_text(text).await
    }

    /// Send a binary message through the session.
    pub async fn send_binary(&mut self, data: impl Into<Bytes>) -> Result<(), NetError> {
        self.stream.send_binary(data).await
    }

    /// Initiate the close handshake and end the session.
    pub async fn close(
        &mut self,
        code: netune_ws::CloseCode,
        reason: &str,
    ) -> Result<(), NetError> {
        self.stream.close(code, reason).await
    }

    /// Delegate to [`WsStream::receive`], surfaced for callers who disabled
    /// the heartbeat and want raw receive semantics.
    async fn next_message(&mut self) -> Result<Option<Message>, NetError> {
        self.stream.receive().await
    }
}
