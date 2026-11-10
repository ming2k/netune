//! Shared bounds for connection-establishment phases.
//!
//! A request does not exist until DNS, TCP, the proxy tunnel, TLS and — when
//! the peer negotiated HTTP/2 — the SETTINGS exchange have completed. Every one
//! of those phases is peer-controlled: a socket that accepts and then stops
//! would otherwise wait for an outer streaming watchdog and surface as a
//! generation failure. The transport therefore bounds every phase with one
//! default, and each connector or client exposes an override for callers that
//! need a different one.
//!
//! The bound is deliberately separate from a request deadline. A streaming
//! response must remain unbounded so a long generation is never cut mid-stream;
//! connection establishment is the part that must finish before that stream
//! exists.

use std::future::Future;
use std::time::Duration;

use crate::error::NetError;

/// Default bound on one connection-establishment phase after DNS/TCP.
///
/// Ten seconds is long enough for a slow resolver plus a transcontinental
/// round trip and far shorter than any legitimate streaming watchdog above the
/// transport. Every phase uses it unless the caller overrides that phase.
pub(crate) const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Run a connection-establishment future under `limit`.
///
/// The outer error is the expired bound; the inner result is the future's own
/// outcome, so a caller can map a protocol error without losing the timeout
/// distinction. The bound produces [`NetError::Connect`] because the request
/// was never dispatched: the peer accepted a connection and failed to finish
/// establishing it. `None` leaves the phase unbounded for a caller whose own
/// deadline reports the stall as a connection failure.
pub(crate) async fn bound<F, T, E>(
    limit: Option<Duration>,
    phase: &str,
    peer: &str,
    future: F,
) -> Result<Result<T, E>, NetError>
where
    F: Future<Output = Result<T, E>>,
{
    match limit {
        Some(limit) => tokio::time::timeout(limit, future)
            .await
            .map_err(|_| timeout_error(phase, peer, limit)),
        None => Ok(future.await),
    }
}

/// The typed, retryable failure an expired handshake bound produces.
pub(crate) fn timeout_error(phase: &str, peer: &str, limit: Duration) -> NetError {
    NetError::Connect(format!(
        "{phase} with {peer} exceeded {} ms",
        limit.as_millis()
    ))
}
