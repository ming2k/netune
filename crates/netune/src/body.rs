//! The response body: one type for every transport.
//!
//! A [`Body`] pulls raw chunks from a [`BodySource`] and does everything that
//! is not protocol framing: `Content-Encoding` decoding, the decoded-size
//! limit, the idle bound, the trace marks and the attempt's evidence. Because
//! that work lives here and not in each protocol, an HTTP/1.1 response, an
//! HTTP/2 response and a mocked one are observed and bounded identically.
//!
//! # The trace is always reachable
//!
//! An attempt can end three ways: the body is read to its end, it fails part
//! way, or the caller stops reading. All three are terminal, and all three
//! leave a trace ([`INV-TRACE-11`]):
//!
//! - a failure returns an [`AttemptError`], which carries the snapshot;
//! - [`Body::trace`] answers once the body is terminal, however it ended;
//! - [`Body::abandon`] makes "the caller stopped reading" an explicit terminal
//!   state, so the trace of a deliberately truncated response can be read.
//!
//! What a trace never does is describe an attempt still in flight: while the
//! body is open [`Body::trace`] is `None`, because a partial log would report
//! stages that have not happened yet as stages that did not happen.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use netune_trace::{
    ConnectionIdentity, ConnectionInfo, Counters, DiagnosticPhase, EventKind, Fidelity,
    RequestTrace, TapArtifact, TraceCollector,
};

use crate::decompress::Decoder;
use crate::error::{AttemptError, NetError};
use crate::exchange::{BodySource, ObservationLevel};

/// How a body reached (or has not reached) its end.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyState {
    /// More may be read.
    Open,
    /// Read to the end.
    Finished,
    /// A read failed; the error carried the evidence.
    Failed,
    /// The caller stopped reading before the end.
    Abandoned,
}

/// Everything about an exchange that outlives its head: where it went, what
/// served it and how it is observed.
pub(crate) struct BodyContext {
    pub recorder: TraceCollector,
    pub observation: ObservationLevel,
    pub identity: ConnectionIdentity,
    pub authority: String,
    pub connection: ConnectionInfo,
    pub decoder: Decoder,
    pub max_decoded: u64,
    pub idle_timeout: Option<Duration>,
    pub deadline: Option<tokio::time::Instant>,
}

/// A streaming response body with its attempt's evidence attached.
pub struct Body {
    source: Option<Box<dyn BodySource>>,
    recorder: TraceCollector,
    observation: ObservationLevel,
    /// Set when the transport is released; `None` until then and for a
    /// transport that was not counting.
    counters: Option<Counters>,
    /// What the released tap proved. Protocol-only until a socket log says
    /// otherwise.
    fidelity: Fidelity,
    identity: ConnectionIdentity,
    authority: String,
    connection: ConnectionInfo,
    state: BodyState,
    started: bool,
    decoder: Decoder,
    /// Decoded bytes emitted so far, bounded so a compression bomb cannot
    /// exhaust memory.
    decoded: u64,
    max_decoded: u64,
    idle_timeout: Option<Duration>,
    deadline: Option<tokio::time::Instant>,
}

impl Body {
    pub(crate) fn new(source: Box<dyn BodySource>, context: BodyContext) -> Self {
        Self {
            source: Some(source),
            recorder: context.recorder,
            observation: context.observation,
            counters: None,
            fidelity: match context.observation {
                ObservationLevel::Off => Fidelity::none(),
                ObservationLevel::Counters | ObservationLevel::Traced => Fidelity::l0(),
            },
            identity: context.identity,
            authority: context.authority,
            connection: context.connection,
            state: BodyState::Open,
            started: false,
            decoder: context.decoder,
            decoded: 0,
            max_decoded: context.max_decoded,
            idle_timeout: context.idle_timeout,
            deadline: context.deadline,
        }
    }

    /// Read the next decoded body bytes, or `None` at the end of the body.
    ///
    /// # Errors
    ///
    /// A transport, framing, decoding or bound failure. The error carries the
    /// attempt's trace; the body is terminal afterwards and further reads
    /// report that it is closed.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, AttemptError> {
        match self.state {
            BodyState::Finished => return Ok(None),
            BodyState::Failed | BodyState::Abandoned => {
                return Err(AttemptError::new(
                    NetError::Protocol("the response body is closed".into()),
                    self.recorder.snapshot(self.fidelity),
                ));
            }
            BodyState::Open => {}
        }
        match self.pull().await {
            Ok(chunk) => Ok(chunk),
            Err(error) => Err(self.fail(error)),
        }
    }

    async fn pull(&mut self) -> Result<Option<Bytes>, NetError> {
        loop {
            let Some(source) = self.source.as_mut() else {
                return Ok(None);
            };
            let idle_deadline = self
                .idle_timeout
                .map(|limit| tokio::time::Instant::now() + limit);
            let effective = match (idle_deadline, self.deadline) {
                (Some(idle), Some(deadline)) => Some(idle.min(deadline)),
                (Some(idle), None) => Some(idle),
                (None, Some(deadline)) => Some(deadline),
                (None, None) => None,
            };
            let raw = match effective {
                Some(at) => {
                    let limit = at.saturating_duration_since(tokio::time::Instant::now());
                    tokio::time::timeout_at(at, source.next_chunk())
                        .await
                        .map_err(|_| NetError::Timeout {
                            phase: DiagnosticPhase::Response,
                            waiting_for: "next response body bytes",
                            limit,
                        })??
                }
                None => source.next_chunk().await?,
            };
            let Some(raw) = raw else {
                let mut tail = Vec::new();
                let remaining = usize::try_from(self.max_decoded.saturating_sub(self.decoded))
                    .unwrap_or(usize::MAX);
                self.decoder.finish(&mut tail, remaining)?;
                self.count_decoded(tail.len())?;
                self.recorder.mark(EventKind::BodyEnd, 0, 0);
                self.close(BodyState::Finished, true);
                return Ok(if tail.is_empty() {
                    None
                } else {
                    Some(Bytes::from(tail))
                });
            };

            let mut decoded = Vec::new();
            let remaining = usize::try_from(self.max_decoded.saturating_sub(self.decoded))
                .unwrap_or(usize::MAX);
            self.decoder.push(&raw, &mut decoded, remaining)?;
            self.count_decoded(decoded.len())?;
            if !self.started {
                self.recorder.mark(EventKind::BodyStart, 0, 0);
                self.started = true;
            }
            if !decoded.is_empty() {
                self.recorder
                    .mark(EventKind::ChunkBoundary, decoded.len() as u32, 0);
                return Ok(Some(Bytes::from(decoded)));
            }
            // The decoder consumed the raw bytes without producing output (a
            // header, or a partial frame): keep reading.
        }
    }

    fn count_decoded(&mut self, bytes: usize) -> Result<(), NetError> {
        self.decoded = self.decoded.saturating_add(bytes as u64);
        if self.decoded > self.max_decoded {
            return Err(NetError::Decode(
                "decoded body exceeded the configured limit".into(),
            ));
        }
        Ok(())
    }

    /// Record the failure, release the transport and hand back the evidence.
    fn fail(&mut self, error: NetError) -> AttemptError {
        // A producer below may already have recorded a more specific account
        // of this failure (an HTTP/2 reset code, a GOAWAY's debug data).
        if self.recorder.diagnostics().last_error().is_none() {
            self.recorder.record_error(error.diagnostic());
        }
        self.close(BodyState::Failed, false);
        AttemptError::new(error, self.recorder.snapshot(self.fidelity))
    }

    /// Release the transport and settle what the attempt was observed at.
    fn close(&mut self, state: BodyState, complete: bool) {
        self.state = state;
        let Some(source) = self.source.take() else {
            return;
        };
        match source.release(complete).artifact {
            TapArtifact::None => {}
            TapArtifact::Counters(counters) => self.counters = Some(counters),
            TapArtifact::Log(log) => {
                self.recorder.merge(log);
                if self.observation == ObservationLevel::Traced {
                    self.fidelity = Fidelity::l1();
                }
            }
        }
    }

    /// Drain the body.
    ///
    /// # Errors
    ///
    /// As [`Body::next_chunk`].
    pub async fn read_to_end(&mut self) -> Result<Bytes, AttemptError> {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.next_chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Stop reading before the end and release the connection.
    ///
    /// The connection is not reused: an unread body leaves it at an unknown
    /// position. Idempotent, and a no-op on a body that already ended.
    pub fn abandon(&mut self) {
        if self.state == BodyState::Open {
            self.close(BodyState::Abandoned, false);
        }
    }

    /// How the body ended, or that it has not.
    pub fn state(&self) -> BodyState {
        self.state
    }

    /// Whether the body has been fully consumed.
    pub fn is_finished(&self) -> bool {
        self.state == BodyState::Finished
    }

    /// Socket byte and call totals, when this attempt was observed with
    /// [`crate::Observation::Counters`] over a transport that has a socket.
    ///
    /// Available once the body is terminal. `None` for `Off` and `Traced`: an
    /// untraced attempt has nothing to count, and a traced attempt reports its
    /// evidence as an event log instead.
    pub fn counters(&self) -> Option<Counters> {
        self.counters
    }

    /// The attempt's trace, once the body is terminal.
    ///
    /// `None` while the body is still open, and `None` when the attempt was
    /// not traced. The envelope's fidelity is what the transport proved: a
    /// socket log makes it L1, anything else is protocol events only.
    pub fn trace(&self) -> Option<RequestTrace> {
        if self.observation != ObservationLevel::Traced
            || self.state == BodyState::Open
            || !self.recorder.is_enabled()
        {
            return None;
        }
        let snapshot = self.recorder.snapshot(self.fidelity);
        Some(
            RequestTrace::new(snapshot.meta, self.authority.clone(), snapshot.log)
                .with_connection(self.connection)
                .with_identity(self.identity.clone())
                .with_fidelity(self.fidelity)
                .with_diagnostics(snapshot.diagnostics),
        )
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        // A redirect hop or a dropped response never reads to the end, but its
        // socket events still belong to the attempt (a sink has seen them, and
        // a caller-supplied recorder outlives this body).
        self.abandon();
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Body")
            .field("authority", &self.authority)
            .field("state", &self.state)
            .field("decoded", &self.decoded)
            .finish_non_exhaustive()
    }
}
