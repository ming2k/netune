//! The chaos twin of [`crate::TimedIo`]: a transport wrapper that
//! *injects* faults instead of recording facts.
//!
//! Where `TimedIo` answers "what did the transport actually do?", `FaultIo`
//! answers "how does the rest of the stack behave when the transport does
//! something hostile?" — delayed reads, split reads, truncated bodies,
//! connection resets mid-stream. This is the L1 counterpart of the L2 forge
//! (`netune-probe`'s `build_ethernet_ipv4_tcp` + `inject`): both change
//! behaviour, this one needs no privileges because it stays inside the
//! process.
//!
//! # Shape
//!
//! A [`FaultScript`] is an ordered list of [`Fault`]s keyed by the number of
//! payload bytes already delivered: the first fault fires when its byte
//! offset is reached, then it is retired and the next one queues. Every
//! failure a real misbehaving transport produces is expressible:
//!
//! - [`Fault::Delay`] — a stall before the next delivery (a buffering proxy
//!   flushing late, a gateway pause),
//! - [`Fault::Split`] — deliver at most *n* bytes per read (the opposite of
//!   transport batching, to prove reassembly),
//! - [`Fault::Truncate`] — EOF before the declared body ends,
//! - [`Fault::Reset`] — `ConnectionResetByPeer` mid-stream.
//!
//! # Discipline
//!
//! The wrapper is inert without a script — every byte passes through
//! untouched, asserted in tests, so "chaos off" is provable, not assumed.
//! Fault state lives in the script; one decision per `poll_read`; no
//! allocation on the unfaulted path.
//!
//! Note what is *not* here by design: no write-path faults (a client's own
//! writes being corrupted is a different threat model than a hostile peer;
//! the L2 forge covers injected writes), and no event recording — a fault
//! the harness knows it injected must not pollute the trace the harness is
//! using to judge real transport behaviour.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// One misbehaviour, positioned by the payload-byte offset it fires at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// Stall for `duration` before delivering further bytes, then continue.
    Delay(Duration),
    /// Deliver at most `per_read` bytes per read while the offset is within
    /// `span` bytes of the fault's position.
    Split {
        /// Number of bytes over which the split cap remains active.
        span: usize,
        /// Maximum bytes delivered per `poll_read` while active.
        per_read: usize,
    },
    /// EOF at the offset: the declared body simply stops.
    Truncate,
    /// `ConnectionResetByPeer` at the offset.
    Reset,
}

/// The script: faults fire in offset order as bytes flow.
#[derive(Debug, Default)]
pub struct FaultScript {
    faults: Vec<(usize, Fault)>,
    /// Index of the next fault to fire.
    next: usize,
    /// Payload bytes delivered to the reader so far.
    delivered: usize,
    /// The in-progress delay's deadline, if one is between polls.
    delay_until: Option<Instant>,
    /// The in-progress split's remaining byte budget, if any.
    split_budget: Option<usize>,
    /// The delivered-byte mark at which an active split ends.
    split_until: usize,
}

impl FaultScript {
    /// An inert script: no faults, pure passthrough.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A script whose faults fire in order at their byte offsets.
    pub fn new(faults: impl IntoIterator<Item = (usize, Fault)>) -> Self {
        let mut faults: Vec<(usize, Fault)> = faults.into_iter().collect();
        faults.sort_by_key(|(offset, _)| *offset);
        Self {
            faults,
            ..Self::default()
        }
    }

    /// Whether the reader may read now, and with what cap.
    ///
    /// The single decision point of the whole module: pure against the
    /// script's state plus `now`, no task runtime — which is what makes the
    /// ordering rules unit-testable without an executor.
    fn admit(&mut self, now: Instant) -> Admit {
        // A delay in progress finishes before anything else is considered.
        if let Some(deadline) = self.delay_until {
            if now < deadline {
                return Admit::Wait(deadline);
            }
            self.delay_until = None;
            self.next += 1; // the delay has fully fired
        }
        // A split in progress caps reads until its span is delivered.
        if let Some(budget) = self.split_budget {
            if self.delivered >= self.split_until {
                self.split_budget = None;
            } else {
                self.split_budget = Some(budget);
                return Admit::Read(Some(budget));
            }
        }
        // The next fault fires once the flow reaches its offset.
        let Some((offset, fault)) = self.faults.get(self.next).map(|(o, f)| (*o, f.clone())) else {
            return Admit::Read(None);
        };
        if offset > self.delivered {
            // Stop this read at the fault's offset. An uncapped read could
            // deliver past it, and the fault would then fire late, or never
            // if the stream had nothing more to give.
            return Admit::Read(Some(offset - self.delivered));
        }
        match fault {
            Fault::Delay(duration) => {
                self.delay_until = Some(now + duration);
                self.admit(now)
            }
            Fault::Split { span, per_read } => {
                self.next += 1;
                self.split_budget = Some(per_read);
                self.split_until = self.delivered + span;
                Admit::Read(Some(per_read))
            }
            Fault::Truncate => {
                self.next += 1;
                Admit::Eof
            }
            Fault::Reset => {
                self.next += 1;
                Admit::Reset
            }
        }
    }

    /// Record a successful read of `bytes` payload bytes.
    fn delivered(&mut self, bytes: usize) {
        self.delivered += bytes;
        // A split whose span has been delivered is finished.
        if self.split_budget.is_some() && self.delivered >= self.split_until {
            self.split_budget = None;
        }
    }
}

/// What the reader should do, decided by [`FaultScript::admit`].
#[derive(Debug, PartialEq, Eq)]
enum Admit {
    /// Proceed with a read capped at the given byte count (a split in
    /// progress), or uncapped.
    Read(Option<usize>),
    /// Nothing to deliver until this instant.
    Wait(Instant),
    /// Report EOF now (a zero-byte read).
    Eof,
    /// Report a connection reset now.
    Reset,
}

/// A transport stream with scripted faults injected on the read path.
pub struct FaultIo<I> {
    inner: I,
    script: Arc<Mutex<FaultScript>>,
}

impl<I> FaultIo<I> {
    /// Wrap `inner` with `script`.
    pub fn new(inner: I, script: Arc<Mutex<FaultScript>>) -> Self {
        Self { inner, script }
    }

    /// Recover the wrapped stream.
    pub fn into_inner(self) -> I {
        self.inner
    }

    /// Reach the wrapped stream's non-byte controls (an observation tap, a
    /// socket option). Reading or writing through this reference bypasses the
    /// script.
    pub fn get_mut(&mut self) -> &mut I {
        &mut self.inner
    }

    fn record_delivery(&self, bytes: usize) {
        let mut script = self.script.lock().unwrap_or_else(|e| e.into_inner());
        script.delivered(bytes);
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for FaultIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let admit = {
            let mut script = this.script.lock().unwrap_or_else(|e| e.into_inner());
            script.admit(Instant::now())
        };
        match admit {
            Admit::Reset => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "injected: connection reset by peer",
                )));
            }
            // Zero-byte read = EOF, the same signal a half-closed peer gives.
            Admit::Eof => return Poll::Ready(Ok(())),
            Admit::Wait(deadline) => {
                wake_at(deadline, cx);
                return Poll::Pending;
            }
            Admit::Read(Some(cap)) if cap < buf.remaining() => {
                // Read into a smaller buffer to enforce the split, then
                // advance the caller's buffer by what arrived.
                let mut capped = ReadBuf::new(buf.initialize_unfilled_to(cap));
                let result = Pin::new(&mut this.inner).poll_read(cx, &mut capped);
                if let Poll::Ready(Ok(())) = &result {
                    let read = capped.filled().len();
                    buf.advance(read);
                    this.record_delivery(read);
                }
                return result;
            }
            Admit::Read(_) => {}
        }
        // Unfaulted read.
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len() - before;
            this.record_delivery(read);
        }
        result
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for FaultIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Register the waker to run again at `deadline`. `tokio::time::sleep`
/// cannot be awaited from inside a `poll_*`, so a one-shot timer task wakes
/// the reader — spawned only on the faulted path, never on clean bytes.
fn wake_at(deadline: Instant, cx: &mut Context<'_>) {
    let waker = cx.waker().clone();
    tokio::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        waker.wake();
    });
}

#[cfg(test)]
mod tests;
