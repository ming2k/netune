//! The tap: an `AsyncRead`/`AsyncWrite` wrapper that records every syscall
//! boundary.
//!
//! This is the only place `netune` touches the trace on the byte path, and it
//! is deliberately thin: two `poll_*` methods, one record call each, no
//! allocation and no lock shared across connections (the [`Recorder`] belongs to
//! this connection's attempt, so the mutex is uncontended in the common case).
//!
//! `TimedIo` wraps the *transport* stream — TCP today, TLS on top of it next —
//! so the recorded timeline is the same regardless of how many layers sit above
//! it.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use netune_trace::{Recorder, TimeSource};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A transport stream whose reads and writes are recorded into `recorder`.
#[derive(Debug)]
pub struct TimedIo<I> {
    inner: I,
    recorder: Arc<Mutex<Recorder>>,
}

impl<I> TimedIo<I> {
    pub fn new(inner: I, recorder: Arc<Mutex<Recorder>>) -> Self {
        Self { inner, recorder }
    }

    /// Recover the wrapped stream.
    pub fn into_inner(self) -> I {
        self.inner
    }

    fn record(&self, bytes: usize, write: bool) {
        let mut recorder = self.recorder.lock().unwrap_or_else(|e| e.into_inner());
        if write {
            recorder.wrote(bytes);
        } else {
            recorder.read(bytes, TimeSource::Syscall);
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for TimedIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len() - before;
            if read > 0 {
                this.record(read, false);
            }
        }
        result
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for TimedIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result
            && *written > 0
        {
            this.record(*written, true);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
