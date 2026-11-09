//! The tap: an `AsyncRead`/`AsyncWrite` wrapper that records every syscall
//! boundary.
//!
//! This is the only place either orchestrator touches the trace on the byte
//! path. The observation strategy is a type parameter ([`Tap`]), owned by this
//! wrapper: there is no `Arc`, no `Mutex`, no `Box<dyn ...>` and no clock read
//! unless the selected tap needs one. `NoTap` is a zero-sized type; the wrapper
//! compiles to the inner stream.
//!
//! `TimedIo` wraps the *transport* stream — TCP today, TLS on top of it next —
//! so the recorded timeline is the same regardless of how many layers sit above
//! it, and the same regardless of whether the bytes are a request being read by
//! a server or a response being read by a client.

use std::pin::Pin;
use std::task::{Context, Poll};

use netune_trace::{NoTap, Ring, Tap, TimeSource, TraceCollector};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A transport stream whose reads and writes are observed by `T`.
#[derive(Debug)]
pub struct TimedIo<I, T = NoTap> {
    inner: I,
    tap: T,
}

impl<I, T: Tap> TimedIo<I, T> {
    /// Wrap `inner` with an owned observation strategy.
    pub fn new(inner: I, tap: T) -> Self {
        Self { inner, tap }
    }

    /// Recover the wrapped stream and the tap artifact.
    ///
    /// The caller is on the cold path: it can finish the tap, merge an event log
    /// into the attempt trace, or report counters.
    pub fn into_parts(self) -> (I, T) {
        (self.inner, self.tap)
    }

    /// Borrow the tap.
    pub fn tap(&self) -> &T {
        &self.tap
    }

    /// Borrow the tap mutably.
    pub fn tap_mut(&mut self) -> &mut T {
        &mut self.tap
    }

    fn record(&mut self, bytes: usize, write: bool) {
        if write {
            self.tap.wrote(bytes);
        } else {
            self.tap.read(bytes, TimeSource::Syscall);
        }
    }
}

impl<I: AsyncRead + Unpin, T: Tap> AsyncRead for TimedIo<I, T> {
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

impl<I: AsyncWrite + Unpin, T: Tap> AsyncWrite for TimedIo<I, T> {
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

/// A transport with an owned `Ring` tap whose log is merged into
/// [`TraceCollector`] when the wrapper is dropped.
///
/// This is the bridge for protocols whose stream is consumed by an outer object
/// (the ingress HTTP/1 reader, a WebSocket stream) and therefore cannot hand the
/// tap back explicitly. The byte path is still lock-free; only the final merge
/// touches the collector's internal mutex.
pub struct RingIo<T> {
    inner: Option<TimedIo<T, Ring>>,
    collector: TraceCollector,
}

impl<T> RingIo<T> {
    pub fn new(inner: T, ring: Ring, collector: TraceCollector) -> Self {
        Self {
            inner: Some(TimedIo::new(inner, ring)),
            collector,
        }
    }

    fn transport(&mut self) -> std::io::Result<&mut TimedIo<T, Ring>>
    where
        T: Unpin,
    {
        self.inner.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the observed transport is already closed",
            )
        })
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for RingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.as_mut().get_mut().transport() {
            Ok(io) => Pin::new(io).poll_read(context, buffer),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.as_mut().get_mut().transport() {
            Ok(io) => Pin::new(io).poll_write(context, buffer),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.as_mut().get_mut().transport() {
            Ok(io) => Pin::new(io).poll_flush(context),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.as_mut().get_mut().transport() {
            Ok(io) => Pin::new(io).poll_shutdown(context),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<T> Drop for RingIo<T> {
    fn drop(&mut self) {
        if let Some(io) = self.inner.take() {
            let (_stream, tap) = io.into_parts();
            self.collector.merge(tap.finish());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn no_tap_does_not_change_the_wrapper_size() {
        // A ZST tap must not add a field's worth of padding or state. The
        // wrapper is the inner stream plus an empty type.
        assert_eq!(size_of::<TimedIo<usize, NoTap>>(), size_of::<usize>());
    }
}
