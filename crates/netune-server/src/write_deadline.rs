//! A write that must make progress: the slow-read defence.
//!
//! `handler_timeout` bounds how long the *application* may take. It cannot bound how long
//! the *peer* may take to accept our bytes, and those are different attacks: a client that
//! opens its receive window one byte at a time holds a connection slot for the whole
//! response without ever running a handler. Every write therefore gets its own deadline.
//!
//! # Why a deadline per operation, not per response
//!
//! A streaming response is legitimately long — a token stream can run for minutes — so a
//! single deadline covering the whole body would either kill honest streams or be so large
//! it bounds nothing. What must be bounded is the interval in which a write makes *no*
//! progress, which is exactly what this adapter measures.
//!
//! # Cancel safety
//!
//! The adapter fails the write it was polling; it never partially writes and retries. A
//! `write_all` on top of it therefore reports an error exactly once, and the caller closes
//! the connection because a partially written message cannot be resumed.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::AsyncWrite;
use tokio::time::Sleep;

/// An `AsyncWrite` that fails an operation that does not complete within `timeout`.
#[derive(Debug)]
pub(crate) struct WriteDeadline<W> {
    inner: W,
    timeout: Duration,
    /// Armed while an operation is in flight.
    sleep: Option<Pin<Box<Sleep>>>,
}

impl<W> WriteDeadline<W> {
    pub(crate) fn new(inner: W, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: None,
        }
    }

    /// Clear the deadline after a completed operation.
    fn disarm(&mut self) {
        self.sleep = None;
    }

    /// Poll the deadline, arming it on first use.
    fn poll_deadline<T>(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<T>> {
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.timeout)));
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the peer did not accept the write within the configured bound",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                this.disarm();
                Poll::Ready(result)
            }
            Poll::Pending => this.poll_deadline(cx),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => {
                this.disarm();
                Poll::Ready(result)
            }
            Poll::Pending => this.poll_deadline(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(result) => {
                this.disarm();
                Poll::Ready(result)
            }
            Poll::Pending => this.poll_deadline(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    /// A writer that never accepts a byte, so the deadline is the only thing that can end
    /// the write.
    struct Stalled;

    impl AsyncWrite for Stalled {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_peer_that_never_reads_is_cut_off_by_the_deadline() {
        let mut io = WriteDeadline::new(Stalled, Duration::from_millis(50));
        let error = io
            .write_all(b"hello")
            .await
            .expect_err("the write must not hang");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_willing_peer_is_never_waited_on() {
        let mut out: Vec<u8> = Vec::new();
        let mut guarded = WriteDeadline::new(&mut out, Duration::from_secs(5));
        guarded.write_all(b"hello").await.expect("write");
        drop(guarded);
        assert_eq!(out, b"hello");
    }
}
