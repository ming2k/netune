//! Containment for a panicking handler.
//!
//! A handler is application code called from inside a connection task. If it panics and the
//! unwind reaches the task, the socket is dropped with no status line: the peer sees a
//! truncated connection and cannot tell an application bug from a network failure, so it
//! cannot decide whether retrying is safe. A production transport therefore contains the
//! panic and answers `500`.
//!
//! # Why this is hand-written
//!
//! `futures::FutureExt::catch_unwind` does exactly this, but taking `futures` as a production
//! dependency to get forty lines of `poll` wiring would add a large crate to the graph of a
//! transport that is otherwise `tokio` + `bytes` + `http`. The version here is the same
//! idea, stated small enough to read: catch a panic in `poll`, remember that it happened, and
//! never poll the inner future again (a future that panicked is not safe to resume).

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Extension for polling a future with panics converted into a value.
pub(crate) trait CatchPanic: Future + Sized {
    /// Poll `self`, producing `Err(payload)` if it panics.
    ///
    /// Once the inner future has panicked it is never polled again: a future that panicked
    /// mid-`poll` may have left its own state inconsistent, and resuming it is undefined
    /// behaviour dressed as resilience.
    fn catch_panic(self) -> CatchPanicFuture<Self>;
}

impl<F: Future> CatchPanic for F {
    fn catch_panic(self) -> CatchPanicFuture<Self> {
        CatchPanicFuture {
            inner: Some(AssertUnwindSafe(self)),
        }
    }
}

/// The future returned by [`CatchPanic::catch_panic`].
pub(crate) struct CatchPanicFuture<F> {
    /// `None` once the inner future has completed, panicked or been dropped.
    inner: Option<AssertUnwindSafe<F>>,
}

impl<F: Future> Future for CatchPanicFuture<F> {
    type Output = Result<F::Output, Box<dyn std::any::Any + Send>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // `inner` is only ever taken out of the struct, never moved out of the pin: the
        // pinned field is behind a `&mut` we get from `Pin::get_unchecked_mut`, and the
        // `Option` is the only thing that changes.
        // SAFETY: `inner` is structurally pinned, and we never move the future it contains —
        // we only replace the whole `Option` with `None` after the future has finished or
        // panicked, at which point it is dropped in place.
        let this = unsafe { self.get_unchecked_mut() };
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(Err(Box::new(PanickedAfterCompletion)));
        };
        // SAFETY: `inner.0` is structurally pinned — we hold it inside `AssertUnwindSafe` inside an
        // `Option` we own a `&mut` to, and we never move the future out of the pin.
        let pinned = unsafe { Pin::new_unchecked(&mut inner.0) };
        match catch_unwind(AssertUnwindSafe(|| pinned.poll(cx))) {
            Ok(Poll::Ready(value)) => {
                this.inner = None;
                Poll::Ready(Ok(value))
            }
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => {
                this.inner = None;
                Poll::Ready(Err(payload))
            }
        }
    }
}

/// The payload produced when a completed [`CatchPanicFuture`] is polled again.
///
/// Polling a finished future is a violation of the `Future` contract, not a panic that
/// happened in application code; distinguishing the two keeps the transport from answering
/// `500` for its own misuse.
#[derive(Debug)]
struct PanickedAfterCompletion;

impl std::fmt::Display for PanickedAfterCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a completed future was polled again")
    }
}

/// One line describing a panic payload, for a trace event or a log.
///
/// The payload is whatever the panicking code passed to `panic!`, so it is either a
/// `&str`, a `String` or something else entirely; the last case is reported by type name
/// rather than silently dropped.
pub(crate) fn describe(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "a non-string panic payload".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panicking_future_is_reported_rather_than_unwound() {
        let outcome = std::panic::AssertUnwindSafe(async { panic!("boom") })
            .catch_panic()
            .await;
        let payload = outcome.expect_err("the panic is captured");
        assert_eq!(describe(payload.as_ref()), "boom");
    }

    #[tokio::test]
    async fn a_normal_future_passes_its_output_through() {
        let outcome = async { 7u8 }.catch_panic().await;
        assert_eq!(outcome.expect("no panic"), 7);
    }

    #[tokio::test]
    async fn a_future_that_pends_before_panicking_still_completes() {
        let outcome = async {
            tokio::task::yield_now().await;
            panic!("after a yield");
        }
        .catch_panic()
        .await;
        let payload = outcome.expect_err("captured");
        assert_eq!(describe(payload.as_ref()), "after a yield");
    }
}
