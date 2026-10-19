//! Evasion transport wrappers: wire segmentation and sub-record splitting (ADR-0006).
//!
//! Deep Packet Inspection (DPI) devices and middleboxes inspect TLS handshakes
//! by matching plaintext Server Name Indication (SNI) patterns within individual
//! TCP segments.
//!
//! [`SegmentingIo`] splits outgoing writes (such as the initial TLS ClientHello flight)
//! into smaller chunks across distinct TCP writes. By pacing chunks with small inter-chunk
//! gaps, the transport forces the OS kernel to flush each slice into an independent TCP packet,
//! preventing pattern matching by stateless DPI filters.

use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// A transport wrapper that limits maximum write chunk size during early flight bytes.
pub struct SegmentingIo<T> {
    inner: T,
    chunk_size: usize,
    /// Only segment the first `limit` bytes (e.g. handshake phase), then pass through full writes.
    segment_limit: usize,
    /// Total bytes written through this stream so far.
    written: usize,
    /// Optional gap between sliced chunks to force separate TCP frames on the wire.
    inter_chunk_gap: Option<Duration>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl<T> SegmentingIo<T> {
    /// Wrap `inner` to chunk outgoing writes into slices of at most `chunk_size` bytes
    /// for the first `segment_limit` bytes.
    pub fn new(inner: T, chunk_size: usize, segment_limit: usize) -> Self {
        Self {
            inner,
            chunk_size: chunk_size.max(1),
            segment_limit,
            written: 0,
            inter_chunk_gap: None,
            sleep: None,
        }
    }

    /// Construct a preset tuned for SNI segmentation: 24-byte chunks with 2ms pacing for the first 512 bytes.
    pub fn for_sni(inner: T) -> Self {
        let mut s = Self::new(inner, 24, 512);
        s.inter_chunk_gap = Some(Duration::from_millis(2));
        s
    }

    /// Set an inter-chunk delay to guarantee discrete TCP segment transmission.
    pub fn with_gap(mut self, gap: Duration) -> Self {
        self.inter_chunk_gap = Some(gap);
        self
    }

    /// Access the underlying transport.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Access the underlying transport mutably.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume this wrapper and return the inner transport.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SegmentingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SegmentingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some(mut sleep) = self.sleep.take()
            && sleep.as_mut().poll(cx).is_pending()
        {
            self.sleep = Some(sleep);
            return Poll::Pending;
        }

        let to_write = if self.written < self.segment_limit {
            min(buf.len(), self.chunk_size)
        } else {
            buf.len()
        };

        match Pin::new(&mut self.inner).poll_write(cx, &buf[..to_write]) {
            Poll::Ready(Ok(n)) => {
                self.written = self.written.saturating_add(n);
                if self.written < self.segment_limit
                    && let Some(gap) = self.inter_chunk_gap
                {
                    self.sleep = Some(Box::pin(tokio::time::sleep(gap)));
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    #[derive(Default, Clone)]
    struct ChunkRecorder {
        chunks: Arc<Mutex<Vec<usize>>>,
        data: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for ChunkRecorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.chunks.lock().unwrap().push(buf.len());
            self.data.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn segmenting_io_caps_write_sizes_during_initial_flight() {
        let recorder = ChunkRecorder::default();
        let mut segmented = SegmentingIo::new(recorder.clone(), 10, 25);

        // First write: 20 bytes -> should be written in chunks of at most 10.
        let data = b"0123456789abcdefghij";
        segmented.write_all(data).await.expect("write_all");

        // Second write: 10 bytes -> first 5 are capped (20 + 5 = 25 limit), subsequent bytes bypass.
        segmented.write_all(b"KLMNOPQRST").await.expect("write_all");

        let recorded_chunks = recorder.chunks.lock().unwrap().clone();
        for &chunk in &recorded_chunks[..2] {
            assert!(chunk <= 10, "chunk was {chunk}");
        }

        let all_data = recorder.data.lock().unwrap().clone();
        assert_eq!(all_data, b"0123456789abcdefghijKLMNOPQRST");
    }
}
