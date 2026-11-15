//! A scripted byte transport.
//!
//! Framing bugs are boundary bugs. An `AsyncRead` that yields exactly the
//! chunks a test asks for lets a decoder be exercised at every split point
//! without depending on how the kernel happened to schedule a loopback write.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// An in-memory transport that yields pre-scripted read chunks and records
/// every written byte.
#[derive(Debug, Default)]
pub struct ScriptedIo {
    chunks: VecDeque<Vec<u8>>,
    written: Vec<u8>,
}

impl ScriptedIo {
    /// Deliver `data` in chunks of exactly `chunk` bytes (the last may be short).
    pub fn chunked(data: &[u8], chunk: usize) -> Self {
        let chunk = chunk.max(1);
        Self {
            chunks: data.chunks(chunk).map(<[u8]>::to_vec).collect(),
            written: Vec::new(),
        }
    }

    /// Deliver each provided slice as one read.
    pub fn from_slices(slices: &[&[u8]]) -> Self {
        Self {
            chunks: slices.iter().map(|slice| slice.to_vec()).collect(),
            written: Vec::new(),
        }
    }

    /// An immediately exhausted stream, i.e. end of input.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Bytes written through [`AsyncWrite`], in order.
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Consume the transport and return the bytes written through it.
    pub fn into_written(self) -> Vec<u8> {
        self.written
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(mut chunk) = self.chunks.pop_front() {
            let take = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..take]);
            if take < chunk.len() {
                chunk.drain(..take);
                self.chunks.push_front(chunk);
            }
        }
        // An exhausted script is end of stream.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn chunked_delivers_the_script_in_order() {
        let mut io = ScriptedIo::chunked(b"abcdef", 2);
        let mut out = Vec::new();
        io.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"abcdef");
    }

    #[tokio::test]
    async fn a_partial_read_is_delivered_before_the_rest() {
        let mut io = ScriptedIo::from_slices(&[b"hello", b"world"]);
        let mut first = [0u8; 3];
        assert_eq!(io.read(&mut first).await.expect("read"), 3);
        assert_eq!(&first, b"hel");
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await.expect("read");
        assert_eq!(rest, b"loworld");
    }

    #[tokio::test]
    async fn writes_are_recorded() {
        use tokio::io::AsyncWriteExt;
        let mut io = ScriptedIo::empty();
        io.write_all(b"written").await.expect("write");
        assert_eq!(io.written(), b"written");
    }
}
