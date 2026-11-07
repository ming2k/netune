// SPDX-License-Identifier: MIT

//! Bidirectional QUIC stream conforming to `AsyncRead + AsyncWrite + Send + Unpin`.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bidirectional QUIC byte stream.
///
/// Satisfies `AsyncRead + AsyncWrite + Send + Unpin`, allowing seamless composition
/// with netune's `Transport` blanket implementation.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    /// Creates a new `QuicStream` from paired send and receive channels.
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    /// Splits the bidirectional stream into independent send and receive halves.
    pub fn into_split(self) -> (quinn::SendStream, quinn::RecvStream) {
        (self.send, self.recv)
    }

    /// Borrows the underlying send stream.
    pub fn send_mut(&mut self) -> &mut quinn::SendStream {
        &mut self.send
    }

    /// Borrows the underlying receive stream.
    pub fn recv_mut(&mut self) -> &mut quinn::RecvStream {
        &mut self.recv
    }
}

impl fmt::Debug for QuicStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicStream")
            .field("stream_id", &self.send.id().index())
            .finish()
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
