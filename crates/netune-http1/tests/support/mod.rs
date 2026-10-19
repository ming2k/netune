//! Shared test support: a scripted transport that delivers bytes in exact
//! chunks, so framing is exercised at arbitrary boundaries rather than only at
//! whatever the OS happens to hand over.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

/// An `AsyncRead` that yields pre-scripted chunks, always ready.
#[derive(Debug, Default)]
pub struct ScriptedIo {
    chunks: VecDeque<Vec<u8>>,
}

impl ScriptedIo {
    /// Deliver `data` in chunks of exactly `chunk` bytes (the last may be short).
    pub fn chunked(data: &[u8], chunk: usize) -> Self {
        let chunk = chunk.max(1);
        Self {
            chunks: data.chunks(chunk).map(<[u8]>::to_vec).collect(),
        }
    }

    /// Deliver each provided slice as one read.
    pub fn from_slices(slices: &[&[u8]]) -> Self {
        Self {
            chunks: slices.iter().map(|slice| slice.to_vec()).collect(),
        }
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

/// A response with a `Content-Length` body.
pub const CONTENT_LENGTH_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
content-type: application/json\r\n\
content-length: 11\r\n\
\r\n\
hello world";

/// A chunked response with a chunk extension and a trailer.
pub const CHUNKED_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
content-type: text/event-stream\r\n\
transfer-encoding: chunked\r\n\
\r\n\
7;ext=1\r\ndata: a\r\n\
8\r\n\ndata: b\r\n\
0\r\n\
x-trace: done\r\n\
\r\n";

/// A close-delimited body: no length, no chunking.
pub const UNTIL_CLOSE_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
content-type: text/plain\r\n\
\r\n\
until the socket closes";
