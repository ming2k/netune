//! `Content-Encoding` decoding, streaming and bounded.
//!
//! A response body is decoded as it arrives, never buffered whole: the same code
//! path serves a 200-byte JSON reply and a minutes-long SSE stream. Decoders are
//! push-based, so `BodyStream` stays a chunk iterator and no synchronous
//! `Read`/`Write` bridge is needed.
//!
//! An encoding this client cannot decode is a **typed error**, never silently
//! compressed bytes handed to a caller that expects text.

use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc, HuffmanCode};

use crate::error::NetError;

/// Working buffer for one decode step. Large enough that a normal chunk is
/// produced in one pass, small enough that a hostile ratio cannot balloon it.
const SCRATCH: usize = 64 * 1024;

/// Decodes a body according to its `Content-Encoding`.
pub enum Decoder {
    Identity,
    Gzip(Box<Gzip>),
    Brotli(Box<Brotli>),
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The decoder state is opaque; the variant is what a trace or an error
        // message needs.
        f.write_str(match self {
            Self::Identity => "Decoder::Identity",
            Self::Gzip(_) => "Decoder::Gzip",
            Self::Brotli(_) => "Decoder::Brotli",
        })
    }
}

impl Decoder {
    /// Build the decoder for an encoding header value.
    pub fn from_encoding(encoding: Option<&str>) -> Result<Self, NetError> {
        match encoding.map(str::trim).filter(|value| !value.is_empty()) {
            None | Some("identity") => Ok(Self::Identity),
            Some("gzip") | Some("x-gzip") => Ok(Self::Gzip(Box::new(Gzip::new()))),
            Some("br") => Ok(Self::Brotli(Box::new(Brotli::new()))),
            Some(other) => Err(NetError::UnsupportedEncoding(other.to_ascii_lowercase())),
        }
    }

    /// Feed raw body bytes, appending decoded bytes to `out`.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), NetError> {
        match self {
            Self::Identity => out.extend_from_slice(input),
            Self::Gzip(decoder) => decoder.push(input, out)?,
            Self::Brotli(decoder) => decoder.push(input, out)?,
        }
        Ok(())
    }

    /// Finish the stream. A truncated stream is an error, not a short body.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), NetError> {
        match self {
            Self::Identity => Ok(()),
            Self::Gzip(decoder) => decoder.finish(out),
            Self::Brotli(decoder) => decoder.finish(out),
        }
    }
}

/// Streaming gzip (RFC 1952) decoder. Constructed only by [`Decoder`].
#[derive(Debug)]
pub struct Gzip {
    inner: flate2::Decompress,
    scratch: Vec<u8>,
}

impl Gzip {
    fn new() -> Self {
        // Window bits 31 selects the gzip container.
        Self {
            inner: flate2::Decompress::new_gzip(15),
            scratch: vec![0; SCRATCH],
        }
    }

    fn push(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<(), NetError> {
        while !input.is_empty() {
            let before_in = self.inner.total_in();
            let before_out = self.inner.total_out();
            let status = self
                .inner
                .decompress(input, &mut self.scratch, flate2::FlushDecompress::None)
                .map_err(|error| NetError::Decode(format!("gzip: {error}")))?;
            let consumed = (self.inner.total_in() - before_in) as usize;
            let produced = (self.inner.total_out() - before_out) as usize;
            out.extend_from_slice(&self.scratch[..produced]);
            input = &input[consumed..];
            if consumed == 0 && produced == 0 {
                // No forward progress: the input needs more bytes than we have.
                break;
            }
            if status == flate2::Status::StreamEnd {
                break;
            }
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), NetError> {
        loop {
            let before_in = self.inner.total_in();
            let before_out = self.inner.total_out();
            let status = self
                .inner
                .decompress(&[], &mut self.scratch, flate2::FlushDecompress::Finish)
                .map_err(|error| NetError::Decode(format!("gzip: {error}")))?;
            let consumed = (self.inner.total_in() - before_in) as usize;
            let produced = (self.inner.total_out() - before_out) as usize;
            out.extend_from_slice(&self.scratch[..produced]);
            if status == flate2::Status::StreamEnd {
                return Ok(());
            }
            if consumed == 0 && produced == 0 {
                return Err(NetError::Decode("gzip: stream ended mid-member".into()));
            }
        }
    }
}

/// Streaming brotli decoder. Constructed only by [`Decoder`].
pub struct Brotli {
    state: BrotliState<HeapAlloc<u8>, HeapAlloc<u32>, HeapAlloc<HuffmanCode>>,
    scratch: Vec<u8>,
    finished: bool,
}

impl Brotli {
    fn new() -> Self {
        Self {
            state: BrotliState::new(
                HeapAlloc::<u8>::default(),
                HeapAlloc::<u32>::default(),
                HeapAlloc::<HuffmanCode>::default(),
            ),
            scratch: vec![0; SCRATCH],
            finished: false,
        }
    }

    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), NetError> {
        let mut consumed = 0usize;
        loop {
            let mut available_in = input.len() - consumed;
            let mut input_offset = 0usize;
            let mut available_out = self.scratch.len();
            let mut output_offset = 0usize;
            let mut total_out = 0usize;
            let result = BrotliDecompressStream(
                &mut available_in,
                &mut input_offset,
                &input[consumed..],
                &mut available_out,
                &mut output_offset,
                &mut self.scratch,
                &mut total_out,
                &mut self.state,
            );
            out.extend_from_slice(&self.scratch[..output_offset]);
            consumed += input_offset;
            match result {
                BrotliResult::NeedsMoreOutput if output_offset > 0 => continue,
                BrotliResult::NeedsMoreOutput => break,
                BrotliResult::NeedsMoreInput => break,
                BrotliResult::ResultSuccess => {
                    self.finished = true;
                    break;
                }
                BrotliResult::ResultFailure => {
                    return Err(NetError::Decode("brotli: corrupt stream".into()));
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), NetError> {
        if self.finished {
            return Ok(());
        }
        self.push(&[], out)?;
        if self.finished {
            Ok(())
        } else {
            Err(NetError::Decode("brotli: stream ended mid-frame".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("compress");
        encoder.finish().expect("finish")
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
        writer.write_all(data).expect("compress");
        writer.flush().expect("flush");
        writer.into_inner()
    }

    fn decode(encoding: Option<&str>, input: &[u8], chunk: usize) -> Vec<u8> {
        let mut decoder = Decoder::from_encoding(encoding).expect("decoder");
        let mut out = Vec::new();
        for part in input.chunks(chunk) {
            decoder.push(part, &mut out).expect("push");
        }
        decoder.finish(&mut out).expect("finish");
        out
    }

    #[test]
    fn identity_passes_bytes_through() {
        let data = b"hello world";
        assert_eq!(decode(None, data, 3), data);
        assert_eq!(decode(Some("identity"), data, 3), data);
        assert_eq!(decode(Some(""), data, 3), data);
    }

    #[test]
    fn gzip_round_trips_at_any_chunk_boundary() {
        let data = "data: the quick brown fox\n".repeat(500).into_bytes();
        let compressed = gzip(&data);
        for chunk in [1, 7, 64, 4096, compressed.len()] {
            assert_eq!(
                decode(Some("gzip"), &compressed, chunk),
                data,
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn brotli_round_trips_at_any_chunk_boundary() {
        let data = "data: the quick brown fox\n".repeat(500).into_bytes();
        let compressed = brotli(&data);
        for chunk in [1, 7, 64, 4096, compressed.len()] {
            assert_eq!(
                decode(Some("br"), &compressed, chunk),
                data,
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn a_truncated_stream_is_an_error_not_a_short_body() {
        let data = "some content".repeat(100).into_bytes();
        for (encoding, mut compressed) in [(Some("gzip"), gzip(&data)), (Some("br"), brotli(&data))]
        {
            compressed.truncate(compressed.len() / 2);
            let mut decoder = Decoder::from_encoding(encoding).expect("decoder");
            let mut out = Vec::new();
            let pushed = decoder.push(&compressed, &mut out);
            let finished = pushed.and_then(|()| decoder.finish(&mut out));
            assert!(finished.is_err(), "{encoding:?} must not report success");
        }
    }

    #[test]
    fn an_unknown_encoding_is_refused_rather_than_passed_through() {
        let error = Decoder::from_encoding(Some("zstd")).expect_err("unsupported");
        assert_eq!(error.class(), "encoding");
        assert!(!error.is_retryable());
    }
}
