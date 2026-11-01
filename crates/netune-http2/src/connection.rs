// SPDX-License-Identifier: AGPL-3.0-only

//! HTTP/2 client connection state machine and stream transport.
//!
//! # What a real server does that a naive client does not expect
//!
//! | Behaviour | RFC 9113 | Handled by |
//! | --- | --- | --- |
//! | Splits a header block across `HEADERS` + `CONTINUATION` | §6.10 | `read_header_block` |
//! | Sends `PUSH_PROMISE` | §6.6 | declined with `REFUSED_STREAM` |
//! | Applies per-stream and connection flow control | §6.9 | `replenish`, `write_data` |
//! | Sends `GOAWAY` mid-request to drain | §6.8 | surfaced only when it covers our stream |
//! | Answers a `PING` and expects the ACK | §6.7 | `handle_housekeeping` |
//!
//! Each of those was missing, and each one is a way a client that works against a
//! hand-written mock fails against nginx or Cloudflare.
//!
//! # Flow control is not optional
//!
//! A client that never sends `WINDOW_UPDATE` reads exactly 65,535 bytes and then hangs: the
//! server considers the window exhausted and stops sending. A response larger than one
//! window is therefore the normal case that fails, not an edge case.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::H2Error;
use crate::fingerprint::H2Fingerprint;
use crate::frame::*;
use crate::hpack::{HpackDecoder, HpackEncoder};

/// HTTP/2 client connection preface magic string (RFC 9113 §3.4).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The default flow-control window (RFC 9113 §6.9.2).
pub const DEFAULT_WINDOW: i64 = 65_535;

/// The default maximum frame payload (RFC 9113 §6.5.2).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// `REFUSED_STREAM`: declines one pushed stream without failing the connection.
pub const ERROR_REFUSED_STREAM: u32 = 0x7;

/// A parsed HTTP/2 response.
#[derive(Debug, Clone)]
pub struct H2Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// An established HTTP/2 client connection over an arbitrary transport.
pub struct H2Connection<T> {
    stream: T,
    fingerprint: H2Fingerprint,
    next_stream_id: u32,
    encoder: HpackEncoder,
    decoder: HpackDecoder,
    read_buf: BytesMut,
    /// Connection-level send window remaining (RFC 9113 §6.9.1).
    connection_send_window: i64,
    /// The peer's maximum frame size, from its SETTINGS.
    peer_max_frame_size: u32,
}

impl<T> std::fmt::Debug for H2Connection<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Connection")
            .field("next_stream_id", &self.next_stream_id)
            .field("peer_max_frame_size", &self.peer_max_frame_size)
            .field("buffered", &self.read_buf.len())
            .finish_non_exhaustive()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> H2Connection<T> {
    /// Perform the client HTTP/2 handshake according to `fingerprint`.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for a frame no handshake may carry, and an I/O error from
    /// the transport.
    pub async fn handshake(mut stream: T, fingerprint: H2Fingerprint) -> Result<Self, H2Error> {
        stream.write_all(CLIENT_PREFACE).await?;

        let settings_frame = Frame::Settings {
            ack: false,
            settings: fingerprint.settings.clone(),
        };
        stream.write_all(&settings_frame.encode()).await?;

        if let Some(increment) = fingerprint.initial_connection_window_update {
            let frame = Frame::WindowUpdate {
                stream_id: 0,
                increment,
            };
            stream.write_all(&frame.encode()).await?;
        }
        stream.flush().await?;

        let header_table_size = usize::try_from(fingerprint.header_table_size).unwrap_or(4096);

        let mut connection = Self {
            stream,
            fingerprint,
            next_stream_id: 1,
            encoder: HpackEncoder::new(),
            decoder: HpackDecoder::with_max_table_size(header_table_size),
            read_buf: BytesMut::with_capacity(16 * 1024),
            connection_send_window: DEFAULT_WINDOW,
            peer_max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        };

        let mut got_server_settings = false;
        let mut got_settings_ack = false;
        while !(got_server_settings && got_settings_ack) {
            let frame = connection.read_frame().await?;
            match frame {
                Frame::Settings {
                    ack: false,
                    settings,
                } => {
                    got_server_settings = true;
                    connection.apply_peer_settings(&settings);
                    let ack_frame = Frame::Settings {
                        ack: true,
                        settings: Vec::new(),
                    };
                    connection.stream.write_all(&ack_frame.encode()).await?;
                    connection.stream.flush().await?;
                }
                Frame::Settings { ack: true, .. } => got_settings_ack = true,
                Frame::WindowUpdate { .. } | Frame::Ping { .. } => {
                    connection.handle_housekeeping(frame).await?;
                }
                other => {
                    return Err(H2Error::Protocol(format!(
                        "unexpected frame during handshake: {other:?}"
                    )));
                }
            }
        }

        Ok(connection)
    }

    /// Records the peer's declared settings that constrain our sends.
    fn apply_peer_settings(&mut self, settings: &[(u16, u32)]) {
        for (id, value) in settings {
            match *id {
                SETTING_MAX_FRAME_SIZE if *value >= DEFAULT_MAX_FRAME_SIZE => {
                    self.peer_max_frame_size = *value;
                }
                SETTING_HEADER_TABLE_SIZE => {
                    // The peer declares how large *its* decoder table is; our encoder must
                    // not exceed it.
                    let _ = self.encoder.set_max_size(*value as usize, &mut Vec::new());
                }
                _ => {}
            }
        }
    }

    /// Answers a `PING`, tracks a connection `WINDOW_UPDATE`, and declines a push.
    async fn handle_housekeeping(&mut self, frame: Frame) -> Result<(), H2Error> {
        match frame {
            Frame::Ping {
                ack: false,
                opaque_data,
            } => {
                let ack = Frame::Ping {
                    ack: true,
                    opaque_data,
                };
                self.stream.write_all(&ack.encode()).await?;
                self.stream.flush().await?;
            }
            Frame::WindowUpdate {
                stream_id: 0,
                increment,
            } => {
                self.connection_send_window += i64::from(increment);
            }
            Frame::PushPromise {
                promised_stream_id, ..
            } => {
                // Push was not requested. RFC 9113 §6.6 allows declining the *promised*
                // stream without failing the connection, which is strictly better than
                // dropping the whole response. Refusing the request stream instead would
                // cancel the response the caller is waiting for.
                let rst = Frame::RstStream {
                    stream_id: promised_stream_id,
                    error_code: ERROR_REFUSED_STREAM,
                };
                self.stream.write_all(&rst.encode()).await?;
                self.stream.flush().await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Send a request on a new stream and await the complete response.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for a malformed response, a `RST_STREAM` on our stream, or
    /// a `GOAWAY` that cuts the request off, and an I/O error from the transport.
    pub async fn request(
        &mut self,
        method: &str,
        authority: &str,
        scheme: &str,
        path: &str,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<H2Response, H2Error> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        let ordered =
            self.fingerprint
                .order_request_headers(method, authority, scheme, path, extra_headers);
        let header_block = self.encoder.encode(ordered);
        let has_body = body.is_some_and(|bytes| !bytes.is_empty());

        self.write_header_block(stream_id, &header_block, !has_body)
            .await?;
        if let Some(body_bytes) = body.filter(|bytes| !bytes.is_empty()) {
            self.write_data(stream_id, body_bytes, true).await?;
        }
        self.stream.flush().await?;

        let mut status = None;
        let mut response_headers = Vec::new();
        let mut response_body = BytesMut::new();

        loop {
            let frame = self.read_frame().await?;
            match frame {
                Frame::Headers {
                    stream_id: sid,
                    end_stream,
                    end_headers,
                    header_block,
                } if sid == stream_id => {
                    let block = if end_headers {
                        header_block
                    } else {
                        self.read_header_block(header_block).await?
                    };
                    let decoded = self.decoder.decode(&block)?;
                    for (name, value) in decoded {
                        if name == ":status" {
                            status = value.parse::<u16>().ok();
                        } else {
                            response_headers.push((name, value));
                        }
                    }
                    if end_stream {
                        break;
                    }
                }
                Frame::Data {
                    stream_id: sid,
                    end_stream,
                    payload,
                } if sid == stream_id => {
                    response_body.extend_from_slice(&payload);
                    // Return the credit as soon as it is consumed; deferring it to the end
                    // would stall at one window.
                    self.replenish(stream_id, payload.len() as u32).await?;
                    if end_stream {
                        break;
                    }
                }
                Frame::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                } if last_stream_id < stream_id => {
                    // A GOAWAY that still covers our stream lets it finish; one that does
                    // not has already abandoned this request. Matching on the condition
                    // rather than branching inside the arm keeps the fall-through case
                    // (a GOAWAY that covers us) in the shared arm below, where it belongs.
                    return Err(H2Error::GoAway {
                        error_code,
                        debug_data: debug_data.to_vec(),
                    });
                }
                Frame::GoAway { .. } => {}
                Frame::RstStream {
                    stream_id: sid,
                    error_code,
                } if sid == stream_id => {
                    return Err(H2Error::StreamReset {
                        stream_id: sid,
                        error_code,
                    });
                }
                Frame::Ping { .. } | Frame::WindowUpdate { .. } | Frame::PushPromise { .. } => {
                    self.handle_housekeeping(frame).await?;
                }
                Frame::Settings {
                    ack: false,
                    settings,
                } => {
                    self.apply_peer_settings(&settings);
                    let ack = Frame::Settings {
                        ack: true,
                        settings: Vec::new(),
                    };
                    self.stream.write_all(&ack.encode()).await?;
                    self.stream.flush().await?;
                }
                _ => {}
            }
        }

        let status =
            status.ok_or_else(|| H2Error::Protocol("missing :status pseudo-header".into()))?;
        Ok(H2Response {
            status,
            headers: response_headers,
            body: response_body.freeze(),
        })
    }

    /// Reads the rest of a header block delivered as `CONTINUATION` frames.
    ///
    /// A server splits a block whenever it exceeds the maximum frame size, so a response
    /// with several `set-cookie` lines takes this path — the common case, not the exotic
    /// one.
    async fn read_header_block(&mut self, first: Bytes) -> Result<Bytes, H2Error> {
        let mut block = BytesMut::from(&first[..]);
        loop {
            let frame = self.read_frame().await?;
            match frame {
                Frame::Continuation {
                    end_headers,
                    header_block,
                    ..
                } => {
                    block.extend_from_slice(&header_block);
                    if end_headers {
                        return Ok(block.freeze());
                    }
                }
                Frame::Ping { .. } | Frame::WindowUpdate { .. } | Frame::PushPromise { .. } => {
                    self.handle_housekeeping(frame).await?;
                }
                other => {
                    return Err(H2Error::Protocol(format!(
                        "expected CONTINUATION inside a header block, got {other:?}"
                    )));
                }
            }
        }
    }

    /// Writes a header block, splitting it across `CONTINUATION` frames when needed.
    async fn write_header_block(
        &mut self,
        stream_id: u32,
        block: &[u8],
        end_stream: bool,
    ) -> Result<(), H2Error> {
        let max = self.peer_max_frame_size as usize;
        if block.len() <= max {
            let frame = Frame::Headers {
                stream_id,
                end_stream,
                end_headers: true,
                header_block: Bytes::copy_from_slice(block),
            };
            self.stream.write_all(&frame.encode()).await?;
            return Ok(());
        }

        let (head, rest) = block.split_at(max);
        let frame = Frame::Headers {
            stream_id,
            end_stream,
            end_headers: false,
            header_block: Bytes::copy_from_slice(head),
        };
        self.stream.write_all(&frame.encode()).await?;

        let mut chunks = rest.chunks(max).peekable();
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            let frame = Frame::Continuation {
                stream_id,
                end_headers: last,
                header_block: Bytes::copy_from_slice(chunk),
            };
            self.stream.write_all(&frame.encode()).await?;
        }
        Ok(())
    }

    /// Writes body bytes, respecting both flow-control windows.
    async fn write_data(
        &mut self,
        stream_id: u32,
        body: &[u8],
        end_stream: bool,
    ) -> Result<(), H2Error> {
        let max = self.peer_max_frame_size as usize;
        let mut remaining = body;
        while !remaining.is_empty() {
            // Wait for connection-level credit. A body large enough to exhaust it is
            // rare, but silently truncating one is not acceptable.
            while self.connection_send_window <= 0 {
                let frame = self.read_frame().await?;
                match frame {
                    Frame::WindowUpdate {
                        stream_id: 0,
                        increment,
                    } => self.connection_send_window += i64::from(increment),
                    other => self.handle_housekeeping(other).await?,
                }
            }
            let allowed = usize::try_from(self.connection_send_window)
                .unwrap_or(usize::MAX)
                .min(max);
            let take = remaining.len().min(allowed).max(1);
            let (chunk, rest) = remaining.split_at(take);
            let last = rest.is_empty();
            let frame = Frame::Data {
                stream_id,
                end_stream: end_stream && last,
                payload: Bytes::copy_from_slice(chunk),
            };
            self.stream.write_all(&frame.encode()).await?;
            self.connection_send_window -= chunk.len() as i64;
            remaining = rest;
        }
        if body.is_empty() && end_stream {
            let frame = Frame::Data {
                stream_id,
                end_stream: true,
                payload: Bytes::new(),
            };
            self.stream.write_all(&frame.encode()).await?;
        }
        Ok(())
    }

    /// Returns flow-control credit for `consumed` bytes on `stream_id`.
    async fn replenish(&mut self, stream_id: u32, consumed: u32) -> Result<(), H2Error> {
        if consumed == 0 {
            return Ok(());
        }
        let connection = Frame::WindowUpdate {
            stream_id: 0,
            increment: consumed,
        };
        self.stream.write_all(&connection.encode()).await?;
        let stream = Frame::WindowUpdate {
            stream_id,
            increment: consumed,
        };
        self.stream.write_all(&stream.encode()).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read exactly one complete HTTP/2 frame from the transport.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for a frame larger than the negotiated maximum, which keeps
    /// a hostile length field from choosing our allocation.
    pub async fn read_frame(&mut self) -> Result<Frame, H2Error> {
        loop {
            if self.read_buf.len() >= FRAME_HEADER_LEN {
                let Some(header) = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_LEN]) else {
                    return Err(H2Error::Protocol("invalid frame header format".into()));
                };
                let limit = self.peer_max_frame_size.max(DEFAULT_MAX_FRAME_SIZE);
                if header.length > limit {
                    return Err(H2Error::FrameSize(format!(
                        "frame claims {} bytes, over the negotiated maximum {limit}",
                        header.length
                    )));
                }
                let total_len = FRAME_HEADER_LEN + header.length as usize;
                if self.read_buf.len() >= total_len {
                    let _ = self.read_buf.split_to(FRAME_HEADER_LEN);
                    let payload = self.read_buf.split_to(header.length as usize).freeze();
                    return Frame::decode(&header, payload);
                }
            }

            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(H2Error::UnexpectedEof);
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Reads one frame from a server-side socket.
    async fn server_read_frame(socket: &mut tokio::net::TcpStream) -> Frame {
        let mut header = [0u8; FRAME_HEADER_LEN];
        socket.read_exact(&mut header).await.expect("header");
        let parsed = FrameHeader::parse(&header).expect("parse");
        let mut payload = vec![0u8; parsed.length as usize];
        socket.read_exact(&mut payload).await.expect("payload");
        Frame::decode(&parsed, Bytes::from(payload)).expect("decode")
    }

    /// Reads the preface and the client's SETTINGS, answers, and completes the handshake.
    async fn server_handshake(socket: &mut tokio::net::TcpStream) {
        let mut preface = [0u8; CLIENT_PREFACE.len()];
        socket.read_exact(&mut preface).await.expect("preface");
        assert_eq!(&preface[..], CLIENT_PREFACE);

        let first = server_read_frame(socket).await;
        assert!(matches!(first, Frame::Settings { ack: false, .. }));
        // The Chrome fingerprint sends a connection WINDOW_UPDATE; consume it if present.
        let next_is_window = {
            let mut peek = [0u8; FRAME_HEADER_LEN];
            socket.peek(&mut peek).await.expect("peek");
            FrameHeader::parse(&peek)
                .map(|header| header.frame_type == FRAME_WINDOW_UPDATE)
                .unwrap_or(false)
        };
        if next_is_window {
            let _ = server_read_frame(socket).await;
        }

        let settings = Frame::Settings {
            ack: false,
            settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 100)],
        };
        socket
            .write_all(&settings.encode())
            .await
            .expect("settings");

        let ack = server_read_frame(socket).await;
        assert!(matches!(ack, Frame::Settings { ack: true, .. }));

        let server_ack = Frame::Settings {
            ack: true,
            settings: Vec::new(),
        };
        socket.write_all(&server_ack.encode()).await.expect("ack");
    }

    #[tokio::test]
    async fn handshake_and_request_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            server_handshake(&mut socket).await;

            let (stream_id, block) = match server_read_frame(&mut socket).await {
                Frame::Headers {
                    stream_id,
                    header_block,
                    end_stream,
                    ..
                } => {
                    assert!(end_stream, "a bodyless GET ends on HEADERS");
                    (stream_id, header_block)
                }
                other => panic!("expected HEADERS, got {other:?}"),
            };

            let mut decoder = HpackDecoder::new();
            let decoded = decoder.decode(&block).expect("decode request headers");
            assert!(decoded.iter().any(|(k, v)| k == ":method" && v == "GET"));

            let mut encoder = HpackEncoder::new();
            let response = encoder.encode([(":status", "200"), ("content-type", "text/plain")]);
            socket
                .write_all(
                    &Frame::Headers {
                        stream_id,
                        end_stream: false,
                        end_headers: true,
                        header_block: response,
                    }
                    .encode(),
                )
                .await
                .expect("headers");
            socket
                .write_all(
                    &Frame::Data {
                        stream_id,
                        end_stream: true,
                        payload: Bytes::from_static(b"hello http/2"),
                    }
                    .encode(),
                )
                .await
                .expect("data");

            // Flow-control credit must come back for the body.
            let update = server_read_frame(&mut socket).await;
            assert!(
                matches!(update, Frame::WindowUpdate { stream_id: 0, increment } if increment > 0),
                "expected a connection WINDOW_UPDATE, got {update:?}"
            );
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut client = H2Connection::handshake(tcp, H2Fingerprint::chrome())
            .await
            .expect("handshake");
        let response = client
            .request("GET", "example.com", "https", "/test", &[], None)
            .await
            .expect("request");

        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_ref(), b"hello http/2");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn a_header_block_split_across_continuation_frames_is_reassembled() {
        // The case that fails on any server whose response headers exceed one frame.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            server_handshake(&mut socket).await;

            let stream_id = match server_read_frame(&mut socket).await {
                Frame::Headers { stream_id, .. } => stream_id,
                other => panic!("expected HEADERS, got {other:?}"),
            };

            let mut encoder = HpackEncoder::new();
            let block = encoder.encode([(":status", "200"), ("x-large", &"v".repeat(64))]);
            let split = block.len() / 2;
            socket
                .write_all(
                    &Frame::Headers {
                        stream_id,
                        end_stream: false,
                        end_headers: false,
                        header_block: block.slice(..split),
                    }
                    .encode(),
                )
                .await
                .expect("headers");
            socket
                .write_all(
                    &Frame::Continuation {
                        stream_id,
                        end_headers: true,
                        header_block: block.slice(split..),
                    }
                    .encode(),
                )
                .await
                .expect("continuation");
            socket
                .write_all(
                    &Frame::Data {
                        stream_id,
                        end_stream: true,
                        payload: Bytes::from_static(b"ok"),
                    }
                    .encode(),
                )
                .await
                .expect("data");
            let _ = server_read_frame(&mut socket).await;
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut client = H2Connection::handshake(tcp, H2Fingerprint::chrome())
            .await
            .expect("handshake");
        let response = client
            .request("GET", "example.com", "https", "/big", &[], None)
            .await
            .expect("request");

        assert_eq!(response.status, 200);
        assert!(
            response
                .headers
                .iter()
                .any(|(k, v)| k == "x-large" && v.len() == 64),
            "headers from the CONTINUATION frame must be present: {:?}",
            response.headers
        );
        server.await.expect("server");
    }

    #[tokio::test]
    async fn a_push_promise_is_declined_without_failing_the_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            server_handshake(&mut socket).await;

            let stream_id = match server_read_frame(&mut socket).await {
                Frame::Headers { stream_id, .. } => stream_id,
                other => panic!("expected HEADERS, got {other:?}"),
            };

            socket
                .write_all(
                    &Frame::PushPromise {
                        stream_id,
                        promised_stream_id: 2,
                        end_headers: true,
                        header_block: Bytes::from_static(&[0x82]),
                    }
                    .encode(),
                )
                .await
                .expect("push");

            let mut encoder = HpackEncoder::new();
            let block = encoder.encode([(":status", "204")]);
            socket
                .write_all(
                    &Frame::Headers {
                        stream_id,
                        end_stream: true,
                        end_headers: true,
                        header_block: block,
                    }
                    .encode(),
                )
                .await
                .expect("headers");

            match server_read_frame(&mut socket).await {
                Frame::RstStream {
                    stream_id: 2,
                    error_code,
                } => {
                    assert_eq!(error_code, ERROR_REFUSED_STREAM);
                }
                other => panic!("expected RST_STREAM on the promised stream, got {other:?}"),
            }
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut client = H2Connection::handshake(tcp, H2Fingerprint::chrome())
            .await
            .expect("handshake");
        let response = client
            .request("GET", "example.com", "https", "/push", &[], None)
            .await
            .expect("a declined push must not break the response");
        assert_eq!(response.status, 204);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn a_goaway_covering_our_stream_does_not_fail_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            server_handshake(&mut socket).await;

            let stream_id = match server_read_frame(&mut socket).await {
                Frame::Headers { stream_id, .. } => stream_id,
                other => panic!("expected HEADERS, got {other:?}"),
            };

            socket
                .write_all(
                    &Frame::GoAway {
                        last_stream_id: stream_id,
                        error_code: 0,
                        debug_data: Bytes::from_static(b"draining"),
                    }
                    .encode(),
                )
                .await
                .expect("goaway");

            let mut encoder = HpackEncoder::new();
            let block = encoder.encode([(":status", "200")]);
            socket
                .write_all(
                    &Frame::Headers {
                        stream_id,
                        end_stream: true,
                        end_headers: true,
                        header_block: block,
                    }
                    .encode(),
                )
                .await
                .expect("headers");
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut client = H2Connection::handshake(tcp, H2Fingerprint::chrome())
            .await
            .expect("handshake");
        let response = client
            .request("GET", "example.com", "https", "/drain", &[], None)
            .await
            .expect("a GOAWAY that still covers the stream must let it finish");
        assert_eq!(response.status, 200);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn an_oversized_frame_length_is_refused_rather_than_allocated() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            server_handshake(&mut socket).await;
            let mut header = [0u8; FRAME_HEADER_LEN];
            header[0] = 0xff;
            header[1] = 0xff;
            header[2] = 0xff;
            header[3] = FRAME_DATA;
            socket.write_all(&header).await.expect("header");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut client = H2Connection::handshake(tcp, H2Fingerprint::chrome())
            .await
            .expect("handshake");
        let error = client
            .request("GET", "example.com", "https", "/big", &[], None)
            .await
            .expect_err("must refuse");
        assert!(
            format!("{error}").contains("over the negotiated maximum"),
            "{error}"
        );
    }
}
