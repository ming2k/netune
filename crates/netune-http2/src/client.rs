//! HTTP/2 *client* role: open a connection with a chosen fingerprint and send requests.
//!
//! The connection layer ([`crate::connection`]) owns framing, `SETTINGS`, flow control and
//! HPACK. This module owns what is the client's alone:
//!
//! 1. **The preface and the advertised settings**, which are the two halves of an Akamai
//!    fingerprint ([`crate::fingerprint`], ADR-0006). A client that normalised either would be
//!    indistinguishable from a library — which is exactly what a bot-management service looks
//!    for.
//! 2. **Stream origination** (odd ids) and one response per request.
//! 3. **The SETTINGS handshake**: send ours, wait for the peer's, acknowledge it, and refuse to
//!    send a request on a connection whose SETTINGS exchange did not complete.
//!
//! # Why requests are serialised in this client
//!
//! The harness this crate serves issues one request per attempt and traces its phases
//! (`ADR-0001`): a trace with two concurrent exchanges on one connection has no single
//! `first token`, and the derivation would have to refuse it. Multi-stream clients are
//! legitimate and the connection layer supports them (see [`crate::server`] for the other
//! direction), but an *egress* attempt is one request by definition here.

use bytes::Bytes;
use http::Method;

use crate::connection::{H2Connection, LocalSettings, Role};
use crate::error::H2Error;
use crate::fingerprint::H2Fingerprint;
use crate::frame::Frame;

/// A parsed HTTP/2 response.
#[derive(Debug, Clone)]
pub struct H2Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// The `:trailers` block, when the peer sent one.
    pub trailers: Vec<(String, String)>,
}

/// The head of a streamed HTTP/2 response.
#[derive(Debug, Clone)]
pub struct H2ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Whether the response head was also the end of the stream (no body).
    pub end_stream: bool,
}

/// One increment of a streamed HTTP/2 response.
#[derive(Debug, Clone)]
pub enum H2ResponseEvent {
    /// A `DATA` frame payload. `end_stream` marks the last payload.
    Data { payload: Bytes, end_stream: bool },
    /// The trailer section: a second `HEADERS` block that ends the stream.
    Trailers(Vec<(String, String)>),
    /// The stream is complete; the connection is idle.
    End,
}

/// An owning, incremental reader over one HTTP/2 response body.
///
/// The connection is owned by this stream because requests on it are
/// serialized: nothing else may write to the connection until the body has
/// ended. [`Self::into_connection`] recovers it for reuse once the stream is
/// complete.
pub struct H2ResponseStream<T> {
    connection: Option<H2ClientConnection<T>>,
    stream_id: u32,
    /// Body bytes received but not yet credited back with `WINDOW_UPDATE`.
    unacked: u32,
    /// This end's remaining receive window for the stream.
    stream_recv_window: i64,
    finished: bool,
    reusable: bool,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> H2ResponseStream<T> {
    /// The stream this body belongs to.
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Whether the response body has ended.
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Read the next event: a data payload, the trailer block, or the end.
    ///
    /// After [`H2ResponseEvent::End`] this method is idempotent.
    ///
    /// # Errors
    ///
    /// A transport error, a stream reset, or a framing/flow-control violation.
    pub async fn next_event(&mut self) -> Result<H2ResponseEvent, H2Error> {
        if self.finished {
            return Ok(H2ResponseEvent::End);
        }
        let Some(connection) = self.connection.as_mut() else {
            return Ok(H2ResponseEvent::End);
        };
        let event = connection
            .next_body_event(
                self.stream_id,
                &mut self.unacked,
                &mut self.stream_recv_window,
            )
            .await?;
        match &event {
            H2ResponseEvent::Data {
                end_stream: true, ..
            }
            | H2ResponseEvent::Trailers(_)
            | H2ResponseEvent::End => self.finished = true,
            H2ResponseEvent::Data {
                end_stream: false, ..
            } => {}
        }
        self.reusable = connection.is_reusable();
        Ok(event)
    }

    /// Recover the connection and whether it may serve another request.
    ///
    /// `None` is returned only if the connection was already taken. The flag is
    /// `false` when the body was not read to completion or the peer sent
    /// `GOAWAY`, in which case the caller must drop the connection rather than
    /// pool it.
    pub fn into_connection(mut self) -> Option<(H2ClientConnection<T>, bool)> {
        let connection = self.connection.take()?;
        let reusable = self.finished && self.reusable && connection.is_reusable();
        Some((connection, reusable))
    }
}

/// Flow-control credit is returned to the peer once this many unacknowledged
/// body bytes accumulate (or when the stream ends).
const REPLENISH_THRESHOLD: u32 = 16 * 1024;

/// An established HTTP/2 client connection over an arbitrary transport.
pub struct H2ClientConnection<T> {
    connection: H2Connection<T>,
    /// The fingerprint this connection was opened with, kept for per-request
    /// pseudo-header ordering.
    fingerprint: H2Fingerprint,
    /// A write failed while returning advisory end-of-stream flow control. The
    /// exchange itself completed, but the socket is no longer safe to reuse.
    unusable: bool,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> H2ClientConnection<T> {
    /// Perform the client handshake according to `fingerprint`.
    ///
    /// This writes the preface, the profile's `SETTINGS` parameters in the profile's order and
    /// its initial connection-level `WINDOW_UPDATE`, then completes the SETTINGS exchange in
    /// both directions. It returns only when the peer has answered, so a request sent on the
    /// result cannot race the negotiation.
    ///
    /// # Errors
    ///
    /// A transport error, or a protocol error from a frame no handshake may carry.
    pub async fn handshake(stream: T, fingerprint: H2Fingerprint) -> Result<Self, H2Error> {
        // The bounds this end advertises are the bounds it must enforce while
        // reading: a peer may use the largest frame and window we announced.
        let local = LocalSettings::advertised(&fingerprint.settings, fingerprint.header_table_size);
        let mut connection = H2Connection::client_handshake(
            stream,
            local,
            fingerprint.settings.clone(),
            fingerprint.initial_connection_window_update,
        )
        .await?;

        let mut got_peer_settings = false;
        let mut got_settings_ack = false;
        while !(got_peer_settings && got_settings_ack) {
            let frame = connection.read_frame().await?;
            match frame {
                Frame::Settings {
                    ack: false,
                    settings,
                } => {
                    got_peer_settings = true;
                    connection.apply_peer_settings(&settings)?;
                    connection
                        .write_frame(&Frame::Settings {
                            ack: true,
                            settings: Vec::new(),
                        })
                        .await?;
                    connection.flush().await?;
                }
                Frame::Settings { ack: true, .. } => got_settings_ack = true,
                // A server may send a connection-level `WINDOW_UPDATE` before its SETTINGS ACK;
                // it is the standard shape of an nginx/Cloudflare preamble.
                Frame::WindowUpdate {
                    stream_id: 0,
                    increment,
                } => {
                    connection.apply_connection_window_update(increment)?;
                }
                other => connection.handle_housekeeping(other).await?,
            }
        }

        Ok(Self {
            connection,
            fingerprint,
            unusable: false,
        })
    }

    /// The fingerprint in force.
    pub const fn fingerprint(&self) -> &H2Fingerprint {
        &self.fingerprint
    }

    /// Write one request and return the stream id it opened.
    ///
    /// `authority` is the `:authority` pseudo-header; `scheme` is `https` or
    /// `http`; `path` is the `:path`.
    ///
    /// Requests on a connection are serialized: the caller MUST read the
    /// response head (and, for a streamed body, the whole body) before sending
    /// the next request.
    ///
    /// # Errors
    ///
    /// A transport error, or a protocol error while framing the request.
    pub async fn start_request(
        &mut self,
        method: &str,
        authority: &str,
        scheme: &str,
        path: &str,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<u32, H2Error> {
        let stream_id = self
            .connection
            .allocate_stream_id()
            .ok_or_else(|| H2Error::Protocol("no stream id remains on this connection".into()))?;

        let pseudo = [
            (":method", method),
            (":authority", authority),
            (":scheme", scheme),
            (":path", path),
        ];
        let ordered = self.fingerprint.pseudo_headers_order.order(&pseudo);
        let mut headers: Vec<(&str, &str)> = ordered;
        for (name, value) in extra_headers {
            headers.push((name.as_str(), value.as_str()));
        }

        let block = self.connection.encode_header_block(headers);
        let no_body = body.is_none_or(<[u8]>::is_empty);
        self.connection
            .write_header_block(stream_id, &block, no_body)
            .await?;
        if !no_body {
            let window = i64::from(self.connection.peer.initial_window_size);
            self.connection
                .write_data(stream_id, body.unwrap_or_default(), true, window)
                .await?;
        }
        self.connection.flush().await?;
        Ok(stream_id)
    }

    /// Read frames until the response head for `stream_id` arrives.
    ///
    /// # Errors
    ///
    /// A transport error, a protocol error, a stream reset, or a `GOAWAY` that
    /// does not cover this stream.
    pub async fn read_response_head(&mut self, stream_id: u32) -> Result<H2ResponseHead, H2Error> {
        loop {
            let frame = self.connection.read_frame().await?;
            match frame {
                Frame::Headers {
                    stream_id: id,
                    end_stream,
                    end_headers,
                    header_block,
                } if id == stream_id => {
                    let block = if end_headers {
                        header_block
                    } else {
                        self.connection.read_header_block(header_block).await?
                    };
                    let fields = self.connection.decoder().decode(&block)?;
                    let (status, headers) = split_response(fields);
                    return Ok(H2ResponseHead {
                        status,
                        headers,
                        end_stream,
                    });
                }
                Frame::Data { stream_id: id, .. } if id == stream_id => {
                    return Err(H2Error::Protocol(
                        "response DATA arrived before its HEADERS".into(),
                    ));
                }
                Frame::RstStream {
                    stream_id: id,
                    error_code,
                } if id == stream_id => {
                    return Err(H2Error::StreamReset {
                        stream_id: id,
                        error_code,
                    });
                }
                Frame::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                } => {
                    // A GOAWAY that still covers our stream lets it finish; one
                    // that does not is the peer saying this request will never
                    // be answered.
                    if last_stream_id < stream_id {
                        return Err(H2Error::GoAway {
                            error_code,
                            debug_data: debug_data.to_vec(),
                        });
                    }
                    self.connection
                        .handle_housekeeping(Frame::GoAway {
                            last_stream_id,
                            error_code,
                            debug_data,
                        })
                        .await?;
                }
                Frame::PushPromise { .. } => {
                    // Never requested (ENABLE_PUSH=0); declining documents the refusal.
                }
                Frame::Continuation { .. } => {
                    return Err(H2Error::Protocol(
                        "CONTINUATION outside a header block".into(),
                    ));
                }
                other => self.connection.handle_housekeeping(other).await?,
            }
        }
    }

    /// Consume the connection into an owning body stream positioned after the
    /// response head for `stream_id`.
    pub fn into_response_stream(
        self,
        stream_id: u32,
        head: &H2ResponseHead,
    ) -> H2ResponseStream<T> {
        let stream_recv_window = i64::from(self.connection.local.initial_window_size);
        let reusable = self.is_reusable();
        H2ResponseStream {
            connection: Some(self),
            stream_id,
            unacked: 0,
            stream_recv_window,
            finished: head.end_stream,
            reusable,
        }
    }

    /// Send one request and return its head plus an owning body stream.
    ///
    /// # Errors
    ///
    /// A transport error, a protocol error, or a `GOAWAY` that does not cover
    /// this stream.
    pub async fn request_stream(
        mut self,
        method: &str,
        authority: &str,
        scheme: &str,
        path: &str,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(H2ResponseHead, H2ResponseStream<T>), H2Error> {
        let stream_id = self
            .start_request(method, authority, scheme, path, extra_headers, body)
            .await?;
        let head = self.read_response_head(stream_id).await?;
        let response = self.into_response_stream(stream_id, &head);
        Ok((head, response))
    }

    /// Send one request and read its complete response.
    ///
    /// Kept for callers that need the whole body in one value; prefer
    /// [`Self::request_stream`] when the response is consumed incrementally.
    ///
    /// # Errors
    ///
    /// A transport error, a protocol error, or a `GOAWAY` that does not cover this stream.
    pub async fn request(
        &mut self,
        method: &str,
        authority: &str,
        scheme: &str,
        path: &str,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<H2Response, H2Error> {
        let stream_id = self
            .start_request(method, authority, scheme, path, extra_headers, body)
            .await?;
        let head = self.read_response_head(stream_id).await?;

        let mut bytes = bytes::BytesMut::new();
        let mut trailers = Vec::new();
        let mut unacked: u32 = 0;
        let mut stream_recv_window = i64::from(self.connection.local.initial_window_size);
        let mut finished = head.end_stream;
        while !finished {
            match self
                .next_body_event(stream_id, &mut unacked, &mut stream_recv_window)
                .await?
            {
                H2ResponseEvent::Data {
                    payload,
                    end_stream,
                } => {
                    bytes.extend_from_slice(&payload);
                    finished = end_stream;
                }
                H2ResponseEvent::Trailers(fields) => {
                    trailers = fields;
                    finished = true;
                }
                H2ResponseEvent::End => finished = true,
            }
        }
        self.return_credit(stream_id, &mut unacked, &mut stream_recv_window, true)
            .await?;

        Ok(H2Response {
            status: head.status,
            headers: head.headers,
            body: bytes.freeze(),
            trailers,
        })
    }

    /// Whether this connection may serve another request.
    pub fn is_reusable(&self) -> bool {
        !self.unusable && self.connection.goaway_last_stream().is_none()
    }

    /// The transport underneath, for a caller that wants to keep the connection.
    pub fn into_inner(self) -> T {
        self.connection.into_inner()
    }

    /// Read one event of the response body for `stream_id`.
    async fn next_body_event(
        &mut self,
        stream_id: u32,
        unacked: &mut u32,
        stream_recv_window: &mut i64,
    ) -> Result<H2ResponseEvent, H2Error> {
        loop {
            let frame = self.connection.read_frame().await?;
            match frame {
                Frame::Headers {
                    stream_id: id,
                    end_stream,
                    end_headers,
                    header_block,
                } if id == stream_id => {
                    let block = if end_headers {
                        header_block
                    } else {
                        self.connection.read_header_block(header_block).await?
                    };
                    let fields = self.connection.decoder().decode(&block)?;
                    if !end_stream {
                        return Err(H2Error::Protocol(
                            "a response trailer block must end the stream".into(),
                        ));
                    }
                    self.return_credit(stream_id, unacked, stream_recv_window, true)
                        .await?;
                    return Ok(H2ResponseEvent::Trailers(fields));
                }
                Frame::Data {
                    stream_id: id,
                    end_stream,
                    payload,
                } if id == stream_id => {
                    let length = payload.len() as u32;
                    *stream_recv_window -= i64::from(length);
                    if *stream_recv_window < 0 {
                        return Err(H2Error::Protocol(
                            "the peer exceeded the stream receive window".into(),
                        ));
                    }
                    self.connection.consume_inbound(length)?;
                    *unacked = unacked.saturating_add(length);
                    // One credit per threshold, plus one at the end of the stream:
                    // replenishing per frame is a WINDOW_UPDATE per DATA, and never
                    // replenishing at the end leaves the peer's view of the window
                    // smaller than ours forever.
                    if *unacked >= REPLENISH_THRESHOLD || end_stream {
                        self.return_credit(stream_id, unacked, stream_recv_window, end_stream)
                            .await?;
                    }
                    if payload.is_empty() {
                        if end_stream {
                            return Ok(H2ResponseEvent::End);
                        }
                        continue;
                    }
                    return Ok(H2ResponseEvent::Data {
                        payload,
                        end_stream,
                    });
                }
                Frame::RstStream {
                    stream_id: id,
                    error_code,
                } if id == stream_id => {
                    return Err(H2Error::StreamReset {
                        stream_id: id,
                        error_code,
                    });
                }
                Frame::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                } => {
                    if last_stream_id < stream_id {
                        return Err(H2Error::GoAway {
                            error_code,
                            debug_data: debug_data.to_vec(),
                        });
                    }
                    self.connection
                        .handle_housekeeping(Frame::GoAway {
                            last_stream_id,
                            error_code,
                            debug_data,
                        })
                        .await?;
                }
                Frame::PushPromise { .. } => {}
                Frame::Continuation { .. } => {
                    return Err(H2Error::Protocol(
                        "CONTINUATION outside a header block".into(),
                    ));
                }
                other => self.connection.handle_housekeeping(other).await?,
            }
        }
    }

    /// Return consumed body credit to the peer.
    ///
    /// Mid-stream both receive windows are restored and a write failure is a
    /// transport failure. At end of stream the stream is closed, so only the
    /// connection window still matters: that credit is advisory, a peer that
    /// already closed the socket cannot use it, and failing a response that
    /// completed because the peer hung up would be wrong.
    async fn return_credit(
        &mut self,
        stream_id: u32,
        unacked: &mut u32,
        stream_recv_window: &mut i64,
        end_of_stream: bool,
    ) -> Result<(), H2Error> {
        if *unacked == 0 {
            return Ok(());
        }
        let credit = std::mem::take(unacked);
        *stream_recv_window += i64::from(credit);
        if end_of_stream {
            if self.connection.replenish_connection(credit).await.is_err()
                || self.connection.flush().await.is_err()
            {
                self.unusable = true;
            }
            return Ok(());
        }
        self.connection.replenish(stream_id, credit).await?;
        self.connection.replenish_connection(credit).await?;
        self.connection.flush().await?;
        Ok(())
    }
}

fn split_response(fields: Vec<(String, String)>) -> (u16, Vec<(String, String)>) {
    let mut status = 0u16;
    let mut headers = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        if name == ":status" {
            status = value.parse().unwrap_or(0);
        } else {
            headers.push((name, value));
        }
    }
    (status, headers)
}

/// Convenience for the pseudo-header ordering: the fingerprint decides which order a server
/// observes.
impl crate::fingerprint::PseudoHeaderOrder {
    fn order<'a>(&self, pseudo: &[(&'a str, &'a str); 4]) -> Vec<(&'a str, &'a str)> {
        let mut out = Vec::with_capacity(4);
        for name in self.names() {
            if let Some((key, value)) = pseudo.iter().find(|(key, _)| *key == *name) {
                out.push((*key, *value));
            }
        }
        // A profile that named a pseudo-header we do not have must not silently drop the
        // others; whatever was not named follows in canonical order.
        for (key, value) in pseudo {
            if !out.iter().any(|(existing, _)| existing == key) {
                out.push((*key, *value));
            }
        }
        out
    }
}

/// Whether `method` may carry a request body in HTTP/2.
pub fn method_carries_body(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::CONNECT | Method::OPTIONS
    )
}

/// A short name for the role, used by callers that log the direction.
pub const fn role() -> Role {
    Role::Client
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::CLIENT_PREFACE;
    use crate::frame::*;
    use crate::hpack::HpackEncoder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A minimal server that completes the handshake and answers one request.
    async fn serve_once(socket: &mut TcpStream, body: &'static [u8], status: &'static str) {
        let mut preface = [0u8; CLIENT_PREFACE.len()];
        socket.read_exact(&mut preface).await.expect("preface");
        assert_eq!(&preface, CLIENT_PREFACE);

        let mut header = [0u8; FRAME_HEADER_LEN];
        socket
            .read_exact(&mut header)
            .await
            .expect("settings header");
        let settings = FrameHeader::parse(&header).expect("parse");
        let mut payload = vec![0u8; settings.length as usize];
        socket
            .read_exact(&mut payload)
            .await
            .expect("settings payload");

        socket
            .write_all(
                &Frame::Settings {
                    ack: false,
                    settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 100)],
                }
                .encode(),
            )
            .await
            .expect("server settings");

        // Client's WINDOW_UPDATE, if the profile sends one.
        loop {
            socket.read_exact(&mut header).await.expect("frame header");
            let frame = FrameHeader::parse(&header).expect("parse");
            let mut payload = vec![0u8; frame.length as usize];
            socket.read_exact(&mut payload).await.expect("payload");
            match frame.frame_type {
                FRAME_WINDOW_UPDATE => continue,
                FRAME_SETTINGS => break,
                other => panic!("unexpected frame {other}"),
            }
        }
        socket
            .write_all(
                &Frame::Settings {
                    ack: true,
                    settings: Vec::new(),
                }
                .encode(),
            )
            .await
            .expect("ack");

        // The request.
        socket.read_exact(&mut header).await.expect("headers");
        let frame = FrameHeader::parse(&header).expect("parse");
        let mut payload = vec![0u8; frame.length as usize];
        socket.read_exact(&mut payload).await.expect("payload");
        assert_eq!(frame.frame_type, FRAME_HEADERS);
        let stream_id = frame.stream_id;

        let mut encoder = HpackEncoder::new();
        let block = encoder.encode([(":status", status), ("content-type", "text/plain")]);
        socket
            .write_all(
                &Frame::Headers {
                    stream_id,
                    end_stream: false,
                    end_headers: true,
                    header_block: block,
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
                    payload: Bytes::from_static(body),
                }
                .encode(),
            )
            .await
            .expect("data");
    }

    /// A server that completes the handshake and sends a head, two data chunks,
    /// and a trailer block, so the client's incremental events can be observed.
    async fn serve_streaming(socket: &mut TcpStream) {
        let mut preface = [0u8; CLIENT_PREFACE.len()];
        socket.read_exact(&mut preface).await.expect("preface");
        assert_eq!(&preface, CLIENT_PREFACE);

        let mut header = [0u8; FRAME_HEADER_LEN];
        socket
            .read_exact(&mut header)
            .await
            .expect("settings header");
        let settings = FrameHeader::parse(&header).expect("parse");
        let mut payload = vec![0u8; settings.length as usize];
        socket
            .read_exact(&mut payload)
            .await
            .expect("settings payload");

        socket
            .write_all(
                &Frame::Settings {
                    ack: false,
                    settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 100)],
                }
                .encode(),
            )
            .await
            .expect("server settings");

        loop {
            socket.read_exact(&mut header).await.expect("frame header");
            let frame = FrameHeader::parse(&header).expect("parse");
            let mut payload = vec![0u8; frame.length as usize];
            socket.read_exact(&mut payload).await.expect("payload");
            match frame.frame_type {
                FRAME_WINDOW_UPDATE => continue,
                FRAME_SETTINGS => break,
                other => panic!("unexpected frame {other}"),
            }
        }
        socket
            .write_all(
                &Frame::Settings {
                    ack: true,
                    settings: Vec::new(),
                }
                .encode(),
            )
            .await
            .expect("ack");

        socket.read_exact(&mut header).await.expect("headers");
        let frame = FrameHeader::parse(&header).expect("parse");
        let mut payload = vec![0u8; frame.length as usize];
        socket.read_exact(&mut payload).await.expect("payload");
        assert_eq!(frame.frame_type, FRAME_HEADERS);
        let stream_id = frame.stream_id;

        let mut encoder = HpackEncoder::new();
        socket
            .write_all(
                &Frame::Headers {
                    stream_id,
                    end_stream: false,
                    end_headers: true,
                    header_block: encoder.encode([(":status", "200")]),
                }
                .encode(),
            )
            .await
            .expect("head");
        socket
            .write_all(
                &Frame::Data {
                    stream_id,
                    end_stream: false,
                    payload: Bytes::from_static(b"hello"),
                }
                .encode(),
            )
            .await
            .expect("data 1");
        socket
            .write_all(
                &Frame::Data {
                    stream_id,
                    end_stream: false,
                    payload: Bytes::from_static(b" world"),
                }
                .encode(),
            )
            .await
            .expect("data 2");
        socket
            .write_all(
                &Frame::Headers {
                    stream_id,
                    end_stream: true,
                    end_headers: true,
                    header_block: encoder.encode([("x-trailer", "done")]),
                }
                .encode(),
            )
            .await
            .expect("trailers");

        // The client returns connection-level credit at the end of the stream.
        // The stream is closed, so no stream-level update is required.
        let mut updates = 0;
        while updates < 1 {
            socket.read_exact(&mut header).await.expect("credit header");
            let frame = FrameHeader::parse(&header).expect("credit parse");
            let mut payload = vec![0u8; frame.length as usize];
            socket
                .read_exact(&mut payload)
                .await
                .expect("credit payload");
            if frame.frame_type == FRAME_WINDOW_UPDATE {
                updates += 1;
            }
        }
    }

    #[tokio::test]
    async fn a_streamed_response_delivers_data_and_trailers_incrementally() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            serve_streaming(&mut socket).await;
        });

        let stream = TcpStream::connect(address).await.expect("connect");
        let client = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
            .await
            .expect("handshake");
        let (head, mut body) = client
            .request_stream("GET", "example.com", "https", "/v1/models", &[], None)
            .await
            .expect("stream");
        assert_eq!(head.status, 200);
        assert!(!head.end_stream);

        match body.next_event().await.expect("event") {
            H2ResponseEvent::Data {
                payload,
                end_stream,
            } => {
                assert_eq!(&payload[..], b"hello");
                assert!(!end_stream);
            }
            other => panic!("expected data, got {other:?}"),
        }
        match body.next_event().await.expect("event") {
            H2ResponseEvent::Data {
                payload,
                end_stream,
            } => {
                assert_eq!(&payload[..], b" world");
                assert!(!end_stream);
            }
            other => panic!("expected data, got {other:?}"),
        }
        match body.next_event().await.expect("event") {
            H2ResponseEvent::Trailers(fields) => assert!(
                fields
                    .iter()
                    .any(|(name, value)| name == "x-trailer" && value == "done"),
                "the trailer block must be surfaced: {fields:?}"
            ),
            other => panic!("expected trailers, got {other:?}"),
        }
        assert!(matches!(
            body.next_event().await.expect("event"),
            H2ResponseEvent::End
        ));
        let (_, reusable) = body.into_connection().expect("connection");
        assert!(reusable, "a cleanly finished exchange must be reusable");

        server.await.expect("server");
    }

    #[tokio::test]
    async fn a_request_round_trips_with_the_profile_it_was_opened_with() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            serve_once(&mut socket, b"hello", "200").await;
        });

        let stream = TcpStream::connect(address).await.expect("connect");
        let mut client = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
            .await
            .expect("handshake");
        let response = client
            .request("GET", "example.com", "https", "/v1/models", &[], None)
            .await
            .expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(&response.body[..], b"hello");
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(name, _)| name == "content-type")
                .map(|(_, value)| value.as_str()),
            Some("text/plain")
        );
        server.await.expect("server");
    }

    #[tokio::test]
    async fn a_non_success_status_is_reported_not_treated_as_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            serve_once(&mut socket, b"nope", "503").await;
        });

        let stream = TcpStream::connect(address).await.expect("connect");
        let mut client = H2ClientConnection::handshake(stream, H2Fingerprint::chrome())
            .await
            .expect("handshake");
        let response = client
            .request("GET", "example.com", "https", "/", &[], None)
            .await
            .expect("a 503 is a response, not a transport failure");
        assert_eq!(response.status, 503);
        server.await.expect("server");
    }

    #[test]
    fn pseudo_headers_follow_the_profiles_order() {
        let pseudo = [
            (":method", "GET"),
            (":authority", "example.com"),
            (":scheme", "https"),
            (":path", "/"),
        ];
        let chrome = crate::fingerprint::PseudoHeaderOrder::MethodAuthoritySchemePath;
        assert_eq!(
            chrome
                .order(&pseudo)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            vec![":method", ":authority", ":scheme", ":path"]
        );
        let firefox = crate::fingerprint::PseudoHeaderOrder::MethodPathAuthorityScheme;
        assert_eq!(
            firefox
                .order(&pseudo)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            vec![":method", ":path", ":authority", ":scheme"]
        );
    }
}
