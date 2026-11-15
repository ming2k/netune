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
use crate::fingerprint::{H2ConnectionProfile, H2Fingerprint, H2RequestProfile};
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
    /// The connection-fixed half of the fingerprint: what the peer saw in the
    /// preface and SETTINGS.
    connection_profile: H2ConnectionProfile,
    /// The request-fixed half: applied to each HEADERS block, never to the pool.
    request_profile: H2RequestProfile,
    /// The seed regular-header order randomization derives from
    /// ([`INV-CUSTOM-22`]); each request mixes its stream id in. Chosen by the
    /// caller for reproducibility, or drawn from process entropy by
    /// [`H2ClientConnection::handshake`].
    header_order_seed: u64,
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
    /// The regular-header order seed is drawn from process entropy; use
    /// [`H2ClientConnection::handshake_with_seed`] when a test must reproduce
    /// the exact wire sequence.
    ///
    /// # Errors
    ///
    /// A transport error, or a protocol error from a frame no handshake may carry.
    pub async fn handshake(stream: T, fingerprint: H2Fingerprint) -> Result<Self, H2Error> {
        Self::handshake_with_seed(stream, fingerprint, process_entropy_seed()).await
    }

    /// [`H2ClientConnection::handshake`] with an explicit regular-header
    /// order seed.
    ///
    /// # Errors
    ///
    /// A transport error, or a protocol error from a frame no handshake may carry.
    pub async fn handshake_with_seed(
        stream: T,
        fingerprint: H2Fingerprint,
        header_order_seed: u64,
    ) -> Result<Self, H2Error> {
        let H2Fingerprint {
            connection: connection_profile,
            request: request_profile,
        } = fingerprint;
        // The bounds this end advertises are the bounds it must enforce while
        // reading: a peer may use the largest frame and window we announced.
        let local = LocalSettings::advertised(
            &connection_profile.settings,
            connection_profile.header_table_size,
        );
        let mut connection = H2Connection::client_handshake(
            stream,
            local,
            connection_profile.settings.clone(),
            connection_profile.initial_connection_window_update,
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
            connection_profile,
            request_profile,
            header_order_seed,
            unusable: false,
        })
    }

    /// The regular-header order seed this connection randomizes from.
    pub const fn header_order_seed(&self) -> u64 {
        self.header_order_seed
    }

    /// The connection-fixed half of the fingerprint in force.
    pub const fn connection_profile(&self) -> &H2ConnectionProfile {
        &self.connection_profile
    }

    /// The request-fixed half of the fingerprint in force.
    pub const fn request_profile(&self) -> &H2RequestProfile {
        &self.request_profile
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
        let profile = self.request_profile;
        self.start_request_with_profile(
            method,
            authority,
            scheme,
            path,
            extra_headers,
            body,
            &profile,
        )
        .await
    }

    /// Write one request using an explicit request-header profile.
    ///
    /// This is the per-exchange override: the connection profile and the socket
    /// do not change, only the pseudo-header order in this HEADERS block.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_request_with_profile(
        &mut self,
        method: &str,
        authority: &str,
        scheme: &str,
        path: &str,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
        request_profile: &H2RequestProfile,
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
        let ordered = request_profile.pseudo_headers_order.order(&pseudo);
        let mut headers: Vec<(&str, &str)> = ordered;

        // Regular headers follow the profile's order policy. Under the
        // go-nethttp policy the request seed is the connection seed mixed
        // with the stream id: every request presents a different order, and
        // the whole sequence is reproducible from the connection seed
        // ([INV-CUSTOM-21], [INV-CUSTOM-22]).
        let mut regular: Vec<(&str, &str)> = extra_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        crate::fingerprint::apply_regular_header_order(
            &mut regular,
            request_profile.regular_header_order,
            self.header_order_seed ^ u64::from(stream_id),
        );
        headers.extend(regular);

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
                    let block = self
                        .connection
                        .read_header_block(header_block, end_headers)
                        .await?;
                    let limit = self.connection.local.max_header_list_size as usize;
                    let fields = self.connection.decoder().decode_with_limit(&block, limit)?;
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
                    let block = self
                        .connection
                        .read_header_block(header_block, end_headers)
                        .await?;
                    let limit = self.connection.local.max_header_list_size as usize;
                    let fields = self.connection.decoder().decode_with_limit(&block, limit)?;
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

/// Draw a seed from process entropy: `RandomState` builds fresh hasher keys
/// per call, so consecutive connections derive unrelated seeds without a
/// dependency on wall clocks or a PRNG crate.
fn process_entropy_seed() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

#[cfg(test)]
mod tests;
