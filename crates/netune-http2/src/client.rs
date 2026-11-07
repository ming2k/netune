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

/// An established HTTP/2 client connection over an arbitrary transport.
pub struct H2ClientConnection<T> {
    connection: H2Connection<T>,
    /// The fingerprint this connection was opened with, kept for per-request
    /// pseudo-header ordering.
    fingerprint: H2Fingerprint,
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
        let local = LocalSettings {
            header_table_size: fingerprint.header_table_size,
            ..LocalSettings::for_client()
        };
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
        })
    }

    /// The fingerprint in force.
    pub const fn fingerprint(&self) -> &H2Fingerprint {
        &self.fingerprint
    }

    /// Send one request and read its complete response.
    ///
    /// `authority` is the `:authority` pseudo-header; `scheme` is `https` or `http`; `path` is
    /// the `:path`.
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

        self.read_response(stream_id).await
    }

    /// Read one response, handling the frames a real server sends in between.
    async fn read_response(&mut self, stream_id: u32) -> Result<H2Response, H2Error> {
        let mut head: Option<(u16, Vec<(String, String)>)> = None;
        let mut body = bytes::BytesMut::new();
        let mut trailers = Vec::new();
        // Bytes consumed from this stream since the last WINDOW_UPDATE; replenished in one
        // credit per frame is wasteful, so it accumulates.
        let mut unacked: u32 = 0;

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
                    if head.is_none() {
                        head = Some(split_response(fields));
                    } else {
                        // A second header block after the head is the trailer section.
                        trailers = fields;
                    }
                    if end_stream {
                        return finish(head, body, trailers);
                    }
                }
                Frame::Data {
                    stream_id: id,
                    end_stream,
                    payload,
                } if id == stream_id => {
                    let len = payload.len() as u32;
                    body.extend_from_slice(&payload);
                    unacked = unacked.saturating_add(len);
                    // One credit per 16 KiB, plus one at the end of the stream: replenishing per frame
                    // is a `WINDOW_UPDATE` per `DATA`, and never replenishing at the end leaves the
                    // peer's view of the window smaller than ours forever.
                    if unacked >= 16 * 1024 || end_stream {
                        self.connection.replenish(stream_id, unacked).await?;
                        self.connection.flush().await?;
                        unacked = 0;
                    }
                    if end_stream {
                        return finish(head, body, trailers);
                    }
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
                    // A GOAWAY that still covers our stream lets it finish; one that does not
                    // is the peer saying this request will never be answered.
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
                Frame::PushPromise { stream_id: id, .. } => {
                    // Never requested (ENABLE_PUSH=0); declining documents the refusal.
                    let _ = id;
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

    /// The transport underneath, for a caller that wants to keep the connection.
    pub fn into_inner(self) -> T {
        self.connection.into_inner()
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

fn finish(
    head: Option<(u16, Vec<(String, String)>)>,
    body: bytes::BytesMut,
    trailers: Vec<(String, String)>,
) -> Result<H2Response, H2Error> {
    let (status, headers) = head.ok_or_else(|| {
        H2Error::Protocol("a stream ended before its response headers arrived".into())
    })?;
    Ok(H2Response {
        status,
        headers,
        body: body.freeze(),
        trailers,
    })
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
