//! HTTP/2 client connection state machine and stream transport.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::H2Error;
use crate::fingerprint::H2Fingerprint;
use crate::frame::*;
use crate::hpack::{HpackDecoder, HpackEncoder};

/// HTTP/2 client connection preface magic string (RFC 9113 Section 3.4).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// An established HTTP/2 client connection over an arbitrary transport.
pub struct H2Connection<T> {
    stream: T,
    fingerprint: H2Fingerprint,
    next_stream_id: u32,
    encoder: HpackEncoder,
    decoder: HpackDecoder,
    read_buf: BytesMut,
}

/// A parsed HTTP/2 response.
#[derive(Debug, Clone)]
pub struct H2Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl<T: AsyncRead + AsyncWrite + Unpin> H2Connection<T> {
    /// Perform the client HTTP/2 handshake according to `fingerprint`.
    pub async fn handshake(mut stream: T, fingerprint: H2Fingerprint) -> Result<Self, H2Error> {
        // 1. Send client connection preface
        stream.write_all(CLIENT_PREFACE).await?;

        // 2. Send initial SETTINGS frame matching the fingerprint
        let settings_frame = Frame::Settings {
            ack: false,
            settings: fingerprint.settings.clone(),
        };
        stream.write_all(&settings_frame.encode()).await?;

        // 3. Send initial connection WINDOW_UPDATE if declared by the fingerprint
        if let Some(inc) = fingerprint.initial_connection_window_update {
            let wu_frame = Frame::WindowUpdate {
                stream_id: 0,
                increment: inc,
            };
            stream.write_all(&wu_frame.encode()).await?;
        }

        stream.flush().await?;

        let mut conn = Self {
            stream,
            fingerprint,
            next_stream_id: 1,
            encoder: HpackEncoder::new(),
            decoder: HpackDecoder::new(),
            read_buf: BytesMut::with_capacity(16 * 1024),
        };

        // 4. Expect and acknowledge server SETTINGS frame
        let mut got_server_settings = false;
        while !got_server_settings {
            let frame = conn.read_frame().await?;
            match frame {
                Frame::Settings { ack, .. } => {
                    if !ack {
                        got_server_settings = true;
                        // Reply with SETTINGS ACK
                        let ack_frame = Frame::Settings {
                            ack: true,
                            settings: Vec::new(),
                        };
                        conn.stream.write_all(&ack_frame.encode()).await?;
                        conn.stream.flush().await?;
                    }
                }
                Frame::WindowUpdate { .. } | Frame::Ping { .. } => {}
                other => {
                    return Err(H2Error::Protocol(format!(
                        "unexpected frame during handshake: {other:?}"
                    )));
                }
            }
        }

        Ok(conn)
    }

    /// Send a request on a new stream and await the complete response.
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

        // Order headers according to the Akamai fingerprint policy
        let ordered =
            self.fingerprint
                .order_request_headers(method, authority, scheme, path, extra_headers);

        let header_block = self.encoder.encode(ordered);
        let has_body = body.is_some_and(|b| !b.is_empty());

        let headers_frame = Frame::Headers {
            stream_id,
            end_stream: !has_body,
            end_headers: true,
            header_block,
        };
        self.stream.write_all(&headers_frame.encode()).await?;

        if let Some(body_bytes) = body
            && !body_bytes.is_empty()
        {
            let data_frame = Frame::Data {
                stream_id,
                end_stream: true,
                payload: Bytes::copy_from_slice(body_bytes),
            };
            self.stream.write_all(&data_frame.encode()).await?;
        }
        self.stream.flush().await?;

        // Await response frames for this stream
        let mut status = None;
        let mut resp_headers = Vec::new();
        let mut resp_body = BytesMut::new();

        loop {
            let frame = self.read_frame().await?;
            match frame {
                Frame::Headers {
                    stream_id: sid,
                    end_stream,
                    header_block,
                    ..
                } if sid == stream_id => {
                    let decoded = self.decoder.decode(&header_block)?;
                    for (k, v) in decoded {
                        if k == ":status" {
                            status = v.parse::<u16>().ok();
                        } else {
                            resp_headers.push((k, v));
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
                    resp_body.extend_from_slice(&payload);
                    if end_stream {
                        break;
                    }
                }
                Frame::Ping { ack, opaque_data } if !ack => {
                    let ping_ack = Frame::Ping {
                        ack: true,
                        opaque_data,
                    };
                    self.stream.write_all(&ping_ack.encode()).await?;
                    self.stream.flush().await?;
                }
                Frame::GoAway {
                    error_code,
                    debug_data,
                    ..
                } => {
                    return Err(H2Error::GoAway {
                        error_code,
                        debug_data: debug_data.to_vec(),
                    });
                }
                Frame::RstStream {
                    stream_id: sid,
                    error_code,
                } if sid == stream_id => {
                    return Err(H2Error::StreamReset {
                        stream_id: sid,
                        error_code,
                    });
                }
                _ => {} // Ignore frames for other streams or window updates
            }
        }

        let status =
            status.ok_or_else(|| H2Error::Protocol("missing :status pseudo-header".into()))?;

        Ok(H2Response {
            status,
            headers: resp_headers,
            body: resp_body.freeze(),
        })
    }

    /// Read exactly one complete HTTP/2 frame from the transport.
    pub async fn read_frame(&mut self) -> Result<Frame, H2Error> {
        loop {
            if self.read_buf.len() >= FRAME_HEADER_LEN {
                let Some(header) = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_LEN]) else {
                    return Err(H2Error::Protocol("invalid frame header format".into()));
                };
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

    #[tokio::test]
    async fn h2_client_server_handshake_and_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Spawn mock HTTP/2 server
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");

            // 1. Read preface
            let mut preface = [0u8; CLIENT_PREFACE.len()];
            socket.read_exact(&mut preface).await.expect("read preface");
            assert_eq!(&preface[..], CLIENT_PREFACE);

            // 2. Read client SETTINGS
            let mut h_buf = [0u8; FRAME_HEADER_LEN];
            socket.read_exact(&mut h_buf).await.expect("header");
            let c_settings_h = FrameHeader::parse(&h_buf).expect("parse header");
            let mut s_payload = vec![0u8; c_settings_h.length as usize];
            socket
                .read_exact(&mut s_payload)
                .await
                .expect("settings payload");

            // Read client WINDOW_UPDATE (if sent)
            socket.read_exact(&mut h_buf).await.expect("header");
            let wu_h = FrameHeader::parse(&h_buf).expect("parse header");
            let mut wu_payload = vec![0u8; wu_h.length as usize];
            socket
                .read_exact(&mut wu_payload)
                .await
                .expect("wu payload");

            // Send server SETTINGS
            let server_settings = Frame::Settings {
                ack: false,
                settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 100)],
            };
            socket
                .write_all(&server_settings.encode())
                .await
                .expect("send settings");

            // Read client SETTINGS ACK
            socket
                .read_exact(&mut h_buf)
                .await
                .expect("read ack header");

            // Read request HEADERS frame
            socket.read_exact(&mut h_buf).await.expect("headers header");
            let req_h = FrameHeader::parse(&h_buf).expect("parse req headers");
            let mut req_payload = vec![0u8; req_h.length as usize];
            socket
                .read_exact(&mut req_payload)
                .await
                .expect("read req payload");

            let decoder = HpackDecoder::new();
            let headers = decoder.decode(&req_payload).expect("decode headers");
            assert!(headers.iter().any(|(k, v)| k == ":method" && v == "GET"));

            // Respond with 200 OK
            let encoder = HpackEncoder::new();
            let resp_block =
                encoder.encode(vec![(":status", "200"), ("content-type", "text/plain")]);
            let resp_headers = Frame::Headers {
                stream_id: req_h.stream_id,
                end_stream: false,
                end_headers: true,
                header_block: resp_block,
            };
            socket
                .write_all(&resp_headers.encode())
                .await
                .expect("write resp headers");

            let resp_data = Frame::Data {
                stream_id: req_h.stream_id,
                end_stream: true,
                payload: Bytes::from_static(b"hello http/2"),
            };
            socket
                .write_all(&resp_data.encode())
                .await
                .expect("write resp data");
        });

        let tcp_stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut client = H2Connection::handshake(tcp_stream, H2Fingerprint::chrome())
            .await
            .expect("handshake");

        let response = client
            .request("GET", "example.com", "https", "/test", &[], None)
            .await
            .expect("request");

        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_ref(), b"hello http/2");

        server.await.expect("server finished");
    }
}
