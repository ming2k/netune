//! High-level HTTP/2 client with Akamai fingerprint impersonation (ADR-0006).
//!
//! Orchestrates the full lifecycle over any [`Connector`] (TCP, TLS, or Proxy),
//! records phase boundaries in [`Recorder`], and executes requests matching
//! a declared [`H2Fingerprint`].

use http::Method;
use netune_http2::{H2Connection, H2Fingerprint, H2Response};
use netune_trace::{EventKind, Recorder};
use std::sync::{Arc, Mutex};

use crate::connect::{Connector, Target};
use crate::error::NetError;

/// An HTTP/2 client that drives requests with precise Akamai fingerprinting.
pub struct H2Client<C: Connector> {
    connector: C,
    fingerprint: H2Fingerprint,
}

impl<C: Connector> H2Client<C> {
    /// Create a new H2 client over `connector` using `fingerprint`.
    pub fn new(connector: C, fingerprint: H2Fingerprint) -> Self {
        Self {
            connector,
            fingerprint,
        }
    }

    /// Access the configured fingerprint.
    pub fn fingerprint(&self) -> &H2Fingerprint {
        &self.fingerprint
    }

    /// Execute a request over a freshly negotiated HTTP/2 connection.
    pub async fn send(
        &self,
        target: &Target,
        method: Method,
        path: &str,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<H2Response, NetError> {
        let established = self.connector.connect(target, recorder).await?;

        {
            let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
            rec.mark(EventKind::RequestWriteStart, 0, 0);
        }

        let scheme = if target.tls_server_name.is_some() {
            "https"
        } else {
            "http"
        };
        let authority = &target.authority;

        let mut h2 = H2Connection::handshake(established.stream, self.fingerprint.clone())
            .await
            .map_err(|e| NetError::Protocol(format!("HTTP/2 handshake: {e}")))?;

        let response = h2
            .request(
                method.as_str(),
                authority,
                scheme,
                path,
                extra_headers,
                body,
            )
            .await
            .map_err(|e| NetError::Protocol(format!("HTTP/2 request: {e}")))?;

        {
            let mut rec = recorder.lock().unwrap_or_else(|e| e.into_inner());
            rec.mark(EventKind::RequestWriteEnd, response.body.len() as u32, 0);
            rec.mark(EventKind::HeadComplete, response.status as u32, 0);
            rec.mark(EventKind::BodyEnd, response.body.len() as u32, 0);
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::TcpConnector;
    use netune_http2::frame::{
        FRAME_HEADER_LEN, Frame, FrameHeader, SETTING_MAX_CONCURRENT_STREAMS,
    };
    use netune_http2::hpack::{HpackDecoder, HpackEncoder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn h2_client_executes_request_and_records_events() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        // Spawn mock H2 server
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");

            let mut preface = [0u8; netune_http2::CLIENT_PREFACE.len()];
            socket.read_exact(&mut preface).await.expect("preface");

            let mut h_buf = [0u8; FRAME_HEADER_LEN];
            // Client SETTINGS
            socket.read_exact(&mut h_buf).await.expect("h");
            let s_h = FrameHeader::parse(&h_buf).expect("parse");
            let mut s_payload = vec![0u8; s_h.length as usize];
            socket.read_exact(&mut s_payload).await.expect("payload");

            // Client WINDOW_UPDATE
            socket.read_exact(&mut h_buf).await.expect("h");
            let wu_h = FrameHeader::parse(&h_buf).expect("parse");
            let mut wu_payload = vec![0u8; wu_h.length as usize];
            socket.read_exact(&mut wu_payload).await.expect("payload");

            // Server SETTINGS
            let s_settings = Frame::Settings {
                ack: false,
                settings: vec![(SETTING_MAX_CONCURRENT_STREAMS, 100)],
            };
            socket
                .write_all(&s_settings.encode())
                .await
                .expect("send settings");

            // Read client ACK
            socket.read_exact(&mut h_buf).await.expect("read ack");

            // Read request HEADERS
            socket.read_exact(&mut h_buf).await.expect("headers");
            let req_h = FrameHeader::parse(&h_buf).expect("req h");
            let mut req_payload = vec![0u8; req_h.length as usize];
            socket.read_exact(&mut req_payload).await.expect("payload");

            let decoder = HpackDecoder::new();
            let headers = decoder.decode(&req_payload).expect("decode");
            assert!(
                headers
                    .iter()
                    .any(|(k, v)| k == ":authority" && v == &format!("127.0.0.1:{port}"))
            );

            // Reply 200 OK
            let encoder = HpackEncoder::new();
            let resp_headers = Frame::Headers {
                stream_id: req_h.stream_id,
                end_stream: false,
                end_headers: true,
                header_block: encoder.encode(vec![(":status", "200")]),
            };
            socket
                .write_all(&resp_headers.encode())
                .await
                .expect("write headers");

            let resp_data = Frame::Data {
                stream_id: req_h.stream_id,
                end_stream: true,
                payload: bytes::Bytes::from_static(b"h2 response data"),
            };
            socket
                .write_all(&resp_data.encode())
                .await
                .expect("write data");
        });

        let target = Target::plain(format!("127.0.0.1:{port}"));
        let connector = TcpConnector::new();
        let client = H2Client::new(connector, H2Fingerprint::chrome());
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));

        let response = client
            .send(&target, Method::GET, "/v1/test", &[], None, &recorder)
            .await
            .expect("send");

        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_ref(), b"h2 response data");

        server.await.expect("server finished");
    }
}
