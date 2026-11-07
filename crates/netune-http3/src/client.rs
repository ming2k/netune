// SPDX-License-Identifier: MIT

//! HTTP/3 client session and request execution (RFC 9114).

use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes, BytesMut};
use netune_trace::{EventKind, Recorder};

use crate::error::H3Error;

/// An active HTTP/3 client session driving a QUIC connection.
pub struct H3Client {
    driver: tokio::task::JoinHandle<()>,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    recorder: Option<Arc<Mutex<Recorder>>>,
    /// Exchange id for the next request. One client serves many requests over one
    /// connection and one recorder, so each exchange needs an identity the trace can be
    /// split by. Starts at `1`: stream `0` is reserved for connection-level facts.
    next_exchange: u32,
}

impl std::fmt::Debug for H3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Client").finish_non_exhaustive()
    }
}

impl H3Client {
    /// Creates a new HTTP/3 client session over an established QUIC connection.
    pub async fn new(
        connection: &netune_quic::quinn::Connection,
        recorder: Option<Arc<Mutex<Recorder>>>,
    ) -> Result<Self, H3Error> {
        let h3_conn = h3_quinn::Connection::new(connection.clone());
        let (mut driver, send_request) = h3::client::new(h3_conn)
            .await
            .map_err(|e| H3Error::H3(format!("h3 client handshake failed: {e}")))?;

        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Ok(Self {
            driver: driver_task,
            send_request,
            recorder,
            next_exchange: 1,
        })
    }

    /// Accesses the underlying Quinn H3 request sender handle.
    pub fn send_request_handle(
        &mut self,
    ) -> &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> {
        &mut self.send_request
    }

    /// Deconstructs the client into its raw components.
    pub fn into_parts(
        self,
    ) -> (
        h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        tokio::task::JoinHandle<()>,
    ) {
        (self.send_request, self.driver)
    }

    /// Executes an HTTP/3 request to completion, buffering the response body.
    pub async fn execute(
        &mut self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, H3Error> {
        let exchange = self.next_exchange;
        self.next_exchange = self.next_exchange.saturating_add(1);

        if let Some(r) = &self.recorder
            && let Ok(mut rec) = r.lock()
        {
            rec.mark_stream(exchange, EventKind::H3StreamStart, 0, 0);
        }

        let (parts, body) = request.into_parts();
        let head = http::Request::from_parts(parts, ());

        let mut stream = self
            .send_request
            .send_request(head)
            .await
            .map_err(|e| H3Error::H3(format!("send request head: {e}")))?;

        if !body.is_empty() {
            stream
                .send_data(body)
                .await
                .map_err(|e| H3Error::H3(format!("send request body: {e}")))?;
        }

        stream
            .finish()
            .await
            .map_err(|e| H3Error::H3(format!("finish request stream: {e}")))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| H3Error::H3(format!("receive response head: {e}")))?;

        if let Some(r) = &self.recorder
            && let Ok(mut rec) = r.lock()
        {
            rec.mark_stream(
                exchange,
                EventKind::H3HeadComplete,
                response.status().as_u16() as u32,
                0,
            );
        }

        let mut body_bytes = BytesMut::new();
        while let Some(chunk) = stream
            .recv_data()
            .await
            .map_err(|e| H3Error::H3(format!("receive response data: {e}")))?
        {
            body_bytes.extend_from_slice(chunk.chunk());
        }

        // Closes the exchange in the trace. Without it `derive_h3` can anchor TTFB but
        // never the body or end-to-end span, and a reader cannot tell a complete
        // response from one whose stream died mid-body.
        if let Some(r) = &self.recorder
            && let Ok(mut rec) = r.lock()
        {
            let bytes = body_bytes.len().min(u32::MAX as usize) as u32;
            rec.mark_stream(exchange, EventKind::H3Finished, bytes, 0);
        }

        let (resp_parts, ()) = response.into_parts();
        Ok(http::Response::from_parts(resp_parts, body_bytes.freeze()))
    }
}
