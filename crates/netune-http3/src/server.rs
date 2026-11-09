// SPDX-License-Identifier: MIT

//! HTTP/3 server-side handshake and per-request streams.
//!
//! The orchestrator owns the listener, admission control and handler boundary;
//! this module owns only the HTTP/3 state machine on an accepted QUIC
//! connection. Keeping the adapter here means `netune-server` never imports
//! the `h3` runtime directly, and `netune-http3` stays a leaf.

use bytes::{Buf, Bytes};

use crate::error::H3Error;
use crate::profile::H3SettingsProfile;

/// One accepted HTTP/3 connection.
pub struct H3ServerConnection {
    inner: h3::server::Connection<h3_quinn::Connection, Bytes>,
}

impl std::fmt::Debug for H3ServerConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3ServerConnection")
            .finish_non_exhaustive()
    }
}

impl H3ServerConnection {
    /// Start HTTP/3 on an accepted QUIC connection.
    pub async fn new(
        connection: netune_quic::quinn::Connection,
        settings: &H3SettingsProfile,
    ) -> Result<Self, H3Error> {
        settings
            .validate()
            .map_err(|reason| H3Error::Profile(reason.to_string()))?;
        let mut builder = h3::server::builder();
        builder
            .max_field_section_size(settings.max_field_section_size)
            .send_grease(settings.send_grease)
            .enable_datagram(settings.enable_datagram)
            .enable_extended_connect(settings.enable_extended_connect)
            .qpack_max_table_capacity(settings.qpack_max_table_capacity)
            .qpack_blocked_streams(settings.qpack_blocked_streams);
        let inner = builder
            .build(h3_quinn::Connection::new(connection))
            .await
            .map_err(|error| H3Error::H3(format!("h3 server handshake failed: {error}")))?;
        Ok(Self { inner })
    }

    /// Accept the next request, or `None` once the peer has closed the
    /// connection.
    pub async fn accept(&mut self) -> Result<Option<H3ServerRequest>, H3Error> {
        self.accept_with_timeout(std::time::Duration::from_secs(10))
            .await
    }

    /// Accept the next request and bound only the time from stream acceptance
    /// to a complete request head.
    ///
    /// An idle connection may wait indefinitely for its next stream; the head
    /// bound starts when the resolver exists, not while the connection is idle.
    pub async fn accept_with_timeout(
        &mut self,
        head_timeout: std::time::Duration,
    ) -> Result<Option<H3ServerRequest>, H3Error> {
        loop {
            let Some(resolver) = self
                .inner
                .accept()
                .await
                .map_err(|error| H3Error::H3(format!("h3 accept: {error}")))?
            else {
                return Ok(None);
            };
            let resolved = tokio::time::timeout(head_timeout, resolver.resolve_request()).await;
            match resolved {
                Ok(Ok((request, stream))) => {
                    return Ok(Some(H3ServerRequest {
                        request,
                        stream: H3ServerStream { inner: stream },
                    }));
                }
                // A malformed or over-large request head is a stream error: the
                // resolver has already answered/reset that stream. Keep the
                // QUIC connection available to its other streams.
                Ok(Err(error)) if error.is_connection_error() => {
                    return Err(H3Error::H3(format!("h3 connection: {error}")));
                }
                Ok(Err(_)) => continue,
                Err(_) => return Err(H3Error::Timeout("request head")),
            }
        }
    }

    /// Send a GOAWAY and wait for in-flight requests to finish.
    pub async fn shutdown(&mut self) -> Result<(), H3Error> {
        self.inner
            .shutdown(0)
            .await
            .map_err(|error| H3Error::H3(format!("h3 shutdown: {error}")))
    }
}

/// A request head plus its bidirectional stream.
pub struct H3ServerRequest {
    request: http::Request<()>,
    stream: H3ServerStream,
}

impl H3ServerRequest {
    /// Split the head from the stream so the orchestrator can hand the body to
    /// its handler boundary.
    pub fn into_parts(self) -> (http::Request<()>, H3ServerStream) {
        (self.request, self.stream)
    }
}

/// The server side of one HTTP/3 request stream.
pub struct H3ServerStream {
    inner: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

impl std::fmt::Debug for H3ServerStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3ServerStream")
            .finish_non_exhaustive()
    }
}

impl H3ServerStream {
    /// The wire stream id, for trace correlation.
    pub fn id(&self) -> u64 {
        self.inner.id().into_inner()
    }

    /// Read the next request-body chunk, or `None` at end of stream.
    pub async fn recv_data(&mut self) -> Result<Option<Bytes>, H3Error> {
        let Some(mut chunk) = self
            .inner
            .recv_data()
            .await
            .map_err(|error| H3Error::H3(format!("h3 request body: {error}")))?
        else {
            return Ok(None);
        };
        Ok(Some(chunk.copy_to_bytes(chunk.remaining())))
    }

    /// Read request trailers after the body.
    pub async fn recv_trailers(&mut self) -> Result<Option<http::HeaderMap>, H3Error> {
        self.inner
            .recv_trailers()
            .await
            .map_err(|error| H3Error::H3(format!("h3 request trailers: {error}")))
    }

    /// Stop accepting request-body bytes on this stream.
    ///
    /// Called when a handler returns without consuming the body; the response
    /// direction remains usable.
    pub fn cancel_body(&mut self) {
        self.inner
            .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    }

    /// Write the response head.
    pub async fn send_response(&mut self, response: http::Response<()>) -> Result<(), H3Error> {
        self.inner
            .send_response(response)
            .await
            .map_err(|error| H3Error::H3(format!("h3 response head: {error}")))
    }

    /// Write one response-body chunk.
    pub async fn send_data(&mut self, bytes: Bytes) -> Result<(), H3Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.inner
            .send_data(bytes)
            .await
            .map_err(|error| H3Error::H3(format!("h3 response body: {error}")))
    }

    /// Finish the response stream.
    pub async fn finish(&mut self) -> Result<(), H3Error> {
        self.inner
            .finish()
            .await
            .map_err(|error| H3Error::H3(format!("h3 response finish: {error}")))
    }
}
