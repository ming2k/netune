// SPDX-License-Identifier: MIT

//! HTTP/3 server-side handshake and per-request streams.
//!
//! The orchestrator owns the listener, admission control and handler boundary;
//! this module owns only the HTTP/3 state machine on an accepted QUIC
//! connection. Keeping the adapter here means `netune-server` never imports a
//! third-party H3 runtime, and `netune-http3` stays a leaf.

use bytes::Bytes;

use crate::connection::{Connection, H3Stream, Role};
use crate::error::H3Error;
use crate::profile::H3SettingsProfile;
use crate::proto::headers::{encode_response, encode_trailers};

/// One accepted HTTP/3 connection.
pub struct H3ServerConnection {
    connection: Connection,
    settings: H3SettingsProfile,
}

impl std::fmt::Debug for H3ServerConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3ServerConnection")
            .field("settings", &self.settings.name)
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
        let connection = Connection::start(connection, settings, Role::Server).await?;
        Ok(Self {
            connection,
            settings: settings.clone(),
        })
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
    /// bound starts when the stream exists, not while the connection is idle.
    pub async fn accept_with_timeout(
        &mut self,
        head_timeout: std::time::Duration,
    ) -> Result<Option<H3ServerRequest>, H3Error> {
        loop {
            let Some(incoming) = self.connection.next_incoming().await? else {
                return Ok(None);
            };
            let mut stream = H3Stream::new(
                self.connection.shared().clone(),
                incoming.id,
                incoming.send,
                incoming.recv,
            );
            let resolved = tokio::time::timeout(head_timeout, stream.read_request_head()).await;
            match resolved {
                Ok(Ok(request)) => {
                    return Ok(Some(H3ServerRequest {
                        request,
                        stream: H3ServerStream { stream },
                    }));
                }
                Ok(Err(error))
                    if matches!(
                        error,
                        H3Error::Connection { .. } | H3Error::Qpack(_) | H3Error::Frame(_)
                    ) =>
                {
                    return Err(error);
                }
                // A malformed or over-large request head is a stream error: reset
                // the stream and keep the QUIC connection available to its other
                // streams.
                Ok(Err(_)) => {
                    stream.cancel_body();
                    continue;
                }
                Err(_) => {
                    stream.cancel_body();
                    return Err(H3Error::Timeout("request head"));
                }
            }
        }
    }

    /// Send a GOAWAY. The caller waits for in-flight requests to finish.
    pub async fn shutdown(&mut self) -> Result<(), H3Error> {
        self.connection.send_goaway(0);
        Ok(())
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
    stream: H3Stream,
}

impl std::fmt::Debug for H3ServerStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3ServerStream")
            .field("id", &self.stream.id())
            .finish_non_exhaustive()
    }
}

impl H3ServerStream {
    /// The wire stream id, for trace correlation.
    pub fn id(&self) -> u64 {
        self.stream.id()
    }

    /// Read the next request-body chunk, or `None` at end of stream.
    pub async fn recv_data(&mut self) -> Result<Option<Bytes>, H3Error> {
        self.stream.next_chunk(64 * 1024).await
    }

    /// Read request trailers after the body.
    pub async fn recv_trailers(&mut self) -> Result<Option<http::HeaderMap>, H3Error> {
        self.stream.read_trailers().await
    }

    /// Stop accepting request-body bytes on this stream.
    ///
    /// Called when a handler returns without consuming the body; the response
    /// direction remains usable.
    pub fn cancel_body(&mut self) {
        self.stream.cancel_body();
    }

    /// Write the response head.
    pub async fn send_response(&mut self, response: http::Response<()>) -> Result<(), H3Error> {
        let fields = encode_response(&response)?;
        self.stream.send_head(&fields).await
    }

    /// Write response trailers and finish the stream.
    pub async fn send_trailers(&mut self, trailers: http::HeaderMap) -> Result<(), H3Error> {
        let fields = encode_trailers(&trailers)?;
        self.stream.send_trailers(&fields).await
    }

    /// Write one response-body chunk.
    pub async fn send_data(&mut self, bytes: Bytes) -> Result<(), H3Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.stream.send_data(&bytes).await
    }

    /// Finish the response stream.
    pub async fn finish(&mut self) -> Result<(), H3Error> {
        self.stream.finish_send()
    }
}
