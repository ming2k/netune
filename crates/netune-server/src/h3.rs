//! HTTP/3 ingress.
//!
//! QUIC is a different transport, not a protocol mode on a TCP listener: one
//! QUIC connection multiplexes request streams, has its own handshake and
//! connection limits, and can be drained independently. This module therefore
//! implements a peer listener, [`H3Server`], rather than adding a branch to
//! [`crate::Server`].
//!
//! The HTTP/3 state machine itself lives in `netune-http3`; this adapter owns
//! only the parts an ingress orchestrator must own: admission, per-stream
//! handler dispatch, body bounds, response translation and trace hand-over.

use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header;
use netune_http1::{BodyKind, HttpError, IncomingRequest, TargetForm};
use netune_http3::{H3ServerConnection, H3ServerStream, H3SettingsProfile};
use netune_quic::owned::{AcceptError, ServerOptions};
use netune_trace::{EventKind, TraceCollector};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, watch};
use tokio::task::JoinSet;

use crate::body::{BodySource, RequestBody};
use crate::config::ServerConfig;
use crate::handler::{BodyStream, Handler, Response, ResponseBody};
use crate::panic::CatchPanic;
use crate::service::{BindError, ServedProtocol, hand_over};

/// A bound HTTP/3 ingress listener.
pub struct H3Server {
    endpoint: netune_quic::owned::Endpoint,
    config: ServerConfig,
    settings: H3SettingsProfile,
    handler: Arc<dyn Handler>,
    permits: Arc<Semaphore>,
    local: SocketAddr,
    handshake_errors: broadcast::Sender<Arc<netune_quic::QuicError>>,
}

impl std::fmt::Debug for H3Server {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H3Server")
            .field("local_addr", &self.local)
            .field("config", &self.config)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl H3Server {
    /// Bind a QUIC listener that speaks HTTP/3.
    ///
    /// `tls` is the same termination configuration the TCP listener accepts;
    /// ALPN is forced to `h3`, because a QUIC endpoint that does not negotiate
    /// HTTP/3 cannot serve this listener. The caller keeps certificate
    /// selection policy in `rustls`; this crate owns the listener.
    pub async fn bind(
        address: impl AsRef<str>,
        config: ServerConfig,
        tls: Arc<rustls::ServerConfig>,
        settings: H3SettingsProfile,
        handler: Arc<dyn Handler>,
    ) -> Result<Self, BindError> {
        config.validate()?;
        settings.validate().map_err(BindError::Invalid)?;
        let address = address
            .as_ref()
            .to_socket_addrs()
            .map_err(BindError::Bind)?
            .next()
            .ok_or(BindError::Invalid("HTTP/3 address did not resolve"))?;

        let server_config = Self::server_config(tls);
        let endpoint =
            netune_quic::owned::Endpoint::server(address.to_string().as_str(), server_config)
                .await
                .map_err(|error| BindError::Transport(error.to_string()))?;
        Self::from_endpoint(endpoint, config, settings, handler)
    }

    /// Bind a QUIC listener over a caller-supplied socket stack.
    ///
    /// This is the ingress counterpart of the egress socket seam: the caller
    /// owns binding, socket configuration and any obfuscation/port-hop layer.
    /// The endpoint owns the socket for one listener lifetime and routes all
    /// accepted connections by connection ID.
    pub async fn bind_with_socket(
        socket: Arc<dyn netune_quic::QuicUdpSocket>,
        config: ServerConfig,
        tls: Arc<rustls::ServerConfig>,
        settings: H3SettingsProfile,
        handler: Arc<dyn Handler>,
    ) -> Result<Self, BindError> {
        Self::bind_with_socket_and_options(
            socket,
            config,
            tls,
            settings,
            handler,
            ServerOptions::default(),
        )
        .await
    }

    /// Bind over a caller-owned socket stack with explicit server-side policy.
    pub async fn bind_with_socket_and_options(
        socket: Arc<dyn netune_quic::QuicUdpSocket>,
        config: ServerConfig,
        tls: Arc<rustls::ServerConfig>,
        settings: H3SettingsProfile,
        handler: Arc<dyn Handler>,
        options: ServerOptions,
    ) -> Result<Self, BindError> {
        config.validate()?;
        settings.validate().map_err(BindError::Invalid)?;
        let server_config = Self::server_config(tls);
        let endpoint = netune_quic::owned::Endpoint::server_with_socket_and_options(
            socket,
            server_config,
            options,
        )
        .await
        .map_err(|error| BindError::Transport(error.to_string()))?;
        Self::from_endpoint(endpoint, config, settings, handler)
    }

    fn server_config(tls: Arc<rustls::ServerConfig>) -> netune_quic::owned::ServerConfigOwned {
        let mut tls = (*tls).clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let transport = netune_quic::wire::transport_parameters::TransportParameters {
            max_idle_timeout: Some(30_000),
            initial_max_data: Some(16 * 1024 * 1024),
            initial_max_stream_data_bidi_local: Some(1 << 20),
            initial_max_stream_data_bidi_remote: Some(1 << 20),
            initial_max_stream_data_uni: Some(1 << 20),
            initial_max_streams_bidi: Some(1024),
            initial_max_streams_uni: Some(1024),
            active_connection_id_limit: Some(4),
            max_datagram_frame_size: Some(65_535),
            ..Default::default()
        };
        netune_quic::owned::ServerConfigOwned {
            tls: Arc::new(tls),
            transport,
            retry: true,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: true,
        }
    }

    fn from_endpoint(
        endpoint: netune_quic::owned::Endpoint,
        config: ServerConfig,
        settings: H3SettingsProfile,
        handler: Arc<dyn Handler>,
    ) -> Result<Self, BindError> {
        let local = endpoint.local_addr();
        let permits = Arc::new(Semaphore::new(config.max_connections));
        let (handshake_errors, _) = broadcast::channel(16);
        Ok(Self {
            endpoint,
            config,
            settings,
            handler,
            permits,
            local,
            handshake_errors,
        })
    }

    /// The actual bound address, including a kernel-assigned port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The configuration in force.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The HTTP/3 SETTINGS profile in force.
    pub fn settings(&self) -> &H3SettingsProfile {
        &self.settings
    }

    /// Observe incoming QUIC/TLS handshake failures.
    ///
    /// A listener keeps serving after a failed handshake; this receiver is how
    /// an operator sees those failures instead of only seeing "no connection".
    pub fn subscribe_handshake_errors(&self) -> broadcast::Receiver<Arc<netune_quic::QuicError>> {
        self.handshake_errors.subscribe()
    }

    /// Accept until `shutdown` resolves, then stop accepting and drain.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) {
        let Self {
            endpoint,
            config,
            settings,
            handler,
            permits,
            local,
            handshake_errors,
        } = self;
        let config = Arc::new(config);
        let settings = Arc::new(settings);
        let (drain_tx, drain_rx) = watch::channel(false);
        let mut connections = JoinSet::new();
        let mut shutdown = Box::pin(shutdown);

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                accepted = endpoint.accept() => {
                    let connection = match accepted {
                        Ok(connection) => connection,
                        Err(AcceptError::EndpointClosed) => break,
                        Err(AcceptError::Handshake(error)) => {
                            let _ = handshake_errors.send(Arc::new(error));
                            continue;
                        }
                    };
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        // Admission is explicit: a peer learns now and may retry,
                        // rather than occupying an unbounded queue.
                        connection.close(0x010b, "server busy");
                        continue;
                    };
                    let handler = Arc::clone(&handler);
                    let config = Arc::clone(&config);
                    let settings = Arc::clone(&settings);
                    let drain = drain_rx.clone();
                    connections.spawn(async move {
                        serve_connection(connection, local, config, settings, handler, permit, drain)
                            .await;
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        let _ = drain_tx.send(true);

        let deadline = tokio::time::Instant::now() + config.drain_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                connections.shutdown().await;
                endpoint.close();
                return;
            }
            tokio::select! {
                joined = connections.join_next() => {
                    if joined.is_none() {
                        endpoint.close();
                        return;
                    }
                }
                () = tokio::time::sleep(remaining) => {
                    connections.shutdown().await;
                    endpoint.close();
                    return;
                }
            }
        }
    }
}

async fn serve_connection(
    connection: netune_quic::owned::Connection,
    local: SocketAddr,
    config: Arc<ServerConfig>,
    settings: Arc<H3SettingsProfile>,
    handler: Arc<dyn Handler>,
    permit: OwnedSemaphorePermit,
    mut drain: watch::Receiver<bool>,
) {
    let peer = connection.remote_address();
    let recorder = if config.trace_sink.is_some() {
        TraceCollector::start_ingress(config.trace_capacity)
    } else {
        TraceCollector::disabled()
    };
    let handshake = tokio::time::timeout(
        config.head_timeout,
        H3ServerConnection::new(connection, &settings),
    )
    .await;
    let mut h3 = match handshake {
        Ok(Ok(h3)) => h3,
        Ok(Err(_)) | Err(_) => {
            recorder.mark(EventKind::Error, crate::h1::ERROR_TLS_HANDSHAKE, 0);
            hand_over(&config, peer, local, ServedProtocol::Http3, 0, &recorder);
            drop(permit);
            return;
        }
    };

    let mut exchanges = 0u32;
    let mut next_exchange = 1u32;
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = drain.changed() => {
                if changed.is_err() || *drain.borrow() {
                    break;
                }
            }
            Some(_) = requests.join_next(), if !requests.is_empty() => {}
            accepted = h3.accept_with_timeout(config.head_timeout) => {
                match accepted {
                    Ok(Some(request)) => {
                        let exchange = next_exchange;
                        next_exchange = next_exchange.saturating_add(1);
                        exchanges = exchanges.saturating_add(1);
                        let handler = Arc::clone(&handler);
                        let config = Arc::clone(&config);
                        let recorder = recorder.clone();
                        requests.spawn(async move {
                            serve_request(request, exchange, config, handler, recorder).await;
                        });
                    }
                    Ok(None) => break,
                    Err(netune_http3::H3Error::Timeout(_)) => {
                        // One stream failed to produce a complete head; reset
                        // that stream and keep the QUIC connection available to
                        // its other streams.
                        recorder.mark(EventKind::Error, crate::h1::ERROR_HEAD_TIMEOUT, 0);
                    }
                    Err(_) => {
                        recorder.mark(EventKind::Error, crate::h1::ERROR_PROTOCOL, 0);
                        break;
                    }
                }
            }
        }
    }

    // GOAWAY before waiting: a request that was accepted is still allowed
    // to finish, but no new stream should be started.
    let _ = h3.shutdown().await;
    while requests.join_next().await.is_some() {}

    hand_over(
        &config,
        peer,
        local,
        ServedProtocol::Http3,
        exchanges,
        &recorder,
    );
    drop(permit);
}

async fn serve_request(
    request: netune_http3::H3ServerRequest,
    stream_id: u32,
    config: Arc<ServerConfig>,
    handler: Arc<dyn Handler>,
    recorder: TraceCollector,
) {
    let (request, mut stream) = request.into_parts();
    let target_len = request
        .uri()
        .path_and_query()
        .map_or(0, |path| path.as_str().len());
    recorder.mark_stream(
        stream_id,
        EventKind::H3StreamStart,
        stream.id().min(u32::MAX as u64) as u32,
        0,
    );
    recorder.mark_stream(
        stream_id,
        EventKind::RequestHeadComplete,
        target_len as u32,
        0,
    );

    if request.method() == http::Method::CONNECT {
        let _ = write_response(
            &mut stream,
            Response::not_implemented(),
            &config,
            &recorder,
            stream_id,
            false,
        )
        .await;
        return;
    }

    let is_head = request.method() == http::Method::HEAD;
    let incoming = incoming_request(&request);
    if config.require_host && !incoming.headers.contains_key(header::HOST) {
        recorder.mark_stream(
            stream_id,
            EventKind::Error,
            crate::h1::ERROR_INVALID_REQUEST,
            0,
        );
        let _ = write_response(
            &mut stream,
            Response::bad_request(),
            &config,
            &recorder,
            stream_id,
            false,
        )
        .await;
        return;
    }

    recorder.mark_stream(stream_id, EventKind::HandlerStart, 0, 0);
    let response = {
        let mut source = H3BodySource {
            stream: &mut stream,
            timeout: config.body_timeout,
            max_body_bytes: config.limits.max_body_bytes,
            read: 0,
        };
        let body = RequestBody::new_at_stream(&mut source, recorder.clone(), stream_id);
        let outcome = tokio::time::timeout(
            config.handler_timeout,
            handler.handle(incoming, body).catch_panic(),
        )
        .await;
        match outcome {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                recorder.mark_stream(
                    stream_id,
                    EventKind::Error,
                    crate::h1::ERROR_HANDLER_PANIC,
                    0,
                );
                Response::internal_error()
            }
            Err(_) => {
                recorder.mark_stream(
                    stream_id,
                    EventKind::Error,
                    crate::h1::ERROR_HANDLER_TIMEOUT,
                    0,
                );
                Response::internal_error()
            }
        }
    };

    // The handler may have ignored the body. Reset the receive side rather than
    // letting unread DATA pin the stream and its flow-control budget.
    stream.cancel_body();

    recorder.mark_stream(
        stream_id,
        EventKind::HandlerEnd,
        response.head.status.as_u16() as u32,
        0,
    );
    let _ = write_response(
        &mut stream,
        response,
        &config,
        &recorder,
        stream_id,
        is_head,
    )
    .await;
}

struct H3BodySource<'a> {
    stream: &'a mut H3ServerStream,
    timeout: Duration,
    max_body_bytes: u64,
    read: u64,
}

impl BodySource for H3BodySource<'_> {
    fn next_chunk(&mut self) -> crate::body::ChunkFuture<'_> {
        Box::pin(async move {
            let chunk = tokio::time::timeout(self.timeout, self.stream.recv_data())
                .await
                .map_err(|_| {
                    HttpError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "HTTP/3 request body timed out",
                    ))
                })?
                .map_err(|_| HttpError::Incomplete("HTTP/3 request body failed"))?;
            let Some(chunk) = chunk else {
                return Ok(None);
            };
            self.read = self.read.saturating_add(chunk.len() as u64);
            if self.read > self.max_body_bytes {
                return Err(HttpError::LimitExceeded("HTTP/3 request body too large"));
            }
            Ok(Some(chunk))
        })
    }
}

fn incoming_request(request: &http::Request<()>) -> IncomingRequest {
    let uri = request.uri();
    let target = uri
        .path_and_query()
        .map(|path| Bytes::copy_from_slice(path.as_str().as_bytes()))
        .unwrap_or_else(|| Bytes::from_static(b"/"));
    let form = if request.method() == http::Method::CONNECT {
        TargetForm::Authority
    } else if uri.scheme().is_some() {
        TargetForm::Absolute
    } else {
        TargetForm::Origin
    };
    let mut headers = request.headers().clone();
    if !headers.contains_key(header::HOST)
        && let Some(authority) = uri.authority()
        && let Ok(value) = http::HeaderValue::from_str(authority.as_str())
    {
        headers.insert(header::HOST, value);
    }
    headers.remove(header::CONNECTION);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::UPGRADE);

    IncomingRequest {
        method: request.method().clone(),
        target,
        form,
        version: http::Version::HTTP_3,
        headers,
        body: BodyKind::UntilClose,
    }
}

async fn write_response(
    stream: &mut H3ServerStream,
    response: Response,
    config: &ServerConfig,
    recorder: &TraceCollector,
    stream_id: u32,
    is_head: bool,
) -> Result<(), netune_http3::H3Error> {
    let Response { head, body } = response;
    let mut headers = head.headers;
    headers.remove(header::CONNECTION);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::UPGRADE);
    headers.remove(header::CONTENT_LENGTH);
    let date = crate::date::http_date();
    if let Ok(value) = http::HeaderValue::from_str(&date) {
        headers.insert(header::DATE, value);
    }

    let mut response_head = http::Response::builder()
        .status(head.status)
        .body(())
        .map_err(netune_http3::H3Error::Http)?;
    *response_head.headers_mut() = headers;
    tokio::time::timeout(config.write_timeout, stream.send_response(response_head))
        .await
        .map_err(|_| netune_http3::H3Error::Timeout("response head"))??;
    recorder.mark_stream(
        stream_id,
        EventKind::ResponseHeadSent,
        u32::from(head.status.as_u16()),
        0,
    );

    if is_head {
        // HEAD carries the response head only; the body is discarded without
        // becoming response bytes.
    } else {
        match body {
            ResponseBody::Empty => {}
            ResponseBody::Bytes(bytes) => {
                if !bytes.is_empty() {
                    let len = bytes.len() as u32;
                    tokio::time::timeout(config.write_timeout, stream.send_data(bytes))
                        .await
                        .map_err(|_| netune_http3::H3Error::Timeout("response write"))??;
                    recorder.mark_stream(stream_id, EventKind::ResponseChunkSent, len, 0);
                }
            }
            ResponseBody::Stream(mut stream_body) => {
                while let Some(chunk) =
                    timeout_chunk(config.write_timeout, &mut stream_body).await?
                {
                    if chunk.is_empty() {
                        continue;
                    }
                    let len = chunk.len() as u32;
                    tokio::time::timeout(config.write_timeout, stream.send_data(chunk))
                        .await
                        .map_err(|_| netune_http3::H3Error::Timeout("response write"))??;
                    recorder.mark_stream(stream_id, EventKind::ResponseChunkSent, len, 0);
                }
            }
        }
    }

    tokio::time::timeout(config.write_timeout, stream.finish())
        .await
        .map_err(|_| netune_http3::H3Error::Timeout("response finish"))??;
    recorder.mark_stream(stream_id, EventKind::ResponseEnd, 0, 0);
    Ok(())
}

async fn timeout_chunk(
    timeout: Duration,
    body: &mut Box<dyn BodyStream>,
) -> Result<Option<Bytes>, netune_http3::H3Error> {
    tokio::time::timeout(timeout, body.next_chunk())
        .await
        .map_err(|_| netune_http3::H3Error::Timeout("response body"))?
        .map_err(|error| netune_http3::H3Error::H3(format!("response body stream failed: {error}")))
}
