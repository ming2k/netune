//! HTTP/2 over an established connection or shared session.

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use netune_http1::{BodyKind, IncomingResponse};
use netune_http2::{
    H2ClientConnection, H2ClientSession, H2HeadFuture, H2ResponseEvent, H2ResponseHead,
    H2StreamPermit, H2StreamReader,
};
use netune_trace::{
    ConnectionInfo, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EventKind, TraceCollector,
};
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::connect::Transport;
use crate::error::NetError;
use crate::exchange::{
    Attempt, BodySource, BoxFuture, Exchange, Released, Request, RequestBody, RequestBodySource,
};
use crate::pool::PoolInFlightPermit;
use crate::tcp_info::{SAMPLE_INTERVAL, Sampler, start as start_sampler};

/// Complete the HTTP/2 preface and SETTINGS exchange under the configured
/// bound, then spawn the multiplexed session driver.
///
/// This is the phase between a verified TLS peer and a usable connection: the
/// peer has accepted the socket but has not yet shown it speaks HTTP/2. It is
/// bounded here, at the orchestrator, because the codec owns framing and must
/// not own clocks. The bound covers the whole exchange, including the peer's
/// SETTINGS and ACK, and a stalled peer is never pooled.
pub(super) async fn handshake(
    mut stream: Box<dyn Transport>,
    attempt: Attempt<'_>,
) -> Result<H2ClientSession, NetError> {
    let plan = attempt.plan;
    let recorder = attempt.recorder;
    let fingerprint = plan.h2_fingerprint().cloned().ok_or_else(|| {
        NetError::Protocol("HTTP/2 was selected but no H2 profile was resolved".into())
    })?;
    // A multiplexed connection is shared by every exchange it will carry, so
    // no single attempt may own its socket tap: the dial tap is retired here
    // and the handshake bytes it saw stay with the attempt that paid for them.
    if let Some(tap) = stream.swap_tap(netune_trace::SocketTap::Off)
        && let netune_trace::TapArtifact::Log(log) = netune_trace::Tap::finish(tap)
    {
        recorder.merge(log);
    }
    let connection = crate::handshake::bound(
        attempt.config.h2_handshake_timeout,
        DiagnosticPhase::Http2,
        "HTTP/2 handshake",
        &plan.target.authority,
        recorder,
        H2ClientConnection::handshake(stream, fingerprint),
    )
    .await?
    .map_err(|error| h2_error_traced("handshake", error, recorder))?;

    Ok(connection.into_session())
}

/// Abort a spawned request-body upload task if the caller abandons the
/// exchange before upload completion.
struct AbortOnDrop(Option<AbortHandle>);

impl AbortOnDrop {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// Open a stream on a live [`H2ClientSession`], drive its request body (buffered
/// or streamed), await the response head under `response_head_timeout`, and
/// hand back the unread response stream.
pub(super) async fn exchange_on_session(
    session: &H2ClientSession,
    permit: H2StreamPermit,
    socket: Option<std::net::TcpStream>,
    info: ConnectionInfo,
    attempt: Attempt<'_>,
    request: &Request,
    in_flight: &mut Option<PoolInFlightPermit>,
) -> Result<Exchange, NetError> {
    let plan = attempt.plan;
    let recorder = attempt.recorder;

    let scheme = if plan.target.tls_server_name().is_some() {
        "https"
    } else {
        "http"
    };
    let (authority, extra_headers) = super::request_parts(&request.head, &plan.target.authority);

    recorder.mark(EventKind::RequestWriteStart, 0, 0);
    let request_profile = plan.h2_request().unwrap_or(*session.request_profile());
    let stream_source = request.body.take_stream()?;
    let streaming_body = stream_source.is_some();
    let initial_body = if streaming_body {
        None
    } else {
        match &request.body {
            RequestBody::Full(bytes) => Some(bytes.clone()),
            _ => None,
        }
    };
    let initial_len = initial_body.as_ref().map_or(0, Bytes::len);

    let (sender, head_fut, mut reader) = session
        .open_request(
            Some(permit),
            request.head.method.as_str(),
            &authority,
            scheme,
            &request.head.target,
            &extra_headers,
            initial_body,
            streaming_body,
            &request_profile,
        )
        .await
        .map_err(|error| h2_error_traced("request", error, recorder))?;

    let (response, upload_abort, upload_done_rx) = if let Some(source) = stream_source {
        let sender = sender.ok_or_else(|| {
            NetError::Protocol("HTTP/2 session did not yield a streaming request sender".into())
        })?;
        await_streaming_head(source, sender, head_fut, attempt, recorder).await?
    } else {
        recorder.mark(EventKind::RequestWriteEnd, initial_len as u32, 0);
        let head = super::h1::bounded(attempt.config.response_head_timeout, head_fut.await_head())
            .await?
            .map_err(|error| h2_error_traced("request", error, recorder))?;
        (head, AbortOnDrop(None), None)
    };

    if response.end_stream {
        reader.mark_empty();
    }

    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK);
    let mut headers = HeaderMap::new();
    for (name, value) in response.headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::try_from(name.as_str()),
            http::header::HeaderValue::try_from(value.as_str()),
        ) {
            headers.append(name, value);
        }
    }
    let body_kind = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(BodyKind::Chunked, BodyKind::Length);

    let sampler = socket.as_ref().and_then(|socket| {
        crate::tcp_info::duplicate(socket)
            .map(|clone| start_sampler(clone, recorder.clone(), SAMPLE_INTERVAL))
    });

    Ok(Exchange {
        head: IncomingResponse {
            version: http::Version::HTTP_2,
            status,
            headers,
            body: body_kind,
        },
        body: Box::new(Body {
            reader: Some(reader),
            recorder: recorder.clone(),
            sampler,
            upload_abort,
            upload_done_rx,
            _in_flight: in_flight.take(),
        }),
        connection: info,
    })
}

async fn pump_request_body(
    mut source: Box<dyn RequestBodySource>,
    mut sender: netune_http2::H2RequestSender,
    recorder: &TraceCollector,
) -> Result<(), NetError> {
    let mut written: u64 = 0;
    while let Some(chunk) = source.next_chunk().await? {
        written = written.saturating_add(chunk.len() as u64);
        sender
            .send_data(chunk)
            .await
            .map_err(|error| h2_error_traced("request", error, recorder))?;
    }
    sender
        .finish()
        .map_err(|error| h2_error_traced("request", error, recorder))?;
    recorder.mark(
        EventKind::RequestWriteEnd,
        u32::try_from(written).unwrap_or(u32::MAX),
        0,
    );
    Ok(())
}

async fn await_streaming_head(
    source: Box<dyn RequestBodySource>,
    sender: netune_http2::H2RequestSender,
    head_fut: H2HeadFuture,
    attempt: Attempt<'_>,
    recorder: &TraceCollector,
) -> Result<
    (
        H2ResponseHead,
        AbortOnDrop,
        Option<oneshot::Receiver<Result<(), NetError>>>,
    ),
    NetError,
> {
    let recorder_upload = recorder.clone();
    let (upload_done_tx, mut upload_done_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let outcome = pump_request_body(source, sender, &recorder_upload).await;
        let _ = upload_done_tx.send(outcome);
    });
    let mut upload_abort = AbortOnDrop(Some(task.abort_handle()));
    let mut head_fut = std::pin::pin!(head_fut.await_head());

    tokio::select! {
        head = &mut head_fut => {
            let head = head.map_err(|error| h2_error_traced("request", error, recorder))?;
            Ok((head, upload_abort, Some(upload_done_rx)))
        }
        upload = &mut upload_done_rx => {
            upload_abort.disarm();
            match upload {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(NetError::Protocol("HTTP/2 streaming upload aborted".into())),
            }
            let head = super::h1::bounded(attempt.config.response_head_timeout, head_fut)
                .await?
                .map_err(|error| h2_error_traced("request", error, recorder))?;
            Ok((head, AbortOnDrop(None), None))
        }
    }
}

/// The unread body of an HTTP/2 response stream on a multiplexed session.
struct Body {
    reader: Option<H2StreamReader>,
    recorder: TraceCollector,
    sampler: Option<Sampler>,
    upload_abort: AbortOnDrop,
    upload_done_rx: Option<oneshot::Receiver<Result<(), NetError>>>,
    _in_flight: Option<PoolInFlightPermit>,
}

impl Body {
    fn take_upload_error(&mut self) -> Option<NetError> {
        let rx = self.upload_done_rx.as_mut()?;
        match rx.try_recv() {
            Ok(Ok(())) => {
                self.upload_done_rx = None;
                self.upload_abort.disarm();
                None
            }
            Ok(Err(err)) => {
                self.upload_done_rx = None;
                self.upload_abort.disarm();
                Some(err)
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                self.upload_done_rx = None;
                self.upload_abort.disarm();
                None
            }
            Err(oneshot::error::TryRecvError::Empty) => None,
        }
    }
}

impl BodySource for Body {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>> {
        Box::pin(async move {
            let Some(reader) = self.reader.as_mut() else {
                return Ok(None);
            };
            loop {
                match reader
                    .next_event()
                    .await
                    .map_err(|error| h2_error_traced("body", error, &self.recorder))?
                {
                    H2ResponseEvent::Data { payload, .. } => {
                        if payload.is_empty() {
                            continue;
                        }
                        return Ok(Some(payload));
                    }
                    // The trailer block ends the stream; the next call returns
                    // `End`.
                    H2ResponseEvent::Trailers(_) => continue,
                    H2ResponseEvent::End => {
                        if let Some(err) = self.take_upload_error() {
                            return Err(err);
                        }
                        return Ok(None);
                    }
                }
            }
        })
    }

    fn release(mut self: Box<Self>, complete: bool) -> Released {
        drop(self.sampler.take());
        if let Some(reader) = self.reader.take() {
            reader.release(complete);
        }
        drop(self);
        Released::untapped()
    }
}

/// Map an HTTP/2 codec failure onto the transport's error taxonomy.
///
/// The distinction matters: a socket that died while no response head existed
/// yet is a *stale pooled connection*, and the transport decides from the
/// error whether the request may be sent again. Reporting every codec failure
/// as [`NetError::Protocol`] would turn a recycled-but-dead HTTP/2 connection
/// into a user-visible failure.
fn h2_error(context: &str, error: netune_http2::H2Error) -> NetError {
    use netune_http2::error_code;
    match error {
        netune_http2::H2Error::Io(error) => NetError::Io(error),
        netune_http2::H2Error::UnexpectedEof => {
            NetError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        // Before the response head, both of these say the peer did not process
        // this stream: a fresh connection may replay it safely.
        netune_http2::H2Error::GoAway { error_code, .. } if context == "request" => {
            NetError::RetryableProtocol(format!(
                "HTTP/2 {context}: peer closed with GOAWAY (error code {error_code})"
            ))
        }
        netune_http2::H2Error::StreamReset {
            stream_id,
            error_code,
        } if context == "request" && error_code == error_code::REFUSED_STREAM => {
            NetError::RetryableProtocol(format!("HTTP/2 {context}: stream {stream_id} was refused"))
        }
        other => NetError::Protocol(format!("HTTP/2 {context}: {other}")),
    }
}

/// Record the H2 failure content that the narrow error string drops.
///
/// GOAWAY debug data and a stream reset code are the first facts an operator
/// needs; they are cold-path fields, not event payload.
fn h2_error_traced(
    context: &str,
    error: netune_http2::H2Error,
    recorder: &TraceCollector,
) -> NetError {
    let mut record = DiagnosticRecord::new(DiagnosticCode::EGRESS_HTTP2_PROTOCOL)
        .with_phase(DiagnosticPhase::Http2)
        .with_message(format!("HTTP/2 {context}: {error}"));
    match &error {
        netune_http2::H2Error::GoAway {
            error_code,
            debug_data,
        } => {
            record = record
                .with_field("goaway_code", error_code.to_string())
                .with_field(
                    "debug_data",
                    String::from_utf8_lossy(debug_data).into_owned(),
                );
        }
        netune_http2::H2Error::StreamReset {
            stream_id,
            error_code,
        } => {
            record = record
                .with_field("stream_id", stream_id.to_string())
                .with_field("reset_code", error_code.to_string());
        }
        _ => {}
    }
    recorder.record_error(record);
    h2_error(context, error)
}

#[cfg(test)]
mod tests {
    use super::super::request_parts;
    use super::*;
    use http::Method;
    use netune_http1::RequestHead;

    #[test]
    fn a_host_header_becomes_the_authority_instead_of_a_regular_field() {
        let head = RequestHead::new(Method::GET, "/v1").with_header("host", "override.example");
        let (authority, headers) = request_parts(&head, "target.example");
        assert_eq!(authority, "override.example");
        assert!(headers.iter().all(|(name, _)| name != "host"));
    }

    #[test]
    fn without_a_host_header_the_target_authority_is_used() {
        let head = RequestHead::new(Method::GET, "/v1");
        let (authority, headers) = request_parts(&head, "target.example");
        assert_eq!(authority, "target.example");
        assert!(headers.iter().all(|(name, _)| name != "host"));
    }

    #[test]
    fn goaway_debug_data_is_recorded_in_the_diagnostic() {
        let recorder = TraceCollector::start(8);
        let mapped = h2_error_traced(
            "request",
            netune_http2::H2Error::GoAway {
                error_code: 7,
                debug_data: b"busy".to_vec(),
            },
            &recorder,
        );
        assert!(mapped.is_stale_connection());
        let record = recorder
            .diagnostics()
            .last_error()
            .cloned()
            .expect("GOAWAY diagnostic");
        assert_eq!(record.code, DiagnosticCode::EGRESS_HTTP2_PROTOCOL);
        assert!(
            record
                .fields
                .iter()
                .any(|field| { field.key == "goaway_code" && field.value == "7" })
        );
        assert!(
            record
                .fields
                .iter()
                .any(|field| { field.key == "debug_data" && field.value == "busy" })
        );
    }

    #[test]
    fn raw_header_casing_is_lowered_for_http2() {
        let head = RequestHead::new(Method::GET, "/v1").with_raw_header("X-Trace-Id", "abc");
        let (_, headers) = request_parts(&head, "target.example");
        assert_eq!(headers, vec![("x-trace-id".to_string(), "abc".to_string())]);
    }

    #[test]
    fn a_refusal_before_the_head_is_replayable_on_a_fresh_connection() {
        let goaway = h2_error(
            "request",
            netune_http2::H2Error::GoAway {
                error_code: 0,
                debug_data: Vec::new(),
            },
        );
        assert!(goaway.is_stale_connection());
        assert!(goaway.is_retryable());

        let refused = h2_error(
            "request",
            netune_http2::H2Error::StreamReset {
                stream_id: 1,
                error_code: netune_http2::error_code::REFUSED_STREAM,
            },
        );
        assert!(refused.is_stale_connection());
        assert!(refused.is_retryable());

        // A reset or GOAWAY after the response head belongs to a stream the peer
        // may already have processed; it must not be replayed transparently.
        let after_head = h2_error(
            "body",
            netune_http2::H2Error::StreamReset {
                stream_id: 1,
                error_code: netune_http2::error_code::REFUSED_STREAM,
            },
        );
        assert!(!after_head.is_stale_connection());
        assert!(!after_head.is_retryable());
    }
}
