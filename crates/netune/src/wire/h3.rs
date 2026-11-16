//! HTTP/3 over a pooled multiplexed QUIC/H3 session.

use std::time::Duration;

use bytes::Bytes;
use http::Version;
use netune_egress::EgressConfinement;
use netune_http1::{BodyKind, IncomingResponse};
use netune_http3::{H3ClientConfig, H3Error, H3ResponseStream, H3Session};
use netune_quic::{QuicConnector, QuicError};
use netune_trace::{ConnectionInfo, DiagnosticPhase, EventKind, TraceCollector};
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::error::{ConnectError, ConnectErrorKind, NetError, ResolveError, ResolveErrorKind};
use crate::exchange::{Attempt, BodySource, BoxFuture, Exchange, Released, Request, RequestBody};
use crate::pool::PoolInFlightPermit;

const NO_INTERNAL_TIMEOUT: Duration = Duration::from_secs(86_400);

/// Dial QUIC through `quic`, honoring inherited egress confinement, and start
/// the owned HTTP/3 state machine.
pub(super) async fn dial_and_handshake(
    quic: &QuicConnector,
    confinement: Option<EgressConfinement>,
    attempt: Attempt<'_>,
) -> Result<H3Session, NetError> {
    let plan = attempt.plan;
    let recorder = attempt.recorder;
    let (quic_profile, settings_profile, _) = plan.h3_plan().ok_or_else(|| {
        NetError::Protocol("HTTP/3 was selected but no H3 plan was resolved".into())
    })?;
    let server_name = plan.target.tls_server_name().ok_or_else(|| {
        NetError::Connect(ConnectError::config(
            DiagnosticPhase::Quic,
            "HTTP/3 requires a TLS server name on Target",
        ))
    })?;

    let mut connector = quic.for_profile(quic_profile.clone());
    if matches!(confinement, Some(EgressConfinement::StrictPublic)) {
        connector = connector.with_confinement(EgressConfinement::StrictPublic);
    }

    let quic_conn = connector
        .connect_authority(&plan.target.authority, server_name, Some(recorder.clone()))
        .await
        .map_err(|error| h3_error_traced("handshake", H3Error::Quic(error), recorder))?;

    H3Session::from_quic(quic_conn, settings_profile.clone())
        .await
        .map_err(|error| h3_error_traced("handshake", error, recorder))
}

/// Open a stream on a live [`H3Session`], send the request head and body
/// (buffered or streamed), await the response head under `response_head_timeout`,
/// and hand back the unread response stream.
pub(super) async fn exchange_on_session(
    session: &H3Session,
    info: ConnectionInfo,
    attempt: Attempt<'_>,
    request: &Request,
    in_flight: &mut Option<PoolInFlightPermit>,
) -> Result<Exchange, NetError> {
    let plan = attempt.plan;
    let recorder = attempt.recorder;
    let (_, _, h3_request_profile) = plan.h3_plan().ok_or_else(|| {
        NetError::Protocol("HTTP/3 was selected but no H3 request plan was resolved".into())
    })?;

    let (authority, extra_headers) = super::request_parts(&request.head, &plan.target.authority);
    let path = if request.head.target.is_empty() {
        "/"
    } else {
        request.head.target.as_str()
    };
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(path)
        .build()
        .map_err(|error| {
            NetError::Protocol(format!("HTTP/3 request URI {path:?} invalid: {error}"))
        })?;

    let mut builder = http::Request::builder()
        .method(request.head.method.clone())
        .uri(uri);
    for (name, value) in extra_headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let http_request = builder
        .body(())
        .map_err(|error| NetError::Protocol(format!("HTTP/3 request invalid: {error}")))?;

    let h3_config = H3ClientConfig {
        request_timeout: attempt
            .config
            .request_timeout
            .unwrap_or(NO_INTERNAL_TIMEOUT),
        response_head_timeout: attempt
            .config
            .response_head_timeout
            .unwrap_or(NO_INTERNAL_TIMEOUT),
        body_chunk_timeout: attempt
            .config
            .body_idle_timeout
            .unwrap_or(NO_INTERNAL_TIMEOUT),
        max_body_bytes: usize::MAX,
    };

    recorder.mark(EventKind::RequestWriteStart, 0, 0);
    let req_body = session
        .open_request(
            http_request,
            h3_request_profile,
            &h3_config,
            Some(recorder.clone()),
            None,
        )
        .await
        .map_err(|error| h3_error_traced("request", error, recorder))?;

    let stream_source = request.body.take_stream()?;
    let buffered = match &request.body {
        RequestBody::Full(bytes) if !bytes.is_empty() => Some(bytes.clone()),
        _ => None,
    };
    let (mut sender, response_fut) = req_body.split();
    let recorder_upload = recorder.clone();
    let (upload_done_tx, mut upload_done_rx) = oneshot::channel();
    let upload = tokio::spawn(async move {
        let outcome: Result<(), NetError> = async {
            let mut written: u64 = 0;
            if let Some(mut source) = stream_source {
                while let Some(chunk) = source.next_chunk().await? {
                    written = written.saturating_add(chunk.len() as u64);
                    sender
                        .send_data(chunk)
                        .await
                        .map_err(|error| h3_error_traced("request", error, &recorder_upload))?;
                }
            } else if let Some(bytes) = buffered {
                written = bytes.len() as u64;
                sender
                    .send_data(bytes)
                    .await
                    .map_err(|error| h3_error_traced("request", error, &recorder_upload))?;
            }
            sender
                .close_send()
                .await
                .map_err(|error| h3_error_traced("request", error, &recorder_upload))?;
            recorder_upload.mark(
                EventKind::RequestWriteEnd,
                u32::try_from(written).unwrap_or(u32::MAX),
                0,
            );
            Ok(())
        }
        .await;
        let _ = upload_done_tx.send(outcome);
    });
    let mut upload_abort = AbortOnDrop(Some(upload.abort_handle()));
    let mut head_fut = std::pin::pin!(super::h1::bounded(
        attempt.config.response_head_timeout,
        response_fut.await_head()
    ));

    // Await the response head and the upload together. If the origin answers
    // before the upload finishes, keep the response and cancel the upload on
    // drop; if the upload finishes first, wait for the head under its bound.
    let (head, upload_done_rx) = tokio::select! {
        head = &mut head_fut => (head, Some(upload_done_rx)),
        done = &mut upload_done_rx => {
            upload_abort.disarm();
            match done {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(NetError::Protocol("HTTP/3 upload task aborted".into())),
            }
            (head_fut.await, None)
        }
    };
    let resp_stream = head?.map_err(|error| h3_error_traced("request", error, recorder))?;

    let status = resp_stream.head().status();
    let headers = resp_stream.head().headers().clone();
    let body_kind = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(BodyKind::Chunked, BodyKind::Length);

    Ok(Exchange {
        head: IncomingResponse {
            version: Version::HTTP_3,
            status,
            headers,
            body: body_kind,
        },
        body: Box::new(Body {
            stream: Some(resp_stream),
            recorder: recorder.clone(),
            upload_abort,
            upload_done_rx,
            _in_flight: in_flight.take(),
        }),
        connection: info,
    })
}

/// Abort an upload task when its response body is dropped before the upload
/// finishes.
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

struct Body {
    stream: Option<H3ResponseStream>,
    recorder: TraceCollector,
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
            Ok(Err(error)) => {
                self.upload_done_rx = None;
                self.upload_abort.disarm();
                Some(error)
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
            let Some(stream) = self.stream.as_mut() else {
                return Ok(None);
            };
            let next = stream
                .next_chunk()
                .await
                .map_err(|error| h3_error_traced("body", error, &self.recorder))?;
            if next.is_none()
                && let Some(error) = self.take_upload_error()
            {
                return Err(error);
            }
            Ok(next)
        })
    }

    fn release(mut self: Box<Self>, _complete: bool) -> Released {
        drop(self.stream.take());
        Released::untapped()
    }
}

fn h3_error_traced(context: &str, error: H3Error, recorder: &TraceCollector) -> NetError {
    recorder.record_error(error.diagnostic());
    h3_error(context, error)
}

fn h3_error(context: &str, error: H3Error) -> NetError {
    match error {
        H3Error::GoAway { id } if context == "request" => {
            NetError::RetryableProtocol(format!("HTTP/3 {context}: peer sent GOAWAY (id {id})"))
        }
        H3Error::Quic(qerr) => quic_error(context, qerr),
        H3Error::Profile(msg) => {
            NetError::Connect(ConnectError::config(DiagnosticPhase::Http3, msg))
        }
        other => NetError::Protocol(format!("HTTP/3 {context}: {other}")),
    }
}

fn quic_error(context: &str, error: QuicError) -> NetError {
    match error {
        QuicError::Dns { host, detail } => {
            NetError::Resolve(ResolveError::new(ResolveErrorKind::Failed, host, detail))
        }
        QuicError::Config(msg) => {
            NetError::Connect(ConnectError::config(DiagnosticPhase::Quic, msg))
        }
        QuicError::Tls(msg) => NetError::Connect(ConnectError::new(
            DiagnosticPhase::Tls,
            ConnectErrorKind::Tls,
            msg,
        )),
        QuicError::Timeout => NetError::Connect(ConnectError::new(
            DiagnosticPhase::Quic,
            ConnectErrorKind::Timeout,
            "quic operation timed out",
        )),
        QuicError::Socket(io) => {
            if context == "handshake" {
                NetError::Connect(
                    ConnectError::new(
                        DiagnosticPhase::Quic,
                        ConnectErrorKind::Io(io.kind()),
                        io.to_string(),
                    )
                    .with_source(io),
                )
            } else {
                NetError::Io(io)
            }
        }
        QuicError::Connect(msg) => {
            if msg.contains("egress confinement refused") {
                NetError::Security(msg)
            } else {
                NetError::Connect(ConnectError::new(
                    DiagnosticPhase::Quic,
                    ConnectErrorKind::Protocol,
                    msg,
                ))
            }
        }
        QuicError::Closed(msg) => {
            if context == "handshake" {
                NetError::Connect(ConnectError::new(
                    DiagnosticPhase::Quic,
                    ConnectErrorKind::Io(std::io::ErrorKind::ConnectionReset),
                    msg,
                ))
            } else {
                NetError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    msg,
                ))
            }
        }
        other => NetError::Protocol(format!("QUIC {context}: {other}")),
    }
}
