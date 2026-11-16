//! HTTP/3 over a pooled multiplexed QUIC/H3 session.

use std::time::Duration;

use bytes::Bytes;
use http::Version;
use netune_egress::EgressConfinement;
use netune_http1::{BodyKind, IncomingResponse};
use netune_http3::{H3ClientConfig, H3Error, H3ResponseStream, H3Session};
use netune_quic::{QuicConnector, QuicError};
use netune_trace::{ConnectionInfo, DiagnosticPhase, EventKind, TraceCollector};

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
    let mut req_body = session
        .open_request(
            http_request,
            h3_request_profile,
            &h3_config,
            Some(recorder.clone()),
            None,
        )
        .await
        .map_err(|error| h3_error_traced("request", error, recorder))?;

    let mut written: u64 = 0;
    if let Some(mut source) = request.body.take_stream()? {
        while let Some(chunk) = source.next_chunk().await? {
            written = written.saturating_add(chunk.len() as u64);
            req_body
                .send_data(chunk)
                .await
                .map_err(|error| h3_error_traced("request", error, recorder))?;
        }
    } else if let RequestBody::Full(bytes) = &request.body
        && !bytes.is_empty()
    {
        written = bytes.len() as u64;
        req_body
            .send_data(bytes.clone())
            .await
            .map_err(|error| h3_error_traced("request", error, recorder))?;
    }

    req_body
        .close_send()
        .await
        .map_err(|error| h3_error_traced("request", error, recorder))?;
    recorder.mark(
        EventKind::RequestWriteEnd,
        u32::try_from(written).unwrap_or(u32::MAX),
        0,
    );

    let resp_stream =
        super::h1::bounded(attempt.config.response_head_timeout, req_body.into_duplex())
            .await?
            .map_err(|error| h3_error_traced("request", error, recorder))?;

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
            _in_flight: in_flight.take(),
        }),
        connection: info,
    })
}

struct Body {
    stream: Option<H3ResponseStream>,
    recorder: TraceCollector,
    _in_flight: Option<PoolInFlightPermit>,
}

impl BodySource for Body {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>> {
        Box::pin(async move {
            let Some(stream) = self.stream.as_mut() else {
                return Ok(None);
            };
            stream
                .next_chunk()
                .await
                .map_err(|error| h3_error_traced("body", error, &self.recorder))
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
