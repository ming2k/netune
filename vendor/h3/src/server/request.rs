use std::{convert::TryFrom, sync::Arc};

use bytes::{Buf, Bytes};
use http::{Request, StatusCode};

use tokio::sync::mpsc::UnboundedSender;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{
    connection::{self},
    error::{
        connection_error_creators::{CloseStream, HandleFrameStreamErrorOnRequestStream},
        internal_error::InternalConnectionError,
        Code, StreamError,
    },
    frame::{FrameStream, FrameStreamError},
    proto::{
        frame::{Frame, PayloadLen},
        headers::Header,
    },
    quic::{self, SendStream, StreamId},
    shared_state::{ConnectionState, SharedState},
};

use super::{connection::RequestEnd, stream::RequestStream};

/// Helper struct to await the request headers and return a `Request` object
pub struct RequestResolver<C, B>
where
    C: quic::Connection<B>,
    C::BidiStream: quic::SendStream<B>,
    B: Buf,
{
    #[doc(hidden)]
    // TODO: make this private
    pub frame_stream: FrameStream<C::BidiStream, B>,
    pub(super) request_end_send: UnboundedSender<StreamId>,
    pub(super) send_grease_frame: bool,
    pub(super) max_field_section_size: u64,
    pub(super) shared: Arc<SharedState>,
}

impl<C, B> ConnectionState for RequestResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.shared
    }
}

impl<C, B> CloseStream for RequestResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
}

impl<C, B> RequestResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Returns a future to await the request headers and return a `Request` object
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn resolve_request(
        mut self,
    ) -> Result<(Request<()>, RequestStream<C::BidiStream, B>), StreamError> {
        let frame = std::future::poll_fn(|cx| self.frame_stream.poll_next(cx)).await;
        let req = self.accept_with_frame(frame)?;
        Ok(req.resolve().await?)
    }

    /// Accepts a http request where the first frame has already been read and decoded.
    ///
    /// This is needed as a bidirectional stream may be read as part of incoming webtransport
    /// bi-streams. If it turns out that the stream is *not* a `WEBTRANSPORT_STREAM` the request
    /// may still want to be handled and passed to the user.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn accept_with_frame(
        mut self,
        frame: Result<Option<Frame<PayloadLen>>, FrameStreamError>,
    ) -> Result<ResolvedRequest<C, B>, StreamError> {
        let encoded = match frame {
            Ok(Some(Frame::Headers(h))) => h,

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# If a client-initiated
            //# stream terminates without enough of the HTTP message to provide a
            //# complete response, the server SHOULD abort its response stream with
            //# the error code H3_REQUEST_INCOMPLETE.
            Ok(None) => {
                self.frame_stream.reset(Code::H3_REQUEST_INCOMPLETE.value());
                return Err(StreamError::StreamError {
                    code: Code::H3_REQUEST_INCOMPLETE,
                    reason: "stream terminated without headers".to_string(),
                });
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            //# A server MUST treat the
            //# receipt of a PUSH_PROMISE frame as a connection error of type
            //# H3_FRAME_UNEXPECTED.
            Ok(Some(_)) => {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Receipt of an invalid sequence of frames MUST be treated as a
                //# connection error of type H3_FRAME_UNEXPECTED.
                // Close if the first frame is not a header frame
                return Err(
                    self.handle_connection_error_on_stream(InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        "first request frame is not headers".to_string(),
                    )),
                );
            }
            Err(e) => {
                return Err(self.handle_frame_stream_error_on_request_stream(e));
            }
        };

        let request_stream = RequestStream {
            request_end: Arc::new(RequestEnd {
                request_end: self.request_end_send.clone(),
                stream_id: self.frame_stream.send_id(),
            }),
            inner: connection::RequestStream::new(
                self.frame_stream,
                self.max_field_section_size,
                self.shared.clone(),
                self.send_grease_frame,
            ),
        };

        // Header decoding is deferred to `resolve`, where it can wait for
        // QPACK dynamic-table insertions that arrive on the peer's encoder
        // stream without blocking the accept loop.
        Ok(ResolvedRequest::new(
            request_stream,
            encoded,
            self.max_field_section_size,
            self.shared,
        ))
    }
}

pub struct ResolvedRequest<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    request_stream: RequestStream<C::BidiStream, B>,
    encoded: Bytes,
    max_field_section_size: u64,
    shared: Arc<SharedState>,
}

impl<B, C> ResolvedRequest<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    pub fn new(
        request_stream: RequestStream<C::BidiStream, B>,
        encoded: Bytes,
        max_field_section_size: u64,
        shared: Arc<SharedState>,
    ) -> Self {
        Self {
            request_stream,
            encoded,
            max_field_section_size,
            shared,
        }
    }

    /// Finishes the resolution of the request
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn resolve(
        mut self,
    ) -> Result<(Request<()>, RequestStream<C::BidiStream, B>), StreamError> {
        let fields = match self
            .shared
            .decode_headers(
                self.request_stream.inner.stream.send_id().into_inner(),
                &self.encoded,
            )
            .await
        {
            Ok(decoded) if decoded.mem_size <= self.max_field_section_size => decoded.fields,
            Ok(decoded) => {
                let cancel_size = decoded.mem_size;
                self.request_stream
                    .send_response(
                        http::Response::builder()
                            .status(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
                            .body(())
                            .expect("header too big response"),
                    )
                    .await?;

                return Err(StreamError::HeaderTooBig {
                    actual_size: cancel_size,
                    max_size: self.max_field_section_size,
                });
            }
            Err(error) => {
                return Err(self.request_stream.handle_connection_error_on_stream(
                    InternalConnectionError {
                        code: Code::QPACK_DECOMPRESSION_FAILED,
                        message: format!("Failed to decode headers: {error}"),
                    },
                ));
            }
        };

        // Parse the request headers
        let result = match Header::try_from(fields) {
            Ok(header) => match header.into_request_parts() {
                Ok(parts) => Ok(parts),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };
        let (method, uri, protocol, headers) = match result {
            Ok(parts) => parts,
            Err(err) => {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
                //# Malformed requests or responses that are
                //# detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.
                let error_code = Code::H3_MESSAGE_ERROR;
                self.request_stream.stop_stream(error_code);
                self.request_stream.stop_sending(error_code);

                return Err(StreamError::StreamError {
                    code: error_code,
                    reason: format!("Malformed request with error: {}", err),
                });
            }
        };

        //  request_stream.stop_stream(Code::H3_MESSAGE_ERROR).await;

        let mut req = http::Request::new(());
        *req.method_mut() = method;
        *req.uri_mut() = uri;
        *req.headers_mut() = headers;
        // NOTE: insert `Protocol` and not `Option<Protocol>`
        if let Some(protocol) = protocol {
            req.extensions_mut().insert(protocol);
        }
        *req.version_mut() = http::Version::HTTP_3;
        #[cfg(feature = "tracing")]
        tracing::trace!("replying with: {:?}", req);

        Ok((req, self.request_stream))
    }
}
