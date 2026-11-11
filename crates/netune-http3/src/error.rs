// SPDX-License-Identifier: MIT

//! Error types for HTTP/3 client and server operations.

use std::ops::Deref;

use netune_trace::{
    Diagnose, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, Fidelity, RetryVerdict,
    TraceCollector, TraceSnapshot,
};

use crate::proto::frame::FrameError;
use crate::proto::headers::HeaderError;
use crate::qpack::QpackError;

/// Errors arising during HTTP/3 connection, framing, or request execution.
#[derive(Debug, thiserror::Error)]
pub enum H3Error {
    /// QUIC transport error.
    #[error("quic transport error: {0}")]
    Quic(#[from] netune_quic::QuicError),

    /// HTTP/3 handshake or framing error.
    #[error("http3 error: {0}")]
    H3(String),

    /// The peer or local endpoint closed the connection with an H3 error code.
    #[error("http3 connection closed with {code:#x}: {message}")]
    Connection { code: u64, message: String },

    /// HTTP request construction or validation failed.
    #[error("http error: {0}")]
    Http(#[from] http::Error),

    /// A field section was malformed or contained a forbidden field.
    #[error("http3 field error: {0}")]
    Header(#[from] HeaderError),

    /// A frame was malformed.
    #[error("http3 frame error: {0}")]
    Frame(#[from] FrameError),

    /// A capsule was malformed or oversized.
    #[error("capsule error: {0}")]
    Capsule(#[from] crate::proto::capsule::CapsuleError),

    /// QPACK encoding or decoding failed.
    #[error("qpack error: {0}")]
    Qpack(#[from] QpackError),

    /// A profile name was not registered.
    #[error("profile error: {0}")]
    Profile(String),

    /// One request phase exceeded its configured deadline.
    #[error("http3 {0} timed out")]
    Timeout(&'static str),

    /// A buffered response exceeded the configured body ceiling.
    #[error("http3 response body exceeded {limit} bytes")]
    BodyTooLarge { limit: usize },
}

impl Diagnose for H3Error {
    fn diagnostic(&self) -> DiagnosticRecord {
        let (code, phase, retry) = match self {
            Self::Quic(error) => (
                DiagnosticCode::EGRESS_QUIC_FAILED,
                DiagnosticPhase::Quic,
                if matches!(error, netune_quic::QuicError::Timeout) {
                    RetryVerdict::Retryable
                } else {
                    RetryVerdict::Terminal
                },
            ),
            Self::Timeout(_) => (
                DiagnosticCode::EGRESS_H3_FAILED,
                DiagnosticPhase::Http3,
                RetryVerdict::Retryable,
            ),
            Self::Connection { .. } => (
                DiagnosticCode::EGRESS_H3_FAILED,
                DiagnosticPhase::Http3,
                RetryVerdict::Terminal,
            ),
            Self::Profile(_) | Self::Http(_) => (
                DiagnosticCode::EGRESS_CONFIG,
                DiagnosticPhase::Http3,
                RetryVerdict::Terminal,
            ),
            Self::H3(_) | Self::Header(_) | Self::Frame(_) | Self::Capsule(_) | Self::Qpack(_) => (
                DiagnosticCode::EGRESS_H3_FAILED,
                DiagnosticPhase::Http3,
                RetryVerdict::Terminal,
            ),
            Self::BodyTooLarge { .. } => (
                DiagnosticCode::EGRESS_H3_FAILED,
                DiagnosticPhase::Response,
                RetryVerdict::Terminal,
            ),
        };
        let mut record = DiagnosticRecord::new(code)
            .with_phase(phase)
            .with_retry(retry)
            .with_message(self.to_string());
        if let Self::Connection { code, .. } = self {
            record = record.with_field("h3_code", format!("{code:#x}"));
        }
        if let Self::Timeout(phase) = self {
            record = record.with_field("phase", *phase);
        }
        if let Self::Qpack(QpackError::MissingInsertions { required, received }) = self {
            record = record
                .with_field("qpack_required", required.to_string())
                .with_field("qpack_received", received.to_string());
        }
        if let Self::Qpack(QpackError::TooManyBlockedStreams { limit }) = self {
            record = record.with_field("qpack_blocked_limit", limit.to_string());
        }
        record
    }
}

impl H3Error {
    /// The registered diagnostic for this failure.
    pub fn diagnostic(&self) -> DiagnosticRecord {
        <Self as Diagnose>::diagnostic(self)
    }

    /// The application error code to send when this error closes a connection.
    pub fn connection_code(&self) -> u64 {
        match self {
            Self::Connection { code, .. } => *code,
            Self::Qpack(QpackError::MissingInsertions { .. })
            | Self::Qpack(QpackError::ReferenceOutsideSection { .. })
            | Self::Qpack(QpackError::InvalidDynamicIndex(_)) => {
                crate::proto::code::error_code::QPACK_DECOMPRESSION_FAILED
            }
            Self::Qpack(QpackError::EncoderStream) => {
                crate::proto::code::error_code::QPACK_ENCODER_STREAM_ERROR
            }
            Self::Qpack(QpackError::DecoderStream) => {
                crate::proto::code::error_code::QPACK_DECODER_STREAM_ERROR
            }
            Self::Header(_) | Self::Frame(_) | Self::Http(_) | Self::Capsule(_) => {
                crate::proto::code::error_code::H3_MESSAGE_ERROR
            }
            _ => crate::proto::code::error_code::H3_INTERNAL_ERROR,
        }
    }
}

/// A failed HTTP/3 attempt with the trace evidence that produced it.
#[derive(Debug)]
pub struct H3AttemptError {
    error: H3Error,
    trace: TraceSnapshot,
    report: DiagnosticRecord,
}

impl H3AttemptError {
    /// Wrap `error` with a snapshot. If no error-level diagnostic was recorded
    /// internally, the error's own classification is appended.
    pub fn new(error: H3Error, mut trace: TraceSnapshot) -> Self {
        if trace.diagnostics.last_error().is_none() {
            trace.diagnostics.push(error.diagnostic());
        }
        let report = trace
            .diagnostics
            .last_error()
            .cloned()
            .unwrap_or_else(|| error.diagnostic());
        Self {
            error,
            trace,
            report,
        }
    }

    /// Wrap an error that happened before a recorder existed.
    pub fn without_evidence(error: H3Error) -> Self {
        let snapshot = TraceCollector::disabled().snapshot(Fidelity::none());
        Self::new(error, snapshot)
    }

    pub fn error(&self) -> &H3Error {
        &self.error
    }

    pub fn trace(&self) -> &TraceSnapshot {
        &self.trace
    }

    pub fn diagnostic(&self) -> &DiagnosticRecord {
        &self.report
    }

    pub fn diagnosis(&self) -> netune_trace::Diagnosis {
        self.trace.diagnose()
    }

    pub fn into_parts(self) -> (H3Error, TraceSnapshot) {
        (self.error, self.trace)
    }
}

impl Deref for H3AttemptError {
    type Target = H3Error;

    fn deref(&self) -> &Self::Target {
        &self.error
    }
}

impl std::fmt::Display for H3AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for H3AttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
