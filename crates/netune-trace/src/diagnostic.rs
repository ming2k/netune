//! Stable failure codes and the bounded diagnostic side table.
//!
//! The event log answers *when*. This module answers *why* without putting a
//! string on the hot path: a failure records a fixed-size [`DiagnosticCode`] in
//! the event, and the human-readable detail travels in a bounded side table on
//! the same envelope.
//!
//! Codes are persisted contract. A code is never renumbered or reused; adding a
//! diagnostic means adding a registry entry and a test, not inventing a number
//! at a call site.

use std::fmt;

/// Largest diagnostic message retained, in bytes.
pub const MAX_DIAGNOSTIC_MESSAGE: usize = 512;
/// Largest individual field value retained, in bytes.
pub const MAX_DIAGNOSTIC_FIELD: usize = 256;
/// Largest number of fields retained on one diagnostic.
pub const MAX_DIAGNOSTIC_FIELDS: usize = 16;
/// Default number of diagnostics retained per attempt.
pub const DEFAULT_DIAGNOSTIC_CAPACITY: usize = 32;

/// How serious a diagnostic is.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DiagnosticLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

/// Where in the transport the diagnostic was raised.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DiagnosticPhase {
    Dispatch = 0,
    Dns = 1,
    Tcp = 2,
    Tls = 3,
    Proxy = 4,
    Pool = 5,
    Http1 = 6,
    Http2 = 7,
    Quic = 8,
    Http3 = 9,
    WebSocket = 10,
    Request = 11,
    Response = 12,
    Server = 13,
    Listener = 14,
    Drain = 15,
    Sink = 16,
    Trace = 17,
    Unknown = 18,
}

/// Whether another attempt could plausibly succeed.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RetryVerdict {
    /// A fresh attempt may succeed.
    Retryable = 0,
    /// The same attempt would fail the same way.
    Terminal = 1,
    /// Safe only under a caller's replay policy.
    Conditional = 2,
}

/// How a field value may be persisted or rendered.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Sensitivity {
    /// Safe to show to an operator.
    Public = 0,
    /// Contextual, but not secret.
    Internal = 1,
    /// Never persisted by default.
    Secret = 2,
}

/// A stable, greppable diagnostic code.
///
/// The numeric value is the persisted contract. `0` is reserved for
/// [`DiagnosticCode::UNCLASSIFIED`] and is forbidden for new producers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct DiagnosticCode(u32);

macro_rules! diagnostic_registry {
    ($( $name:ident = $raw:literal => $symbol:literal, $phase:ident, $level:ident, $retry:ident; )*) => {
        impl DiagnosticCode {
            $(pub const $name: Self = Self($raw);)*

            /// Every registered code, in registry order.
            pub const REGISTERED: &'static [Self] = &[$(Self::$name),*];

            /// The symbolic name of this code.
            pub const fn symbol(self) -> &'static str {
                match self.0 {
                    $($raw => $symbol,)*
                    _ => "NET-E-UNKNOWN",
                }
            }

            /// The phase this code belongs to.
            pub const fn phase(self) -> DiagnosticPhase {
                match self.0 {
                    $($raw => DiagnosticPhase::$phase,)*
                    _ => DiagnosticPhase::Unknown,
                }
            }

            /// The severity this code belongs to.
            pub const fn level(self) -> DiagnosticLevel {
                match self.0 {
                    $($raw => DiagnosticLevel::$level,)*
                    _ => DiagnosticLevel::Error,
                }
            }

            /// The retry verdict this code belongs to.
            pub const fn retry(self) -> RetryVerdict {
                match self.0 {
                    $($raw => RetryVerdict::$retry,)*
                    _ => RetryVerdict::Terminal,
                }
            }
        }
    };
}

diagnostic_registry! {
    UNCLASSIFIED = 0 => "NET-E-UNCLASSIFIED", Unknown, Error, Terminal;

    EGRESS_DNS_FAILED = 0x0101 => "NET-E-DNS-FAILED", Dns, Error, Retryable;
    EGRESS_TCP_FAILED = 0x0201 => "NET-E-TCP-FAILED", Tcp, Error, Retryable;
    EGRESS_TLS_FAILED = 0x0301 => "NET-E-TLS-FAILED", Tls, Error, Terminal;
    EGRESS_PROXY_FAILED = 0x0401 => "NET-E-PROXY-FAILED", Proxy, Error, Retryable;
    EGRESS_POOL_STALE = 0x0501 => "NET-E-POOL-STALE", Pool, Warn, Retryable;
    EGRESS_HTTP1_PROTOCOL = 0x0601 => "NET-E-HTTP1-PROTOCOL", Http1, Error, Terminal;
    EGRESS_HTTP1_LIMIT = 0x0602 => "NET-E-HTTP1-LIMIT", Http1, Error, Terminal;
    EGRESS_HTTP1_INCOMPLETE = 0x0603 => "NET-E-HTTP1-INCOMPLETE", Http1, Error, Retryable;
    EGRESS_HTTP1_IO = 0x0604 => "NET-E-HTTP1-IO", Http1, Error, Retryable;
    EGRESS_HTTP2_PROTOCOL = 0x0701 => "NET-E-HTTP2-PROTOCOL", Http2, Error, Terminal;
    EGRESS_HTTP2_HANDSHAKE = 0x0702 => "NET-E-HTTP2-HANDSHAKE", Http2, Error, Retryable;
    EGRESS_HTTP2_REFUSED = 0x0703 => "NET-E-HTTP2-REFUSED", Http2, Error, Retryable;
    EGRESS_QUIC_FAILED = 0x0801 => "NET-E-QUIC-FAILED", Quic, Error, Retryable;
    EGRESS_QUIC_PATH_MTU = 0x0802 => "NET-I-QUIC-PATH-MTU", Quic, Info, Conditional;
    EGRESS_QUIC_CLOSED = 0x0803 => "NET-I-QUIC-CLOSED", Quic, Info, Conditional;
    EGRESS_H3_FAILED = 0x0901 => "NET-E-H3-FAILED", Http3, Error, Terminal;
    EGRESS_WS_FAILED = 0x0a01 => "NET-E-WS-FAILED", WebSocket, Error, Terminal;
    EGRESS_WS_CLOSED = 0x0a02 => "NET-I-WS-CLOSED", WebSocket, Info, Terminal;
    EGRESS_SECURITY = 0x0b01 => "NET-E-EGRESS-SECURITY", Tcp, Error, Terminal;
    EGRESS_DECODE = 0x0c01 => "NET-E-DECODE-FAILED", Response, Error, Terminal;
    EGRESS_UNSUPPORTED_ENCODING = 0x0c02 => "NET-E-UNSUPPORTED-ENCODING", Response, Error, Terminal;
    EGRESS_REDIRECT_LIMIT = 0x0d01 => "NET-E-REDIRECT-LIMIT", Response, Error, Terminal;
    EGRESS_PROTOCOL = 0x0e01 => "NET-E-PROTOCOL", Unknown, Error, Terminal;
    EGRESS_IO = 0x0e02 => "NET-E-IO", Unknown, Error, Retryable;
    EGRESS_TIMEOUT = 0x0e03 => "NET-E-TIMEOUT", Unknown, Error, Retryable;
    EGRESS_CONFIG = 0x0e04 => "NET-E-CONFIG", Request, Error, Terminal;
    EGRESS_TRACE_INCOMPLETE = 0x0e05 => "NET-E-TRACE-INCOMPLETE", Trace, Warn, Conditional;

    SERVER_PROTOCOL = 0x1001 => "NET-E-SERVER-PROTOCOL", Http1, Error, Terminal;
    SERVER_LIMIT = 0x1002 => "NET-E-SERVER-LIMIT", Http1, Error, Terminal;
    SERVER_INCOMPLETE = 0x1003 => "NET-E-SERVER-INCOMPLETE", Http1, Error, Retryable;
    SERVER_IO = 0x1004 => "NET-E-SERVER-IO", Http1, Error, Retryable;
    SERVER_HEAD_TIMEOUT = 0x1005 => "NET-E-SERVER-HEAD-TIMEOUT", Http1, Error, Terminal;
    SERVER_BODY_TIMEOUT = 0x1006 => "NET-E-SERVER-BODY-TIMEOUT", Http1, Error, Terminal;
    SERVER_HANDLER_TIMEOUT = 0x1007 => "NET-E-SERVER-HANDLER-TIMEOUT", Server, Error, Terminal;
    SERVER_HANDLER_PANIC = 0x1008 => "NET-E-SERVER-HANDLER-PANIC", Server, Error, Terminal;
    SERVER_INVALID_REQUEST = 0x1009 => "NET-E-SERVER-INVALID-REQUEST", Http1, Error, Terminal;
    SERVER_TLS_HANDSHAKE = 0x100a => "NET-E-SERVER-TLS-HANDSHAKE", Tls, Error, Terminal;
    SERVER_BIND = 0x100b => "NET-E-SERVER-BIND", Listener, Error, Terminal;
    SERVER_SHED = 0x100c => "NET-E-SERVER-SHED", Listener, Warn, Retryable;
    SERVER_ACCEPT = 0x100d => "NET-E-SERVER-ACCEPT", Listener, Warn, Retryable;
    SERVER_DRAIN_EXPIRED = 0x100e => "NET-E-SERVER-DRAIN-EXPIRED", Drain, Warn, Conditional;
    SERVER_H2_STREAM = 0x100f => "NET-E-SERVER-H2-STREAM", Http2, Error, Conditional;
    SERVER_CONFIG = 0x1010 => "NET-E-SERVER-CONFIG", Listener, Error, Terminal;
    SERVER_H3_HANDSHAKE = 0x1011 => "NET-E-SERVER-H3-HANDSHAKE", Http3, Warn, Retryable;
    SERVER_BODY_LIMIT = 0x1012 => "NET-E-SERVER-BODY-LIMIT", Http1, Error, Terminal;

    TRACE_DROPPED = 0x2001 => "NET-W-TRACE-DROPPED", Trace, Warn, Conditional;
    DIAGNOSTIC_DROPPED = 0x2002 => "NET-W-DIAGNOSTIC-DROPPED", Trace, Warn, Conditional;
    SINK_DROPPED = 0x2003 => "NET-W-SINK-DROPPED", Sink, Warn, Conditional;
    TRACE_INCOMPLETE = 0x2004 => "NET-W-TRACE-INCOMPLETE", Trace, Warn, Conditional;
}

impl DiagnosticCode {
    /// Decode a persisted code.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// The persisted numeric value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Whether this code is registered.
    pub const fn is_registered(self) -> bool {
        self.0 != 0 && !matches!(self.symbol().as_bytes(), b"NET-E-UNKNOWN")
    }

    /// The documentation anchor for this code.
    pub fn docs_anchor(self) -> String {
        self.symbol().to_ascii_lowercase().replace('-', "_")
    }
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol())
    }
}

/// A failure that can describe itself in the diagnostic vocabulary.
///
/// Implemented by each crate's error vocabulary at the boundary where the
/// orchestrator owns the attempt. It is deliberately not implemented for
/// arbitrary `std::error::Error`: a diagnostic code is a reviewed classification,
/// not a downcast guess.
pub trait Diagnose {
    fn diagnostic(&self) -> DiagnosticRecord;
}

/// One bounded, human-readable diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiagnosticRecord {
    /// Producer sequence assigned by [`DiagnosticTable::push`].
    pub sequence: u32,
    pub code: DiagnosticCode,
    pub level: DiagnosticLevel,
    pub phase: DiagnosticPhase,
    pub retry: RetryVerdict,
    pub message: String,
    /// How the message may be persisted.
    pub message_sensitivity: Sensitivity,
    pub fields: Vec<DiagnosticField>,
    pub cause: Option<String>,
    /// How the cause text may be persisted.
    pub cause_sensitivity: Sensitivity,
}

/// One key/value field attached to a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiagnosticField {
    pub key: String,
    pub value: String,
    pub sensitivity: Sensitivity,
}

impl DiagnosticField {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: truncate(key.into(), MAX_DIAGNOSTIC_FIELD),
            value: truncate(value.into(), MAX_DIAGNOSTIC_FIELD),
            sensitivity: Sensitivity::Internal,
        }
    }

    pub fn secret(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: truncate(key.into(), MAX_DIAGNOSTIC_FIELD),
            value: truncate(value.into(), MAX_DIAGNOSTIC_FIELD),
            sensitivity: Sensitivity::Secret,
        }
    }

    pub fn public(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: truncate(key.into(), MAX_DIAGNOSTIC_FIELD),
            value: truncate(value.into(), MAX_DIAGNOSTIC_FIELD),
            sensitivity: Sensitivity::Public,
        }
    }
}

impl DiagnosticRecord {
    /// Create a diagnostic with the registry's default phase, level and retry.
    pub fn new(code: DiagnosticCode) -> Self {
        Self {
            sequence: 0,
            code,
            level: code.level(),
            phase: code.phase(),
            retry: code.retry(),
            message: String::new(),
            message_sensitivity: Sensitivity::Internal,
            fields: Vec::new(),
            cause: None,
            cause_sensitivity: Sensitivity::Internal,
        }
    }

    #[must_use]
    pub fn with_phase(mut self, phase: DiagnosticPhase) -> Self {
        self.phase = phase;
        self
    }

    #[must_use]
    pub fn with_level(mut self, level: DiagnosticLevel) -> Self {
        self.level = level;
        self
    }

    #[must_use]
    pub fn with_retry(mut self, retry: RetryVerdict) -> Self {
        self.retry = retry;
        self
    }

    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = truncate(message.into(), MAX_DIAGNOSTIC_MESSAGE);
        self.message_sensitivity = Sensitivity::Internal;
        self
    }

    #[must_use]
    pub fn with_public_message(mut self, message: impl Into<String>) -> Self {
        self.message = truncate(message.into(), MAX_DIAGNOSTIC_MESSAGE);
        self.message_sensitivity = Sensitivity::Public;
        self
    }

    #[must_use]
    pub fn with_secret_message(mut self, message: impl Into<String>) -> Self {
        self.message = truncate(message.into(), MAX_DIAGNOSTIC_MESSAGE);
        self.message_sensitivity = Sensitivity::Secret;
        self
    }

    #[must_use]
    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(truncate(cause.into(), MAX_DIAGNOSTIC_MESSAGE));
        self.cause_sensitivity = Sensitivity::Internal;
        self
    }

    #[must_use]
    pub fn with_public_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(truncate(cause.into(), MAX_DIAGNOSTIC_MESSAGE));
        self.cause_sensitivity = Sensitivity::Public;
        self
    }

    #[must_use]
    pub fn with_secret_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(truncate(cause.into(), MAX_DIAGNOSTIC_MESSAGE));
        self.cause_sensitivity = Sensitivity::Secret;
        self
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        if self.fields.len() < MAX_DIAGNOSTIC_FIELDS {
            self.fields.push(DiagnosticField::new(key, value));
        }
        self
    }

    #[must_use]
    pub fn with_public_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        if self.fields.len() < MAX_DIAGNOSTIC_FIELDS {
            self.fields.push(DiagnosticField::public(key, value));
        }
        self
    }

    #[must_use]
    pub fn with_secret_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        if self.fields.len() < MAX_DIAGNOSTIC_FIELDS {
            self.fields.push(DiagnosticField::secret(key, value));
        }
        self
    }
}

/// A bounded side table of diagnostics for one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiagnosticTable {
    capacity: usize,
    records: Vec<DiagnosticRecord>,
    dropped: u32,
    next_sequence: u32,
}

impl Default for DiagnosticTable {
    fn default() -> Self {
        Self::new(DEFAULT_DIAGNOSTIC_CAPACITY)
    }
}

impl DiagnosticTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            records: Vec::new(),
            dropped: 0,
            next_sequence: 1,
        }
    }

    /// Append a diagnostic and return its producer sequence.
    pub fn push(&mut self, mut record: DiagnosticRecord) -> u32 {
        if self.records.len() == self.capacity {
            self.records.remove(0);
            self.dropped = self.dropped.saturating_add(1);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        record.sequence = sequence;
        self.records.push(record);
        sequence
    }

    /// Look up a diagnostic by producer sequence.
    pub fn get(&self, sequence: u32) -> Option<&DiagnosticRecord> {
        self.records
            .iter()
            .find(|record| record.sequence == sequence)
    }

    pub fn iter(&self) -> impl Iterator<Item = &DiagnosticRecord> {
        self.records.iter()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The newest error-level diagnostic, when one exists.
    pub fn last_error(&self) -> Option<&DiagnosticRecord> {
        self.records
            .iter()
            .rev()
            .find(|record| record.level == DiagnosticLevel::Error)
    }
}

fn truncate(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut boundary = limit;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_codes_are_unique_and_have_symbols() {
        let mut seen = std::collections::HashSet::new();
        for code in DiagnosticCode::REGISTERED {
            if *code == DiagnosticCode::UNCLASSIFIED {
                continue;
            }
            assert!(seen.insert(code.raw()), "duplicate code {code}");
            assert!(!code.symbol().is_empty());
            assert!(code.is_registered(), "{code} is not registered");
        }
    }

    #[test]
    fn every_registered_code_is_documented() {
        let docs = include_str!("../../../docs/reference/diagnostics.md");
        for code in DiagnosticCode::REGISTERED {
            if *code == DiagnosticCode::UNCLASSIFIED {
                continue;
            }
            assert!(
                docs.contains(code.symbol()),
                "{} is not documented in docs/reference/diagnostics.md",
                code.symbol()
            );
        }
    }

    #[test]
    fn unclassified_is_not_a_registered_producer_code() {
        assert!(!DiagnosticCode::UNCLASSIFIED.is_registered());
        assert_eq!(DiagnosticCode::UNCLASSIFIED.symbol(), "NET-E-UNCLASSIFIED");
    }

    #[test]
    fn diagnostic_messages_and_fields_are_bounded() {
        let record = DiagnosticRecord::new(DiagnosticCode::EGRESS_TLS_FAILED)
            .with_message("x".repeat(MAX_DIAGNOSTIC_MESSAGE * 2))
            .with_field("k".repeat(MAX_DIAGNOSTIC_FIELD * 2), "v");
        assert!(record.message.len() <= MAX_DIAGNOSTIC_MESSAGE);
        assert!(record.fields[0].key.len() <= MAX_DIAGNOSTIC_FIELD);
    }

    #[test]
    fn the_table_counts_what_it_evicts_and_keeps_sequences_stable() {
        let mut table = DiagnosticTable::new(2);
        let first = table.push(DiagnosticRecord::new(DiagnosticCode::EGRESS_IO));
        let second = table.push(DiagnosticRecord::new(DiagnosticCode::EGRESS_TLS_FAILED));
        let third = table.push(DiagnosticRecord::new(DiagnosticCode::EGRESS_HTTP1_LIMIT));
        assert_eq!(table.len(), 2);
        assert_eq!(table.dropped(), 1);
        assert_eq!(table.get(first), None);
        assert_eq!(table.get(second).expect("second").sequence, second);
        assert_eq!(table.get(third).expect("third").sequence, third);
    }
}
