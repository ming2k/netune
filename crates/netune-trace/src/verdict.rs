//! Verdicts: the reason a number is absent, and the only way to reach one that
//! is present.
//!
//! ADR-0200's first invariant is that a scope which was not measured, does not
//! apply, or cannot be estimated is *never* a fabricated number. [`Reading`]
//! enforces that structurally: the value is private, and [`Reading::value`]
//! returns `Some` only for [`Validity::Measured`]. A surface cannot render a
//! number without having matched on its verdict, because there is no other
//! accessor.

use serde::{Deserialize, Serialize};

/// Why a scope carries no number.
///
/// Reason codes are stable identifiers, not prose: the UI owns the wording, and
/// an aggregate can filter on a code (`Batched` samples must not enter a
/// server-side efficiency average) without parsing English.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No event of the required kind was recorded.
    PhaseAbsent = 0,
    /// The connection came from the pool, so DNS/TCP/TLS never happened.
    ConnectionReused = 1,
    /// The response head and the first body byte arrived in one flush, so the
    /// interval between them says nothing about the origin.
    TransportBatched = 2,
    /// The response was never validated (failed or interrupted attempt).
    ResponseNotValidated = 3,
    /// Fewer than two output events: there is no span to divide by.
    FewerThanTwoOutputEvents = 4,
    /// Too few tokens or batches for a rate to mean anything.
    InsufficientSamples = 5,
    /// The estimate exceeds the physically plausible ceiling, which indicates
    /// burst arrival rather than decode.
    ImplausibleRate = 6,
    /// `TCP_INFO` is unavailable (non-Linux, or the trace is L0).
    TcpInfoUnavailable = 7,
    /// The trace has no dispatch origin, so nothing is measurable against it.
    NoOrigin = 8,
}

impl Reason {
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// One short line for a UI to render beside a dash.
    pub const fn label(self) -> &'static str {
        match self {
            Self::PhaseAbsent => "not recorded",
            Self::ConnectionReused => "connection reused",
            Self::TransportBatched => "transport batched",
            Self::ResponseNotValidated => "not validated",
            Self::FewerThanTwoOutputEvents => "fewer than two output events",
            Self::InsufficientSamples => "insufficient samples",
            Self::ImplausibleRate => "implausible rate",
            Self::TcpInfoUnavailable => "TCP_INFO unavailable",
            Self::NoOrigin => "no origin",
        }
    }
}

/// The verdict attached to every derived quantity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validity {
    /// The quantity was measured and is defensible.
    Measured,
    /// The quantity does not apply to this attempt (e.g. DNS on a reused
    /// connection). Absence is a fact, not a gap.
    NotApplicable(Reason),
    /// The quantity applies but the transport hid it (batching, missing
    /// telemetry). Absence is a limitation.
    NotEstimable(Reason),
    /// The quantity applies and is observable, but there is not enough data.
    InsufficientSamples,
}

impl Validity {
    /// Whether a number may be rendered at all.
    pub const fn is_measured(self) -> bool {
        matches!(self, Self::Measured)
    }

    /// The reason, when there is one.
    pub const fn reason(self) -> Option<Reason> {
        match self {
            Self::Measured => None,
            Self::NotApplicable(reason) | Self::NotEstimable(reason) => Some(reason),
            Self::InsufficientSamples => Some(Reason::InsufficientSamples),
        }
    }

    /// One short line for a UI, `None` when the value is present.
    pub const fn label(self) -> Option<&'static str> {
        match self.reason() {
            Some(reason) => Some(reason.label()),
            None => None,
        }
    }
}

/// A value that carries its own verdict.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Reading<T> {
    value: Option<T>,
    validity: Validity,
}

impl<T: Copy> Reading<T> {
    /// A measured value.
    pub const fn measured(value: T) -> Self {
        Self {
            value: Some(value),
            validity: Validity::Measured,
        }
    }

    /// A quantity that does not apply to this attempt.
    pub const fn not_applicable(reason: Reason) -> Self {
        Self {
            value: None,
            validity: Validity::NotApplicable(reason),
        }
    }

    /// A quantity the transport made unobservable.
    pub const fn not_estimable(reason: Reason) -> Self {
        Self {
            value: None,
            validity: Validity::NotEstimable(reason),
        }
    }

    /// A quantity with too little data behind it.
    pub const fn insufficient() -> Self {
        Self {
            value: None,
            validity: Validity::InsufficientSamples,
        }
    }

    /// A reading that carries a verdict but no value.
    ///
    /// `Measured` is not a legal verdict without a value, so it is coerced to
    /// [`Validity::InsufficientSamples`]: the type cannot represent "measured,
    /// but nothing to show".
    pub const fn absent(validity: Validity) -> Self {
        let validity = match validity {
            Validity::Measured => Validity::InsufficientSamples,
            other => other,
        };
        Self {
            value: None,
            validity,
        }
    }

    /// The number, only when it is measured. This is the sole accessor: a
    /// surface that ignores the verdict cannot obtain a value.
    pub const fn value(&self) -> Option<T> {
        match self.validity {
            Validity::Measured => self.value,
            _ => None,
        }
    }

    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// Whether a number may be rendered.
    pub const fn is_measured(&self) -> bool {
        self.validity.is_measured()
    }

    /// Map the value while preserving the verdict. The mapping is applied only
    /// when the reading is measured, so a transformation cannot invent a value.
    pub fn map<U: Copy>(self, f: impl FnOnce(T) -> U) -> Reading<U> {
        match self.value() {
            Some(value) => Reading::measured(f(value)),
            None => Reading {
                value: None,
                validity: self.validity,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_is_only_reachable_when_measured() {
        let measured: Reading<u64> = Reading::measured(120);
        assert_eq!(measured.value(), Some(120));
        assert!(measured.is_measured());

        let absent: Reading<u64> = Reading::not_applicable(Reason::ConnectionReused);
        assert_eq!(absent.value(), None);
        assert_eq!(
            absent.validity(),
            Validity::NotApplicable(Reason::ConnectionReused)
        );
        assert_eq!(absent.validity().label(), Some("connection reused"));

        let hidden: Reading<u64> = Reading::not_estimable(Reason::TransportBatched);
        assert_eq!(hidden.value(), None);
        assert!(!hidden.is_measured());

        let thin: Reading<u64> = Reading::insufficient();
        assert_eq!(thin.value(), None);
        assert_eq!(thin.validity().reason(), Some(Reason::InsufficientSamples));
    }

    #[test]
    fn map_preserves_the_verdict_and_never_invents_a_value() {
        let measured: Reading<u64> = Reading::measured(1_000);
        assert_eq!(measured.map(|ns| ns / 1_000).value(), Some(1));
        let absent: Reading<u64> = Reading::not_estimable(Reason::ImplausibleRate);
        assert_eq!(absent.map(|ns| ns / 1_000).value(), None);
        assert_eq!(
            absent.map(|ns| ns / 1_000).validity(),
            Validity::NotEstimable(Reason::ImplausibleRate)
        );
    }

    #[test]
    fn reason_labels_are_stable_and_non_empty() {
        for reason in [
            Reason::PhaseAbsent,
            Reason::ConnectionReused,
            Reason::TransportBatched,
            Reason::ResponseNotValidated,
            Reason::FewerThanTwoOutputEvents,
            Reason::InsufficientSamples,
            Reason::ImplausibleRate,
            Reason::TcpInfoUnavailable,
            Reason::NoOrigin,
        ] {
            assert!(!reason.label().is_empty());
        }
    }

    #[test]
    fn readings_round_trip_through_serde() {
        let measured: Reading<u64> = Reading::measured(42);
        let json = serde_json::to_string(&measured).expect("serialize");
        let back: Reading<u64> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, measured);

        let absent: Reading<u64> = Reading::not_estimable(Reason::TransportBatched);
        let json = serde_json::to_string(&absent).expect("serialize");
        let back: Reading<u64> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, absent);
    }
}
