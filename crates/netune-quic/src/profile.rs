// SPDX-License-Identifier: MIT

//! QUIC handshake and transport profile shaping (RFC 9000).
//!
//! Mirrors `TlsProfile` for QUIC: ensures the client's wire identity,
//! transport parameters, and initial flight behaviors are explicit data
//! rather than hard-coded library defaults.

use std::collections::HashMap;
use std::time::Duration;

use crate::error::QuicError;

/// Congestion-control algorithm carried by a QUIC profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionAlgorithm {
    #[default]
    NewReno,
    Cubic,
    Bbr,
}

/// Transport parameters governing flow control, concurrency, and idle bounds (RFC 9000 §18.2).
#[derive(Debug, Clone)]
pub struct QuicTransportParameters {
    /// Maximum connection-level receive window (initial_max_data).
    pub initial_max_data: u64,
    /// Maximum stream-level receive window for locally-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// Maximum stream-level receive window for remotely-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Maximum stream-level receive window for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// Maximum concurrent bidirectional streams allowed to peer.
    pub initial_max_streams_bidi: u64,
    /// Maximum concurrent unidirectional streams allowed to peer.
    pub initial_max_streams_uni: u64,
    /// Maximum idle timeout before connection is dropped.
    pub max_idle_timeout: Option<Duration>,
    /// Maximum incoming UDP payload size advertised to peer.
    pub max_udp_payload_size: Option<u16>,
    /// Number of active connection IDs supported.
    pub active_connection_id_limit: u64,
    /// Whether RFC 9221 unreliable datagram support is enabled.
    pub enable_datagrams: bool,
}

impl Default for QuicTransportParameters {
    fn default() -> Self {
        Self {
            initial_max_data: 10_000_000,                   // 10 MB
            initial_max_stream_data_bidi_local: 5_000_000,  // 5 MB
            initial_max_stream_data_bidi_remote: 5_000_000, // 5 MB
            initial_max_stream_data_uni: 1_000_000,         // 1 MB
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_idle_timeout: Some(Duration::from_secs(30)),
            max_udp_payload_size: Some(1472),
            active_connection_id_limit: 4,
            enable_datagrams: true,
        }
    }
}

/// Named QUIC profiles. Built-ins and caller-supplied profiles share one
/// resolution path; an unknown name is a hard error, never a silent default.
#[derive(Debug, Clone)]
pub struct QuicProfileRegistry {
    profiles: HashMap<String, QuicProfile>,
}

impl Default for QuicProfileRegistry {
    fn default() -> Self {
        let mut profiles = HashMap::new();
        for profile in [
            QuicProfile::default_profile(),
            QuicProfile::chrome_quic(),
            QuicProfile::cloud_optimized(),
        ] {
            profiles.insert(profile.name.to_string(), profile);
        }
        Self { profiles }
    }
}

impl QuicProfileRegistry {
    pub fn with_profile(mut self, profile: QuicProfile) -> Self {
        self.profiles.insert(profile.name.to_string(), profile);
        self
    }

    pub fn resolve(&self, name: &str) -> Result<&QuicProfile, QuicError> {
        self.profiles.get(name).ok_or_else(|| {
            QuicError::Config(format!(
                "unknown QUIC profile {name:?}; registered: {}",
                self.names().join(", ")
            ))
        })
    }

    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
}

/// Explicit wire identity and transport profile for QUIC.
#[derive(Debug, Clone)]
pub struct QuicProfile {
    /// Human-readable identifier for the profile.
    pub name: &'static str,
    /// Transport parameters applied to the QUIC state machine.
    pub transport_parameters: QuicTransportParameters,
    /// Congestion-control algorithm applied to recovery.
    pub congestion: CongestionAlgorithm,
    /// Whether a resumed session may use 0-RTT early data.
    pub enable_0rtt: bool,
    /// ALPN strings in wire preference order.
    pub alpn: Vec<Vec<u8>>,
}

impl Default for QuicProfile {
    fn default() -> Self {
        Self::default_profile()
    }
}

impl QuicProfile {
    /// Standard balanced QUIC profile.
    pub fn default_profile() -> Self {
        Self {
            name: "quic-default",
            transport_parameters: QuicTransportParameters::default(),
            congestion: CongestionAlgorithm::NewReno,
            enable_0rtt: false,
            alpn: vec![b"h3".to_vec()],
        }
    }

    /// Profile aligned with stable Google Chrome QUIC transport parameters.
    pub fn chrome_quic() -> Self {
        Self {
            name: "chrome-quic",
            transport_parameters: QuicTransportParameters {
                initial_max_data: 15_728_640,
                initial_max_stream_data_bidi_local: 6_291_456,
                initial_max_stream_data_bidi_remote: 6_291_456,
                initial_max_stream_data_uni: 6_291_456,
                initial_max_streams_bidi: 100,
                initial_max_streams_uni: 100,
                max_idle_timeout: Some(Duration::from_secs(30)),
                max_udp_payload_size: Some(1472),
                active_connection_id_limit: 4,
                enable_datagrams: true,
            },
            congestion: CongestionAlgorithm::Bbr,
            enable_0rtt: true,
            alpn: vec![b"h3".to_vec()],
        }
    }

    /// High-throughput profile with aggressive initial windows for tunneling.
    pub fn cloud_optimized() -> Self {
        Self {
            name: "cloud-optimized",
            transport_parameters: QuicTransportParameters {
                initial_max_data: 32_000_000,
                initial_max_stream_data_bidi_local: 16_000_000,
                initial_max_stream_data_bidi_remote: 16_000_000,
                initial_max_stream_data_uni: 8_000_000,
                initial_max_streams_bidi: 1024,
                initial_max_streams_uni: 1024,
                max_idle_timeout: Some(Duration::from_secs(60)),
                max_udp_payload_size: Some(1472),
                active_connection_id_limit: 8,
                enable_datagrams: true,
            },
            congestion: CongestionAlgorithm::Bbr,
            enable_0rtt: true,
            alpn: vec![b"h3".to_vec()],
        }
    }

    /// Resolves a named profile preset through the default registry.
    pub fn by_name(name: &str) -> Option<Self> {
        QuicProfileRegistry::default().resolve(name).ok().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_profiles_resolve_through_one_registry() {
        let registry = QuicProfileRegistry::default();
        assert_eq!(
            registry.resolve("chrome-quic").expect("built-in").name,
            "chrome-quic"
        );
        assert_eq!(
            registry.resolve("quic-default").expect("built-in").name,
            "quic-default"
        );

        let custom = QuicProfile {
            name: "my-quic",
            ..QuicProfile::default_profile()
        };
        let registry = registry.with_profile(custom);
        assert_eq!(registry.resolve("my-quic").expect("custom").name, "my-quic");
    }

    #[test]
    fn an_unknown_quic_profile_is_a_loud_error() {
        let registry = QuicProfileRegistry::default();
        let error = registry.resolve("does-not-exist").expect_err("must fail");
        assert!(error.to_string().contains("unknown QUIC profile"));
    }
}
