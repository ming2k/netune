// SPDX-License-Identifier: MIT

//! H3 connection SETTINGS and request-header profiles.
//!
//! HTTP/3 header *order* is a request-level wire decision. The resolved QUIC
//! profile remains the connection identity; [`H3RequestProfile`] names the
//! order applied to a request's QPACK header block.
//!
//! SETTINGS are different: they are sent once, before any request, and a peer
//! can key behaviour on them. [`H3SettingsProfile`] is therefore a
//! connection-level identity and is recorded as
//! `ConnectionIdentity.h3_settings_profile` when a session is opened.

use std::collections::HashMap;

use crate::error::H3Error;
use crate::proto::headers::RequestHeaderOrder;
use crate::proto::settings::Settings;

/// An enforceable HTTP/3 SETTINGS profile.
///
/// QPACK dynamic-table capacity is present because the owned decoder and
/// encoder enforce it. A profile that advertises a capacity the transport
/// cannot enforce is rejected; zero keeps the stateless path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3SettingsProfile {
    pub name: String,
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`, in bytes.
    pub max_field_section_size: u64,
    /// Whether reserved/grease SETTINGS identifiers are emitted.
    pub send_grease: bool,
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` we advertise for peer encoders.
    ///
    /// Non-zero requires the QPACK decoder path; this crate owns it and waits
    /// for missing insertions instead of failing closed.
    pub qpack_max_table_capacity: u64,
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` we advertise.
    pub qpack_blocked_streams: u64,
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220).
    pub enable_connect_protocol: bool,
    /// `SETTINGS_H3_DATAGRAM` (RFC 9297).
    pub h3_datagram: bool,
}

impl Default for H3SettingsProfile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            max_field_section_size: 16 * 1024 * 1024,
            send_grease: true,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            enable_connect_protocol: false,
            h3_datagram: false,
        }
    }
}

impl H3SettingsProfile {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// A minimal SETTINGS frame: no grease, no extensions.
    pub fn minimal() -> Self {
        Self {
            name: "minimal".to_string(),
            send_grease: false,
            ..Self::default()
        }
    }

    /// Dynamic QPACK enabled with a small, explicit table.
    pub fn dynamic() -> Self {
        Self {
            name: "dynamic".to_string(),
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 16,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_max_field_section_size(mut self, size: u64) -> Self {
        self.max_field_section_size = size;
        self
    }

    /// Enable RFC 9220 extended CONNECT.
    #[must_use]
    pub fn with_extended_connect(mut self) -> Self {
        self.enable_connect_protocol = true;
        self
    }

    /// Enable RFC 9297 HTTP/3 datagrams.
    #[must_use]
    pub fn with_datagrams(mut self) -> Self {
        self.h3_datagram = true;
        self
    }

    #[must_use]
    pub fn with_qpack(mut self, max_table_capacity: u64, blocked_streams: u64) -> Self {
        self.qpack_max_table_capacity = max_table_capacity;
        self.qpack_blocked_streams = blocked_streams;
        self
    }

    /// Reject capacities the QPACK state machine cannot represent.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_field_section_size == 0 {
            return Err("http3.max_field_section_size must be at least 1");
        }
        if self.max_field_section_size > (1u64 << 62) - 1 {
            return Err("http3.max_field_section_size exceeds VarInt range");
        }
        if self.qpack_max_table_capacity > 1_073_741_823 {
            return Err("http3.qpack_max_table_capacity exceeds 2^30-1");
        }
        if self.qpack_blocked_streams >= 65_535 {
            return Err("http3.qpack_blocked_streams must be below 65535");
        }
        if self.qpack_max_table_capacity == 0 && self.qpack_blocked_streams != 0 {
            return Err("http3.qpack_blocked_streams requires a non-zero table capacity");
        }
        Ok(())
    }

    /// Lower this profile into the SETTINGS frame payload.
    pub fn to_settings(&self) -> Settings {
        Settings {
            qpack_max_table_capacity: self.qpack_max_table_capacity,
            max_field_section_size: Some(self.max_field_section_size),
            qpack_blocked_streams: self.qpack_blocked_streams,
            enable_connect_protocol: self.enable_connect_protocol,
            h3_datagram: self.h3_datagram,
            grease: if self.send_grease {
                vec![(0x21, 0)]
            } else {
                Vec::new()
            },
        }
    }
}

/// Built-in and caller-supplied H3 SETTINGS profiles.
#[derive(Debug, Clone)]
pub struct H3SettingsRegistry {
    profiles: HashMap<String, H3SettingsProfile>,
}

impl Default for H3SettingsRegistry {
    fn default() -> Self {
        let mut registry = Self {
            profiles: HashMap::new(),
        };
        for profile in [
            H3SettingsProfile::default(),
            H3SettingsProfile::minimal(),
            H3SettingsProfile::dynamic(),
        ] {
            registry = registry.with_profile(profile);
        }
        registry
    }
}

impl H3SettingsRegistry {
    pub fn with_profile(mut self, profile: H3SettingsProfile) -> Self {
        self.profiles.insert(profile.name.clone(), profile);
        self
    }

    pub fn resolve(&self, name: &str) -> Result<&H3SettingsProfile, H3Error> {
        self.profiles.get(name).ok_or_else(|| {
            H3Error::Profile(format!(
                "unknown H3 SETTINGS profile {name:?}; registered: {}",
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

/// A named H3 request-header order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3RequestProfile {
    pub name: String,
    pub order: RequestHeaderOrder,
}

impl Default for H3RequestProfile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            order: RequestHeaderOrder::default(),
        }
    }
}

impl H3RequestProfile {
    pub fn new(name: impl Into<String>, order: RequestHeaderOrder) -> Self {
        Self {
            name: name.into(),
            order,
        }
    }

    /// Chromium-shaped pseudo-header order for the common H3 request path.
    pub fn chrome() -> Self {
        Self::new(
            "chrome",
            RequestHeaderOrder::new(
                [":method", ":authority", ":scheme", ":path"],
                [
                    "user-agent",
                    "accept",
                    "accept-language",
                    "accept-encoding",
                    "content-type",
                    "content-length",
                    "authorization",
                ],
            ),
        )
    }

    /// Firefox-shaped pseudo-header order.
    pub fn firefox() -> Self {
        Self::new(
            "firefox",
            RequestHeaderOrder::new(
                [":method", ":path", ":authority", ":scheme"],
                [
                    "user-agent",
                    "accept",
                    "accept-language",
                    "accept-encoding",
                    "content-type",
                    "content-length",
                    "authorization",
                ],
            ),
        )
    }

    /// Safari-shaped pseudo-header order.
    pub fn safari() -> Self {
        Self::new(
            "safari",
            RequestHeaderOrder::new(
                [":method", ":scheme", ":authority", ":path"],
                [
                    "user-agent",
                    "accept",
                    "accept-language",
                    "accept-encoding",
                    "content-type",
                    "content-length",
                    "authorization",
                ],
            ),
        )
    }
}

/// Built-in and caller-supplied H3 request profiles.
#[derive(Debug, Clone)]
pub struct H3RequestRegistry {
    profiles: HashMap<String, H3RequestProfile>,
}

impl Default for H3RequestRegistry {
    fn default() -> Self {
        let mut registry = Self {
            profiles: HashMap::new(),
        };
        for profile in [
            H3RequestProfile::default(),
            H3RequestProfile::chrome(),
            H3RequestProfile::firefox(),
            H3RequestProfile::safari(),
        ] {
            registry = registry.with_profile(profile);
        }
        registry
    }
}

impl H3RequestRegistry {
    pub fn with_profile(mut self, profile: H3RequestProfile) -> Self {
        self.profiles.insert(profile.name.clone(), profile);
        self
    }

    pub fn resolve(&self, name: &str) -> Result<&H3RequestProfile, H3Error> {
        self.profiles.get(name).ok_or_else(|| {
            H3Error::Profile(format!(
                "unknown H3 request profile {name:?}; registered: {}",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_profiles_resolve_and_custom_profiles_are_first_class() {
        let registry = H3RequestRegistry::default();
        assert_eq!(
            registry.resolve("chrome").expect("chrome").order.pseudo,
            vec![":method", ":authority", ":scheme", ":path"]
        );
        assert_eq!(
            registry.resolve("firefox").expect("firefox").order.pseudo,
            vec![":method", ":path", ":authority", ":scheme"]
        );

        let custom = H3RequestProfile::new(
            "custom",
            RequestHeaderOrder::new([":method", ":path"], ["x-test"]),
        );
        let registry = registry.with_profile(custom);
        assert_eq!(
            registry.resolve("custom").expect("custom").order.regular,
            vec!["x-test"]
        );
    }

    #[test]
    fn unknown_profiles_fail_loudly() {
        let registry = H3RequestRegistry::default();
        let error = registry.resolve("does-not-exist").expect_err("must fail");
        assert!(error.to_string().contains("unknown H3 request profile"));

        let settings = H3SettingsRegistry::default();
        let error = settings
            .resolve("does-not-exist")
            .expect_err("settings must fail");
        assert!(error.to_string().contains("unknown H3 SETTINGS profile"));
    }

    #[test]
    fn settings_profiles_are_enforceable_and_independent() {
        let registry = H3SettingsRegistry::default();
        assert!(!registry.resolve("minimal").expect("minimal").send_grease);
        assert_eq!(
            H3SettingsProfile::default().max_field_section_size,
            16 * 1024 * 1024
        );
        assert!(
            H3SettingsProfile::default()
                .with_qpack(1_073_741_824, 0)
                .validate()
                .is_err()
        );
        assert!(
            H3SettingsProfile::default()
                .with_qpack(0, 65_536)
                .validate()
                .is_err()
        );
        assert!(
            H3SettingsProfile::default()
                .with_qpack(0, 1)
                .validate()
                .is_err()
        );
        assert_eq!(
            H3SettingsProfile::dynamic()
                .to_settings()
                .qpack_max_table_capacity,
            4096
        );
    }
}
