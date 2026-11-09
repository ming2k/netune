// SPDX-License-Identifier: MIT

//! HTTP/3 SETTINGS frame payload (RFC 9114 Section 7.2.4).

use bytes::{BufMut, BytesMut};

use super::code::{frame_type, setting_id};
use super::varint::{self, VarIntError};

/// A decoded peer SETTINGS payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    pub qpack_max_table_capacity: u64,
    pub max_field_section_size: Option<u64>,
    pub qpack_blocked_streams: u64,
    pub enable_connect_protocol: bool,
    pub h3_datagram: bool,
    /// Reserved identifiers are ignored after validation.
    pub grease: Vec<(u64, u64)>,
}

/// A malformed SETTINGS frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    #[error("truncated SETTINGS payload")]
    Truncated,
    #[error("duplicate SETTINGS identifier 0x{0:x}")]
    Duplicate(u64),
    #[error("invalid value {1} for SETTINGS identifier 0x{0:x}")]
    InvalidValue(u64, u64),
    #[error("QPACK capacity {0} exceeds 2^30-1")]
    CapacityTooLarge(u64),
    #[error("QPACK blocked streams {0} exceeds 2^16-1")]
    TooManyBlockedStreams(u64),
}

impl Settings {
    /// Encode the SETTINGS frame, including its type and length.
    pub fn encode(&self, out: &mut BytesMut) {
        let mut payload = BytesMut::new();
        for (id, value) in self.entries() {
            let _ = varint::encode(&mut payload, id);
            let _ = varint::encode(&mut payload, value);
        }
        let _ = varint::encode(out, frame_type::SETTINGS);
        let _ = varint::encode(out, payload.len() as u64);
        out.put_slice(&payload);
    }

    /// Decode a SETTINGS frame payload (without the frame type and length).
    pub fn decode(mut payload: &[u8]) -> Result<Self, SettingsError> {
        let mut settings = Self::default();
        let mut seen = Vec::new();
        while !payload.is_empty() {
            let id = varint::decode(&mut payload).map_err(|_| SettingsError::Truncated)?;
            let value = varint::decode(&mut payload).map_err(|_| SettingsError::Truncated)?;
            if seen.contains(&id) {
                return Err(SettingsError::Duplicate(id));
            }
            seen.push(id);
            match id {
                setting_id::QPACK_MAX_TABLE_CAPACITY => {
                    if value > 1_073_741_823 {
                        return Err(SettingsError::CapacityTooLarge(value));
                    }
                    settings.qpack_max_table_capacity = value;
                }
                setting_id::MAX_FIELD_SECTION_SIZE => {
                    settings.max_field_section_size = Some(value);
                }
                setting_id::QPACK_BLOCKED_STREAMS => {
                    if value > 65_535 {
                        return Err(SettingsError::TooManyBlockedStreams(value));
                    }
                    settings.qpack_blocked_streams = value;
                }
                setting_id::ENABLE_CONNECT_PROTOCOL => {
                    settings.enable_connect_protocol = boolean(id, value)?
                }
                setting_id::H3_DATAGRAM => settings.h3_datagram = boolean(id, value)?,
                _ => settings.grease.push((id, value)),
            }
        }
        Ok(settings)
    }

    fn entries(&self) -> Vec<(u64, u64)> {
        let mut entries = vec![
            (
                setting_id::QPACK_MAX_TABLE_CAPACITY,
                self.qpack_max_table_capacity,
            ),
            (
                setting_id::QPACK_BLOCKED_STREAMS,
                self.qpack_blocked_streams,
            ),
        ];
        if let Some(size) = self.max_field_section_size {
            entries.push((setting_id::MAX_FIELD_SECTION_SIZE, size));
        }
        if self.enable_connect_protocol {
            entries.push((setting_id::ENABLE_CONNECT_PROTOCOL, 1));
        }
        if self.h3_datagram {
            entries.push((setting_id::H3_DATAGRAM, 1));
        }
        entries.extend(self.grease.iter().copied());
        entries
    }
}

fn boolean(id: u64, value: u64) -> Result<bool, SettingsError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SettingsError::InvalidValue(id, value)),
    }
}

impl From<VarIntError> for SettingsError {
    fn from(_: VarIntError) -> Self {
        Self::Truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip() {
        let settings = Settings {
            qpack_max_table_capacity: 4096,
            max_field_section_size: Some(1 << 20),
            qpack_blocked_streams: 16,
            enable_connect_protocol: true,
            h3_datagram: true,
            grease: vec![(0x21, 0)],
        };
        let mut wire = BytesMut::new();
        settings.encode(&mut wire);
        // Strip the frame type and length before decoding the payload.
        let mut payload = &wire[..];
        assert_eq!(
            varint::decode(&mut payload).expect("type"),
            frame_type::SETTINGS
        );
        let length = varint::decode(&mut payload).expect("length") as usize;
        assert_eq!(payload.len(), length);
        assert_eq!(Settings::decode(payload).expect("decode"), settings);
    }

    #[test]
    fn duplicate_settings_are_rejected() {
        let mut payload = BytesMut::new();
        varint::encode(&mut payload, setting_id::QPACK_MAX_TABLE_CAPACITY).expect("id");
        varint::encode(&mut payload, 0).expect("value");
        varint::encode(&mut payload, setting_id::QPACK_MAX_TABLE_CAPACITY).expect("id");
        varint::encode(&mut payload, 0).expect("value");
        assert!(matches!(
            Settings::decode(&payload),
            Err(SettingsError::Duplicate(_))
        ));
    }

    #[test]
    fn boolean_settings_are_strict() {
        let mut payload = BytesMut::new();
        varint::encode(&mut payload, setting_id::ENABLE_CONNECT_PROTOCOL).expect("id");
        varint::encode(&mut payload, 2).expect("value");
        assert!(matches!(
            Settings::decode(&payload),
            Err(SettingsError::InvalidValue(..))
        ));
    }

    #[test]
    fn capacities_are_bounded() {
        let mut payload = BytesMut::new();
        varint::encode(&mut payload, setting_id::QPACK_MAX_TABLE_CAPACITY).expect("id");
        varint::encode(&mut payload, 1_073_741_824).expect("value");
        assert!(matches!(
            Settings::decode(&payload),
            Err(SettingsError::CapacityTooLarge(_))
        ));
    }
}
