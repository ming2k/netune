// SPDX-License-Identifier: MIT

//! QUIC transport parameters (RFC 9000 Section 18, RFC 9221 for DATAGRAM).

use bytes::{BufMut, BytesMut};

use super::error::WireError;
use super::varint;

pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
pub const STATELESS_RESET_TOKEN: u64 = 0x02;
pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
pub const INITIAL_MAX_DATA: u64 = 0x04;
pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
pub const MAX_ACK_DELAY: u64 = 0x0b;
pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
pub const PREFERRED_ADDRESS: u64 = 0x0d;
pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;
pub const RESET_STREAM_AT: u64 = 0x1d;

/// The preferred-address transport parameter payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferredAddress {
    pub ipv4: [u8; 4],
    pub ipv4_port: u16,
    pub ipv6: [u8; 16],
    pub ipv6_port: u16,
    pub connection_id: Vec<u8>,
    pub stateless_reset_token: [u8; 16],
}

/// A decoded set of QUIC transport parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransportParameters {
    pub original_destination_connection_id: Option<Vec<u8>>,
    pub max_idle_timeout: Option<u64>,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: Option<u64>,
    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
    pub ack_delay_exponent: Option<u64>,
    pub max_ack_delay: Option<u64>,
    pub disable_active_migration: bool,
    pub preferred_address: Option<PreferredAddress>,
    pub active_connection_id_limit: Option<u64>,
    pub initial_source_connection_id: Option<Vec<u8>>,
    pub retry_source_connection_id: Option<Vec<u8>>,
    pub max_datagram_frame_size: Option<u64>,
    pub reset_stream_at: bool,
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl TransportParameters {
    pub fn max_udp_payload_size_or_default(&self) -> u64 {
        self.max_udp_payload_size.unwrap_or(65_527)
    }

    pub fn ack_delay_exponent_or_default(&self) -> u64 {
        self.ack_delay_exponent.unwrap_or(3)
    }

    pub fn max_ack_delay_or_default(&self) -> u64 {
        self.max_ack_delay.unwrap_or(25)
    }

    pub fn active_connection_id_limit_or_default(&self) -> u64 {
        self.active_connection_id_limit.unwrap_or(2)
    }

    /// Encode the parameters in wire order.
    pub fn encode(&self) -> Result<BytesMut, WireError> {
        let mut out = BytesMut::new();
        if let Some(cid) = &self.original_destination_connection_id {
            put_bytes(&mut out, ORIGINAL_DESTINATION_CONNECTION_ID, cid)?;
        }
        put_optional_varint(&mut out, MAX_IDLE_TIMEOUT, self.max_idle_timeout)?;
        if let Some(token) = &self.stateless_reset_token {
            put_bytes(&mut out, STATELESS_RESET_TOKEN, token)?;
        }
        put_optional_varint(&mut out, MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size)?;
        put_optional_varint(&mut out, INITIAL_MAX_DATA, self.initial_max_data)?;
        put_optional_varint(
            &mut out,
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        )?;
        put_optional_varint(
            &mut out,
            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        )?;
        put_optional_varint(
            &mut out,
            INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        )?;
        put_optional_varint(
            &mut out,
            INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
        )?;
        put_optional_varint(
            &mut out,
            INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
        )?;
        put_optional_varint(&mut out, ACK_DELAY_EXPONENT, self.ack_delay_exponent)?;
        put_optional_varint(&mut out, MAX_ACK_DELAY, self.max_ack_delay)?;
        if self.disable_active_migration {
            varint::encode(&mut out, DISABLE_ACTIVE_MIGRATION)?;
            varint::encode(&mut out, 0)?;
        }
        if let Some(preferred) = &self.preferred_address {
            let mut payload = BytesMut::new();
            payload.put_slice(&preferred.ipv4);
            payload.put_u16(preferred.ipv4_port);
            payload.put_slice(&preferred.ipv6);
            payload.put_u16(preferred.ipv6_port);
            varint::encode(&mut payload, preferred.connection_id.len() as u64)?;
            payload.put_slice(&preferred.connection_id);
            payload.put_slice(&preferred.stateless_reset_token);
            put_bytes(&mut out, PREFERRED_ADDRESS, &payload)?;
        }
        put_optional_varint(
            &mut out,
            ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
        )?;
        if let Some(cid) = &self.initial_source_connection_id {
            put_bytes(&mut out, INITIAL_SOURCE_CONNECTION_ID, cid)?;
        }
        if let Some(cid) = &self.retry_source_connection_id {
            put_bytes(&mut out, RETRY_SOURCE_CONNECTION_ID, cid)?;
        }
        put_optional_varint(
            &mut out,
            MAX_DATAGRAM_FRAME_SIZE,
            self.max_datagram_frame_size,
        )?;
        if self.reset_stream_at {
            varint::encode(&mut out, RESET_STREAM_AT)?;
            varint::encode(&mut out, 0)?;
        }
        for (id, value) in &self.unknown {
            put_bytes(&mut out, *id, value)?;
        }
        Ok(out)
    }

    /// Decode a transport-parameters payload.
    pub fn decode(mut payload: &[u8]) -> Result<Self, WireError> {
        let mut parameters = Self::default();
        let mut seen = Vec::new();
        while !payload.is_empty() {
            let id = varint::decode(&mut payload)?;
            if seen.contains(&id) {
                return Err(WireError::DuplicateTransportParameter(id));
            }
            seen.push(id);
            let len = usize::try_from(varint::decode(&mut payload)?)
                .map_err(|_| WireError::IntegerOverflow)?;
            if payload.len() < len {
                return Err(WireError::UnexpectedEnd);
            }
            let (value, rest) = payload.split_at(len);
            payload = rest;
            match id {
                ORIGINAL_DESTINATION_CONNECTION_ID => {
                    parameters.original_destination_connection_id = Some(read_cid(id, value)?);
                }
                MAX_IDLE_TIMEOUT => parameters.max_idle_timeout = Some(read_varint(id, value)?),
                STATELESS_RESET_TOKEN => {
                    if value.len() != 16 {
                        return Err(invalid(id, "stateless reset token must be 16 bytes"));
                    }
                    let mut token = [0u8; 16];
                    token.copy_from_slice(value);
                    parameters.stateless_reset_token = Some(token);
                }
                MAX_UDP_PAYLOAD_SIZE => {
                    let size = read_varint(id, value)?;
                    if size < 1200 {
                        return Err(invalid(id, "maximum UDP payload is below 1200"));
                    }
                    parameters.max_udp_payload_size = Some(size);
                }
                INITIAL_MAX_DATA => parameters.initial_max_data = Some(read_varint(id, value)?),
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    parameters.initial_max_stream_data_bidi_local = Some(read_varint(id, value)?);
                }
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    parameters.initial_max_stream_data_bidi_remote = Some(read_varint(id, value)?);
                }
                INITIAL_MAX_STREAM_DATA_UNI => {
                    parameters.initial_max_stream_data_uni = Some(read_varint(id, value)?);
                }
                INITIAL_MAX_STREAMS_BIDI => {
                    let maximum = read_varint(id, value)?;
                    if maximum > (1 << 60) {
                        return Err(invalid(id, "stream count exceeds 2^60"));
                    }
                    parameters.initial_max_streams_bidi = Some(maximum);
                }
                INITIAL_MAX_STREAMS_UNI => {
                    let maximum = read_varint(id, value)?;
                    if maximum > (1 << 60) {
                        return Err(invalid(id, "stream count exceeds 2^60"));
                    }
                    parameters.initial_max_streams_uni = Some(maximum);
                }
                ACK_DELAY_EXPONENT => {
                    let exponent = read_varint(id, value)?;
                    if exponent > 20 {
                        return Err(invalid(id, "ack delay exponent exceeds 20"));
                    }
                    parameters.ack_delay_exponent = Some(exponent);
                }
                MAX_ACK_DELAY => {
                    let delay = read_varint(id, value)?;
                    if delay >= (1 << 14) {
                        return Err(invalid(id, "max ack delay is not below 2^14"));
                    }
                    parameters.max_ack_delay = Some(delay);
                }
                DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return Err(invalid(id, "disable active migration must be empty"));
                    }
                    parameters.disable_active_migration = true;
                }
                PREFERRED_ADDRESS => {
                    parameters.preferred_address = Some(decode_preferred(value)?);
                }
                ACTIVE_CONNECTION_ID_LIMIT => {
                    let limit = read_varint(id, value)?;
                    if limit < 2 {
                        return Err(invalid(id, "active connection ID limit is below 2"));
                    }
                    parameters.active_connection_id_limit = Some(limit);
                }
                INITIAL_SOURCE_CONNECTION_ID => {
                    parameters.initial_source_connection_id = Some(read_cid(id, value)?);
                }
                RETRY_SOURCE_CONNECTION_ID => {
                    parameters.retry_source_connection_id = Some(read_cid(id, value)?);
                }
                MAX_DATAGRAM_FRAME_SIZE => {
                    parameters.max_datagram_frame_size = Some(read_varint(id, value)?);
                }
                RESET_STREAM_AT => {
                    if !value.is_empty() {
                        return Err(invalid(id, "reset_stream_at must be empty"));
                    }
                    parameters.reset_stream_at = true;
                }
                _ => {
                    if value.len() > 1 << 20 {
                        return Err(invalid(id, "unknown parameter exceeds 1 MiB"));
                    }
                    parameters.unknown.push((id, value.to_vec()));
                }
            }
        }
        Ok(parameters)
    }
}

fn put_optional_varint(out: &mut BytesMut, id: u64, value: Option<u64>) -> Result<(), WireError> {
    if let Some(value) = value {
        let mut encoded = BytesMut::new();
        varint::encode(&mut encoded, value)?;
        put_bytes(out, id, &encoded)?;
    }
    Ok(())
}

fn put_bytes(out: &mut BytesMut, id: u64, value: &[u8]) -> Result<(), WireError> {
    varint::encode(out, id)?;
    varint::encode(out, value.len() as u64)?;
    out.put_slice(value);
    Ok(())
}

fn read_varint(id: u64, value: &[u8]) -> Result<u64, WireError> {
    let mut cursor = value;
    let number = varint::decode(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(invalid(id, "parameter value has trailing bytes"));
    }
    Ok(number)
}

fn read_cid(id: u64, value: &[u8]) -> Result<Vec<u8>, WireError> {
    if value.len() > 20 {
        return Err(invalid(id, "connection ID length must be at most 20"));
    }
    Ok(value.to_vec())
}

fn decode_preferred(value: &[u8]) -> Result<PreferredAddress, WireError> {
    let mut cursor = value;
    if cursor.len() < 4 + 2 + 16 + 2 + 1 + 16 {
        return Err(invalid(PREFERRED_ADDRESS, "preferred address is truncated"));
    }
    let mut ipv4 = [0u8; 4];
    ipv4.copy_from_slice(&cursor[..4]);
    cursor = &cursor[4..];
    let ipv4_port = u16::from_be_bytes([cursor[0], cursor[1]]);
    cursor = &cursor[2..];
    let mut ipv6 = [0u8; 16];
    ipv6.copy_from_slice(&cursor[..16]);
    cursor = &cursor[16..];
    let ipv6_port = u16::from_be_bytes([cursor[0], cursor[1]]);
    cursor = &cursor[2..];
    let cid_len =
        usize::try_from(varint::decode(&mut cursor)?).map_err(|_| WireError::IntegerOverflow)?;
    if cid_len > 20 || cursor.len() < cid_len + 16 {
        return Err(invalid(PREFERRED_ADDRESS, "invalid preferred address CID"));
    }
    let connection_id = cursor[..cid_len].to_vec();
    cursor = &cursor[cid_len..];
    let mut stateless_reset_token = [0u8; 16];
    stateless_reset_token.copy_from_slice(&cursor[..16]);
    if cursor.len() != 16 {
        return Err(invalid(
            PREFERRED_ADDRESS,
            "preferred address has trailing bytes",
        ));
    }
    Ok(PreferredAddress {
        ipv4,
        ipv4_port,
        ipv6,
        ipv6_port,
        connection_id,
        stateless_reset_token,
    })
}

fn invalid(id: u64, reason: &str) -> WireError {
    WireError::InvalidTransportParameter(id, reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> TransportParameters {
        TransportParameters {
            original_destination_connection_id: Some(vec![1, 2, 3, 4]),
            max_idle_timeout: Some(30_000),
            stateless_reset_token: Some([7; 16]),
            max_udp_payload_size: Some(1472),
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 18),
            initial_max_stream_data_bidi_remote: Some(1 << 18),
            initial_max_stream_data_uni: Some(1 << 18),
            initial_max_streams_bidi: Some(100),
            initial_max_streams_uni: Some(100),
            ack_delay_exponent: Some(3),
            max_ack_delay: Some(25),
            disable_active_migration: true,
            preferred_address: Some(PreferredAddress {
                ipv4: [127, 0, 0, 1],
                ipv4_port: 4433,
                ipv6: [0; 16],
                ipv6_port: 4433,
                connection_id: vec![9, 9, 9],
                stateless_reset_token: [8; 16],
            }),
            active_connection_id_limit: Some(4),
            initial_source_connection_id: Some(vec![5, 6, 7]),
            retry_source_connection_id: Some(vec![8, 9]),
            max_datagram_frame_size: Some(1200),
            reset_stream_at: true,
            unknown: vec![(0x1f * 2 + 0x21, vec![1, 2, 3])],
        }
    }

    #[test]
    fn transport_parameters_round_trip() {
        let parameters = full();
        let wire = parameters.encode().expect("encode");
        assert_eq!(
            TransportParameters::decode(&wire).expect("decode"),
            parameters
        );
    }

    #[test]
    fn defaults_are_explicit() {
        let parameters = TransportParameters::default();
        assert_eq!(parameters.max_udp_payload_size_or_default(), 65_527);
        assert_eq!(parameters.ack_delay_exponent_or_default(), 3);
        assert_eq!(parameters.max_ack_delay_or_default(), 25);
        assert_eq!(parameters.active_connection_id_limit_or_default(), 2);
    }

    #[test]
    fn duplicate_and_invalid_parameters_are_rejected() {
        let mut payload = BytesMut::new();
        put_bytes(&mut payload, MAX_IDLE_TIMEOUT, &[0]).expect("first");
        put_bytes(&mut payload, MAX_IDLE_TIMEOUT, &[0]).expect("second");
        assert!(matches!(
            TransportParameters::decode(&payload),
            Err(WireError::DuplicateTransportParameter(MAX_IDLE_TIMEOUT))
        ));

        let mut payload = BytesMut::new();
        put_bytes(&mut payload, MAX_UDP_PAYLOAD_SIZE, &[0]).expect("value");
        assert!(matches!(
            TransportParameters::decode(&payload),
            Err(WireError::InvalidTransportParameter(
                MAX_UDP_PAYLOAD_SIZE,
                _
            ))
        ));
    }
}
