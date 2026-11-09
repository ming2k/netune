// SPDX-License-Identifier: MIT

//! QUIC packet headers (RFC 9000 Section 17), without header protection.
//!
//! Header protection is applied after this codec by `crypto::packet`.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::error::WireError;
use super::varint;

/// QUIC version 1.
pub const VERSION_1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369).
pub const VERSION_2: u32 = 0x6b33_43cf;

/// A long-header packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongType {
    /// Long-header type bits for a QUIC version (RFC 9369 changes them in v2).
    pub fn bits_for(self, version: u32) -> u8 {
        if version == VERSION_2 {
            match self {
                Self::Retry => 0x00,
                Self::Initial => 0x10,
                Self::ZeroRtt => 0x20,
                Self::Handshake => 0x30,
            }
        } else {
            match self {
                Self::Initial => 0x00,
                Self::ZeroRtt => 0x10,
                Self::Handshake => 0x20,
                Self::Retry => 0x30,
            }
        }
    }

    pub fn from_bits_for(version: u32, bits: u8) -> Self {
        if version == VERSION_2 {
            match bits & 0x30 {
                0x00 => Self::Retry,
                0x10 => Self::Initial,
                0x20 => Self::ZeroRtt,
                _ => Self::Handshake,
            }
        } else {
            match bits & 0x30 {
                0x00 => Self::Initial,
                0x10 => Self::ZeroRtt,
                0x20 => Self::Handshake,
                _ => Self::Retry,
            }
        }
    }

    pub fn from_bits(bits: u8) -> Self {
        Self::from_bits_for(VERSION_1, bits)
    }
}

/// A decoded long-header packet (headers unprotected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongPacket {
    pub ty: LongType,
    pub version: u32,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
    pub token: Vec<u8>,
    pub packet_number: u64,
    pub packet_number_len: u8,
    pub payload: Bytes,
}

impl LongPacket {
    /// The offset of the packet-number field from the start of the packet.
    pub fn packet_number_offset(&self) -> usize {
        let mut offset = 1 + 4;
        offset += 1 + self.destination_connection_id.len();
        offset += 1 + self.source_connection_id.len();
        if self.ty == LongType::Initial {
            offset += varint::encoded_len(self.token.len() as u64) + self.token.len();
        }
        offset += varint::encoded_len(self.length_field());
        offset
    }

    /// The value that belongs in the Length field.
    pub fn length_field(&self) -> u64 {
        self.packet_number_len as u64 + self.payload.len() as u64
    }

    /// Encode the header and payload. The packet number must fit the declared
    /// length.
    pub fn encode(&self) -> Result<Bytes, WireError> {
        if self.ty == LongType::Retry {
            return Err(WireError::InvalidPacket(
                "Retry packets require an integrity tag and are not encoded here".to_string(),
            ));
        }
        validate_packet_number_len(self.packet_number_len)?;
        let mut out = BytesMut::new();
        let first = 0xc0 | self.ty.bits_for(self.version) | (self.packet_number_len - 1);
        out.put_u8(first);
        out.put_u32(self.version);
        put_cid(&mut out, &self.destination_connection_id)?;
        put_cid(&mut out, &self.source_connection_id)?;
        if self.ty == LongType::Initial {
            put_bytes(&mut out, &self.token)?;
        }
        varint::encode(&mut out, self.length_field())?;
        put_packet_number(&mut out, self.packet_number, self.packet_number_len);
        out.put_slice(&self.payload);
        Ok(out.freeze())
    }

    /// Decode a long-header packet. `max_payload` bounds the retained payload.
    pub fn decode(buf: &mut &[u8], max_payload: usize) -> Result<Self, WireError> {
        let first = buf.try_get_u8().map_err(|_| WireError::UnexpectedEnd)?;
        if first & 0x80 == 0 || first & 0x40 == 0 {
            return Err(WireError::InvalidPacket(
                "long header requires the fixed bit".to_string(),
            ));
        }
        if first & 0x0c != 0 {
            return Err(WireError::InvalidPacket(
                "reserved bits are not zero".to_string(),
            ));
        }
        let version = buf.try_get_u32().map_err(|_| WireError::UnexpectedEnd)?;
        if version == 0 {
            return Err(WireError::InvalidPacket(
                "version negotiation is not a data packet".to_string(),
            ));
        }
        let ty = LongType::from_bits_for(version, first);
        if ty == LongType::Retry {
            return Err(WireError::InvalidPacket(
                "Retry packets require an integrity tag and are not decoded here".to_string(),
            ));
        }
        let destination_connection_id = read_cid(buf)?;
        let source_connection_id = read_cid(buf)?;
        let token = if ty == LongType::Initial {
            read_bytes(buf)?
        } else {
            Vec::new()
        };
        let length =
            usize::try_from(varint::decode(buf)?).map_err(|_| WireError::IntegerOverflow)?;
        let packet_number_len = (first & 0x03) + 1;
        if length < packet_number_len as usize {
            return Err(WireError::InvalidPacket(
                "length is shorter than the packet number".to_string(),
            ));
        }
        let packet_number = read_packet_number(buf, packet_number_len)?;
        let payload_len = length - packet_number_len as usize;
        if payload_len > max_payload {
            return Err(WireError::FieldTooLarge("packet payload", max_payload));
        }
        if buf.len() < payload_len {
            return Err(WireError::UnexpectedEnd);
        }
        let payload = Bytes::copy_from_slice(&buf[..payload_len]);
        buf.advance(payload_len);
        Ok(Self {
            ty,
            version,
            destination_connection_id,
            source_connection_id,
            token,
            packet_number,
            packet_number_len,
            payload,
        })
    }
}

/// A decoded short-header packet (headers unprotected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortPacket {
    pub spin: bool,
    pub key_phase: bool,
    pub destination_connection_id: Vec<u8>,
    pub packet_number: u64,
    pub packet_number_len: u8,
    pub payload: Bytes,
}

impl ShortPacket {
    pub fn packet_number_offset(&self) -> usize {
        1 + self.destination_connection_id.len()
    }

    pub fn encode(&self) -> Result<Bytes, WireError> {
        validate_packet_number_len(self.packet_number_len)?;
        if self.destination_connection_id.len() > 20 {
            return Err(WireError::InvalidPacket(
                "destination connection ID is longer than 20 bytes".to_string(),
            ));
        }
        let mut out = BytesMut::new();
        let first = 0x40
            | (u8::from(self.spin) << 5)
            | (u8::from(self.key_phase) << 2)
            | (self.packet_number_len - 1);
        out.put_u8(first);
        out.put_slice(&self.destination_connection_id);
        put_packet_number(&mut out, self.packet_number, self.packet_number_len);
        out.put_slice(&self.payload);
        Ok(out.freeze())
    }

    /// Decode a short-header packet. The local connection ID length is known
    /// from connection state, not from the packet.
    pub fn decode(
        buf: &mut &[u8],
        destination_connection_id_len: usize,
        max_payload: usize,
    ) -> Result<Self, WireError> {
        let first = buf.try_get_u8().map_err(|_| WireError::UnexpectedEnd)?;
        if first & 0x80 != 0 || first & 0x40 == 0 {
            return Err(WireError::InvalidPacket(
                "short header requires the fixed bit and short form".to_string(),
            ));
        }
        if first & 0x18 != 0 {
            return Err(WireError::InvalidPacket(
                "reserved bits are not zero".to_string(),
            ));
        }
        if destination_connection_id_len > 20 {
            return Err(WireError::InvalidPacket(
                "destination connection ID is longer than 20 bytes".to_string(),
            ));
        }
        let destination_connection_id = read_exact(buf, destination_connection_id_len)?.to_vec();
        let packet_number_len = (first & 0x03) + 1;
        let packet_number = read_packet_number(buf, packet_number_len)?;
        if buf.len() > max_payload {
            return Err(WireError::FieldTooLarge("packet payload", max_payload));
        }
        let payload = Bytes::copy_from_slice(buf);
        *buf = &[];
        Ok(Self {
            spin: first & 0x20 != 0,
            key_phase: first & 0x04 != 0,
            destination_connection_id,
            packet_number,
            packet_number_len,
            payload,
        })
    }
}

/// A Retry packet, including its integrity tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPacket {
    pub version: u32,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
    pub token: Vec<u8>,
    pub integrity_tag: [u8; 16],
}

impl RetryPacket {
    pub fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let first = buf.try_get_u8().map_err(|_| WireError::UnexpectedEnd)?;
        if first & 0x80 == 0 {
            return Err(WireError::InvalidPacket(
                "Retry requires a long header".to_string(),
            ));
        }
        let version = buf.try_get_u32().map_err(|_| WireError::UnexpectedEnd)?;
        if version == 0 {
            return Err(WireError::InvalidPacket(
                "Retry requires a nonzero version".to_string(),
            ));
        }
        let destination_connection_id = read_cid(buf)?;
        let source_connection_id = read_cid(buf)?;
        if buf.len() < 16 {
            return Err(WireError::UnexpectedEnd);
        }
        let token_end = buf.len() - 16;
        let token = Bytes::copy_from_slice(&buf[..token_end]);
        let mut integrity_tag = [0u8; 16];
        integrity_tag.copy_from_slice(&buf[token_end..]);
        *buf = &[];
        Ok(Self {
            version,
            destination_connection_id,
            source_connection_id,
            token: token.to_vec(),
            integrity_tag,
        })
    }

    pub fn encode_without_tag(&self) -> Result<Bytes, WireError> {
        let mut out = BytesMut::new();
        out.put_u8(0xc0 | LongType::Retry.bits_for(self.version));
        out.put_u32(self.version);
        put_cid(&mut out, &self.destination_connection_id)?;
        put_cid(&mut out, &self.source_connection_id)?;
        out.put_slice(&self.token);
        Ok(out.freeze())
    }

    pub fn encode(&self) -> Result<Bytes, WireError> {
        let mut out = BytesMut::from(self.encode_without_tag()?.as_ref());
        out.put_slice(&self.integrity_tag);
        Ok(out.freeze())
    }
}

/// A parsed Version Negotiation packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNegotiation {
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
    pub versions: Vec<u32>,
}

impl VersionNegotiation {
    pub fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let first = buf.try_get_u8().map_err(|_| WireError::UnexpectedEnd)?;
        if first & 0x80 == 0 {
            return Err(WireError::InvalidPacket(
                "version negotiation requires the long form".to_string(),
            ));
        }
        let version = buf.try_get_u32().map_err(|_| WireError::UnexpectedEnd)?;
        if version != 0 {
            return Err(WireError::InvalidPacket(
                "not a version negotiation packet".to_string(),
            ));
        }
        let destination_connection_id = read_cid(buf)?;
        let source_connection_id = read_cid(buf)?;
        if !buf.len().is_multiple_of(4) {
            return Err(WireError::InvalidPacket(
                "version negotiation list is not a multiple of four".to_string(),
            ));
        }
        let mut versions = Vec::with_capacity(buf.len() / 4);
        while buf.len() >= 4 {
            versions.push(buf.get_u32());
        }
        Ok(Self {
            destination_connection_id,
            source_connection_id,
            versions,
        })
    }

    pub fn encode(&self) -> Result<Bytes, WireError> {
        let mut out = BytesMut::new();
        out.put_u8(0x80);
        out.put_u32(0);
        put_cid(&mut out, &self.destination_connection_id)?;
        put_cid(&mut out, &self.source_connection_id)?;
        for version in &self.versions {
            out.put_u32(*version);
        }
        Ok(out.freeze())
    }
}

/// Reconstruct a full packet number from the truncated value (RFC 9000 A.3).
pub fn decode_packet_number(
    largest_acknowledged: u64,
    truncated: u64,
    packet_number_len: u8,
) -> u64 {
    let expected = largest_acknowledged.saturating_add(1);
    let window = 1u64 << (packet_number_len as u32 * 8);
    let half_window = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | (truncated & mask);
    if candidate + half_window <= expected && candidate + window < (1u64 << 62) {
        candidate + window
    } else if candidate > expected + half_window && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

fn validate_packet_number_len(len: u8) -> Result<(), WireError> {
    if (1..=4).contains(&len) {
        Ok(())
    } else {
        Err(WireError::InvalidPacket(
            "packet number length must be 1..=4".to_string(),
        ))
    }
}

fn put_packet_number(out: &mut BytesMut, packet_number: u64, len: u8) {
    let bytes = packet_number.to_be_bytes();
    let start = 8 - len as usize;
    out.put_slice(&bytes[start..]);
}

fn read_packet_number(buf: &mut &[u8], len: u8) -> Result<u64, WireError> {
    let bytes = read_exact(buf, len as usize)?;
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

fn put_cid(out: &mut BytesMut, cid: &[u8]) -> Result<(), WireError> {
    if cid.len() > 20 {
        return Err(WireError::InvalidPacket(
            "connection ID is longer than 20 bytes".to_string(),
        ));
    }
    out.put_u8(cid.len() as u8);
    out.put_slice(cid);
    Ok(())
}

fn read_cid(buf: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    let len = buf.try_get_u8().map_err(|_| WireError::UnexpectedEnd)? as usize;
    if len > 20 {
        return Err(WireError::InvalidPacket(
            "connection ID is longer than 20 bytes".to_string(),
        ));
    }
    Ok(read_exact(buf, len)?.to_vec())
}

fn put_bytes(out: &mut BytesMut, bytes: &[u8]) -> Result<(), WireError> {
    varint::encode(out, bytes.len() as u64)?;
    out.put_slice(bytes);
    Ok(())
}

fn read_bytes(buf: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    let len = usize::try_from(varint::decode(buf)?).map_err(|_| WireError::IntegerOverflow)?;
    if len > 20 * 1024 {
        return Err(WireError::FieldTooLarge("token", 20 * 1024));
    }
    Ok(read_exact(buf, len)?.to_vec())
}

fn read_exact<'a>(buf: &mut &'a [u8], len: usize) -> Result<&'a [u8], WireError> {
    if buf.len() < len {
        return Err(WireError::UnexpectedEnd);
    }
    let (head, tail) = buf.split_at(len);
    *buf = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_long_packet_round_trips() {
        let packet = LongPacket {
            ty: LongType::Initial,
            version: VERSION_1,
            destination_connection_id: vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
            source_connection_id: vec![0x11, 0x22, 0x33, 0x44],
            token: vec![0xaa, 0xbb],
            packet_number: 2,
            packet_number_len: 4,
            payload: Bytes::from_static(b"initial payload"),
        };
        let wire = packet.encode().expect("encode");
        let mut read: &[u8] = &wire;
        assert_eq!(LongPacket::decode(&mut read, 1024).expect("decode"), packet);
    }

    #[test]
    fn handshake_and_short_packets_round_trip() {
        let handshake = LongPacket {
            ty: LongType::Handshake,
            version: VERSION_1,
            destination_connection_id: vec![1, 2, 3],
            source_connection_id: vec![4, 5, 6],
            token: Vec::new(),
            packet_number: 10,
            packet_number_len: 2,
            payload: Bytes::from_static(b"handshake"),
        };
        let wire = handshake.encode().expect("encode");
        let mut read: &[u8] = &wire;
        assert_eq!(
            LongPacket::decode(&mut read, 1024).expect("decode"),
            handshake
        );

        let short = ShortPacket {
            spin: false,
            key_phase: true,
            destination_connection_id: vec![9, 8, 7, 6],
            packet_number: 42,
            packet_number_len: 1,
            payload: Bytes::from_static(b"short"),
        };
        let wire = short.encode().expect("encode");
        let mut read: &[u8] = &wire;
        assert_eq!(
            ShortPacket::decode(&mut read, 4, 1024).expect("decode"),
            short
        );
    }

    #[test]
    fn version_negotiation_round_trips() {
        let packet = VersionNegotiation {
            destination_connection_id: vec![1, 2],
            source_connection_id: vec![3, 4],
            versions: vec![VERSION_1, VERSION_2, 0x0a0a_0a0a],
        };
        let wire = packet.encode().expect("encode");
        let mut read: &[u8] = &wire;
        assert_eq!(
            VersionNegotiation::decode(&mut read).expect("decode"),
            packet
        );
    }

    #[test]
    fn packet_number_reconstruction_matches_the_rfc_example() {
        // RFC 9000 A.3: largest 0xa82f30ea, truncated 0x9b32, length 2.
        assert_eq!(decode_packet_number(0xa82f30ea, 0x9b32, 2), 0xa82f9b32);
    }

    #[test]
    fn retry_round_trips() {
        let packet = RetryPacket {
            version: VERSION_1,
            destination_connection_id: vec![1, 2, 3, 4],
            source_connection_id: vec![5, 6, 7, 8],
            token: b"retry token".to_vec(),
            integrity_tag: [9; 16],
        };
        let wire = packet.encode().expect("encode");
        let mut read: &[u8] = &wire;
        assert_eq!(RetryPacket::decode(&mut read).expect("decode"), packet);
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let mut short: &[u8] = &[0x80, 0x00];
        assert!(matches!(
            ShortPacket::decode(&mut short, 0, 1024),
            Err(WireError::InvalidPacket(_))
        ));
        let mut long: &[u8] = &[0x00];
        assert!(matches!(
            LongPacket::decode(&mut long, 1024),
            Err(WireError::InvalidPacket(_)) | Err(WireError::UnexpectedEnd)
        ));
    }
}
