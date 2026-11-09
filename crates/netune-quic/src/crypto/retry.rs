// SPDX-License-Identifier: MIT

//! Retry integrity protection (RFC 9001 Section 5.8).
//!
//! Retry packets are not protected with connection keys; they use a fixed
//! version-specific AES-128-GCM key and nonce. The tag authenticates the
//! pseudo-packet built from the original destination connection ID and the
//! Retry packet itself.

use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use bytes::Bytes;

use crate::wire::WireError;
use crate::wire::packet::{RetryPacket, VERSION_1, VERSION_2};

const V1_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const V1_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
const V2_KEY: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
const V2_NONCE: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

/// Build a Retry packet with a valid integrity tag.
pub fn encode_retry(
    version: u32,
    destination_connection_id: Vec<u8>,
    source_connection_id: Vec<u8>,
    token: Vec<u8>,
    original_destination_connection_id: &[u8],
) -> Result<Bytes, WireError> {
    let mut packet = RetryPacket {
        version,
        destination_connection_id,
        source_connection_id,
        token,
        integrity_tag: [0u8; 16],
    };
    let without_tag = packet.encode_without_tag()?;
    packet.integrity_tag = retry_tag(version, original_destination_connection_id, &without_tag)?;
    packet.encode()
}

/// Verify a Retry packet's integrity tag and return the decoded packet.
pub fn decode_retry(
    bytes: &[u8],
    original_destination_connection_id: &[u8],
) -> Result<RetryPacket, WireError> {
    let mut cursor = bytes;
    let packet = RetryPacket::decode(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(WireError::InvalidPacket(
            "trailing bytes after Retry packet".to_string(),
        ));
    }
    let without_tag = &bytes[..bytes.len() - 16];
    let expected = retry_tag(
        packet.version,
        original_destination_connection_id,
        without_tag,
    )?;
    if expected != packet.integrity_tag {
        return Err(WireError::InvalidPacket(
            "Retry integrity tag did not verify".to_string(),
        ));
    }
    Ok(packet)
}

fn retry_tag(version: u32, odcid: &[u8], packet: &[u8]) -> Result<[u8; 16], WireError> {
    let (key, nonce) = match version {
        VERSION_1 => (&V1_KEY, &V1_NONCE),
        VERSION_2 => (&V2_KEY, &V2_NONCE),
        _ => {
            return Err(WireError::InvalidPacket(
                "Retry is only defined for QUIC v1 and v2".to_string(),
            ));
        }
    };
    let mut pseudo = Vec::with_capacity(1 + odcid.len() + packet.len());
    pseudo.push(odcid.len() as u8);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(packet);
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_128_GCM, key)
            .map_err(|_| WireError::InvalidPacket("invalid Retry key".to_string()))?,
    );
    let nonce = Nonce::assume_unique_for_key(*nonce);
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(&pseudo), &mut [])
        .map_err(|_| WireError::InvalidPacket("Retry tag encryption failed".to_string()))?;
    let mut output = [0u8; 16];
    output.copy_from_slice(tag.as_ref());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_integrity_round_trips_and_rejects_tampering() {
        let odcid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let wire = encode_retry(
            VERSION_1,
            vec![9, 8, 7, 6],
            vec![5, 4, 3, 2],
            b"token".to_vec(),
            &odcid,
        )
        .expect("encode");
        let packet = decode_retry(&wire, &odcid).expect("verify");
        assert_eq!(packet.token, b"token");

        let mut tampered = wire.to_vec();
        tampered[12] ^= 0x80;
        assert!(decode_retry(&tampered, &odcid).is_err());
        assert!(decode_retry(&wire, &[0; 8]).is_err());
    }
}
