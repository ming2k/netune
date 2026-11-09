// SPDX-License-Identifier: MIT

//! Owned QUIC packet-protection wiring (RFC 9001).
//!
//! The cryptographic primitives and key schedule are provided by `rustls` and
//! `aws-lc-rs`; this module owns the QUIC header/packet protection order and
//! packet-number recovery.

use rustls::quic::{DirectionalKeys, HeaderProtectionKey, PacketKey};

use crate::wire::WireError;
use crate::wire::packet::{LongPacket, ShortPacket};

/// A TLS-handshake or packet-protection failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("no QUIC-capable TLS 1.3 cipher suite is available")]
    NoQuicSuite,
    #[error("TLS handshake error: {0}")]
    Handshake(String),
    #[error("packet protection error: {0}")]
    PacketProtection(String),
    #[error("packet is too short for header protection")]
    PacketTooShort,
    #[error("packet sample is too short")]
    SampleTooShort,
    #[error("packet number recovery failed")]
    PacketNumber,
    #[error("wire error: {0}")]
    Wire(#[from] WireError),
}

impl From<rustls::Error> for CryptoError {
    fn from(error: rustls::Error) -> Self {
        Self::Handshake(error.to_string())
    }
}

/// Derive the Initial keys for `destination_connection_id`.
pub fn initial_keys(
    destination_connection_id: &[u8],
    side: rustls::Side,
) -> Result<rustls::quic::Keys, CryptoError> {
    initial_keys_for_version(
        destination_connection_id,
        side,
        crate::wire::packet::VERSION_1,
    )
}

/// Derive Initial keys for a specific QUIC version.
pub fn initial_keys_for_version(
    destination_connection_id: &[u8],
    side: rustls::Side,
    version: u32,
) -> Result<rustls::quic::Keys, CryptoError> {
    use rustls::SupportedCipherSuite;
    use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;

    let SupportedCipherSuite::Tls13(suite) = TLS13_AES_128_GCM_SHA256 else {
        return Err(CryptoError::NoQuicSuite);
    };
    let quic = suite.quic.ok_or(CryptoError::NoQuicSuite)?;
    let rustls_version = match version {
        crate::wire::packet::VERSION_1 => rustls::quic::Version::V1,
        crate::wire::packet::VERSION_2 => rustls::quic::Version::V2,
        _ => return Err(CryptoError::NoQuicSuite),
    };
    Ok(rustls::quic::Suite { suite, quic }.keys(destination_connection_id, side, rustls_version))
}

/// Apply packet protection and header protection to a long-header packet.
pub fn protect_long(
    packet: &LongPacket,
    keys: &DirectionalKeys,
) -> Result<bytes::Bytes, CryptoError> {
    let tag_len = keys.packet.tag_len();
    let mut plaintext = packet.payload.to_vec();
    pad_for_sample(
        packet.packet_number_len,
        tag_len,
        keys.header.sample_len(),
        &mut plaintext,
    );
    let header_len = packet.packet_number_len as u64 + plaintext.len() as u64 + tag_len as u64;
    let header = encode_long_header(packet, header_len)?;
    protect(
        keys.header.as_ref(),
        keys.packet.as_ref(),
        header,
        packet.packet_number,
        packet.packet_number_len,
        plaintext,
    )
}

/// Apply packet protection and header protection to a short-header packet.
pub fn protect_short(
    packet: &ShortPacket,
    keys: &DirectionalKeys,
) -> Result<bytes::Bytes, CryptoError> {
    let tag_len = keys.packet.tag_len();
    let mut plaintext = packet.payload.to_vec();
    pad_for_sample(
        packet.packet_number_len,
        tag_len,
        keys.header.sample_len(),
        &mut plaintext,
    );
    let header = encode_short_header(packet)?;
    protect(
        keys.header.as_ref(),
        keys.packet.as_ref(),
        header,
        packet.packet_number,
        packet.packet_number_len,
        plaintext,
    )
}

/// Remove header protection and packet protection from a long-header packet.
///
/// `largest_packet_number` is the largest packet number successfully received
/// in the same packet-number space.
pub fn unprotect_long(
    packet: &mut [u8],
    largest_packet_number: u64,
    keys: &DirectionalKeys,
) -> Result<(u64, u8, bytes::Bytes), CryptoError> {
    let (pn_offset, packet_end) = long_header_info(packet)?;
    let (packet_number, packet_number_len, _phase, payload) = unprotect(
        packet,
        pn_offset,
        packet_end,
        largest_packet_number,
        keys.header.as_ref(),
        keys.packet.as_ref(),
    )?;
    Ok((packet_number, packet_number_len, payload))
}

/// Remove header protection and packet protection from a short-header packet.
pub fn unprotect_short(
    packet: &mut [u8],
    destination_connection_id_len: usize,
    largest_packet_number: u64,
    keys: &DirectionalKeys,
) -> Result<(u64, u8, bytes::Bytes), CryptoError> {
    let pn_offset = 1 + destination_connection_id_len;
    let packet_end = packet.len();
    let (packet_number, packet_number_len, _phase, payload) = unprotect(
        packet,
        pn_offset,
        packet_end,
        largest_packet_number,
        keys.header.as_ref(),
        keys.packet.as_ref(),
    )?;
    Ok((packet_number, packet_number_len, payload))
}

/// Protect a short-header packet with separately supplied packet and header keys.
///
/// Header-protection keys are stable across 1-RTT key updates; only the packet
/// protection key changes.
pub fn protect_short_with(
    packet: &ShortPacket,
    header_key: &dyn HeaderProtectionKey,
    packet_key: &dyn PacketKey,
) -> Result<bytes::Bytes, CryptoError> {
    let tag_len = packet_key.tag_len();
    let mut plaintext = packet.payload.to_vec();
    pad_for_sample(
        packet.packet_number_len,
        tag_len,
        header_key.sample_len(),
        &mut plaintext,
    );
    let header = encode_short_header(packet)?;
    protect(
        header_key,
        packet_key,
        header,
        packet.packet_number,
        packet.packet_number_len,
        plaintext,
    )
}

/// Unprotect a short-header packet with separately supplied packet and header keys.
pub fn unprotect_short_with(
    packet: &mut [u8],
    destination_connection_id_len: usize,
    largest_packet_number: u64,
    header_key: &dyn HeaderProtectionKey,
    packet_key: &dyn PacketKey,
) -> Result<(u64, u8, bool, bytes::Bytes), CryptoError> {
    let pn_offset = 1 + destination_connection_id_len;
    let packet_end = packet.len();
    unprotect(
        packet,
        pn_offset,
        packet_end,
        largest_packet_number,
        header_key,
        packet_key,
    )
}

fn protect(
    header_key: &dyn HeaderProtectionKey,
    packet_key: &dyn PacketKey,
    header: Vec<u8>,
    packet_number: u64,
    packet_number_len: u8,
    plaintext: Vec<u8>,
) -> Result<bytes::Bytes, CryptoError> {
    let mut ciphertext = plaintext;
    let tag = packet_key
        .encrypt_in_place(packet_number, &header, &mut ciphertext)
        .map_err(|error| CryptoError::PacketProtection(error.to_string()))?;
    ciphertext.extend_from_slice(tag.as_ref());

    let mut packet = header;
    let pn_offset = packet.len() - packet_number_len as usize;
    packet.extend_from_slice(&ciphertext);

    let sample_start = pn_offset + 4;
    let sample_end = sample_start + header_key.sample_len();
    if packet.len() < sample_end {
        return Err(CryptoError::SampleTooShort);
    }
    let sample = packet[sample_start..sample_end].to_vec();
    let mut first = packet[0];
    let mut pn_bytes = packet[pn_offset..pn_offset + packet_number_len as usize].to_vec();
    header_key
        .encrypt_in_place(&sample, &mut first, &mut pn_bytes)
        .map_err(|error| CryptoError::PacketProtection(error.to_string()))?;
    packet[0] = first;
    packet[pn_offset..pn_offset + packet_number_len as usize].copy_from_slice(&pn_bytes);
    Ok(packet.into())
}

fn unprotect(
    packet: &mut [u8],
    pn_offset: usize,
    packet_end: usize,
    largest_packet_number: u64,
    header_key: &dyn HeaderProtectionKey,
    packet_key: &dyn PacketKey,
) -> Result<(u64, u8, bool, bytes::Bytes), CryptoError> {
    if packet_end > packet.len() || packet_end < pn_offset {
        return Err(CryptoError::PacketTooShort);
    }
    let sample_len = header_key.sample_len();
    let sample_start = pn_offset + 4;
    let sample_end = sample_start + sample_len;
    if packet_end < sample_end {
        return Err(CryptoError::SampleTooShort);
    }
    let sample = packet[sample_start..sample_end].to_vec();
    let mut first = packet[0];
    let mut pn_bytes = [0u8; 4];
    let available = packet_end.saturating_sub(pn_offset).min(4);
    pn_bytes[..available].copy_from_slice(&packet[pn_offset..pn_offset + available]);
    header_key
        .decrypt_in_place(&sample, &mut first, &mut pn_bytes[..available])
        .map_err(|error| CryptoError::PacketProtection(error.to_string()))?;
    let packet_number_len = (first & 0x03) + 1;
    if available < packet_number_len as usize {
        return Err(CryptoError::PacketTooShort);
    }
    let truncated = pn_bytes[..packet_number_len as usize]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let packet_number = crate::wire::packet::decode_packet_number(
        largest_packet_number,
        truncated,
        packet_number_len,
    );
    let header_len = pn_offset + packet_number_len as usize;
    let mut header = packet[..header_len].to_vec();
    header[0] = first;
    header[pn_offset..header_len].copy_from_slice(&pn_bytes[..packet_number_len as usize]);
    let key_phase = first & 0x04 != 0;
    let payload = packet_key
        .decrypt_in_place(packet_number, &header, &mut packet[header_len..packet_end])
        .map_err(|error| CryptoError::PacketProtection(error.to_string()))?;
    Ok((
        packet_number,
        packet_number_len,
        key_phase,
        payload.to_vec().into(),
    ))
}

fn pad_for_sample(
    packet_number_len: u8,
    tag_len: usize,
    sample_len: usize,
    plaintext: &mut Vec<u8>,
) {
    let minimum = (4 + sample_len).saturating_sub(packet_number_len as usize + tag_len);
    if plaintext.len() < minimum {
        plaintext.resize(minimum, 0);
    }
}

fn encode_long_header(packet: &LongPacket, length: u64) -> Result<Vec<u8>, CryptoError> {
    use crate::wire::packet::LongType;
    use crate::wire::varint;
    use bytes::BufMut;

    let mut header = bytes::BytesMut::new();
    if packet.ty == LongType::Retry {
        return Err(CryptoError::Wire(WireError::InvalidPacket(
            "Retry packets are not protected here".to_string(),
        )));
    }
    let first = 0xc0 | packet.ty.bits_for(packet.version) | (packet.packet_number_len - 1);
    header.put_u8(first);
    header.put_u32(packet.version);
    header.put_u8(packet.destination_connection_id.len() as u8);
    header.put_slice(&packet.destination_connection_id);
    header.put_u8(packet.source_connection_id.len() as u8);
    header.put_slice(&packet.source_connection_id);
    if packet.ty == LongType::Initial {
        varint::encode(&mut header, packet.token.len() as u64)?;
        header.put_slice(&packet.token);
    }
    varint::encode(&mut header, length)?;
    let pn = packet.packet_number.to_be_bytes();
    header.put_slice(&pn[8 - packet.packet_number_len as usize..]);
    Ok(header.to_vec())
}

fn encode_short_header(packet: &ShortPacket) -> Result<Vec<u8>, CryptoError> {
    use bytes::BufMut;

    let mut header = bytes::BytesMut::new();
    let first = 0x40
        | (u8::from(packet.spin) << 5)
        | (u8::from(packet.key_phase) << 2)
        | (packet.packet_number_len - 1);
    header.put_u8(first);
    header.put_slice(&packet.destination_connection_id);
    let pn = packet.packet_number.to_be_bytes();
    header.put_slice(&pn[8 - packet.packet_number_len as usize..]);
    Ok(header.to_vec())
}

/// Find the packet-number offset in a protected long-header packet.
pub fn long_packet_number_offset(packet: &[u8]) -> Result<usize, CryptoError> {
    long_header_info(packet).map(|(offset, _)| offset)
}

pub fn long_header_info(packet: &[u8]) -> Result<(usize, usize), CryptoError> {
    use crate::wire::packet::LongType;
    use crate::wire::varint;

    let mut cursor = packet;
    let first = *cursor.first().ok_or(CryptoError::PacketTooShort)?;
    if first & 0x80 == 0 {
        return Err(CryptoError::Wire(WireError::InvalidPacket(
            "not a long-header packet".to_string(),
        )));
    }
    cursor = &cursor[1..];
    if cursor.len() < 4 {
        return Err(CryptoError::PacketTooShort);
    }
    let version = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    if version == 0 {
        return Err(CryptoError::Wire(WireError::InvalidPacket(
            "version negotiation has no packet number".to_string(),
        )));
    }
    cursor = &cursor[4..];
    cursor = skip_cid(cursor)?;
    cursor = skip_cid(cursor)?;
    let ty = LongType::from_bits_for(version, first);
    if ty == LongType::Retry {
        return Err(CryptoError::Wire(WireError::InvalidPacket(
            "Retry packets are not protected packets".to_string(),
        )));
    }
    if ty == LongType::Initial {
        let token_len =
            usize::try_from(varint::decode(&mut cursor)?).map_err(|_| CryptoError::PacketNumber)?;
        if cursor.len() < token_len {
            return Err(CryptoError::PacketTooShort);
        }
        cursor = &cursor[token_len..];
    }
    let length =
        usize::try_from(varint::decode(&mut cursor)?).map_err(|_| CryptoError::PacketNumber)?;
    let pn_offset = packet.len() - cursor.len();
    let packet_end = pn_offset
        .checked_add(length)
        .ok_or(CryptoError::PacketNumber)?;
    if packet_end > packet.len() {
        return Err(CryptoError::PacketTooShort);
    }
    Ok((pn_offset, packet_end))
}

fn skip_cid(mut cursor: &[u8]) -> Result<&[u8], CryptoError> {
    let len = usize::from(*cursor.first().ok_or(CryptoError::PacketTooShort)?);
    if len > 20 {
        return Err(CryptoError::Wire(WireError::InvalidPacket(
            "connection ID is longer than 20 bytes".to_string(),
        )));
    }
    cursor = &cursor[1..];
    if cursor.len() < len {
        return Err(CryptoError::PacketTooShort);
    }
    Ok(&cursor[len..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::packet::{LongPacket, LongType, VERSION_1};

    fn hex(input: &str) -> Vec<u8> {
        let digits: Vec<u8> = input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert!(digits.len().is_multiple_of(2));
        digits
            .chunks(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex");
                u8::from_str_radix(text, 16).expect("hex")
            })
            .collect()
    }

    fn rfc_client_initial() -> Vec<u8> {
        hex(concat!(
            "c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11",
            "d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399",
            "1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c",
            "8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212",
            "30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5",
            "457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208",
            "4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec",
            "4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3",
            "485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db",
            "059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c",
            "7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8",
            "9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556",
            "be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74",
            "68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a",
            "c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00",
            "f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632",
            "291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964",
            "25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd",
            "14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff",
            "ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198",
            "e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd",
            "c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73",
            "203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f",
            "cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e",
            "fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade",
            "a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047",
            "90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2",
            "162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4",
            "40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0",
            "6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e",
            "8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0",
            "be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400",
            "54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab",
            "760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9",
            "f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4",
            "056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064",
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241",
            "e221af44860018ab0856972e194cd934"
        ))
    }

    #[test]
    fn rfc9001_client_initial_decrypts_and_reprotects() {
        let dcid = hex("8394c8f03e515708");
        let server_keys = initial_keys(&dcid, rustls::Side::Server).expect("keys");
        let mut packet = rfc_client_initial();
        let (packet_number, pn_len, payload) =
            unprotect_long(&mut packet, 0, &server_keys.remote).expect("unprotect");
        assert_eq!(packet_number, 2);
        assert_eq!(pn_len, 4);
        assert_eq!(payload.len(), 1162);
        assert_eq!(payload[0], 0x06, "CRYPTO frame type");

        let client_keys = initial_keys(&dcid, rustls::Side::Client).expect("keys");
        let protected = protect_long(
            &LongPacket {
                ty: LongType::Initial,
                version: VERSION_1,
                destination_connection_id: dcid,
                source_connection_id: Vec::new(),
                token: Vec::new(),
                packet_number: 2,
                packet_number_len: 4,
                payload: payload.clone(),
            },
            &client_keys.local,
        )
        .expect("protect");
        assert_eq!(protected.as_ref(), rfc_client_initial());
    }

    #[test]
    fn short_packet_protection_round_trips() {
        let dcid = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let keys = initial_keys(&dcid, rustls::Side::Client).expect("keys");
        let packet = ShortPacket {
            spin: false,
            key_phase: false,
            destination_connection_id: dcid.clone(),
            packet_number: 7,
            packet_number_len: 1,
            payload: bytes::Bytes::from_static(b"x"),
        };
        let mut wire = protect_short(&packet, &keys.local)
            .expect("protect")
            .to_vec();
        let (packet_number, pn_len, payload) =
            unprotect_short(&mut wire, dcid.len(), 6, &keys.local).expect("unprotect");
        assert_eq!((packet_number, pn_len), (7, 1));
        // Header protection is symmetric with the same key in this test; the
        // plaintext includes the PADDING used to reach the sample.
        assert_eq!(&payload[..1], b"x");
    }
}
