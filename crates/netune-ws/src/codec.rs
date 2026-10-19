use bytes::{Buf, BytesMut};

use crate::error::WsError;
use crate::frame::{CloseCode, Frame, Opcode, Role};
use crate::mask::apply_mask;

/// A stateless, zero-allocation RFC 6455 frame decoder.
#[derive(Debug, Default)]
pub struct FrameDecoder;

impl FrameDecoder {
    /// Attempt to parse one frame from `buf` according to `role` and limits.
    ///
    /// If `buf` contains fewer bytes than the complete frame, returns `Ok(None)`
    /// without consuming any data.
    pub fn decode(
        buf: &mut BytesMut,
        role: Role,
        max_frame_bytes: usize,
    ) -> Result<Option<Frame>, WsError> {
        if buf.len() < 2 {
            return Ok(None);
        }

        let b0 = buf[0];
        let b1 = buf[1];

        let fin = (b0 & 0x80) != 0;
        let rsv = [(b0 & 0x40) != 0, (b0 & 0x20) != 0, (b0 & 0x10) != 0];
        let opcode_raw = b0 & 0x0F;

        // RSV bits must be 0 unless an extension negotiates otherwise
        if rsv[0] || rsv[1] || rsv[2] {
            return Err(WsError::protocol(
                "WebSocket reserved bits (RSV1-3) must be zero",
                CloseCode::PROTOCOL_ERROR,
            ));
        }

        let opcode = Opcode::try_from_u8(opcode_raw).map_err(|raw| {
            WsError::protocol(
                format!("Invalid WebSocket opcode: {raw:#x}"),
                CloseCode::PROTOCOL_ERROR,
            )
        })?;

        // Control frame constraints (RFC 6455 §5.5)
        if opcode.is_control() && !fin {
            return Err(WsError::protocol(
                "Control frames must not be fragmented (FIN must be set)",
                CloseCode::PROTOCOL_ERROR,
            ));
        }

        let is_masked = (b1 & 0x80) != 0;
        let len_code = b1 & 0x7F;

        // Role-based masking check (RFC 6455 §5.1 & §5.3)
        match role {
            Role::Client => {
                if is_masked {
                    return Err(WsError::protocol(
                        "Server-to-client frames must not be masked (RFC 6455 §5.1)",
                        CloseCode::PROTOCOL_ERROR,
                    ));
                }
            }
            Role::Server => {
                if !is_masked {
                    return Err(WsError::protocol(
                        "Client-to-server frames must be masked (RFC 6455 §5.3)",
                        CloseCode::PROTOCOL_ERROR,
                    ));
                }
            }
        }

        if opcode.is_control() && len_code > 125 {
            return Err(WsError::protocol(
                "Control frame payload cannot exceed 125 bytes",
                CloseCode::PROTOCOL_ERROR,
            ));
        }

        // Determine header size and payload length
        let (payload_len, header_len) = match len_code {
            126 => {
                if buf.len() < 4 {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                let header = 4 + if is_masked { 4 } else { 0 };
                (len, header)
            }
            127 => {
                if buf.len() < 10 {
                    return Ok(None);
                }
                let len = u64::from_be_bytes([
                    buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                ]) as usize;
                let header = 10 + if is_masked { 4 } else { 0 };
                (len, header)
            }
            small => {
                let header = 2 + if is_masked { 4 } else { 0 };
                (small as usize, header)
            }
        };

        if payload_len > max_frame_bytes {
            return Err(WsError::PayloadTooLarge {
                length: payload_len,
                max: max_frame_bytes,
            });
        }

        let total_frame_len = header_len + payload_len;
        if buf.len() < total_frame_len {
            // Wait for remaining bytes to arrive
            return Ok(None);
        }

        // Extract mask if present
        let mask = if is_masked {
            let mask_offset = header_len - 4;
            Some([
                buf[mask_offset],
                buf[mask_offset + 1],
                buf[mask_offset + 2],
                buf[mask_offset + 3],
            ])
        } else {
            None
        };

        // Advance past header
        buf.advance(header_len);

        // Split payload bytes
        let mut payload = buf.split_to(payload_len);

        if let Some(m) = mask {
            apply_mask(&mut payload, m);
        }

        Ok(Some(Frame {
            fin,
            rsv,
            opcode,
            payload: payload.freeze(),
        }))
    }
    /// Parse the close status code from a close frame's payload, if present.
    ///
    /// Returns `None` for an empty payload (no code given) and `None` for a
    /// malformed payload — malformed close payloads are the assembler's
    /// terminal error, but the handshake reply should still use a sane echo.
    pub fn parse_close_code(payload: &[u8]) -> Option<CloseCode> {
        if payload.len() < 2 {
            return None;
        }
        let code = CloseCode(u16::from_be_bytes([payload[0], payload[1]]));
        code.is_wire_legal().then_some(code)
    }
}

/// A stateless, zero-allocation RFC 6455 frame encoder.
#[derive(Debug, Default)]
pub struct FrameEncoder;

impl FrameEncoder {
    /// Encode a frame with optional masking into `out`.
    pub fn encode(frame: &Frame, mask: Option<[u8; 4]>, out: &mut BytesMut) {
        let b0 = (if frame.fin { 0x80 } else { 0 })
            | (if frame.rsv[0] { 0x40 } else { 0 })
            | (if frame.rsv[1] { 0x20 } else { 0 })
            | (if frame.rsv[2] { 0x10 } else { 0 })
            | (frame.opcode as u8);

        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let len = frame.payload.len();

        out.reserve(14 + len);
        out.extend_from_slice(&[b0]);

        if len <= 125 {
            out.extend_from_slice(&[mask_bit | (len as u8)]);
        } else if len <= 65535 {
            out.extend_from_slice(&[mask_bit | 126]);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.extend_from_slice(&[mask_bit | 127]);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }

        if let Some(m) = mask {
            out.extend_from_slice(&m);
            let start = out.len();
            out.extend_from_slice(&frame.payload);
            apply_mask(&mut out[start..], m);
        } else {
            out.extend_from_slice(&frame.payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_encode_and_decode_roundtrip_client_to_server() {
        let text = "Hello, WebSocket wire!";
        let frame = Frame::text(Bytes::from_static(text.as_bytes()));
        let mask = Some([0xaa, 0xbb, 0xcc, 0xdd]);

        let mut buf = BytesMut::new();
        FrameEncoder::encode(&frame, mask, &mut buf);

        // Server decodes masked frame
        let decoded = FrameDecoder::decode(&mut buf, Role::Server, 64 * 1024)
            .unwrap()
            .unwrap();

        assert_eq!(decoded.opcode, Opcode::Text);
        assert!(decoded.fin);
        assert_eq!(decoded.payload.as_ref(), text.as_bytes());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_encode_and_decode_roundtrip_server_to_client() {
        let payload = Bytes::from_static(b"binary payload from origin");
        let frame = Frame::binary(payload.clone());

        let mut buf = BytesMut::new();
        FrameEncoder::encode(&frame, None, &mut buf);

        // Client decodes unmasked frame
        let decoded = FrameDecoder::decode(&mut buf, Role::Client, 64 * 1024)
            .unwrap()
            .unwrap();

        assert_eq!(decoded.opcode, Opcode::Binary);
        assert!(decoded.fin);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_client_rejects_masked_server_frame() {
        let frame = Frame::ping(Bytes::from_static(b"test"));
        let mut buf = BytesMut::new();
        FrameEncoder::encode(&frame, Some([1, 2, 3, 4]), &mut buf);

        let err = FrameDecoder::decode(&mut buf, Role::Client, 1024).unwrap_err();
        match err {
            WsError::Protocol { code, .. } => assert_eq!(code, CloseCode::PROTOCOL_ERROR),
            _ => panic!("Expected protocol error"),
        }
    }

    #[test]
    fn test_server_rejects_unmasked_client_frame() {
        let frame = Frame::text(Bytes::from_static(b"test"));
        let mut buf = BytesMut::new();
        FrameEncoder::encode(&frame, None, &mut buf);

        let err = FrameDecoder::decode(&mut buf, Role::Server, 1024).unwrap_err();
        match err {
            WsError::Protocol { code, .. } => assert_eq!(code, CloseCode::PROTOCOL_ERROR),
            _ => panic!("Expected protocol error"),
        }
    }

    #[test]
    fn test_control_frame_payload_limit_enforced() {
        let large_payload = Bytes::from(vec![0u8; 126]);
        let frame = Frame::ping(large_payload);
        let mut buf = BytesMut::new();
        FrameEncoder::encode(&frame, None, &mut buf);

        let err = FrameDecoder::decode(&mut buf, Role::Client, 1024).unwrap_err();
        match err {
            WsError::Protocol { code, .. } => assert_eq!(code, CloseCode::PROTOCOL_ERROR),
            _ => panic!("Expected protocol error"),
        }
    }

    #[test]
    fn test_fragmented_control_frame_rejected() {
        let frame = Frame::new(false, Opcode::Ping, Bytes::from_static(b"ping"));
        let mut buf = BytesMut::new();
        FrameEncoder::encode(&frame, None, &mut buf);

        let err = FrameDecoder::decode(&mut buf, Role::Client, 1024).unwrap_err();
        match err {
            WsError::Protocol { code, .. } => assert_eq!(code, CloseCode::PROTOCOL_ERROR),
            _ => panic!("Expected protocol error"),
        }
    }

    #[test]
    fn test_incomplete_frame_returns_none_until_buffered() {
        let text = "Full WebSocket Payload";
        let frame = Frame::text(Bytes::from_static(text.as_bytes()));
        let mut buf = BytesMut::new();
        FrameEncoder::encode(&frame, None, &mut buf);

        let full_bytes = buf.split();
        // Give only first 5 bytes
        buf.extend_from_slice(&full_bytes[..5]);
        assert_eq!(
            FrameDecoder::decode(&mut buf, Role::Client, 1024).unwrap(),
            None
        );

        // Give the rest
        buf.extend_from_slice(&full_bytes[5..]);
        let decoded = FrameDecoder::decode(&mut buf, Role::Client, 1024)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.payload.as_ref(), text.as_bytes());
    }

    #[test]
    fn test_oversized_frame_declared_but_incomplete_is_refused_by_limit() {
        // A frame whose header declares 1 KiB payload against a 64-byte limit
        // must fail immediately — before its body arrives — so an attacker
        // cannot stream unbounded bytes into the buffer while we wait.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x81, 127]);
        buf.extend_from_slice(&1024u64.to_be_bytes());

        let err = FrameDecoder::decode(&mut buf, Role::Client, 64).unwrap_err();
        match err {
            WsError::PayloadTooLarge { length, max } => {
                assert_eq!(length, 1024);
                assert_eq!(max, 64);
            }
            _ => panic!("Expected payload too large"),
        }
    }
}
