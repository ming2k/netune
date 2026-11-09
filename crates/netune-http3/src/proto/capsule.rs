// SPDX-License-Identifier: MIT

//! RFC 9297 Capsule Protocol framing.
//!
//! Capsules are carried inside an HTTP message body (for QUIC, inside DATA
//! frame payloads). A capsule is a QUIC varint type, a QUIC varint length, and
//! that many value bytes. The codec is independent of the WebTransport
//! application protocol: WebTransport defines capsule types on top of it.

use bytes::{BufMut, Bytes, BytesMut};

use super::varint::{self, VarIntError};

/// Default ceiling for a capsule value retained by the H3 connection.
pub const MAX_CAPSULE_VALUE: usize = 16 * 1024 * 1024;

/// A decoded RFC 9297 capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    pub kind: u64,
    pub value: Bytes,
}

/// A malformed or oversized capsule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapsuleError {
    #[error("capsule varint is invalid: {0}")]
    VarInt(#[from] VarIntError),
    #[error("capsule value length {0} exceeds the configured maximum")]
    TooLarge(usize),
    #[error("stream ended inside a capsule header or value")]
    Truncated,
}

impl Capsule {
    pub fn new(kind: u64, value: impl Into<Bytes>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    /// Try to decode one capsule from `buf`.
    ///
    /// Returns `Ok(None)` when the buffer is a valid prefix but incomplete. The
    /// returned consumed length lets the caller retain the suffix for the next
    /// read.
    pub fn decode(buf: &[u8], max_value: usize) -> Result<Option<(Self, usize)>, CapsuleError> {
        let mut cursor = buf;
        let kind = match varint::decode(&mut cursor) {
            Ok(kind) => kind,
            Err(VarIntError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let length = match varint::decode(&mut cursor) {
            Ok(length) => {
                usize::try_from(length).map_err(|_| CapsuleError::TooLarge(usize::MAX))?
            }
            Err(VarIntError::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if length > max_value {
            return Err(CapsuleError::TooLarge(length));
        }
        let header = buf.len() - cursor.len();
        if cursor.len() < length {
            return Ok(None);
        }
        let consumed = header + length;
        Ok(Some((
            Self {
                kind,
                value: Bytes::copy_from_slice(&cursor[..length]),
            },
            consumed,
        )))
    }

    /// Encode a capsule into `out`.
    pub fn encode(&self, out: &mut BytesMut, max_value: usize) -> Result<(), CapsuleError> {
        if self.value.len() > max_value {
            return Err(CapsuleError::TooLarge(self.value.len()));
        }
        varint::encode(out, self.kind)?;
        varint::encode(out, self.value.len() as u64)?;
        out.put_slice(&self.value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_round_trips_and_retains_partial_suffix() {
        let capsule = Capsule::new(0x2843, Bytes::from_static(b"payload"));
        let mut wire = BytesMut::new();
        capsule
            .encode(&mut wire, MAX_CAPSULE_VALUE)
            .expect("encode");
        wire.extend_from_slice(b"next");
        let (decoded, consumed) = Capsule::decode(&wire, MAX_CAPSULE_VALUE)
            .expect("decode")
            .expect("complete");
        assert_eq!(decoded, capsule);
        assert_eq!(&wire[consumed..], b"next");
    }

    #[test]
    fn incomplete_and_oversized_capsules_are_distinct() {
        let mut wire = BytesMut::new();
        Capsule::new(1, Bytes::from_static(b"abc"))
            .encode(&mut wire, MAX_CAPSULE_VALUE)
            .expect("encode");
        assert!(
            Capsule::decode(&wire[..3], MAX_CAPSULE_VALUE)
                .expect("prefix")
                .is_none()
        );
        let over = Capsule::new(1, Bytes::from_static(b"too large"));
        assert!(matches!(
            Capsule::decode(&wire, 2).expect_err("bound"),
            CapsuleError::TooLarge(_)
        ));
        let mut out = BytesMut::new();
        assert!(matches!(
            over.encode(&mut out, 2).expect_err("bound"),
            CapsuleError::TooLarge(_)
        ));
    }
}
