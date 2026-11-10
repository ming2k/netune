// SPDX-License-Identifier: MIT

//! QUIC frame codec (RFC 9000 Section 19, RFC 9221 for DATAGRAM).

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::error::WireError;
use super::varint;

/// Default ceiling for a frame payload we are willing to retain.
pub const MAX_FRAME_PAYLOAD: usize = 1 << 20;

/// ACK ECN counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

/// One gap/range pair in an ACK frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    pub gap: u64,
    pub range: u64,
}

/// ACK frame payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame {
    pub largest_acknowledged: u64,
    pub ack_delay: u64,
    pub first_ack_range: u64,
    pub ranges: Vec<AckRange>,
    pub ecn: Option<EcnCounts>,
}

/// A QUIC frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding {
        len: usize,
    },
    Ping,
    Ack(AckFrame),
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    ResetStreamAt {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
        reliable_size: u64,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
    },
    Crypto {
        offset: u64,
        data: Bytes,
    },
    NewToken {
        token: Bytes,
    },
    Stream {
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: Bytes,
    },
    MaxData(u64),
    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },
    MaxStreams {
        bidi: bool,
        maximum: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        stream_id: u64,
        maximum: u64,
    },
    StreamsBlocked {
        bidi: bool,
        maximum: u64,
    },
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        connection_id: Vec<u8>,
        reset_token: [u8; 16],
    },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionCloseTransport {
        error_code: u64,
        frame_type: u64,
        reason: Bytes,
    },
    ConnectionCloseApplication {
        error_code: u64,
        reason: Bytes,
    },
    HandshakeDone,
    Datagram {
        data: Bytes,
    },
}

impl Frame {
    /// The number of bytes this frame encodes to.
    pub(crate) fn encoded_len(&self) -> Result<usize, WireError> {
        let mut buffer = BytesMut::new();
        self.encode(&mut buffer)?;
        Ok(buffer.len())
    }

    /// Decode one frame from `buf`. STREAM and DATAGRAM frames without a length
    /// consume the rest of the packet.
    pub fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let ty = varint::decode(buf)?;
        match ty {
            0x00 => {
                let mut len = 1usize;
                while buf.first() == Some(&0) {
                    buf.advance(1);
                    len += 1;
                }
                Ok(Self::Padding { len })
            }
            0x01 => Ok(Self::Ping),
            0x02 | 0x03 => decode_ack(buf, ty == 0x03),
            0x04 => Ok(Self::ResetStream {
                stream_id: varint::decode(buf)?,
                error_code: varint::decode(buf)?,
                final_size: varint::decode(buf)?,
            }),
            0x24 => Ok(Self::ResetStreamAt {
                stream_id: varint::decode(buf)?,
                error_code: varint::decode(buf)?,
                final_size: varint::decode(buf)?,
                reliable_size: varint::decode(buf)?,
            }),
            0x05 => Ok(Self::StopSending {
                stream_id: varint::decode(buf)?,
                error_code: varint::decode(buf)?,
            }),
            0x06 => {
                let offset = varint::decode(buf)?;
                let data = read_bytes(buf, "CRYPTO data")?;
                Ok(Self::Crypto { offset, data })
            }
            0x07 => {
                let token = read_bytes(buf, "NEW_TOKEN token")?;
                Ok(Self::NewToken { token })
            }
            0x08..=0x0f => {
                let stream_id = varint::decode(buf)?;
                let offset = if ty & 0x04 != 0 {
                    varint::decode(buf)?
                } else {
                    0
                };
                let data = if ty & 0x02 != 0 {
                    read_bytes(buf, "STREAM data")?
                } else {
                    take_rest(buf)
                };
                Ok(Self::Stream {
                    stream_id,
                    offset,
                    fin: ty & 0x01 != 0,
                    data,
                })
            }
            0x10 => Ok(Self::MaxData(varint::decode(buf)?)),
            0x11 => Ok(Self::MaxStreamData {
                stream_id: varint::decode(buf)?,
                maximum: varint::decode(buf)?,
            }),
            0x12 | 0x13 => Ok(Self::MaxStreams {
                bidi: ty == 0x12,
                maximum: varint::decode(buf)?,
            }),
            0x14 => Ok(Self::DataBlocked(varint::decode(buf)?)),
            0x15 => Ok(Self::StreamDataBlocked {
                stream_id: varint::decode(buf)?,
                maximum: varint::decode(buf)?,
            }),
            0x16 | 0x17 => Ok(Self::StreamsBlocked {
                bidi: ty == 0x16,
                maximum: varint::decode(buf)?,
            }),
            0x18 => {
                let sequence = varint::decode(buf)?;
                let retire_prior_to = varint::decode(buf)?;
                if retire_prior_to > sequence {
                    return Err(WireError::InvalidFrame(
                        "NEW_CONNECTION_ID retire_prior_to exceeds sequence".to_string(),
                    ));
                }
                let cid_len = usize::try_from(varint::decode(buf)?)
                    .map_err(|_| WireError::IntegerOverflow)?;
                if !(1..=20).contains(&cid_len) {
                    return Err(WireError::InvalidFrame(
                        "NEW_CONNECTION_ID length must be 1..=20".to_string(),
                    ));
                }
                let connection_id = read_exact(buf, cid_len, "connection ID")?.to_vec();
                let mut reset_token = [0u8; 16];
                reset_token.copy_from_slice(read_exact(buf, 16, "reset token")?);
                Ok(Self::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    connection_id,
                    reset_token,
                })
            }
            0x19 => Ok(Self::RetireConnectionId(varint::decode(buf)?)),
            0x1a => Ok(Self::PathChallenge(read_array(buf)?)),
            0x1b => Ok(Self::PathResponse(read_array(buf)?)),
            0x1c => {
                let error_code = varint::decode(buf)?;
                let frame_type = varint::decode(buf)?;
                let reason = read_reason(buf)?;
                Ok(Self::ConnectionCloseTransport {
                    error_code,
                    frame_type,
                    reason,
                })
            }
            0x1d => {
                let error_code = varint::decode(buf)?;
                let reason = read_reason(buf)?;
                Ok(Self::ConnectionCloseApplication { error_code, reason })
            }
            0x1e => Ok(Self::HandshakeDone),
            0x30 | 0x31 => {
                let data = if ty == 0x31 {
                    read_bytes(buf, "DATAGRAM data")?
                } else {
                    take_rest(buf)
                };
                Ok(Self::Datagram { data })
            }
            _ => Err(WireError::UnknownFrame(ty)),
        }
    }

    /// Append the frame to `out`.
    pub fn encode(&self, out: &mut BytesMut) -> Result<(), WireError> {
        match self {
            Self::Padding { len } => {
                if *len == 0 {
                    return Err(WireError::InvalidFrame(
                        "PADDING must contain at least one byte".to_string(),
                    ));
                }
                out.resize(out.len() + len, 0);
            }
            Self::Ping => varint::encode(out, 0x01)?,
            Self::Ack(ack) => encode_ack(out, ack)?,
            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                varint::encode(out, 0x04)?;
                varint::encode(out, *stream_id)?;
                varint::encode(out, *error_code)?;
                varint::encode(out, *final_size)?;
            }
            Self::ResetStreamAt {
                stream_id,
                error_code,
                final_size,
                reliable_size,
            } => {
                varint::encode(out, 0x24)?;
                varint::encode(out, *stream_id)?;
                varint::encode(out, *error_code)?;
                varint::encode(out, *final_size)?;
                varint::encode(out, *reliable_size)?;
            }
            Self::StopSending {
                stream_id,
                error_code,
            } => {
                varint::encode(out, 0x05)?;
                varint::encode(out, *stream_id)?;
                varint::encode(out, *error_code)?;
            }
            Self::Crypto { offset, data } => {
                varint::encode(out, 0x06)?;
                varint::encode(out, *offset)?;
                encode_bytes(out, data)?;
            }
            Self::NewToken { token } => {
                varint::encode(out, 0x07)?;
                encode_bytes(out, token)?;
            }
            Self::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => {
                let mut ty = 0x08 | 0x02;
                if *offset != 0 {
                    ty |= 0x04;
                }
                if *fin {
                    ty |= 0x01;
                }
                varint::encode(out, ty)?;
                varint::encode(out, *stream_id)?;
                if *offset != 0 {
                    varint::encode(out, *offset)?;
                }
                encode_bytes(out, data)?;
            }
            Self::MaxData(maximum) => {
                varint::encode(out, 0x10)?;
                varint::encode(out, *maximum)?;
            }
            Self::MaxStreamData { stream_id, maximum } => {
                varint::encode(out, 0x11)?;
                varint::encode(out, *stream_id)?;
                varint::encode(out, *maximum)?;
            }
            Self::MaxStreams { bidi, maximum } => {
                varint::encode(out, if *bidi { 0x12 } else { 0x13 })?;
                varint::encode(out, *maximum)?;
            }
            Self::DataBlocked(maximum) => {
                varint::encode(out, 0x14)?;
                varint::encode(out, *maximum)?;
            }
            Self::StreamDataBlocked { stream_id, maximum } => {
                varint::encode(out, 0x15)?;
                varint::encode(out, *stream_id)?;
                varint::encode(out, *maximum)?;
            }
            Self::StreamsBlocked { bidi, maximum } => {
                varint::encode(out, if *bidi { 0x16 } else { 0x17 })?;
                varint::encode(out, *maximum)?;
            }
            Self::NewConnectionId {
                sequence,
                retire_prior_to,
                connection_id,
                reset_token,
            } => {
                if !(1..=20).contains(&connection_id.len()) {
                    return Err(WireError::InvalidFrame(
                        "connection ID length must be 1..=20".to_string(),
                    ));
                }
                if retire_prior_to > sequence {
                    return Err(WireError::InvalidFrame(
                        "retire_prior_to exceeds sequence".to_string(),
                    ));
                }
                varint::encode(out, 0x18)?;
                varint::encode(out, *sequence)?;
                varint::encode(out, *retire_prior_to)?;
                varint::encode(out, connection_id.len() as u64)?;
                out.put_slice(connection_id);
                out.put_slice(reset_token);
            }
            Self::RetireConnectionId(sequence) => {
                varint::encode(out, 0x19)?;
                varint::encode(out, *sequence)?;
            }
            Self::PathChallenge(data) => {
                varint::encode(out, 0x1a)?;
                out.put_slice(data);
            }
            Self::PathResponse(data) => {
                varint::encode(out, 0x1b)?;
                out.put_slice(data);
            }
            Self::ConnectionCloseTransport {
                error_code,
                frame_type,
                reason,
            } => {
                varint::encode(out, 0x1c)?;
                varint::encode(out, *error_code)?;
                varint::encode(out, *frame_type)?;
                encode_bytes(out, reason)?;
            }
            Self::ConnectionCloseApplication { error_code, reason } => {
                varint::encode(out, 0x1d)?;
                varint::encode(out, *error_code)?;
                encode_bytes(out, reason)?;
            }
            Self::HandshakeDone => varint::encode(out, 0x1e)?,
            Self::Datagram { data } => {
                varint::encode(out, 0x31)?;
                encode_bytes(out, data)?;
            }
        }
        Ok(())
    }
}

fn decode_ack(buf: &mut &[u8], ecn: bool) -> Result<Frame, WireError> {
    let largest_acknowledged = varint::decode(buf)?;
    let ack_delay = varint::decode(buf)?;
    let range_count =
        usize::try_from(varint::decode(buf)?).map_err(|_| WireError::IntegerOverflow)?;
    let first_ack_range = varint::decode(buf)?;
    if first_ack_range > largest_acknowledged {
        return Err(WireError::InvalidFrame(
            "ACK first range exceeds largest acknowledged".to_string(),
        ));
    }
    let mut ranges = Vec::with_capacity(range_count.min(1024));
    for _ in 0..range_count {
        ranges.push(AckRange {
            gap: varint::decode(buf)?,
            range: varint::decode(buf)?,
        });
    }
    let ecn = if ecn {
        Some(EcnCounts {
            ect0: varint::decode(buf)?,
            ect1: varint::decode(buf)?,
            ce: varint::decode(buf)?,
        })
    } else {
        None
    };
    Ok(Frame::Ack(AckFrame {
        largest_acknowledged,
        ack_delay,
        first_ack_range,
        ranges,
        ecn,
    }))
}

fn encode_ack(out: &mut BytesMut, ack: &AckFrame) -> Result<(), WireError> {
    if ack.first_ack_range > ack.largest_acknowledged {
        return Err(WireError::InvalidFrame(
            "ACK first range exceeds largest acknowledged".to_string(),
        ));
    }
    varint::encode(out, if ack.ecn.is_some() { 0x03 } else { 0x02 })?;
    varint::encode(out, ack.largest_acknowledged)?;
    varint::encode(out, ack.ack_delay)?;
    varint::encode(out, ack.ranges.len() as u64)?;
    varint::encode(out, ack.first_ack_range)?;
    for range in &ack.ranges {
        varint::encode(out, range.gap)?;
        varint::encode(out, range.range)?;
    }
    if let Some(ecn) = ack.ecn {
        varint::encode(out, ecn.ect0)?;
        varint::encode(out, ecn.ect1)?;
        varint::encode(out, ecn.ce)?;
    }
    Ok(())
}

fn read_bytes(buf: &mut &[u8], field: &'static str) -> Result<Bytes, WireError> {
    let len = usize::try_from(varint::decode(buf)?).map_err(|_| WireError::IntegerOverflow)?;
    if len > MAX_FRAME_PAYLOAD {
        return Err(WireError::FieldTooLarge(field, MAX_FRAME_PAYLOAD));
    }
    let bytes = read_exact(buf, len, field)?;
    Ok(Bytes::copy_from_slice(bytes))
}

fn read_reason(buf: &mut &[u8]) -> Result<Bytes, WireError> {
    read_bytes(buf, "CONNECTION_CLOSE reason")
}

fn read_exact<'a>(
    buf: &mut &'a [u8],
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], WireError> {
    if buf.len() < len {
        return Err(WireError::UnexpectedEnd);
    }
    if len > MAX_FRAME_PAYLOAD {
        return Err(WireError::FieldTooLarge(field, MAX_FRAME_PAYLOAD));
    }
    let (head, tail) = buf.split_at(len);
    *buf = tail;
    Ok(head)
}

fn read_array<const N: usize>(buf: &mut &[u8]) -> Result<[u8; N], WireError> {
    let mut array = [0u8; N];
    array.copy_from_slice(read_exact(buf, N, "fixed field")?);
    Ok(array)
}

fn take_rest(buf: &mut &[u8]) -> Bytes {
    let data = Bytes::copy_from_slice(buf);
    *buf = &[];
    data
}

fn encode_bytes(out: &mut BytesMut, data: &[u8]) -> Result<(), WireError> {
    if data.len() > MAX_FRAME_PAYLOAD {
        return Err(WireError::FieldTooLarge("frame data", MAX_FRAME_PAYLOAD));
    }
    varint::encode(out, data.len() as u64)?;
    out.put_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(frame: Frame) {
        let mut wire = BytesMut::new();
        frame.encode(&mut wire).expect("encode");
        let mut read: &[u8] = &wire;
        assert_eq!(Frame::decode(&mut read).expect("decode"), frame);
        assert!(read.is_empty());
    }

    #[test]
    fn control_frames_round_trip() {
        for frame in [
            Frame::Ping,
            Frame::ResetStream {
                stream_id: 4,
                error_code: 0x10,
                final_size: 1024,
            },
            Frame::ResetStreamAt {
                stream_id: 6,
                error_code: 0x12,
                final_size: 2048,
                reliable_size: 1024,
            },
            Frame::StopSending {
                stream_id: 8,
                error_code: 0x11,
            },
            Frame::MaxData(1 << 20),
            Frame::MaxStreamData {
                stream_id: 12,
                maximum: 1 << 19,
            },
            Frame::MaxStreams {
                bidi: true,
                maximum: 100,
            },
            Frame::MaxStreams {
                bidi: false,
                maximum: 50,
            },
            Frame::DataBlocked(4096),
            Frame::StreamDataBlocked {
                stream_id: 4,
                maximum: 2048,
            },
            Frame::StreamsBlocked {
                bidi: true,
                maximum: 10,
            },
            Frame::RetireConnectionId(3),
            Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]),
            Frame::PathResponse([8, 7, 6, 5, 4, 3, 2, 1]),
            Frame::HandshakeDone,
        ] {
            round_trip(frame);
        }
    }

    #[test]
    fn data_frames_round_trip() {
        for frame in [
            Frame::Crypto {
                offset: 0,
                data: Bytes::from_static(b"client hello"),
            },
            Frame::NewToken {
                token: Bytes::from_static(b"token"),
            },
            Frame::Stream {
                stream_id: 0,
                offset: 0,
                fin: false,
                data: Bytes::from_static(b"hello"),
            },
            Frame::Stream {
                stream_id: 4,
                offset: 100,
                fin: true,
                data: Bytes::from_static(b"world"),
            },
            Frame::Datagram {
                data: Bytes::from_static(b"dgram"),
            },
        ] {
            round_trip(frame);
        }
    }

    #[test]
    fn ack_ranges_and_ecn_round_trip() {
        round_trip(Frame::Ack(AckFrame {
            largest_acknowledged: 100,
            ack_delay: 25,
            first_ack_range: 5,
            ranges: vec![AckRange { gap: 2, range: 3 }, AckRange { gap: 0, range: 1 }],
            ecn: Some(EcnCounts {
                ect0: 10,
                ect1: 20,
                ce: 1,
            }),
        }));
    }

    #[test]
    fn connection_id_and_close_round_trip() {
        round_trip(Frame::NewConnectionId {
            sequence: 7,
            retire_prior_to: 2,
            connection_id: vec![1, 2, 3, 4],
            reset_token: [9; 16],
        });
        round_trip(Frame::ConnectionCloseTransport {
            error_code: 0x0a,
            frame_type: 0x06,
            reason: Bytes::from_static(b"bad frame"),
        });
        round_trip(Frame::ConnectionCloseApplication {
            error_code: 0x100,
            reason: Bytes::from_static(b"done"),
        });
    }

    #[test]
    fn padding_runs_and_unlengthed_streams_are_decoded() {
        let mut padding: &[u8] = &[0, 0, 0, 1];
        assert_eq!(
            Frame::decode(&mut padding).expect("padding"),
            Frame::Padding { len: 3 }
        );
        assert_eq!(Frame::decode(&mut padding).expect("ping"), Frame::Ping);

        // STREAM without LEN (0x08) takes the rest of the packet.
        let mut stream: &[u8] = &[0x08, 0x00, b'h', b'i'];
        assert_eq!(
            Frame::decode(&mut stream).expect("stream"),
            Frame::Stream {
                stream_id: 0,
                offset: 0,
                fin: false,
                data: Bytes::from_static(b"hi"),
            }
        );
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let mut empty: &[u8] = &[];
        assert!(matches!(
            Frame::decode(&mut empty),
            Err(WireError::UnexpectedEnd)
        ));
        let mut unknown: &[u8] = &[0x3f];
        assert!(matches!(
            Frame::decode(&mut unknown),
            Err(WireError::UnknownFrame(0x3f))
        ));
        let mut bad_cid: &[u8] = &[0x18, 0x01, 0x00, 0x00];
        assert!(matches!(
            Frame::decode(&mut bad_cid),
            Err(WireError::InvalidFrame(_))
        ));
    }
}
