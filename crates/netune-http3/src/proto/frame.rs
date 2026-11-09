// SPDX-License-Identifier: MIT

//! HTTP/3 frame framing and asynchronous readers (RFC 9114 Section 7.2).

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::code::frame_type;
use super::settings::{Settings, SettingsError};
use super::varint;

/// A frame read from a request, response, or control stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A DATA frame header. The caller reads exactly `len` payload bytes.
    Data(u64),
    Headers(Bytes),
    Settings(Settings),
    GoAway(u64),
    CancelPush(u64),
    MaxPushId(u64),
    /// An unknown extension frame, already skipped.
    Unknown {
        ty: u64,
        len: u64,
    },
}

/// A malformed frame or a transport read failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("unexpected end of HTTP/3 frame")]
    UnexpectedEnd,
    #[error("invalid QUIC varint in HTTP/3 frame")]
    VarInt,
    #[error("HTTP/3 frame payload {len} exceeds limit {limit}")]
    TooLarge { len: u64, limit: usize },
    #[error("invalid SETTINGS frame: {0}")]
    Settings(#[from] SettingsError),
    #[error("HTTP/3 stream read failed: {0}")]
    Io(String),
}

impl Frame {
    pub fn frame_type(&self) -> u64 {
        match self {
            Self::Data(_) => frame_type::DATA,
            Self::Headers(_) => frame_type::HEADERS,
            Self::Settings(_) => frame_type::SETTINGS,
            Self::GoAway(_) => frame_type::GOAWAY,
            Self::CancelPush(_) => frame_type::CANCEL_PUSH,
            Self::MaxPushId(_) => frame_type::MAX_PUSH_ID,
            Self::Unknown { ty, .. } => *ty,
        }
    }
}

/// Read one frame. `Ok(None)` means the stream ended cleanly at a frame
/// boundary. A DATA frame is returned as a length; its payload remains unread.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_payload: usize,
) -> Result<Option<Frame>, FrameError> {
    let Some(ty) = read_varint(reader).await? else {
        return Ok(None);
    };
    let len = read_varint(reader)
        .await?
        .ok_or(FrameError::UnexpectedEnd)?;

    if ty == frame_type::DATA {
        return Ok(Some(Frame::Data(len)));
    }

    let known_payload = matches!(
        ty,
        frame_type::HEADERS
            | frame_type::SETTINGS
            | frame_type::GOAWAY
            | frame_type::CANCEL_PUSH
            | frame_type::MAX_PUSH_ID
    );
    if known_payload && len > max_payload as u64 {
        return Err(FrameError::TooLarge {
            len,
            limit: max_payload,
        });
    }
    if !known_payload {
        // Unknown and push frames do not need a payload. Skipping in chunks
        // avoids allocating up to the frame length for data we will discard.
        skip_exact(reader, len).await?;
        return Ok(Some(Frame::Unknown { ty, len }));
    }

    let payload = read_exact(reader, len as usize).await?;
    let frame = match ty {
        frame_type::HEADERS => Frame::Headers(payload),
        frame_type::SETTINGS => Frame::Settings(Settings::decode(&payload)?),
        frame_type::GOAWAY => Frame::GoAway(parse_single_varint(&payload)?),
        frame_type::CANCEL_PUSH => Frame::CancelPush(parse_single_varint(&payload)?),
        frame_type::MAX_PUSH_ID => Frame::MaxPushId(parse_single_varint(&payload)?),
        _ => Frame::Unknown { ty, len },
    };
    Ok(Some(frame))
}

fn parse_single_varint(payload: &[u8]) -> Result<u64, FrameError> {
    let mut cursor = payload;
    let value = varint::decode(&mut cursor).map_err(|_| FrameError::VarInt)?;
    if !cursor.is_empty() {
        return Err(FrameError::VarInt);
    }
    Ok(value)
}

pub(crate) async fn read_varint<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<u64>, FrameError> {
    let mut first = [0u8; 1];
    let read = reader
        .read(&mut first)
        .await
        .map_err(|error| FrameError::Io(error.to_string()))?;
    if read == 0 {
        return Ok(None);
    }
    let length = 1usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    let mut rest = [0u8; 7];
    let rest = &mut rest[..length - 1];
    reader
        .read_exact(rest)
        .await
        .map_err(|_| FrameError::UnexpectedEnd)?;
    for byte in rest {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(Some(value))
}

async fn read_exact<R: AsyncRead + Unpin>(reader: &mut R, len: usize) -> Result<Bytes, FrameError> {
    let mut payload = BytesMut::zeroed(len);
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| FrameError::UnexpectedEnd)?;
    Ok(payload.freeze())
}

async fn skip_exact<R: AsyncRead + Unpin>(reader: &mut R, mut len: u64) -> Result<(), FrameError> {
    let mut buffer = [0u8; 8192];
    while len > 0 {
        let take = usize::try_from(len.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = reader
            .read(&mut buffer[..take])
            .await
            .map_err(|error| FrameError::Io(error.to_string()))?;
        if read == 0 {
            return Err(FrameError::UnexpectedEnd);
        }
        len -= read as u64;
    }
    Ok(())
}

/// Write a HEADERS frame and its QPACK block.
pub async fn write_headers<W: AsyncWrite + Unpin>(
    writer: &mut W,
    block: &[u8],
) -> Result<(), FrameError> {
    write_header(writer, frame_type::HEADERS, block.len() as u64).await?;
    writer
        .write_all(block)
        .await
        .map_err(|error| FrameError::Io(error.to_string()))
}

/// Write a DATA frame header; the caller follows with exactly `len` bytes.
pub async fn write_data_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    len: u64,
) -> Result<(), FrameError> {
    write_header(writer, frame_type::DATA, len).await
}

/// Write a complete SETTINGS frame.
pub async fn write_settings<W: AsyncWrite + Unpin>(
    writer: &mut W,
    settings: &Settings,
) -> Result<(), FrameError> {
    let mut frame = BytesMut::new();
    settings.encode(&mut frame);
    writer
        .write_all(&frame)
        .await
        .map_err(|error| FrameError::Io(error.to_string()))
}

/// Write a GOAWAY frame.
pub async fn write_goaway<W: AsyncWrite + Unpin>(
    writer: &mut W,
    stream_id: u64,
) -> Result<(), FrameError> {
    let mut payload = BytesMut::new();
    varint::encode(&mut payload, stream_id).map_err(|_| FrameError::VarInt)?;
    write_header(writer, frame_type::GOAWAY, payload.len() as u64).await?;
    writer
        .write_all(&payload)
        .await
        .map_err(|error| FrameError::Io(error.to_string()))
}

async fn write_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ty: u64,
    len: u64,
) -> Result<(), FrameError> {
    let mut header = BytesMut::new();
    varint::encode(&mut header, ty).map_err(|_| FrameError::VarInt)?;
    varint::encode(&mut header, len).map_err(|_| FrameError::VarInt)?;
    writer
        .write_all(&header)
        .await
        .map_err(|error| FrameError::Io(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frames_round_trip_over_an_async_stream() {
        let (mut client, mut server) = duplex(1024);
        let task = tokio::spawn(async move {
            write_settings(&mut client, &Settings::default())
                .await
                .expect("settings");
            write_headers(&mut client, b"block").await.expect("headers");
            write_goaway(&mut client, 12).await.expect("goaway");
            write_data_header(&mut client, 3).await.expect("data");
            client.write_all(b"abc").await.expect("data payload");
        });

        assert!(matches!(
            read_frame(&mut server, 1024)
                .await
                .expect("settings")
                .expect("frame"),
            Frame::Settings(_)
        ));
        assert_eq!(
            read_frame(&mut server, 1024)
                .await
                .expect("headers")
                .expect("frame"),
            Frame::Headers(Bytes::from_static(b"block"))
        );
        assert_eq!(
            read_frame(&mut server, 1024)
                .await
                .expect("goaway")
                .expect("frame"),
            Frame::GoAway(12)
        );
        assert_eq!(
            read_frame(&mut server, 1024)
                .await
                .expect("data")
                .expect("frame"),
            Frame::Data(3)
        );
        let mut payload = [0u8; 3];
        server.read_exact(&mut payload).await.expect("payload");
        assert_eq!(&payload, b"abc");
        assert_eq!(read_frame(&mut server, 1024).await.expect("eof"), None);
        task.await.expect("writer");
    }

    #[tokio::test]
    async fn oversized_frames_are_rejected() {
        let (mut client, mut server) = duplex(1024);
        tokio::spawn(async move {
            let mut bytes = BytesMut::new();
            varint::encode(&mut bytes, frame_type::HEADERS).expect("type");
            varint::encode(&mut bytes, 2048).expect("len");
            let _ = client.write_all(&bytes).await;
        });
        assert!(matches!(
            read_frame(&mut server, 1024).await,
            Err(FrameError::TooLarge { .. })
        ));
    }
}
