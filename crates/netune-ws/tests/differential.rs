#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Differential oracle: our codec must agree with `tungstenite` (the
//! battle-tested RFC 6455 engine under `tokio-tungstenite`) on frame encoding
//! and decoding.
//!
//! Mirrors `netune-http1`'s `tests/differential.rs` discipline: the same
//! logical frame is encoded by both implementations and compared
//! byte-for-byte, and the same wire bytes are decoded by both and compared
//! field-for-field, across the length-boundary sizes (125/126/65535/65536)
//! where hand-rolled codecs historically go wrong.
//!
//! `tokio-tungstenite` is a dev-dependency only; it never enters the
//! production graph ([INV-TRANSPORT-00]).

use std::io::Cursor;

use bytes::{Bytes, BytesMut};
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Control, Data, OpCode as TOpCode};
use tokio_tungstenite::tungstenite::protocol::frame::{Frame as TFrame, FrameHeader, FrameSocket};

use netune_ws::{Frame, FrameDecoder, FrameEncoder, Opcode, Role};

/// The tungstenite `OpCode` for one of our opcodes.
fn t_opcode(opcode: Opcode) -> TOpCode {
    match opcode {
        Opcode::Continuation => TOpCode::Data(Data::Continue),
        Opcode::Text => TOpCode::Data(Data::Text),
        Opcode::Binary => TOpCode::Data(Data::Binary),
        Opcode::Close => TOpCode::Control(Control::Close),
        Opcode::Ping => TOpCode::Control(Control::Ping),
        Opcode::Pong => TOpCode::Control(Control::Pong),
    }
}

/// Encode with tungstenite into raw wire bytes (unmasked — the same shape our
/// `mask: None` encoding produces for server-to-client frames).
fn tungstenite_encode(frame: &Frame) -> Vec<u8> {
    let header = FrameHeader {
        is_final: frame.fin,
        rsv1: frame.rsv[0],
        rsv2: frame.rsv[1],
        rsv3: frame.rsv[2],
        opcode: t_opcode(frame.opcode),
        mask: None,
    };
    let tframe = TFrame::from_payload(header, Bytes::from(frame.payload.to_vec()));
    let mut out = Vec::new();
    tframe.format(&mut out).expect("tungstenite format");
    out
}

fn our_frame(size: usize, seed: u8) -> Frame {
    let payload: Vec<u8> = (0..size).map(|i| ((i as u8) ^ seed) % 128).collect();
    Frame::binary(Bytes::from(payload))
}

#[test]
fn frame_encoding_agrees_with_tungstenite_across_length_boundaries() {
    for size in [0usize, 1, 125, 126, 127, 65535, 65536] {
        let frame = our_frame(size, 31);

        let mut ours = BytesMut::new();
        FrameEncoder::encode(&frame, None, &mut ours);

        let theirs = tungstenite_encode(&frame);
        assert_eq!(
            ours.as_ref(),
            theirs.as_slice(),
            "frame encoding diverges from tungstenite at size {size}"
        );
    }
}

#[test]
fn wire_bytes_decode_identically_across_length_boundaries() {
    for size in [0usize, 1, 125, 126, 127, 65535, 65536] {
        let frame = our_frame(size, 17);
        let expected: Vec<u8> = (0..size).map(|i| ((i as u8) ^ 17) % 128).collect();

        // Encode with tungstenite, decode with ours.
        let wire = tungstenite_encode(&frame);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&wire);
        let ours_decoded = FrameDecoder::decode(&mut buf, Role::Client, 1024 * 1024)
            .expect("our decode of tungstenite bytes")
            .expect("complete frame");
        assert_eq!(ours_decoded.opcode, Opcode::Binary);
        assert_eq!(ours_decoded.payload.as_ref(), expected.as_slice());

        // Encode with ours, decode with tungstenite (via its public
        // FrameSocket reader over an in-memory stream).
        let mut buf = BytesMut::new();
        FrameEncoder::encode(&frame, None, &mut buf);
        let mut socket = FrameSocket::new(Cursor::new(buf.to_vec()));
        let tframe = socket
            .read(Some(1024 * 1024))
            .expect("tungstenite parses our wire bytes")
            .expect("complete tungstenite frame");
        assert_eq!(tframe.payload().len(), size);
        assert_eq!(tframe.payload(), expected.as_slice());
    }
}

#[test]
fn masked_frame_unmasking_agrees() {
    // Our decoder must unmask exactly what tungstenite's apply_mask unmasks.
    // tungstenite's `apply_mask` is not publicly re-exported, so the oracle
    // here is its `Frame::parse` path: build a masked frame via
    // `FrameHeader { mask: Some(...) }` + `format`, which runs tungstenite's
    // own masking on the way out, then decode with ours.
    let payload: Vec<u8> = (0..300u16).map(|i| (i * 7) as u8).collect();
    let mask = [0xde, 0xad, 0xbe, 0xef];

    let header = FrameHeader {
        is_final: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: TOpCode::Data(Data::Binary),
        mask: Some(mask),
    };
    let tframe = TFrame::from_payload(header, Bytes::from(payload.clone()));
    let mut masked_wire = Vec::new();
    tframe
        .format(&mut masked_wire)
        .expect("tungstenite masked format");

    let mut buf = BytesMut::new();
    buf.extend_from_slice(&masked_wire);
    let decoded = FrameDecoder::decode(&mut buf, Role::Server, 1024 * 1024)
        .expect("our unmasking decode")
        .expect("complete frame");
    assert_eq!(decoded.payload.as_ref(), payload.as_slice());
}
