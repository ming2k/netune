// SPDX-License-Identifier: MIT

//! In-workspace byte-stream fuzz harness for `netune-http2` frame and HPACK decoders.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use bytes::Bytes;
use netune_http2::frame::{FRAME_HEADER_LEN, Frame, FrameHeader};
use netune_http2::hpack::HpackDecoder;
use netune_http2::huffman;
use test_support::fuzz::{run_fuzz, run_fuzz_soak};

const SEEDS: &[&[u8]] = &[
    // Empty SETTINGS frame
    &[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00],
    // SETTINGS ACK
    &[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00],
    // PING frame
    &[
        0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8,
    ],
    // WINDOW_UPDATE frame
    &[
        0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ],
    // HEADERS with indexed :method GET (0x82), :scheme https (0x87), :path / (0x84)
    &[
        0x00, 0x00, 0x03, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x82, 0x87, 0x84,
    ],
    // Padded DATA frame
    &[
        0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x02, b'h', b'i', 0x00, 0x00,
    ],
];

fn exercise(data: &[u8]) {
    let mut cursor = data;
    while cursor.len() >= FRAME_HEADER_LEN {
        let Some(header) = FrameHeader::parse(cursor) else {
            break;
        };
        let total = FRAME_HEADER_LEN + header.length as usize;
        if cursor.len() < total {
            break;
        }
        let payload = Bytes::copy_from_slice(&cursor[FRAME_HEADER_LEN..total]);
        let _ = Frame::decode(&header, payload);
        cursor = &cursor[total..];
    }

    let mut hpack = HpackDecoder::new();
    let _ = hpack.decode(data);
    let _ = huffman::decode(data);
}

#[test]
fn fuzz_http2_frames_and_hpack() {
    run_fuzz(SEEDS, exercise);
}

#[test]
#[ignore = "scheduled soak campaign; run with --profile soak --run-ignored ignored-only"]
fn soak_fuzz_http2_frames_and_hpack() {
    run_fuzz_soak(SEEDS, exercise);
}
