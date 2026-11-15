// SPDX-License-Identifier: MIT

//! In-workspace byte-stream fuzz harness for `netune-quic` frame, packet, and transport-parameter decoders.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use netune_quic::wire::frame::Frame;
use netune_quic::wire::packet::{LongPacket, ShortPacket, VersionNegotiation};
use netune_quic::wire::transport_parameters::TransportParameters;
use test_support::fuzz::{run_fuzz, run_fuzz_soak};

const SEEDS: &[&[u8]] = &[
    // PING + PADDING + ACK
    &[0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00],
    // STREAM frame with offset and length
    &[0x0e, 0x00, 0x00, 0x04, b'p', b'i', b'n', b'g'],
    // RESET_STREAM_AT frame (0x24)
    &[0x24, 0x00, 0x07, 0x08, 0x04],
    // DATAGRAM frame (0x31)
    &[0x31, 0x03, 0x00, b'h', b'i'],
    // Long header Initial stub
    &[
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x01,
    ],
    // Version Negotiation stub
    &[
        0x80, 0x00, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4, 0x04, 5, 6, 7, 8, 0x00, 0x00, 0x00, 0x01,
    ],
];

fn exercise(data: &[u8]) {
    let mut cursor = data;
    while !cursor.is_empty() {
        if Frame::decode(&mut cursor).is_err() {
            break;
        }
    }

    let mut cursor = data;
    let _ = LongPacket::decode(&mut cursor, 1 << 20);
    let mut cursor = data;
    let _ = ShortPacket::decode(&mut cursor, 8, 1 << 20);
    let mut cursor = data;
    let _ = VersionNegotiation::decode(&mut cursor);
    let _ = TransportParameters::decode(data);
}

#[test]
fn fuzz_quic_frames_packets_and_transport_parameters() {
    run_fuzz(SEEDS, exercise);
}

#[test]
#[ignore = "scheduled soak campaign; run with --profile soak --run-ignored ignored-only"]
fn soak_fuzz_quic_frames_packets_and_transport_parameters() {
    run_fuzz_soak(SEEDS, exercise);
}
