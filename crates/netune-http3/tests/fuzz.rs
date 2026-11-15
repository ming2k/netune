// SPDX-License-Identifier: MIT

//! In-workspace byte-stream fuzz harness for `netune-http3` QPACK, frame, and capsule decoders.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use netune_http3::Capsule;
use netune_http3::qpack::decoder::decode_required_insert_count;
use netune_http3::qpack::instructions::{decode_decoder_instruction, decode_encoder_instruction};
use netune_http3::qpack::prefix::{decode_int, decode_string};
use netune_http3::qpack::{Decoder, huffman};
use test_support::fuzz::{run_fuzz, run_fuzz_soak};

const SEEDS: &[&[u8]] = &[
    &[0x00, 0x00, 0xd1, 0xd7, 0xc1],
    &[0x3f, 0x00],
    &[0x85, 0xf2, 0xb2, 0x4a, 0x84, 0xff],
    &[0x00, 0x04, b't', b'e', b's', b't'],
    &[0x40, 0x28, 0x43, 0x04, 0x00, 0x00, 0x00, 0x00],
];

fn exercise(data: &[u8]) {
    let mut cursor = data;
    let _ = decode_int(&mut cursor, 6);
    let mut cursor = data;
    let _ = decode_string(&mut cursor, 7, 1 << 20);
    let _ = decode_encoder_instruction(data, 1 << 20);
    let _ = decode_decoder_instruction(data);
    let _ = huffman::decode(data);
    if let Some((prefix, _)) = data.split_first() {
        let _ = decode_required_insert_count(u64::from(*prefix), 0, 1 << 20);
    }
    let mut decoder = Decoder::new(0);
    let _ = decoder.decode_section(0, data);
    let _ = Capsule::decode(data, 1 << 20);
}

#[test]
fn fuzz_h3_qpack_and_capsules() {
    run_fuzz(SEEDS, exercise);
}

#[test]
#[ignore = "scheduled soak campaign; run with --profile soak --run-ignored ignored-only"]
fn soak_fuzz_h3_qpack_and_capsules() {
    run_fuzz_soak(SEEDS, exercise);
}
