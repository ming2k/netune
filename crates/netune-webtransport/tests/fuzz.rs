// SPDX-License-Identifier: MIT

//! In-workspace byte-stream fuzz harness for `netune-webtransport` capsules, stream headers, and origins.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use netune_http3::Capsule;
use netune_webtransport::{
    ControlCapsule, WebTransportOrigin, parse_bidi_header, parse_uni_header,
};
use test_support::fuzz::{run_fuzz, run_fuzz_soak};

const SEEDS: &[&[u8]] = &[
    // WT_UNI_STREAM_TYPE (0x54) + session 0
    &[0x40, 0x54, 0x00],
    // WT_STREAM_SIGNAL (0x41) + session 4
    &[0x40, 0x41, 0x04],
    // WT_CLOSE_SESSION (0x2843) capsule
    &[0x68, 0x43, 0x06, 0x00, 0x00, 0x00, 0x07, b'o', b'k'],
    // WT_DRAIN_SESSION (0x78ae) capsule
    &[0x78, 0xae, 0x00],
    // WT_MAX_DATA (0x190b4d3d) capsule
    &[0x99, 0x0b, 0x4d, 0x3d, 0x02, 0x44, 0x00],
    b"https://localhost:8443",
];

fn exercise(data: &[u8]) {
    if let Ok(Some((capsule, _))) = Capsule::decode(data, 1 << 20) {
        let _ = ControlCapsule::from_capsule(&capsule);
    }
    let _ = parse_uni_header(data);
    let _ = parse_bidi_header(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = WebTransportOrigin::parse(text);
    }
}

#[test]
fn fuzz_webtransport_capsules_and_headers() {
    run_fuzz(SEEDS, exercise);
}

#[test]
#[ignore = "scheduled soak campaign; run with --profile soak --run-ignored ignored-only"]
fn soak_fuzz_webtransport_capsules_and_headers() {
    run_fuzz_soak(SEEDS, exercise);
}
