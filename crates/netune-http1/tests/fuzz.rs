// SPDX-License-Identifier: MIT

//! In-workspace byte-stream fuzz harness for `netune-http1` parsers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::Method;
use netune_http1::{classify_target, validate_host_bytes};
use test_support::fuzz::{run_fuzz, run_fuzz_soak};

const SEEDS: &[&[u8]] = &[
    b"/",
    b"/index.html?x=1&y=2",
    b"*",
    b"example.com:443",
    b"[::1]:8443",
    b"http://example.com:8080/path",
    b"localhost",
    b"sub.domain.example.com:8080",
    b"bad host\r\ninjected: 1",
    b"http://[::1]:80/a?b#c",
];

fn exercise(data: &[u8]) {
    let _ = classify_target(&Method::GET, data);
    let _ = classify_target(&Method::CONNECT, data);
    let _ = classify_target(&Method::OPTIONS, data);
    let _ = validate_host_bytes(data);
}

#[test]
fn fuzz_http1_target_and_host_grammar() {
    run_fuzz(SEEDS, exercise);
}

#[test]
#[ignore = "scheduled soak campaign; run with --profile soak --run-ignored ignored-only"]
fn soak_fuzz_http1_target_and_host_grammar() {
    run_fuzz_soak(SEEDS, exercise);
}
