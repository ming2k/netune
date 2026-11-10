#![no_main]

use libfuzzer_sys::fuzz_target;
use netune_quic::wire::frame::Frame;

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;
    while !cursor.is_empty() {
        match Frame::decode(&mut cursor) {
            Ok(_) => {}
            Err(_) => break,
        }
    }
});
