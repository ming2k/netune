#![no_main]

use libfuzzer_sys::fuzz_target;
use netune_http3::Capsule;
use netune_webtransport::{ControlCapsule, parse_bidi_header, parse_uni_header};

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((capsule, _))) = Capsule::decode(data, 1 << 20) {
        let _ = ControlCapsule::from_capsule(&capsule);
    }
    let _ = parse_uni_header(data);
    let _ = parse_bidi_header(data);
});
