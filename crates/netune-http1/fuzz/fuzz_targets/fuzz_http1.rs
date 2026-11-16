#![no_main]

use http::Method;
use libfuzzer_sys::fuzz_target;
use netune_http1::{classify_target, validate_host_bytes};

fuzz_target!(|data: &[u8]| {
    let _ = classify_target(&Method::GET, data);
    let _ = classify_target(&Method::CONNECT, data);
    let _ = classify_target(&Method::OPTIONS, data);
    let _ = validate_host_bytes(data);
});
