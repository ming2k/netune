#![no_main]

use libfuzzer_sys::fuzz_target;
use netune_tls::cert::subject_public_key_info;
use netune_tls::record::RecordHeader;

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;
    while cursor.len() >= 5 {
        let Ok(header) = RecordHeader::parse(&cursor[..5]) else {
            break;
        };
        let rest = &cursor[5..];
        let len = usize::from(header.payload_len);
        if rest.len() < len {
            break;
        }
        cursor = &rest[len..];
    }
    let _ = subject_public_key_info(data);
});
