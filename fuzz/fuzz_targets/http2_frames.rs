#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use netune_http2::frame::{FRAME_HEADER_LEN, Frame, FrameHeader};

fuzz_target!(|data: &[u8]| {
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
});
