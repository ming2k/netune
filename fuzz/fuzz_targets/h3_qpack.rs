#![no_main]

use libfuzzer_sys::fuzz_target;
use netune_http3::qpack::decoder::decode_required_insert_count;
use netune_http3::qpack::instructions::{decode_decoder_instruction, decode_encoder_instruction};
use netune_http3::qpack::prefix::{decode_int, decode_string};
use netune_http3::qpack::{Decoder, huffman};

fuzz_target!(|data: &[u8]| {
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
});
