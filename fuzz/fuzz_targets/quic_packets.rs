#![no_main]

use libfuzzer_sys::fuzz_target;
use netune_quic::wire::packet::{LongPacket, ShortPacket, VersionNegotiation};

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;
    let _ = LongPacket::decode(&mut cursor, 1 << 20);
    let mut cursor = data;
    let _ = ShortPacket::decode(&mut cursor, 8, 1 << 20);
    let mut cursor = data;
    let _ = VersionNegotiation::decode(&mut cursor);
});
