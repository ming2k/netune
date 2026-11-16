#![no_main]

use libfuzzer_sys::fuzz_target;
use netune_quic::wire::frame::Frame;
use netune_quic::wire::packet::{LongPacket, ShortPacket, VersionNegotiation};
use netune_quic::wire::transport_parameters::TransportParameters;

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;
    while !cursor.is_empty() {
        if Frame::decode(&mut cursor).is_err() {
            break;
        }
    }

    let mut cursor = data;
    let _ = LongPacket::decode(&mut cursor, 1 << 20);
    let mut cursor = data;
    let _ = ShortPacket::decode(&mut cursor, 8, 1 << 20);
    let mut cursor = data;
    let _ = VersionNegotiation::decode(&mut cursor);
    let _ = TransportParameters::decode(data);
});
