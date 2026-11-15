use super::*;

/// Build an Ethernet + IPv4 + TCP frame with the given payload.
fn frame(
    source: ([u8; 4], u16),
    destination: ([u8; 4], u16),
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let ip_len = 20 + tcp_len;
    let mut frame = vec![0u8; ETH_HEADER_LEN + ip_len];
    // Ethernet
    frame[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    // IPv4
    let ip = &mut frame[ETH_HEADER_LEN..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    ip[12..16].copy_from_slice(&source.0);
    ip[16..20].copy_from_slice(&destination.0);
    // TCP
    let tcp = &mut ip[20..];
    tcp[0..2].copy_from_slice(&source.1.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination.1.to_be_bytes());
    tcp[4..8].copy_from_slice(&1234u32.to_be_bytes());
    tcp[8..12].copy_from_slice(&5678u32.to_be_bytes());
    tcp[12] = 0x50; // 20-byte data offset
    tcp[13] = flags;
    tcp[20..].copy_from_slice(payload);
    frame
}

#[test]
fn a_data_segment_parses_with_its_flow_and_payload_length() {
    let bytes = frame(
        ([127, 0, 0, 1], 51_234),
        ([127, 0, 0, 1], 443),
        FLAG_PSH | FLAG_ACK,
        b"data: hello\n\n",
    );
    let segment = parse_ethernet_ipv4_tcp(&bytes).expect("parse");
    assert_eq!(segment.source, ([127, 0, 0, 1], 51_234));
    assert_eq!(segment.destination, ([127, 0, 0, 1], 443));
    assert_eq!(segment.flags, FLAG_PSH | FLAG_ACK);
    assert_eq!(segment.payload_len, 13);
    assert_eq!(
        matches_flow(&segment, ([127, 0, 0, 1], 51_234), ([127, 0, 0, 1], 443)),
        Some(true)
    );
    assert_eq!(
        matches_flow(&segment, ([127, 0, 0, 1], 443), ([127, 0, 0, 1], 51_234)),
        Some(false)
    );
    assert_eq!(
        matches_flow(&segment, ([127, 0, 0, 1], 9), ([127, 0, 0, 1], 443)),
        None
    );
}

#[test]
fn a_bare_ack_has_no_payload() {
    let bytes = frame(([10, 0, 0, 1], 443), ([10, 0, 0, 2], 51_234), FLAG_ACK, &[]);
    let segment = parse_ethernet_ipv4_tcp(&bytes).expect("parse");
    assert_eq!(segment.payload_len, 0);
    assert!(segment.is_bare_ack());
    assert!(!segment.carries_data());
}

#[test]
fn ethernet_padding_is_not_counted_as_payload() {
    // A 60-byte frame: the NIC pads the tail, the IP length does not.
    let mut bytes = frame(
        ([10, 0, 0, 1], 443),
        ([10, 0, 0, 2], 51_234),
        FLAG_ACK,
        b"hi",
    );
    bytes.resize(60, 0);
    let segment = parse_ethernet_ipv4_tcp(&bytes).expect("parse");
    assert_eq!(
        segment.payload_len, 2,
        "padding must not inflate the payload"
    );
}

#[test]
fn ip_options_and_tcp_options_shift_the_payload_correctly() {
    let mut bytes = frame(
        ([10, 0, 0, 1], 443),
        ([10, 0, 0, 2], 51_234),
        FLAG_ACK,
        b"payload",
    );
    // Give the TCP header 4 bytes of options and adjust both lengths.
    let tcp_start = ETH_HEADER_LEN + 20;
    let mut new = Vec::new();
    new.extend_from_slice(&bytes[..tcp_start]);
    new.extend_from_slice(&bytes[tcp_start..tcp_start + 12]);
    new.push(0x60); // data offset 6 words = 24 bytes
    new.extend_from_slice(&bytes[tcp_start + 13..tcp_start + 20]);
    new.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // NOP padding
    new.extend_from_slice(&bytes[tcp_start + 20..]);
    bytes = new;
    let ip_len = (bytes.len() - ETH_HEADER_LEN) as u16;
    bytes[ETH_HEADER_LEN + 2..ETH_HEADER_LEN + 4].copy_from_slice(&ip_len.to_be_bytes());
    let segment = parse_ethernet_ipv4_tcp(&bytes).expect("parse");
    assert_eq!(segment.payload_len, 7);
}

#[test]
fn a_vlan_tagged_frame_is_unwrapped() {
    let plain = frame(
        ([10, 0, 0, 1], 443),
        ([10, 0, 0, 2], 51_234),
        FLAG_ACK,
        b"x",
    );
    let mut tagged = Vec::new();
    tagged.extend_from_slice(&plain[..12]);
    tagged.extend_from_slice(&0x8100u16.to_be_bytes());
    tagged.extend_from_slice(&[0x00, 0x64]); // VLAN id 100
    tagged.extend_from_slice(&plain[12..]);
    let segment = parse_ethernet_ipv4_tcp(&tagged).expect("parse");
    assert_eq!(segment.payload_len, 1);
}

#[test]
fn frames_we_do_not_model_are_refused_rather_than_guessed() {
    // Truncated Ethernet.
    assert_eq!(parse_ethernet_ipv4_tcp(&[0u8; 10]), None);
    // IPv6.
    let mut ipv6 = frame(([10, 0, 0, 1], 443), ([10, 0, 0, 2], 51_234), FLAG_ACK, b"");
    ipv6[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
    assert_eq!(parse_ethernet_ipv4_tcp(&ipv6), None);
    // Non-TCP.
    let mut udp = frame(([10, 0, 0, 1], 443), ([10, 0, 0, 2], 51_234), FLAG_ACK, b"");
    udp[ETH_HEADER_LEN + 9] = 17;
    assert_eq!(parse_ethernet_ipv4_tcp(&udp), None);
    // A non-first fragment carries no transport header.
    let mut fragmented = frame(([10, 0, 0, 1], 443), ([10, 0, 0, 2], 51_234), FLAG_ACK, b"");
    fragmented[ETH_HEADER_LEN + 6] = 0x00;
    fragmented[ETH_HEADER_LEN + 7] = 0x08;
    assert_eq!(parse_ethernet_ipv4_tcp(&fragmented), None);
}

// -- the construction half --------------------------------------------

fn spec() -> FrameSpec {
    FrameSpec {
        source_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        destination_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        source: ([127, 0, 0, 1], 51_234),
        destination: ([127, 0, 0, 1], 443),
        seq: 1_000_000,
        ack: 65_535,
        flags: FLAG_RST | FLAG_ACK,
        window: 502,
        payload: b"",
    }
}

#[test]
fn a_built_rst_parses_back_with_every_forged_field() {
    let bytes = build_ethernet_ipv4_tcp(&spec());
    let segment = parse_ethernet_ipv4_tcp(&bytes).expect("a built frame always parses");
    assert_eq!(segment.source, ([127, 0, 0, 1], 51_234));
    assert_eq!(segment.destination, ([127, 0, 0, 1], 443));
    assert_eq!(segment.seq, 1_000_000, "the forged sequence number");
    assert_eq!(segment.ack, 65_535, "the forged acknowledgement");
    assert_eq!(segment.flags, FLAG_RST | FLAG_ACK);
    assert_eq!(segment.payload_len, 0);
    // The receiver's direction: a frame from `local` toward `remote`.
    assert_eq!(
        matches_flow(&segment, ([127, 0, 0, 1], 51_234), ([127, 0, 0, 1], 443)),
        Some(true)
    );
}

#[test]
fn a_built_data_segment_round_trips_its_payload() {
    let mut forged = spec();
    forged.flags = FLAG_PSH | FLAG_ACK;
    forged.payload = b"data: forged\n\n";
    let bytes = build_ethernet_ipv4_tcp(&forged);
    let segment = parse_ethernet_ipv4_tcp(&bytes).expect("parse");
    assert_eq!(segment.payload_len, 14);
    assert!(segment.carries_data());
    assert!(!segment.is_bare_ack());
}

#[test]
fn a_built_frame_carries_a_valid_ipv4_checksum() {
    let bytes = build_ethernet_ipv4_tcp(&spec());
    let header = &bytes[ETH_HEADER_LEN..ETH_HEADER_LEN + 20];
    assert!(
        ipv4_checksum_ok(header),
        "the builder writes a checksum a validator accepts: {header:02x?}"
    );
}

#[test]
fn a_corrupted_checksum_is_detected() {
    let mut bytes = build_ethernet_ipv4_tcp(&spec());
    bytes[ETH_HEADER_LEN + 10] ^= 0xFF;
    assert!(!ipv4_checksum_ok(
        &bytes[ETH_HEADER_LEN..ETH_HEADER_LEN + 20]
    ));
}

#[test]
fn seq_and_ack_are_independent_dials() {
    // The whole point of the forge: same flow, arbitrary chosen seq/ack.
    for (seq, ack) in [
        (0u32, 0u32),
        (0xFFFF_FFFF, 1),
        (4_294_967_000, 4_294_967_295),
    ] {
        let mut forged = spec();
        forged.seq = seq;
        forged.ack = ack;
        let segment = parse_ethernet_ipv4_tcp(&build_ethernet_ipv4_tcp(&forged)).expect("parse");
        assert_eq!(segment.seq, seq);
        assert_eq!(segment.ack, ack);
    }
}

// The privilege gate is structural, not a test: `Capture::send_frame`
// exists only under `--features inject`, so the default build has no
// transmit path to call. `cargo build` (no features) + `cargo build
// --features inject` both being green above is the gate; this comment is
// the map from here to the boundary.
#[cfg(feature = "inject")]
#[test]
fn compile_only_marker_for_the_inject_feature() {
    // Referencing the gated symbol so the feature's code is not dead in
    // a feature-enabled test build; the assertion itself is trivial.
    assert!(
        std::any::type_name::<crate::capture::Capture>().contains("Capture"),
        "the send path compiles under inject"
    );
}
