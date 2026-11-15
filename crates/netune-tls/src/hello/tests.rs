//! The 1.5.9 capture corpus is the acceptance criterion (ADR-0045 step 1).
//!
//! Every test here parses the serialized hello with the independent
//! `netune-trace` parser and compares against the measured values: the fixed
//! extension order, the 13-suite / 7-group / 13-scheme offers, and the JA3
//! and JA4 fingerprints reported for the captured hellos.

use super::{
    BlueprintBuildParams, ClientHello, ClientHelloBlueprint, Extension, ExtensionBody, GoIdentity,
    KeyShareEntry,
};
use netune_trace::{ClientHello as Parsed, is_grease, ja3, ja4};

/// The 32-byte random of a corpus probe; the value is arbitrary, the length
/// is the contract.
const TEST_RANDOM: [u8; 32] = [0x5a; 32];

/// A 32-byte session id, the shape the captured hello carries.
const TEST_SESSION_ID: [u8; 32] = [0xc3; 32];

/// Key shares of the measured shape: hybrid group first, then `x25519`.
/// The bytes are arbitrary; the groups and order are the contract.
fn test_key_shares() -> Vec<KeyShareEntry> {
    vec![
        KeyShareEntry {
            group: 0x11ec, // X25519MLKEM768
            share: vec![0x11; 1216],
        },
        KeyShareEntry {
            group: 0x001d, // x25519
            share: vec![0x22; 32],
        },
    ]
}

fn unary_identity() -> ClientHello {
    ClientHello::go_identity(GoIdentity {
        server_name: "daily-cloudcode-pa.googleapis.com",
        alpn: &[b"http/1.1"],
        random: TEST_RANDOM,
        session_id: &TEST_SESSION_ID,
        key_shares: test_key_shares(),
        cipher_suites: None,
        kx_groups: None,
    })
}

/// The measured extension order, as captured on all 75 hellos.
const MEASURED_EXTENSION_ORDER: [u16; 12] = [
    0x0000, 0x000b, 0xff01, 0x0017, 0x0012, 0x0005, 0x000a, 0x000d, 0x0032, 0x0010, 0x002b, 0x0033,
];

#[test]
fn unary_hello_matches_the_measured_corpus() {
    let hello = unary_identity();
    let bytes = hello.serialize().expect("the corpus hello encodes");
    let parsed = Parsed::parse(&bytes).expect("the corpus hello parses");

    // No GREASE anywhere, as measured.
    assert!(!hello.cipher_suites.iter().copied().any(is_grease));
    assert!(!parsed.extensions.iter().copied().any(is_grease));

    // The fixed extension order is the identity.
    assert_eq!(parsed.extensions, MEASURED_EXTENSION_ORDER);

    // 13 suites, in Go's offer order.
    assert_eq!(
        parsed.cipher_suites,
        vec![
            0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x1301,
            0x1302, 0x1303
        ],
    );

    // 7 hybrid-first groups, in Go's offer order.
    assert_eq!(
        parsed.supported_groups,
        vec![0x11ec, 0x11eb, 0x11ed, 0x001d, 0x0017, 0x0018, 0x0019],
    );

    // 13 ML-DSA-first signature schemes, in Go's offer order.
    assert_eq!(
        parsed.signature_algorithms,
        vec![
            0x0904, 0x0905, 0x0906, 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
            0x0503, 0x0603
        ],
    );

    // The rest of the measured shape.
    assert_eq!(parsed.ec_point_formats, vec![0x00]);
    assert_eq!(parsed.legacy_version, 0x0303);
    assert_eq!(parsed.supported_versions_max, Some(0x0304));
    assert!(parsed.has_sni);
    assert_eq!(parsed.alpn_protocols, vec![b"http/1.1".to_vec()]);

    // The measured fingerprints.
    let ja3 = ja3(&parsed).expect("all JA3 lists present");
    assert_eq!(
        ja3.string,
        "771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-4865-4866-4867,\
         0-11-65281-23-18-5-10-13-50-16-43-51,4588-4587-4589-29-23-24-25,0",
    );
    assert_eq!(ja3.md5, "03117a8ed39ef02427ebbc39f121275c");
    assert_eq!(
        ja4(&parsed).fingerprint,
        "t13d1312h1_f57a46bbacb6_f50d94e863eb"
    );
}

#[test]
fn stream_offer_matches_the_h2_ja4() {
    let hello = ClientHello::go_identity(GoIdentity {
        server_name: "play.googleapis.com",
        alpn: &[b"h2", b"http/1.1"],
        random: TEST_RANDOM,
        session_id: &TEST_SESSION_ID,
        key_shares: test_key_shares(),
        cipher_suites: None,
        kx_groups: None,
    });
    let bytes = hello.serialize().expect("the stream hello encodes");
    let parsed = Parsed::parse(&bytes).expect("the stream hello parses");

    assert_eq!(
        parsed.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    // Only the ALPN digit differs between the two measured offers.
    assert_eq!(
        ja4(&parsed).fingerprint,
        "t13d1312h2_f57a46bbacb6_f50d94e863eb"
    );
}

#[test]
fn extension_order_is_identity() {
    // Swapping two extensions leaves every list intact and changes the JA3
    // extension field: order is data, not serialization accident.
    let base = unary_identity();
    let bytes = base.serialize().expect("encodes");
    let base_ja3 = ja3(&Parsed::parse(&bytes).expect("parses")).expect("lists present");

    let mut swapped = unary_identity();
    swapped.extensions.swap(4, 5); // SCT before/after status_request
    let bytes = swapped.serialize().expect("encodes");
    let swapped_ja3 = ja3(&Parsed::parse(&bytes).expect("parses")).expect("lists present");

    assert_ne!(
        base_ja3.md5, swapped_ja3.md5,
        "extension order changed the JA3"
    );
}

#[test]
fn extension_types_follow_the_bodies() {
    let hello = unary_identity();
    let kinds: Vec<u16> = hello.extensions.iter().map(Extension::kind).collect();
    assert_eq!(kinds, MEASURED_EXTENSION_ORDER);
}

#[test]
fn record_layer_frames_the_handshake() {
    let hello = unary_identity();
    let message = hello.serialize().expect("encodes");
    let record = hello.serialize_record().expect("encodes");

    assert_eq!(record[0], 0x16, "content type: handshake");
    assert_eq!(
        &record[1..3],
        &0x0301u16.to_be_bytes(),
        "legacy record version"
    );
    assert_eq!(
        u16::from_be_bytes([record[3], record[4]]) as usize,
        message.len(),
        "record length covers the handshake message",
    );
    assert_eq!(&record[5..], &message[..], "the message follows the header");
    assert_eq!(message[0], 0x01, "handshake type: client_hello");
}

#[test]
fn wire_limit_refusals() {
    // Session id over the RFC 5246 32-byte bound.
    let mut hello = unary_identity();
    hello.session_id = vec![0x00; 33];
    assert_eq!(
        hello.serialize().unwrap_err().to_string(),
        "session id of 33 bytes exceeds the 32-byte RFC 5246 limit"
    );

    // Empty key share: a real offer never carries one.
    let mut hello = unary_identity();
    for extension in &mut hello.extensions {
        if let ExtensionBody::KeyShare { shares } = &mut extension.body {
            shares.push(KeyShareEntry {
                group: 0x001d,
                share: Vec::new(),
            });
        }
    }
    assert_eq!(
        hello.serialize().unwrap_err().to_string(),
        "key share for group 0x001d is empty"
    );

    // Empty ALPN name: refused by RFC 7301 §3.1.
    let mut hello = unary_identity();
    for extension in &mut hello.extensions {
        if let ExtensionBody::Alpn { protocols } = &mut extension.body {
            protocols.insert(0, Vec::new());
        }
    }
    assert_eq!(
        hello.serialize().unwrap_err().to_string(),
        "ALPN protocol names must be non-empty (RFC 7301 §3.1)"
    );

    // An extension body over the 16-bit vector limit.
    let mut hello = unary_identity();
    hello.extensions.push(Extension {
        body: ExtensionBody::Raw {
            kind: 0x1234,
            body: vec![0x00; u16::MAX as usize + 1],
        },
    });
    assert_eq!(
        hello.serialize().unwrap_err().to_string(),
        "extension 0x1234 body of 65536 bytes exceeds the 65,535-byte wire limit"
    );
}

#[test]
fn the_h2_offer_randomizes_like_go_does_at_the_h1_layer_not_here() {
    // The connection-level hello is byte-stable for a fixed identity; the
    // per-request regular-header randomization lives in the h2 request
    // profile (ADR-0046), not in the TLS handshake.
    let first = unary_identity();
    let second = unary_identity();
    assert_eq!(
        first, second,
        "same identity, same hello: the profile is pure"
    );
}

#[test]
fn go_boringcrypto_blueprint_matches_go_identity_byte_for_byte() {
    let expected_hello = unary_identity();
    let expected = expected_hello.serialize().expect("unary encodes");
    let blueprint = ClientHelloBlueprint::go_boringcrypto();
    let built = blueprint
        .build(BlueprintBuildParams {
            server_name: "daily-cloudcode-pa.googleapis.com",
            random: TEST_RANDOM,
            session_id: &expected_hello.session_id,
            key_shares: match &expected_hello.extensions.last().unwrap().body {
                ExtensionBody::KeyShare { shares } => shares.clone(),
                _ => unreachable!(),
            },
            grease_seed: [0; 8],
            permutation_seed: [0; 32],
        })
        .expect("blueprint builds")
        .serialize()
        .expect("blueprint encodes");
    assert_eq!(built, expected);
}

#[test]
fn chrome_blueprint_applies_grease_permutation_and_517_padding() {
    let blueprint = ClientHelloBlueprint::chrome_current();
    let params_a = BlueprintBuildParams {
        server_name: "example.com",
        random: [0xaa; 32],
        session_id: &[0xbb; 32],
        key_shares: vec![
            KeyShareEntry {
                group: 0x11ec,
                share: vec![0x11; 1216],
            },
            KeyShareEntry {
                group: 0x001d,
                share: vec![0x22; 32],
            },
        ],
        grease_seed: [0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x06, 0x07],
        permutation_seed: [0x55; 32],
    };
    let hello_a1 = blueprint
        .build(params_a.clone())
        .expect("builds")
        .serialize()
        .expect("encodes");
    let hello_a2 = blueprint
        .build(params_a)
        .expect("builds")
        .serialize()
        .expect("encodes");
    assert_eq!(hello_a1, hello_a2, "same seeds produce identical bytes");

    let parsed_a =
        netune_trace::ClientHello::parse(&hello_a1).expect("chrome hello parses via trace");
    assert!(
        crate::wire::is_grease(parsed_a.cipher_suites[0]),
        "first cipher suite is GREASE"
    );
    assert!(
        crate::wire::is_grease(parsed_a.extensions[0]),
        "first extension slot is pinned GREASE"
    );
    // Two GREASE extensions in the same hello must never collide.
    let grease_exts: Vec<u16> = parsed_a
        .extensions
        .iter()
        .copied()
        .filter(|&k| crate::wire::is_grease(k))
        .collect();
    assert_eq!(grease_exts.len(), 2);
    assert_ne!(grease_exts[0], grease_exts[1]);

    // Different permutation seed changes the non-pinned extension order.
    let hello_b = blueprint
        .build(BlueprintBuildParams {
            server_name: "example.com",
            random: [0xaa; 32],
            session_id: &[0xbb; 32],
            key_shares: vec![
                KeyShareEntry {
                    group: 0x11ec,
                    share: vec![0x11; 1216],
                },
                KeyShareEntry {
                    group: 0x001d,
                    share: vec![0x22; 32],
                },
            ],
            grease_seed: [0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x06, 0x07],
            permutation_seed: [0x99; 32],
        })
        .expect("builds")
        .serialize()
        .expect("encodes");
    let parsed_b =
        netune_trace::ClientHello::parse(&hello_b).expect("chrome hello b parses via trace");
    assert_ne!(parsed_a.extensions, parsed_b.extensions);
    assert_eq!(parsed_a.extensions[0], parsed_b.extensions[0]);

    // When unpadded body is in 256..512 (e.g. without X25519MLKEM768 share),
    // BoringSsl517 pads the body to 512 bytes (516-byte handshake message).
    let compact_hello = blueprint
        .build(BlueprintBuildParams {
            server_name: "example.com",
            random: [0xaa; 32],
            session_id: &[0xbb; 32],
            key_shares: vec![KeyShareEntry {
                group: 0x001d,
                share: vec![0x22; 32],
            }],
            grease_seed: [0x01; 8],
            permutation_seed: [0x55; 32],
        })
        .expect("builds")
        .serialize()
        .expect("encodes");
    assert_eq!(compact_hello.len() - 4, 512, "padded to 512-byte body");
}

#[test]
fn firefox_safari_and_go_standard_blueprints_parse_cleanly() {
    for (name, bp) in [
        ("go_standard", ClientHelloBlueprint::go_standard()),
        ("firefox_current", ClientHelloBlueprint::firefox_current()),
        ("safari_current", ClientHelloBlueprint::safari_current()),
    ] {
        let shares: Vec<KeyShareEntry> = bp
            .key_share_groups
            .iter()
            .map(|&group| KeyShareEntry {
                group,
                share: vec![0x77; 32],
            })
            .collect();
        let bytes = bp
            .build(BlueprintBuildParams {
                server_name: "example.com",
                random: [0x33; 32],
                session_id: &[0x44; 32],
                key_shares: shares,
                grease_seed: [0x12; 8],
                permutation_seed: [0x34; 32],
            })
            .unwrap_or_else(|e| panic!("{name} build: {e}"))
            .serialize()
            .unwrap_or_else(|e| panic!("{name} serialize: {e}"));
        let parsed = netune_trace::ClientHello::parse(&bytes)
            .unwrap_or_else(|| panic!("{name} parse failed"));
        assert!(!parsed.extensions.is_empty(), "{name}: extensions");
    }
}
