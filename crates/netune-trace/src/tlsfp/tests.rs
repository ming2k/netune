use super::*;

#[test]
fn grease_values_are_recognized() {
    assert!(is_grease(0x0A0A));
    assert!(is_grease(0x1A1A));
    assert!(is_grease(0xFAFA));
    assert!(!is_grease(0x1301));
    assert!(!is_grease(0x0000));
    assert!(!is_grease(0xFF01));
    assert!(is_grease(0xAAAA), "0x?A?A with ? = 0xA is GREASE");
}

/// The FoxIO JA4 worked example, reconstructed field by field: a
/// Chrome-shaped hello with 15 ciphers, 16 extensions, ALPN `h2`, SNI,
/// TLS 1.3. Both truncated hashes are asserted against the digests
/// FoxIO publishes — an exact cross-tool anchor, not a shape check.
#[test]
fn ja4_matches_the_foxio_worked_example_exactly() {
    let hello = foxio_example_hello();
    let ja4 = ja4(&hello);
    assert_eq!(ja4.tls_version, 0x0304);
    assert!(ja4.has_sni);
    assert_eq!(ja4.cipher_count, 15);
    assert_eq!(ja4.extension_count, 16);
    assert_eq!(ja4.alpn_abbr.as_deref(), Some("h2"));
    assert_eq!(
        ja4.fingerprint, "t13d1516h2_8daaf6152771_e5627efa2ab1",
        "the exact FoxIO published fingerprint"
    );
}

#[test]
fn ja4_reports_13_when_supported_versions_offer_tls13() {
    let hello = minimal_hello(0x0303, Some(0x0304));
    assert_eq!(&ja4(&hello).fingerprint[..3], "t13");
}

#[test]
fn ja4_reports_12_when_only_tls12_is_offered() {
    let hello = minimal_hello(0x0303, None);
    assert_eq!(&ja4(&hello).fingerprint[..3], "t12");
}

#[test]
fn ja4_marks_sni_absence_with_i() {
    let mut hello = minimal_hello(0x0303, Some(0x0304));
    hello.has_sni = false;
    assert!(ja4(&hello).fingerprint.starts_with("t13i"));
}

#[test]
fn http11_alpn_abbreviates_to_h1() {
    let mut hello = minimal_hello(0x0303, Some(0x0304));
    hello.alpn_protocols = vec![b"http/1.1".to_vec()];
    assert_eq!(ja4(&hello).alpn_abbr.as_deref(), Some("h1"));
}

#[test]
fn no_alpn_renders_00() {
    let mut hello = minimal_hello(0x0303, Some(0x0304));
    hello.alpn_protocols.clear();
    assert!(ja4(&hello).fingerprint.starts_with("t13d010900_"));
    assert_eq!(ja4(&hello).alpn_abbr, None);
}

#[test]
fn grease_is_excluded_from_ja4_but_kept_in_ja3() {
    let mut hello = minimal_hello(0x0303, Some(0x0304));
    hello.extensions.insert(0, 0x0A0A);
    hello.cipher_suites.insert(0, 0x1A1A);
    let ja4 = ja4(&hello);
    assert_eq!(ja4.extension_count, 9);
    assert_eq!(ja4.cipher_count, 1);
    let ja3 = ja3(&hello).expect("all lists present");
    // JA3 keeps GREASE; fields are comma-joined, values within a field
    // dash-joined.
    let expected = format!(
        "771,{},{},29,0",
        dashed_list(&hello.cipher_suites),
        dashed_list(&hello.extensions)
    );
    assert_eq!(
        ja3.string, expected,
        "GREASE kept, decimal, dash-joined lists"
    );
}

#[test]
fn an_empty_extension_list_hashes_to_zeroes_not_to_the_digest_of_nothing() {
    let mut hello = minimal_hello(0x0303, None);
    hello.extensions.clear();
    assert!(ja4(&hello).fingerprint.ends_with("_000000000000"));
}

#[test]
fn ja3_needs_every_list_it_hashes() {
    let mut hello = minimal_hello(0x0303, Some(0x0304));
    assert!(ja3(&hello).is_some());
    hello.ec_point_formats.clear();
    assert!(ja3(&hello).is_none(), "absent point formats: honest None");
}

#[test]
fn md5_and_sha256_agree_with_the_standard_vectors() {
    // RFC 1321 test suite.
    assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    // NIST FIPS 180-4 test vectors.
    assert_eq!(
        sha256_hex_12(b"abc"),
        "ba7816bf8f01",
        "first 12 hex of abc's SHA-256"
    );
    assert_eq!(sha256_hex_12(b""), "e3b0c44298fc");
}

#[test]
fn parsing_rejects_a_truncated_or_non_hello_message() {
    assert!(ClientHello::parse(&[]).is_none());
    assert!(
        ClientHello::parse(&[0x02]).is_none(),
        "server_hello, not ours"
    );
    assert!(
        ClientHello::parse(&[0x01, 0x00, 0x00, 0xFF]).is_none(),
        "length beyond the bytes"
    );
}

#[test]
fn parsing_survives_unknown_extensions() {
    let hello = ClientHello::parse(&unknown_extension_hello()).expect("valid hello");
    assert_eq!(hello.extensions, vec![0xFFFE, 0x000A]);
    assert_eq!(hello.supported_groups, vec![0x001D]);
}

#[test]
fn alpn_parsing_reads_every_offered_protocol() {
    let hello = ClientHello::parse(&alpn_hello()).expect("valid hello");
    assert_eq!(
        hello.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

#[test]
fn supported_versions_takes_the_maximum() {
    let hello =
        ClientHello::parse(&versions_hello(&[0x0302, 0x0303, 0x0304])).expect("valid hello");
    assert_eq!(hello.supported_versions_max, Some(0x0304));
}

// -- helpers ----------------------------------------------------------

/// The FoxIO worked example as structured fields (see the doc's cipher
/// and extension lists). Counts and both hashes are asserted exactly in
/// the test above.
fn foxio_example_hello() -> ClientHello {
    let ciphers: [u16; 15] = [
        0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
    ];
    let extensions: [u16; 16] = [
        0x0000, 0x0017, 0xFF01, 0x000B, 0x000A, 0x0010, 0x000D, 0x0015, 0x002B, 0x002D, 0x0033,
        0x4469, 0x001B, 0x0012, 0x0023, 0x0005,
    ];
    ClientHello {
        cipher_suites: ciphers.to_vec(),
        extensions: extensions.to_vec(),
        supported_groups: vec![0x001D, 0x0017, 0x0018],
        ec_point_formats: vec![0x00],
        signature_algorithms: vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        supported_versions_max: Some(0x0304),
        legacy_version: 0x0303,
        has_sni: true,
    }
}

/// A 1-cipher, 9-extension hello whose only variation points are the two
/// version fields; used by the small behavioural assertions above.
fn minimal_hello(legacy: u16, supported_max: Option<u16>) -> ClientHello {
    let mut extensions = vec![
        0x000B, 0x000A, 0x0010, 0x000D, 0x0015, 0x002B, 0x002D, 0x0033, 0xFF01,
    ];
    if supported_max.is_none() {
        extensions.retain(|e| *e != 0x002B);
    }
    ClientHello {
        cipher_suites: vec![0x1301],
        extensions,
        supported_groups: vec![0x001D],
        ec_point_formats: vec![0x00],
        signature_algorithms: vec![0x0403],
        alpn_protocols: vec![b"h2".to_vec()],
        supported_versions_max: supported_max,
        legacy_version: legacy,
        has_sni: true,
    }
}

fn hello_bytes(extensions: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy version
    bytes.extend_from_slice(&[0u8; 32]); // random
    bytes.push(0); // session_id: empty
    bytes.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher (2-byte length)
    bytes.push(1);
    bytes.push(0); // compression: null
    bytes.extend_from_slice(extensions);
    // Patch in the handshake length (24-bit) ahead of the body.
    let body_len = (bytes.len() as u32).to_be_bytes();
    let mut message = vec![0x01u8, body_len[1], body_len[2], body_len[3]];
    message.extend_from_slice(&bytes);
    message
}

fn unknown_extension_hello() -> Vec<u8> {
    hello_bytes(&[
        0x00, 0x0C, // block length: (4+2) + (4+2)
        0xFF, 0xFE, 0x00, 0x00, // unknown extension, empty
        0x00, 0x0A, 0x00, 0x04, // supported_groups
        0x00, 0x02, 0x00, 0x1D, // one group: x25519
    ])
}

fn alpn_hello() -> Vec<u8> {
    // Block: one extension (type 0x0010), payload 14 bytes
    // (2 list-length + 1 + 2 "h2" + 1 + 8 "http/1.1") → block length 18.
    hello_bytes(&[
        0x00, 0x12, // block length: 4 + 14
        0x00, 0x10, 0x00, 0x0E, // ALPN, 14 bytes of payload
        0x00, 0x0C, // list length
        0x02, b'h', b'2', // 1-byte-prefixed name
        0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
    ])
}

fn versions_hello(versions: &[u16]) -> Vec<u8> {
    let mut payload = vec![versions.len() as u8 * 2];
    for version in versions {
        payload.extend_from_slice(&version.to_be_bytes());
    }
    let mut extensions = vec![0x00, 0x2B];
    extensions.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&payload);
    let mut block = (extensions.len() as u16).to_be_bytes().to_vec();
    block.extend_from_slice(&extensions);
    hello_bytes(&block)
}
