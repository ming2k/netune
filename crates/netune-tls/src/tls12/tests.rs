//! The TLS 1.2 derivations are pinned against vectors recomputed with an
//! independent implementation of RFC 5246 §5 (Python's `hashlib`/`hmac`),
//! cross-checked against the `aws-lc-sys` FFI's own dual-PRF spell for
//! `MD5-SHA1`. The CBC records add `openssl enc -aes-128-cbc -nopad` as the
//! block-cipher oracle. The inputs are: a 48-byte pre-master of `0x33`, a
//! 32-byte client random of `0x11`, a 32-byte server random of `0x22`.

use super::{Cipher12, Prf12, handshake_hash, key_block, master_secret, suite12};

const PRE_MASTER: &str = "
    33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33
    33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33";
const CLIENT_RANDOM: &str = "
    11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11";
const SERVER_RANDOM: &str = "
    22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22";

/// Parse RFC-style spaced hex.
fn unhex(hex: &str) -> Vec<u8> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..cleaned.len() / 2)
        .map(|index| u8::from_str_radix(&cleaned[index * 2..index * 2 + 2], 16).expect("hex digit"))
        .collect()
}

#[test]
fn master_secrets_match_the_independent_prf() {
    let pre_master = unhex(PRE_MASTER);
    let client_random = unhex(CLIENT_RANDOM);
    let server_random = unhex(SERVER_RANDOM);
    for (prf, expected) in [
        (
            Prf12::Sha256,
            "0258BBAF6891D32CD983E0BCAC28D2BF017BE4CB579109CB2EB316C4B09723413A1479756639F45C3763BD1C5A64EC74",
        ),
        (
            Prf12::Sha384,
            "760E3FE844516C9F04F46F500CE85D917C93F83CD4EDBFE6F17C5011A8142990939B69FA0FD269EACC3A1E6E59D49003",
        ),
        (
            Prf12::Md5Sha1,
            "B6BAC8A7BAD9AB6CB4EF60C582F0C652B487F04F2D56604A792C46C23AF95DAE283CF3CE3AD894F41AB964C7F9B4828F",
        ),
    ] {
        let master =
            master_secret(prf, &pre_master, &client_random, &server_random).expect("master");
        assert_eq!(master.as_slice(), unhex(expected).as_slice(), "{prf:?}");
    }
}

#[test]
fn the_cbc_key_block_matches_the_independent_prf() {
    let pre_master = unhex(PRE_MASTER);
    let client_random = unhex(CLIENT_RANDOM);
    let server_random = unhex(SERVER_RANDOM);
    let master =
        master_secret(Prf12::Md5Sha1, &pre_master, &client_random, &server_random).expect("master");
    // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: 20+20 MAC, 16+16 key, 16+16 IV.
    let block =
        key_block(Prf12::Md5Sha1, &master, &server_random, &client_random, 104).expect("key block");
    assert_eq!(
        block.as_slice(),
        unhex(
            "1A249905ABC9832DA76B161E1F866A107D0A4E0C7790EC8517D14D35FA5FF1640D2751B445D316D185ED3E622D74D1FDE67C00A23B5814D3D4310CCC035DD4B125DB7B0F674BE3B7EC85E5527441849DE60D7502B02E5B14ACADB7309ECC31E8702AF46929C8EC8C"
        )
        .as_slice(),
    );
    // The RFC 5246 §6.3 split: client MAC, server MAC, client key, server
    // key, client IV, server IV.
    assert_eq!(
        &block[..20],
        unhex("1A249905ABC9832DA76B161E1F866A107D0A4E0C").as_slice()
    );
    assert_eq!(
        &block[40..56],
        unhex("85ED3E622D74D1FDE67C00A23B5814D3").as_slice()
    );
    assert_eq!(
        &block[72..88],
        unhex("EC85E5527441849DE60D7502B02E5B14").as_slice()
    );
    assert_eq!(
        &block[88..104],
        unhex("ACADB7309ECC31E8702AF46929C8EC8C").as_slice()
    );
}

#[test]
fn the_gcm_key_block_matches_the_independent_prf() {
    let pre_master = unhex(PRE_MASTER);
    let client_random = unhex(CLIENT_RANDOM);
    let server_random = unhex(SERVER_RANDOM);
    let master =
        master_secret(Prf12::Sha256, &pre_master, &client_random, &server_random).expect("master");
    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: no MAC keys, 16+16 key,
    // 4+4 salt.
    let block =
        key_block(Prf12::Sha256, &master, &server_random, &client_random, 40).expect("key block");
    assert_eq!(
        block.as_slice(),
        unhex("74D7210EACA40AF29C3DC7537B2B201D609B7E11ACBC0DF135366DD87D0EC0B48541F583F14DC438")
            .as_slice(),
    );
}

#[test]
fn the_finished_handshake_hash_spreads_across_the_prfs() {
    // SHA-256 PRF suites hash with SHA-256; the dual-PRF suites hash with
    // MD5 || SHA-1 (36 bytes).
    assert_eq!(handshake_hash(Prf12::Sha256, b"abc").len(), 32);
    assert_eq!(handshake_hash(Prf12::Sha384, b"abc").len(), 48);
    let hash = handshake_hash(Prf12::Md5Sha1, b"abc");
    assert_eq!(hash.len(), 36);
    // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 (RFC 1321).
    assert_eq!(
        &hash[..16],
        unhex("900150983cd24fb0d6963f7d28e17f72").as_slice()
    );
    // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d (FIPS 180-4).
    assert_eq!(
        &hash[16..],
        unhex("a9993e364706816aba3e25717850c26c9cd0d89d").as_slice()
    );
}

#[test]
fn the_suite_table_covers_exactly_the_offered_tls_1_2_suites() {
    // The ten TLS 1.2 suites of the go-shaped hello.
    for (suite, expected) in [
        (0xc02b, (Cipher12::AesGcm { bits: 128 }, Prf12::Sha256)),
        (0xc02f, (Cipher12::AesGcm { bits: 128 }, Prf12::Sha256)),
        (0xc02c, (Cipher12::AesGcm { bits: 256 }, Prf12::Sha384)),
        (0xc030, (Cipher12::AesGcm { bits: 256 }, Prf12::Sha384)),
        (0xcca9, (Cipher12::ChaCha20, Prf12::Sha256)),
        (0xcca8, (Cipher12::ChaCha20, Prf12::Sha256)),
        (0xc009, (Cipher12::AesCbc { bits: 128 }, Prf12::Md5Sha1)),
        (0xc013, (Cipher12::AesCbc { bits: 128 }, Prf12::Md5Sha1)),
        (0xc00a, (Cipher12::AesCbc { bits: 256 }, Prf12::Md5Sha1)),
        (0xc014, (Cipher12::AesCbc { bits: 256 }, Prf12::Md5Sha1)),
    ] {
        let params = suite12(suite).unwrap_or_else(|| panic!("suite {suite:#06x} implemented"));
        assert_eq!((params.kind, params.prf), expected);
    }
    // The TLS 1.3 suites are not TLS 1.2 suites.
    for suite in [0x1301, 0x1302, 0x1303] {
        assert!(suite12(suite).is_none());
    }
}

#[test]
fn the_cbc_record_layer_reproduces_the_openssl_goldens() {
    use crate::record::{
        CONTENT_APPLICATION_DATA, RecordProtector12, RecordUnprotector12,
        record_ciphers_from_key_block,
    };

    let pre_master = unhex(PRE_MASTER);
    let client_random = unhex(CLIENT_RANDOM);
    let server_random = unhex(SERVER_RANDOM);
    let master =
        master_secret(Prf12::Md5Sha1, &pre_master, &client_random, &server_random).expect("master");
    let block =
        key_block(Prf12::Md5Sha1, &master, &server_random, &client_random, 104).expect("key block");
    let params = suite12(0xc009).expect("c009");
    let (client, server) =
        record_ciphers_from_key_block(params, block.as_slice()).expect("key block split");

    // The client's record for `hello` at sequence 0, generated with
    // `openssl enc -aes-128-cbc -nopad` over the Python-recomputed MAC.
    let protector = RecordProtector12::new(client).expect("protector");
    let record = protector
        .seal(0, CONTENT_APPLICATION_DATA, b"hello")
        .expect("seal");
    assert_eq!(
        record,
        unhex(
            "170303003049CE520600CE64F77BEBB936A81C182082B2437CB530793DAD2AA2E096F66FC7DB27FBE5B3DD4F0BFF7D8E7EE42D5B36"
        )
    );

    // The server's record for `goodbye` opens to its fragment.
    let unprotector = RecordUnprotector12::new(server).expect("unprotector");
    let (content_type, fragment) = unprotector
        .open(0, &unhex("170303003049CE520600CE64F77BEBB936A81C18209F2AB25D830A8A4B73F5BB2E7EE2CBE61F0059FDCD00B3691B3D536714C5AEC1"))
        .expect("open");
    assert_eq!(content_type, CONTENT_APPLICATION_DATA);
    assert_eq!(fragment, b"goodbye");
}

#[test]
fn cbc_tampering_and_bad_padding_are_refused_uniformly() {
    use crate::record::{
        CONTENT_APPLICATION_DATA, RecordProtector12, RecordUnprotector12,
        record_ciphers_from_key_block,
    };

    let pre_master = unhex(PRE_MASTER);
    let client_random = unhex(CLIENT_RANDOM);
    let server_random = unhex(SERVER_RANDOM);
    let master =
        master_secret(Prf12::Md5Sha1, &pre_master, &client_random, &server_random).expect("master");
    let block =
        key_block(Prf12::Md5Sha1, &master, &server_random, &client_random, 104).expect("key block");
    let params = suite12(0xc009).expect("c009");
    let (client, server) =
        record_ciphers_from_key_block(params, block.as_slice()).expect("key block split");
    let protector = RecordProtector12::new(client).expect("protector");
    let unprotector = RecordUnprotector12::new(server).expect("unprotector");

    // A flipped ciphertext byte fails authentication.
    let mut record = protector
        .seal(0, CONTENT_APPLICATION_DATA, b"hello")
        .expect("seal");
    let last = record.len() - 1;
    record[last] ^= 0x01;
    assert_eq!(
        unprotector.open(0, &record),
        Err(crate::record::RecordError::DecryptionFailed)
    );

    // A replayed sequence number is the wrong MAC input and the wrong IV.
    let record = protector
        .seal(0, CONTENT_APPLICATION_DATA, b"hello")
        .expect("seal");
    assert_eq!(
        unprotector.open(1, &record),
        Err(crate::record::RecordError::DecryptionFailed)
    );
}

#[test]
fn the_gcm_record_layer_reproduces_the_independent_golden() {
    use crate::record::{
        CONTENT_APPLICATION_DATA, RecordProtector12, RecordUnprotector12,
        record_ciphers_from_key_block,
    };

    let pre_master = unhex(PRE_MASTER);
    let client_random = unhex(CLIENT_RANDOM);
    let server_random = unhex(SERVER_RANDOM);
    let master =
        master_secret(Prf12::Sha256, &pre_master, &client_random, &server_random).expect("master");
    let block =
        key_block(Prf12::Sha256, &master, &server_random, &client_random, 48).expect("key block");
    let params = suite12(0xc02b).expect("c02b");
    let (client, _) =
        record_ciphers_from_key_block(params, block.as_slice()).expect("key block split");

    // The record the ctypes/libcrypto GCM oracle produced for the same key
    // material (key block 74D7210E…4032BF244E8D5CA1): explicit = seed XOR
    // seq, nonce = salt || explicit, AAD = seq || header(plain length).
    let protector = RecordProtector12::new(client).expect("protector");
    let record = protector
        .seal(0, CONTENT_APPLICATION_DATA, b"hello")
        .expect("seal");
    assert_eq!(
        record,
        unhex("170303001D4032BF244E8D5CA1BD4679EF41079D3879D1F30EDFEEFADA39B1BA52C3")
    );

    // Round trip through the same direction's unprotector.
    let (client_cipher, _) =
        record_ciphers_from_key_block(params, block.as_slice()).expect("key block split");
    let unprotector = RecordUnprotector12::new(client_cipher).expect("unprotector");
    let (inner, fragment) = unprotector.open(0, &record).expect("open");
    assert_eq!(inner, CONTENT_APPLICATION_DATA);
    assert_eq!(fragment, b"hello");
}
