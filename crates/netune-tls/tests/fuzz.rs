// SPDX-License-Identifier: MIT

//! Dual-tier in-workspace fuzz harness for `netune-tls` (ADR-0049, `[INV-TEST-06]`):
//! - Record layer header parsing & TLS 1.2/1.3 AEAD/CBC unprotection
//! - ASN.1 SPKI extraction (`cert::subject_public_key_info`)
//! - TLS 1.2/1.3 handshake state machine including encrypted inner flights and
//!   RFC 8879 `CompressedCertificate` (zlib & brotli)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::sync::LazyLock;

use aws_lc_rs::aead;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use netune_tls::cert::subject_public_key_info;
use netune_tls::handshake::{ClientHandshake, HandshakeProgress, ServerCertVerifier};
use netune_tls::hello::{ClientHello, Extension, ExtensionBody, KeyShareEntry};
use netune_tls::key_exchange::ClientKeyShare;
use netune_tls::key_schedule::{Hash, Secret, empty_transcript_hash, transcript_hash};
use netune_tls::record::{
    CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE,
    LEGACY_VERSION_TLS12, LEGACY_VERSION_TLS13, RecordCipher12, RecordHeader, RecordProtector12,
    RecordProtector13, RecordUnprotector12, RecordUnprotector13,
};
use netune_tls::wire::{
    CERT_COMP_BROTLI, CERT_COMP_ZLIB, GROUP_X25519, SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PKCS1_SHA256, SIG_RSA_PSS_RSAE_SHA256, SUITE_ECDHE_ECDSA_CHACHA20_POLY1305,
    SUITE_ECDHE_RSA_AES_128_CBC, SUITE_ECDHE_RSA_AES_128_GCM, SUITE_TLS13_AES_128_GCM,
};
use test_support::fuzz::{run_fuzz, run_fuzz_soak};

const CLIENT_PRIV: [u8; 32] = [
    0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca,
    0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05,
];

const SERVER_PRIV: [u8; 32] = [0x55; 32];

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

#[derive(Clone, Copy)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_chain(
        &mut self,
        _server_name: &str,
        _end_entity: &[u8],
        _intermediates: &[Vec<u8>],
    ) -> Result<(), String> {
        Ok(())
    }
}

struct RecordContext {
    u13_gcm: RecordUnprotector13,
    u13_chacha: RecordUnprotector13,
    u12_gcm: RecordUnprotector12,
    u12_chacha: RecordUnprotector12,
    u12_cbc: RecordUnprotector12,
    seeds: Vec<Vec<u8>>,
}

static RECORD_CTX: LazyLock<RecordContext> = LazyLock::new(|| {
    let key16 = [0x11u8; 16];
    let key32 = [0x22u8; 32];
    let iv12 = [0x33u8; 12];
    let mac20 = [0x44u8; 20];
    let cbc_iv = [0x55u8; 16];

    let p13_gcm = RecordProtector13::new(&aead::AES_128_GCM, &key16, iv12).expect("p13 gcm");
    let u13_gcm = RecordUnprotector13::new(&aead::AES_128_GCM, &key16, iv12).expect("u13 gcm");
    let p13_chacha =
        RecordProtector13::new(&aead::CHACHA20_POLY1305, &key32, iv12).expect("p13 chacha");
    let u13_chacha =
        RecordUnprotector13::new(&aead::CHACHA20_POLY1305, &key32, iv12).expect("u13 chacha");

    let mk_gcm = || RecordCipher12::AesGcm {
        key: key16.to_vec(),
        salt: [0x01, 0x02, 0x03, 0x04],
        explicit_seed: [0x10; 8],
        algorithm: &aead::AES_128_GCM,
    };
    let mk_chacha = || RecordCipher12::ChaCha20 {
        key: key32.to_vec(),
        iv: iv12,
    };
    let mk_cbc = || RecordCipher12::AesCbcSha1 {
        mac_key: mac20.to_vec(),
        write_key: key16.to_vec(),
        fixed_iv: cbc_iv,
        algorithm: &aws_lc_rs::cipher::AES_128,
    };

    let p12_gcm = RecordProtector12::new(mk_gcm()).expect("p12 gcm");
    let u12_gcm = RecordUnprotector12::new(mk_gcm()).expect("u12 gcm");
    let p12_chacha = RecordProtector12::new(mk_chacha()).expect("p12 chacha");
    let u12_chacha = RecordUnprotector12::new(mk_chacha()).expect("u12 chacha");
    let p12_cbc = RecordProtector12::new(mk_cbc()).expect("p12 cbc");
    let u12_cbc = RecordUnprotector12::new(mk_cbc()).expect("u12 cbc");

    let identity = test_support::tls::identity(&["server"], &[]);
    let cert_der = identity.certificate.as_ref().to_vec();

    let mut multi = p13_gcm
        .seal(0, CONTENT_HANDSHAKE, b"hello")
        .expect("seal 1");
    multi.extend_from_slice(&p13_chacha.seal(0, CONTENT_ALERT, &[2, 40]).expect("seal 2"));

    let seeds = vec![
        vec![CONTENT_HANDSHAKE, 0x03, 0x03, 0x00, 0x00],
        vec![CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01],
        vec![CONTENT_APPLICATION_DATA, 0x03, 0x03, 0xff, 0xff],
        p13_gcm
            .seal(0, CONTENT_APPLICATION_DATA, b"tls13-gcm-payload")
            .expect("tls13 gcm"),
        p13_chacha
            .seal(0, CONTENT_APPLICATION_DATA, b"tls13-chacha-payload")
            .expect("tls13 chacha"),
        p12_gcm
            .seal(0, CONTENT_APPLICATION_DATA, b"tls12-gcm-payload")
            .expect("tls12 gcm"),
        p12_chacha
            .seal(0, CONTENT_APPLICATION_DATA, b"tls12-chacha-payload")
            .expect("tls12 chacha"),
        p12_cbc
            .seal(
                0,
                CONTENT_APPLICATION_DATA,
                b"tls12-cbc-payload-0123456789abcdef",
            )
            .expect("tls12 cbc"),
        multi,
        cert_der,
    ];

    RecordContext {
        u13_gcm,
        u13_chacha,
        u12_gcm,
        u12_chacha,
        u12_cbc,
        seeds,
    }
});

struct HandshakeContext {
    hello13: ClientHello,
    hello12: ClientHello,
    server_hello13_record: Vec<u8>,
    enc_encrypted_extensions: Vec<u8>,
    server_hs_protector: RecordProtector13,
    seeds: Vec<Vec<u8>>,
}

fn wrap_tls_record(content_type: u8, legacy_version: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(content_type);
    out.extend_from_slice(&legacy_version.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn handshake_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push(msg_type);
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(body);
    out
}

fn push_u24(out: &mut Vec<u8>, value: usize) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

fn compressed_cert_msg(alg: u16, uncompressed_len: usize, compressed: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + compressed.len());
    body.extend_from_slice(&alg.to_be_bytes());
    push_u24(&mut body, uncompressed_len);
    push_u24(&mut body, compressed.len());
    body.extend_from_slice(compressed);
    handshake_msg(25, &body)
}

fn build_server_hello(random: [u8; 32], suite: u16, exts: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
    body.extend_from_slice(&random);
    body.push(0x00); // session_id len
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0x00); // compression null
    if !exts.is_empty() {
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(exts);
    }
    handshake_msg(0x02, &body)
}

static HANDSHAKE_CTX: LazyLock<HandshakeContext> = LazyLock::new(|| {
    let client_share = ClientKeyShare::x25519_from_private(GROUP_X25519, &CLIENT_PRIV)
        .expect("fixed client x25519 share");
    let server_share = ClientKeyShare::x25519_from_private(GROUP_X25519, &SERVER_PRIV)
        .expect("fixed server x25519 share");

    let hello13 = ClientHello {
        legacy_version: LEGACY_VERSION_TLS12,
        random: [0xaa; 32],
        session_id: Vec::new(),
        cipher_suites: vec![SUITE_TLS13_AES_128_GCM],
        compression_methods: vec![0x00],
        extensions: vec![
            Extension {
                body: ExtensionBody::ServerName {
                    name: "server".into(),
                },
            },
            Extension {
                body: ExtensionBody::SupportedGroups {
                    groups: vec![GROUP_X25519],
                },
            },
            Extension {
                body: ExtensionBody::KeyShare {
                    shares: vec![KeyShareEntry {
                        group: GROUP_X25519,
                        share: client_share.share.clone(),
                    }],
                },
            },
            Extension {
                body: ExtensionBody::SupportedVersions {
                    versions: vec![LEGACY_VERSION_TLS13],
                },
            },
            Extension {
                body: ExtensionBody::SignatureAlgorithms {
                    schemes: vec![
                        SIG_ECDSA_SECP256R1_SHA256,
                        SIG_RSA_PSS_RSAE_SHA256,
                        SIG_RSA_PKCS1_SHA256,
                    ],
                },
            },
            Extension {
                body: ExtensionBody::CompressCertificate {
                    algorithms: vec![CERT_COMP_ZLIB, CERT_COMP_BROTLI],
                },
            },
        ],
    };

    let hello12 = ClientHello {
        legacy_version: LEGACY_VERSION_TLS12,
        random: [0xbb; 32],
        session_id: Vec::new(),
        cipher_suites: vec![
            SUITE_ECDHE_RSA_AES_128_GCM,
            SUITE_ECDHE_RSA_AES_128_CBC,
            SUITE_ECDHE_ECDSA_CHACHA20_POLY1305,
        ],
        compression_methods: vec![0x00],
        extensions: vec![
            Extension {
                body: ExtensionBody::ServerName {
                    name: "server".into(),
                },
            },
            Extension {
                body: ExtensionBody::ExtendedMasterSecret,
            },
            Extension {
                body: ExtensionBody::RenegotiationInfo,
            },
            Extension {
                body: ExtensionBody::SupportedGroups {
                    groups: vec![GROUP_X25519],
                },
            },
            Extension {
                body: ExtensionBody::EcPointFormats {
                    formats: vec![0x00],
                },
            },
            Extension {
                body: ExtensionBody::SignatureAlgorithms {
                    schemes: vec![
                        SIG_ECDSA_SECP256R1_SHA256,
                        SIG_RSA_PSS_RSAE_SHA256,
                        SIG_RSA_PKCS1_SHA256,
                    ],
                },
            },
        ],
    };

    // Build TLS 1.3 ServerHello extensions: supported_versions(0x0304) + key_share(SERVER_PUB).
    let mut exts13 = vec![
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
    ];
    exts13.extend_from_slice(&server_share.share);
    let server_hello13_msg = build_server_hello([0xcc; 32], SUITE_TLS13_AES_128_GCM, &exts13);
    let server_hello13_record =
        wrap_tls_record(CONTENT_HANDSHAKE, LEGACY_VERSION_TLS12, &server_hello13_msg);

    // Derive server handshake protector matching `hello13` + `server_hello13_msg`.
    let shared = client_share
        .agree(&server_share.share)
        .expect("agree deterministic x25519");
    let early = Secret::extract(&[0u8; 32], &[0u8; 32], Hash::Sha256);
    let derived = early
        .derive_secret("derived", &empty_transcript_hash(Hash::Sha256))
        .expect("derived");
    let hs = Secret::extract(derived.as_bytes(), &shared, Hash::Sha256);
    let mut transcript = hello13.serialize().expect("hello13");
    transcript.extend_from_slice(&server_hello13_msg);
    let s_hs = hs
        .derive_secret("s hs traffic", &transcript_hash(Hash::Sha256, &transcript))
        .expect("s hs traffic");
    let s_keys = s_hs.traffic_keys(16).expect("traffic keys");
    let server_hs_protector =
        RecordProtector13::new(&aead::AES_128_GCM, &s_keys.key, s_keys.iv).expect("protector");

    let ee_msg = handshake_msg(0x08, &[0x00, 0x00]);
    let enc_encrypted_extensions = server_hs_protector
        .seal(0, CONTENT_HANDSHAKE, &ee_msg)
        .expect("seal ee");

    let identity = test_support::tls::identity(&["server"], &[]);
    let cert_der = identity.certificate.as_ref();
    let mut cert_body = vec![0x00]; // request context len
    let entries_len = 3 + cert_der.len() + 2;
    push_u24(&mut cert_body, entries_len);
    push_u24(&mut cert_body, cert_der.len());
    cert_body.extend_from_slice(cert_der);
    cert_body.extend_from_slice(&[0x00, 0x00]); // per-cert extensions

    let mut zlib_enc = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib_enc.write_all(&cert_body).expect("zlib write");
    let zlib_bytes = zlib_enc.finish().expect("zlib finish");
    let comp_zlib = compressed_cert_msg(CERT_COMP_ZLIB, cert_body.len(), &zlib_bytes);

    let mut brotli_bytes = Vec::new();
    {
        let mut bw = brotli::CompressorWriter::new(&mut brotli_bytes, 4096, 5, 22);
        bw.write_all(&cert_body).expect("brotli write");
    }
    let comp_brotli = compressed_cert_msg(CERT_COMP_BROTLI, cert_body.len(), &brotli_bytes);

    let cert_msg = handshake_msg(11, &cert_body);

    let mut flight_zlib = server_hello13_record.clone();
    flight_zlib.extend_from_slice(&enc_encrypted_extensions);
    flight_zlib.extend_from_slice(
        &server_hs_protector
            .seal(1, CONTENT_HANDSHAKE, &comp_zlib)
            .expect("seal zlib"),
    );

    let mut flight_brotli = server_hello13_record.clone();
    flight_brotli.extend_from_slice(&enc_encrypted_extensions);
    flight_brotli.extend_from_slice(
        &server_hs_protector
            .seal(1, CONTENT_HANDSHAKE, &comp_brotli)
            .expect("seal brotli"),
    );

    let mut flight_plain_cert = server_hello13_record.clone();
    flight_plain_cert.extend_from_slice(&enc_encrypted_extensions);
    flight_plain_cert.extend_from_slice(
        &server_hs_protector
            .seal(1, CONTENT_HANDSHAKE, &cert_msg)
            .expect("seal cert"),
    );

    // HRR seed (supported_versions 0x0304 + selected_group SECP256R1).
    let hrr_exts = [
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x2c, 0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb,
    ];
    let hrr_record = wrap_tls_record(
        CONTENT_HANDSHAKE,
        LEGACY_VERSION_TLS12,
        &build_server_hello(HRR_RANDOM, SUITE_TLS13_AES_128_GCM, &hrr_exts),
    );

    // TLS 1.2 ServerHello + Certificate + ServerHelloDone seed.
    let mut tls12_flight = wrap_tls_record(
        CONTENT_HANDSHAKE,
        LEGACY_VERSION_TLS12,
        &build_server_hello(
            [0xdd; 32],
            SUITE_ECDHE_RSA_AES_128_GCM,
            &[0xff, 0x01, 0x00, 0x01, 0x00],
        ),
    );
    let mut cert12_body = Vec::new();
    push_u24(&mut cert12_body, 3 + cert_der.len());
    push_u24(&mut cert12_body, cert_der.len());
    cert12_body.extend_from_slice(cert_der);
    tls12_flight.extend_from_slice(&wrap_tls_record(
        CONTENT_HANDSHAKE,
        LEGACY_VERSION_TLS12,
        &handshake_msg(11, &cert12_body),
    ));
    tls12_flight.extend_from_slice(&wrap_tls_record(
        CONTENT_HANDSHAKE,
        LEGACY_VERSION_TLS12,
        &handshake_msg(14, &[]),
    ));

    let seeds = vec![
        flight_zlib,
        flight_brotli,
        flight_plain_cert,
        hrr_record,
        tls12_flight,
        cert_msg,
        comp_zlib,
        comp_brotli,
        wrap_tls_record(CONTENT_ALERT, LEGACY_VERSION_TLS12, &[2, 40]),
    ];

    HandshakeContext {
        hello13,
        hello12,
        server_hello13_record,
        enc_encrypted_extensions,
        server_hs_protector,
        seeds,
    }
});

fn exercise_records(data: &[u8]) {
    let ctx = &*RECORD_CTX;
    let _ = RecordHeader::parse(data);
    let _ = ctx.u13_gcm.open(0, data);
    let _ = ctx.u13_chacha.open(0, data);
    let _ = ctx.u12_gcm.open(0, data);
    let _ = ctx.u12_chacha.open(0, data);
    let _ = ctx.u12_cbc.open(0, data);
    let _ = subject_public_key_info(data);

    let mut cursor = data;
    while let Ok(header) = RecordHeader::parse(cursor) {
        let total = 5 + usize::from(header.payload_len);
        if cursor.len() < total {
            break;
        }
        let frame = &cursor[..total];
        let _ = ctx.u13_gcm.open(0, frame);
        let _ = ctx.u12_cbc.open(0, frame);
        cursor = &cursor[total..];
    }
}

fn drive_tls13(input: &[u8], chunked: bool) {
    let ctx = &*HANDSHAKE_CTX;
    let share =
        ClientKeyShare::x25519_from_private(GROUP_X25519, &CLIENT_PRIV).expect("client share");
    let Ok(mut hs) = ClientHandshake::start(ctx.hello13.clone(), vec![share], AcceptAny) else {
        return;
    };
    if chunked && input.len() > 7 {
        if let Ok(HandshakeProgress::Blocked) = hs.progress(&input[..7]) {
            let _ = hs.progress(&input[7..]);
        }
    } else {
        let _ = hs.progress(input);
    }
}

fn exercise_handshake(data: &[u8]) {
    let ctx = &*HANDSHAKE_CTX;

    // 1. Raw wire bytes against TLS 1.3 and TLS 1.2 state machines.
    drive_tls13(data, false);
    drive_tls13(data, true);
    if let Ok(mut hs12) = ClientHandshake::start(ctx.hello12.clone(), Vec::new(), AcceptAny) {
        let _ = hs12.progress(data);
    }

    // 2. Wrap fuzzed inner handshake bytes inside authentic ServerHello + AEAD
    //    handshake protection so mutations reach EncryptedExtensions/Certificate parsing.
    if data.len() <= 2048
        && let Ok(sealed) = ctx.server_hs_protector.seal(1, CONTENT_HANDSHAKE, data)
    {
        drive_after_ee(&sealed);
    }

    // 3. Inject fuzzed CompressedCertificate payloads (zlib & brotli) directly
    //    at FlightStage::Certificate under authentic AEAD protection.
    if data.len() <= 2000 {
        let uncompressed = 64 + usize::from(*data.first().unwrap_or(&0));
        for alg in [CERT_COMP_ZLIB, CERT_COMP_BROTLI] {
            let msg = compressed_cert_msg(alg, uncompressed, data);
            if let Ok(sealed) = ctx.server_hs_protector.seal(1, CONTENT_HANDSHAKE, &msg) {
                drive_after_ee(&sealed);
            }
        }
    }
}

fn drive_after_ee(sealed_cert_record: &[u8]) {
    let ctx = &*HANDSHAKE_CTX;
    let share =
        ClientKeyShare::x25519_from_private(GROUP_X25519, &CLIENT_PRIV).expect("client share");
    let Ok(mut hs) = ClientHandshake::start(ctx.hello13.clone(), vec![share], AcceptAny) else {
        return;
    };
    if hs.progress(&ctx.server_hello13_record).is_err() {
        return;
    }
    if hs.progress(&ctx.enc_encrypted_extensions).is_err() {
        return;
    }
    let _ = hs.progress(sealed_cert_record);
}

#[test]
fn fuzz_tls_records_and_der() {
    let refs: Vec<&[u8]> = RECORD_CTX.seeds.iter().map(Vec::as_slice).collect();
    run_fuzz(&refs, exercise_records);
}

#[test]
#[ignore = "scheduled soak campaign; run with --profile soak --run-ignored ignored-only"]
fn soak_fuzz_tls_records_and_der() {
    let refs: Vec<&[u8]> = RECORD_CTX.seeds.iter().map(Vec::as_slice).collect();
    run_fuzz_soak(&refs, exercise_records);
}

#[test]
fn fuzz_tls_handshake_and_compressed_certs() {
    let refs: Vec<&[u8]> = HANDSHAKE_CTX.seeds.iter().map(Vec::as_slice).collect();
    run_fuzz(&refs, exercise_handshake);
}

#[test]
#[ignore = "scheduled soak campaign; run with --profile soak --run-ignored ignored-only"]
fn soak_fuzz_tls_handshake_and_compressed_certs() {
    let refs: Vec<&[u8]> = HANDSHAKE_CTX.seeds.iter().map(Vec::as_slice).collect();
    run_fuzz_soak(&refs, exercise_handshake);
}
