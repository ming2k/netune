//! The key schedule is checked incrementally against RFC 8448 §3, the
//! "Simple 1-RTT Handshake" trace (TLS_AES_128_GCM_SHA256, x25519), which
//! publishes every intermediate value. The hex strings are copied from the
//! RFC with their original spacing so a transcription error is visible
//! against the source.

use super::{Hash, Secret, empty_transcript_hash, transcript_hash};

/// The RFC 8448 §3 ClientHello handshake message (196 octets).
const CLIENT_HELLO: &str = "
    01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
    02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01
    00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33
    00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13
    69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04
    01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

/// The RFC 8448 §3 ServerHello handshake message (90 octets).
const SERVER_HELLO: &str = "
    02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
    d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1
    56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";

/// Parse RFC-style spaced hex.
fn unhex(hex: &str) -> Vec<u8> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..cleaned.len() / 2)
        .map(|index| u8::from_str_radix(&cleaned[index * 2..index * 2 + 2], 16).expect("hex digit"))
        .collect()
}

/// The RFC 8448 §3 early secret: HKDF-Extract(zero salt, zero IKM).
const EARLY_SECRET: &str = "
    33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a";

/// The RFC 8448 §3 `tls13 derived` secret over the empty transcript hash.
const DERIVED_FROM_EARLY: &str = "
    6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba";

/// The RFC 8448 §3 (EC)DHE shared secret of the trace's x25519 pair.
const SHARED_SECRET: &str = "
    8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d";

/// The RFC 8448 §3 handshake secret.
const HANDSHAKE_SECRET: &str = "
    1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac";

/// The RFC 8448 §3 transcript hash over ClientHello || ServerHello.
const TRANSCRIPT_CH_SH: &str = "
    86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8";

/// The RFC 8448 §3 transcript hash over the full server flight.
const TRANSCRIPT_FULL: &str = "
    96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13";

/// The RFC 8448 §3 client handshake traffic secret (`tls13 c hs traffic`).
const C_HS_TRAFFIC: &str = "
    b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21";

/// The RFC 8448 §3 server handshake traffic secret (`tls13 s hs traffic`).
const S_HS_TRAFFIC: &str = "
    b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38";

/// The RFC 8448 §3 `tls13 derived` secret feeding the master extract.
const DERIVED_FROM_HANDSHAKE: &str = "
    43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4";

/// The RFC 8448 §3 master secret.
const MASTER_SECRET: &str = "
    18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19";

/// The RFC 8448 §3 client application traffic secret (`tls13 c ap traffic`).
const C_AP_TRAFFIC: &str = "
    9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5";

/// The RFC 8448 §3 server application traffic secret (`tls13 s ap traffic`).
const S_AP_TRAFFIC: &str = "
    a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43";

/// The RFC 8448 §3 client handshake write key.
const CLIENT_HS_KEY: &str = "
    db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01";

/// The RFC 8448 §3 client handshake write IV.
const CLIENT_HS_IV: &str = "
    5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f";

/// The RFC 8448 §3 client application write key.
const CLIENT_APP_KEY: &str = "
    17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51";

/// The RFC 8448 §3 client application write IV.
const CLIENT_APP_IV: &str = "
    5b 78 92 3d ee 08 57 90 33 e5 23 d9";

/// The RFC 8448 §3 client `tls13 finished` base key.
const CLIENT_FINISHED_KEY: &str = "
    b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d 6b f8 3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4";

#[test]
fn extract_with_zero_input_matches_the_rfc_8448_early_secret() {
    let zeros = vec![0u8; 32];
    let early = Secret::extract(&zeros, &zeros, Hash::Sha256);
    assert_eq!(early.bytes, unhex(EARLY_SECRET));
}

#[test]
fn the_full_schedule_chain_matches_rfc_8448() {
    let zeros = vec![0u8; 32];
    let empty_hash = empty_transcript_hash(Hash::Sha256);
    assert_eq!(
        empty_hash,
        unhex(
            "e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55"
        ),
        "SHA-256 over nothing, as the RFC states it"
    );

    let early = Secret::extract(&zeros, &zeros, Hash::Sha256);
    let derived = early.derive_secret("derived", &empty_hash).expect("derive");
    assert_eq!(derived.as_bytes(), unhex(DERIVED_FROM_EARLY).as_slice());

    let handshake = Secret::extract(derived.as_bytes(), &unhex(SHARED_SECRET), Hash::Sha256);
    assert_eq!(handshake.bytes, unhex(HANDSHAKE_SECRET));

    let transcript_ch_sh = unhex(TRANSCRIPT_CH_SH);
    let c_hs = handshake
        .derive_secret("c hs traffic", &transcript_ch_sh)
        .expect("derive");
    assert_eq!(c_hs.as_bytes(), unhex(C_HS_TRAFFIC).as_slice());
    let s_hs = handshake
        .derive_secret("s hs traffic", &transcript_ch_sh)
        .expect("derive");
    assert_eq!(s_hs.as_bytes(), unhex(S_HS_TRAFFIC).as_slice());

    let derived_master = handshake
        .derive_secret("derived", &empty_hash)
        .expect("derive");
    assert_eq!(
        derived_master.as_bytes(),
        unhex(DERIVED_FROM_HANDSHAKE).as_slice()
    );

    let master = Secret::extract(derived_master.as_bytes(), &zeros, Hash::Sha256);
    assert_eq!(master.bytes, unhex(MASTER_SECRET));

    let transcript_full = unhex(TRANSCRIPT_FULL);
    let c_ap = master
        .derive_secret("c ap traffic", &transcript_full)
        .expect("derive");
    assert_eq!(c_ap.as_bytes(), unhex(C_AP_TRAFFIC).as_slice());
    let s_ap = master
        .derive_secret("s ap traffic", &transcript_full)
        .expect("derive");
    assert_eq!(s_ap.as_bytes(), unhex(S_AP_TRAFFIC).as_slice());
}

#[test]
fn traffic_keys_and_finished_key_match_rfc_8448() {
    let c_hs = Secret {
        bytes: unhex(C_HS_TRAFFIC),
        hash: Hash::Sha256,
    };
    let keys = c_hs.traffic_keys(16).expect("traffic keys");
    assert_eq!(keys.key, unhex(CLIENT_HS_KEY));
    assert_eq!(keys.iv.as_slice(), &unhex(CLIENT_HS_IV)[..]);

    let c_ap = Secret {
        bytes: unhex(C_AP_TRAFFIC),
        hash: Hash::Sha256,
    };
    let keys = c_ap.traffic_keys(16).expect("traffic keys");
    assert_eq!(keys.key, unhex(CLIENT_APP_KEY));
    assert_eq!(keys.iv.as_slice(), &unhex(CLIENT_APP_IV)[..]);

    let finished = c_hs.finished_key().expect("finished key");
    assert_eq!(finished, unhex(CLIENT_FINISHED_KEY));
}

#[test]
fn transcript_hash_matches_the_rfc_8448_worked_values() {
    let mut messages = unhex(CLIENT_HELLO);
    messages.extend(unhex(SERVER_HELLO));
    assert_eq!(
        transcript_hash(Hash::Sha256, &messages),
        unhex(TRANSCRIPT_CH_SH)
    );
}

#[test]
fn sha384_derives_independently() {
    let zeros = vec![0u8; 48];
    let early = Secret::extract(&zeros, &zeros, Hash::Sha384);
    assert_eq!(early.hash().output_len(), 48);
    let keys = early.traffic_keys(32).expect("traffic keys");
    assert_eq!(keys.key.len(), 32);
    // The SHA-256 schedule must not leak into the SHA-384 one.
    assert_ne!(
        early.bytes,
        Secret::extract(&zeros, &zeros, Hash::Sha256).bytes
    );
}
