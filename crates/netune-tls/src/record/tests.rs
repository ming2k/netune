//! Record protection is checked against the RFC 8448 §3 ciphertexts: the
//! client's Finished record, the client's application-data record and the
//! client's closing alert record, all produced with the trace's client keys.
//! The hex strings are copied from the RFC with their original spacing.

use super::{
    CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE, LEGACY_VERSION_TLS12,
    LEGACY_VERSION_TLS13, MAX_CIPHERTEXT_LEN, RECORD_HEADER_LEN, RecordError, RecordHeader,
    RecordProtector13, RecordUnprotector13, unprotected_record,
};
use aws_lc_rs::aead;

/// Parse RFC-style spaced hex.
fn unhex(hex: &str) -> Vec<u8> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..cleaned.len() / 2)
        .map(|index| u8::from_str_radix(&cleaned[index * 2..index * 2 + 2], 16).expect("hex digit"))
        .collect()
}

/// The RFC 8448 §3 client handshake write key (`tls13 key` over
/// `tls13 c hs traffic`).
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

/// The RFC 8448 §3 client Finished handshake message (36 octets).
const CLIENT_FINISHED_MESSAGE: &str = "
    14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed
    d5 ce 61";

/// The RFC 8448 §3 complete record carrying that Finished message (58 octets).
const CLIENT_FINISHED_RECORD: &str = "
    17 03 03 00 35 75 ec 4d c2 38 cc e6 0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44
    d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7 26 c4 05 46";

/// The RFC 8448 §3 application-data payload (50 octets, 0x00 through 0x31).
fn app_payload() -> Vec<u8> {
    (0..=0x31).collect()
}

/// The RFC 8448 §3 complete record carrying that payload (72 octets).
const CLIENT_APP_RECORD: &str = "
    17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b
    98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6 3a ee
    bb 21 69 49 15 e4";

/// The RFC 8448 §3 complete record carrying a `close_notify` alert (24 octets).
const CLIENT_ALERT_RECORD: &str = "
    17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3";

fn handshake_protector() -> RecordProtector13 {
    RecordProtector13::new(
        &aead::AES_128_GCM,
        &unhex(CLIENT_HS_KEY),
        unhex(CLIENT_HS_IV).try_into().expect("12-byte IV"),
    )
    .expect("handshake protector")
}

fn app_protector() -> RecordProtector13 {
    RecordProtector13::new(
        &aead::AES_128_GCM,
        &unhex(CLIENT_APP_KEY),
        unhex(CLIENT_APP_IV).try_into().expect("12-byte IV"),
    )
    .expect("application protector")
}

fn app_unprotector() -> RecordUnprotector13 {
    RecordUnprotector13::new(
        &aead::AES_128_GCM,
        &unhex(CLIENT_APP_KEY),
        unhex(CLIENT_APP_IV).try_into().expect("12-byte IV"),
    )
    .expect("application unprotector")
}

fn handshake_unprotector() -> RecordUnprotector13 {
    RecordUnprotector13::new(
        &aead::AES_128_GCM,
        &unhex(CLIENT_HS_KEY),
        unhex(CLIENT_HS_IV).try_into().expect("12-byte IV"),
    )
    .expect("handshake unprotector")
}

#[test]
fn seal_reproduces_the_rfc_8448_finished_record() {
    let record = handshake_protector()
        .seal(0, CONTENT_HANDSHAKE, &unhex(CLIENT_FINISHED_MESSAGE))
        .expect("seal");
    assert_eq!(record, unhex(CLIENT_FINISHED_RECORD));
}

#[test]
fn seal_reproduces_the_rfc_8448_application_record() {
    let record = app_protector()
        .seal(0, CONTENT_APPLICATION_DATA, &app_payload())
        .expect("seal");
    assert_eq!(record, unhex(CLIENT_APP_RECORD));
}

#[test]
fn seal_reproduces_the_rfc_8448_alert_record_at_sequence_one() {
    // Sequence numbers continue across records within one key epoch: the
    // alert is the client's second application-key record.
    let record = app_protector()
        .seal(1, CONTENT_ALERT, &[0x01, 0x00])
        .expect("seal");
    assert_eq!(record, unhex(CLIENT_ALERT_RECORD));
}

#[test]
fn open_recovers_the_inner_content_type_and_payload() {
    let (content_type, payload) = handshake_unprotector()
        .open(0, &unhex(CLIENT_FINISHED_RECORD))
        .expect("open");
    assert_eq!(content_type, CONTENT_HANDSHAKE);
    assert_eq!(payload, unhex(CLIENT_FINISHED_MESSAGE));

    let (content_type, payload) = app_unprotector()
        .open(0, &unhex(CLIENT_APP_RECORD))
        .expect("open");
    assert_eq!(content_type, CONTENT_APPLICATION_DATA);
    assert_eq!(payload, app_payload());

    let (content_type, payload) = app_unprotector()
        .open(1, &unhex(CLIENT_ALERT_RECORD))
        .expect("open");
    assert_eq!(content_type, CONTENT_ALERT);
    assert_eq!(payload, vec![0x01, 0x00]);
}

#[test]
fn open_strips_sender_zero_padding_and_refuses_padding_only_plaintexts() {
    // A padded inner plaintext — the RFC 8446 §5.4 padding case a
    // traffic-analysis-motivated sender produces. Our own seal never pads,
    // so the test seals `content || content_type || zeros` itself with the
    // same key (seq 0: the nonce is the static IV unchanged).
    let payload = app_payload();
    let mut inner = payload.clone();
    inner.push(CONTENT_APPLICATION_DATA);
    inner.extend_from_slice(&[0u8; 5]);
    let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &unhex(CLIENT_APP_KEY)).expect("key");
    let key = aead::LessSafeKey::new(unbound);
    let mut inner_and_tag = inner;
    // The header declares the ciphertext length: plaintext plus tag.
    let ciphertext_len = inner_and_tag.len() + aead::AES_128_GCM.tag_len();
    let header = {
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0] = CONTENT_APPLICATION_DATA;
        header[1] = 0x03;
        header[2] = 0x03;
        header[3] = (ciphertext_len >> 8) as u8;
        header[4] = (ciphertext_len & 0xff) as u8;
        header
    };
    key.seal_in_place_append_tag(
        aead::Nonce::try_assume_unique_for_key(&unhex(CLIENT_APP_IV)).expect("nonce"),
        aead::Aad::from(&header),
        &mut inner_and_tag,
    )
    .expect("test seal");
    let mut record = header.to_vec();
    record.extend_from_slice(&inner_and_tag);

    let (content_type, opened) = app_unprotector().open(0, &record).expect("open");
    assert_eq!(content_type, CONTENT_APPLICATION_DATA);
    assert_eq!(opened, payload, "the sender's padding is stripped");

    // A content type of zero is not a content type: after the strip nothing
    // remains, and that is a refusal, not an empty payload.
    let record = app_protector().seal(3, 0, &[]).expect("seal");
    assert_eq!(
        app_unprotector().open(3, &record),
        Err(RecordError::InnerPlaintextEmpty)
    );
}

#[test]
fn tampered_records_fail_authentication() {
    let mut record = unhex(CLIENT_APP_RECORD);
    let last = record.len() - 1;
    record[last] ^= 0x01;
    assert_eq!(
        app_unprotector().open(0, &record),
        Err(RecordError::DecryptionFailed),
        "a flipped ciphertext byte is rejected"
    );

    // The header is additional data: a modified version byte must fail
    // authentication, not just decrypt something else. (A modified length
    // byte is caught earlier, as a framing refusal.)
    let mut record = unhex(CLIENT_APP_RECORD);
    record[1] ^= 0x01;
    assert_eq!(
        app_unprotector().open(0, &record),
        Err(RecordError::DecryptionFailed)
    );

    // A replayed sequence number is the wrong nonce: it fails.
    assert_eq!(
        app_unprotector().open(1, &unhex(CLIENT_APP_RECORD)),
        Err(RecordError::DecryptionFailed)
    );
}

#[test]
fn framing_refusals() {
    assert_eq!(
        RecordHeader::parse(&[]).unwrap_err().to_string(),
        "record header of 0 bytes is shorter than the 5-byte minimum",
        "a short input is a framing refusal, not a guess",
    );

    // Declared length must match the bytes present.
    let mut record = unhex(CLIENT_APP_RECORD);
    record[4] = 0x44; // declares 68 bytes of payload, 67 present
    assert_eq!(
        app_unprotector().open(0, &record),
        Err(RecordError::LengthMismatch {
            got: 72,
            declared: 73
        }),
    );

    // A protected record's outer type is always application_data.
    let mut record = unhex(CLIENT_APP_RECORD);
    record[0] = CONTENT_HANDSHAKE;
    assert_eq!(
        app_unprotector().open(0, &record),
        Err(RecordError::OuterTypeNotApplicationData { got: 0x16 }),
    );

    // A key that does not fit the algorithm is refused before any primitive
    // runs.
    let result = RecordProtector13::new(&aead::AES_128_GCM, &[0x00; 32], [0u8; 12]);
    assert_eq!(
        result.unwrap_err(),
        RecordError::InvalidKeyLength {
            expected: 16,
            got: 32
        },
    );
}

#[test]
fn oversized_records_are_refused() {
    // One byte past the RFC 8446 §5.2 ceiling: the content type byte plus
    // the payload plus the tag must fit 2^14 + 256.
    let plaintext_len = MAX_CIPHERTEXT_LEN - aead::AES_128_GCM.tag_len();
    assert_eq!(
        app_protector().seal(0, CONTENT_APPLICATION_DATA, &vec![0u8; plaintext_len]),
        Err(RecordError::RecordTooLarge {
            len: MAX_CIPHERTEXT_LEN + 1,
            max: MAX_CIPHERTEXT_LEN,
        }),
        "the inner content type byte is part of the ciphertext length",
    );
}

#[test]
fn unprotected_records_frame_verbatim() {
    let record = unprotected_record(0x16, LEGACY_VERSION_TLS12, &[0x01, 0x02]);
    assert_eq!(
        record,
        vec![0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x02],
        "header + payload, nothing added",
    );
    let header = RecordHeader::parse(&record).expect("parse");
    assert_eq!(
        header,
        RecordHeader {
            content_type: CONTENT_HANDSHAKE,
            legacy_version: LEGACY_VERSION_TLS12,
            payload_len: 2,
        },
    );
    // The TLS 1.3 post-ServerHello records carry 0x0303.
    let record = unprotected_record(CONTENT_APPLICATION_DATA, LEGACY_VERSION_TLS13, &[]);
    assert_eq!(record[..RECORD_HEADER_LEN], [0x17, 0x03, 0x03, 0x00, 0x00]);
}
