use crate::message::*;

fn validate(bytes: &[u8]) -> Result<(), ()> {
    let mut v = Utf8Validator::new(usize::MAX);
    v.push(bytes).map_err(|_| ())?;
    v.finish().map(|_| ()).map_err(|_| ())
}

#[test]
fn plain_ascii_passes() {
    assert!(validate(b"hello").is_ok());
}

#[test]
fn two_byte_sequences() {
    assert!(validate("héllo".as_bytes()).is_ok());
    // é = C3 A9
}

#[test]
fn overlong_two_byte_rejected() {
    // C0 AF is the overlong encoding of '/' — must reject.
    assert!(validate(&[0xC0, 0xAF]).is_err());
    assert!(validate(&[0xC1, 0xBF]).is_err());
}

#[test]
fn surrogate_range_rejected() {
    // ED A0 80 = U+D800 surrogate — must reject.
    assert!(validate(&[0xED, 0xA0, 0x80]).is_err());
    // ED 80 80 = U+D000 (below surrogate range) — must accept.
    assert!(validate(&[0xED, 0x80, 0x80]).is_ok());
}

#[test]
fn f4_beyond_plane_16_rejected() {
    // F4 90 80 80 would be U+110000 — must reject.
    assert!(validate(&[0xF4, 0x90, 0x80, 0x80]).is_err());
    // F4 8F BF BD = U+10FFFF — must accept.
    assert!(validate(&[0xF4, 0x8F, 0xBF, 0xBD]).is_ok());
}

#[test]
fn truncated_sequence_rejected() {
    assert!(validate(&[0xC3]).is_err());
    assert!(validate(&[0xE2, 0x82]).is_err());
}

#[test]
fn fragmented_split_sequence_validates_incrementally() {
    // "é" split across two pushes: C3 | A9.
    let mut v = Utf8Validator::new(1024);
    v.push(&[0xC3]).expect("first half");
    v.push(&[0xA9]).expect("second half");
    v.finish().expect("assembles");
}

#[test]
fn fragmented_invalid_byte_fails_at_that_frame() {
    let mut v = Utf8Validator::new(1024);
    v.push(b"good ").expect("first frame ok");
    // A stray continuation byte with no lead: fails here, not at finish.
    let err = v.push(&[0x80]);
    assert!(err.is_err());
}
