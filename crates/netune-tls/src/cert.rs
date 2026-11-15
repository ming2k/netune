//! Minimal DER reading over the pieces of an X.509 certificate the TLS 1.3
//! handshake needs.
//!
//! This is certificate *structure*, not certificate *validation*: it walks
//! the outer SEQUENCE down to the SubjectPublicKeyInfo so a signature can be
//! verified against the key the certificate binds. Trust is the verifier's
//! job ([`INV-TLS-08`]); this module only finds the bytes.

/// The content of one DER TLV: everything after its header.
fn tlv_value(tlv: &[u8]) -> Option<&[u8]> {
    match tlv.get(1)? {
        length if *length < 0x80 => tlv.get(2..),
        0x81 => tlv.get(3..),
        0x82 => tlv.get(4..),
        _ => None,
    }
}

/// Read one DER tag-length-value from the front of `input`, returning the
/// encoded TLV and the rest.
fn take_tlv(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_tag, rest) = input.split_first()?;
    // Long-form lengths only go up to two bytes here; certificates never
    // need more, and the u32 arithmetic is bounded by the slice length.
    let (length, rest) = match rest.first()? {
        length if *length < 0x80 => (*length as usize, &rest[1..]),
        // 0x81/0x82 announce two- and one-byte lengths; the marker byte
        // itself is not part of the length.
        0x81 => {
            let (&len, rest) = rest[1..].split_first()?;
            (len as usize, rest)
        }
        0x82 => {
            let (bytes, rest) = rest[1..].split_first_chunk::<2>()?;
            (u16::from_be_bytes(*bytes) as usize, rest)
        }
        _ => return None,
    };
    let (_value, rest) = rest.split_at_checked(length)?;
    // The encoded TLV is everything before `rest`: header plus content.
    let encoded_len = input.len() - rest.len();
    Some((&input[..encoded_len], rest))
}

/// The SubjectPublicKeyInfo DER of a certificate: the input for signature
/// verification, however the verifier chooses to validate the chain.
///
/// `None` when the DER does not parse; the caller refuses the certificate
/// rather than guessing.
#[must_use]
pub fn subject_public_key_info(certificate: &[u8]) -> Option<&[u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    //                            signatureValue }
    let (outer, _) = take_tlv(certificate)?;
    let outer_body = tlv_value(outer)?;
    let (tbs, _) = take_tlv(outer_body)?;
    // The body of the tbsCertificate SEQUENCE: the elements begin here.
    let tbs = tlv_value(tbs)?;
    // tbsCertificate ::= SEQUENCE {
    //     [0] version OPTIONAL, serialNumber, signature, issuer, validity,
    //     subject, subjectPublicKeyInfo, ... }
    let (first, rest) = take_tlv(tbs)?;
    // The first element is the version only when it carries context tag 0.
    let rest = if first.first() == Some(&0xa0) {
        rest
    } else {
        tbs
    };
    // Skip serialNumber, signature, issuer, validity, subject.
    let mut rest = rest;
    for _ in 0..5 {
        let (_, tail) = take_tlv(rest)?;
        rest = tail;
    }
    let (spki, _) = take_tlv(rest)?;
    Some(spki)
}

#[cfg(test)]
mod tests {
    use super::subject_public_key_info;

    #[test]
    fn a_synthetic_certificate_yields_a_spki_a_truncated_one_does_not() {
        // SPKI ::= SEQUENCE { SEQUENCE(alg) BITSTRING }
        let spki = [
            0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x00, 0x03, 0x03, 0x00, 0xaa, 0xbb,
        ];
        // Certificate ::= SEQUENCE { tbs ::= SEQUENCE { version, serial,
        // sig, issuer, validity, subject, spki } }
        let mut tbs = vec![0x30, 0x00]; // length patched below
        tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x03]); // version
        tbs.extend_from_slice(&[0x02, 0x01, 0x01]); // serial
        tbs.extend_from_slice(&[0x30, 0x00]); // signature
        tbs.extend_from_slice(&[0x30, 0x00]); // issuer
        tbs.extend_from_slice(&[0x30, 0x00]); // validity
        tbs.extend_from_slice(&[0x30, 0x00]); // subject
        tbs.extend_from_slice(&spki);
        tbs[1] = (tbs.len() - 2) as u8;
        let mut certificate = vec![0x30, 0x00];
        certificate.extend_from_slice(&tbs);
        certificate.extend_from_slice(&[0x30, 0x00]); // signatureAlgorithm
        certificate.extend_from_slice(&[0x03, 0x00]); // signatureValue
        certificate[1] = (certificate.len() - 2) as u8;

        let extracted = subject_public_key_info(&certificate).expect("the SPKI parses");
        assert_eq!(extracted, spki);

        assert!(subject_public_key_info(&[]).is_none());
        assert!(subject_public_key_info(&[0x30]).is_none());
        assert!(subject_public_key_info(&[0x30, 0x03, 0x00]).is_none());
    }
}
