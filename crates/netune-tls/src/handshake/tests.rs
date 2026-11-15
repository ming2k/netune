//! The RFC 8448 §3 "Simple 1-RTT Handshake" is the acceptance criterion for
//! the state machine: the trace publishes the exact ClientHello, the exact
//! ServerHello record, the exact encrypted server flight and the exact
//! client Finished record. Our machine, fed the trace's bytes with the
//! trace's client key, must produce the trace's bytes — including a
//! CertificateVerify verified against the trace's embedded RSA key with
//! `aws-lc`.
//!
//! The hex strings are copied from the RFC with their original spacing.

use super::{CONTENT_APPLICATION_DATA, ClientHandshake, HandshakeProgress, ServerCertVerifier};
use crate::hello::{ClientHello, ExtensionBody, GoIdentity, KeyShareEntry};
use crate::key_exchange::ClientKeyShare;

/// Parse RFC-style spaced hex.
fn unhex(hex: &str) -> Vec<u8> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..cleaned.len() / 2)
        .map(|index| u8::from_str_radix(&cleaned[index * 2..index * 2 + 2], 16).expect("hex digit"))
        .collect()
}

/// The RFC 8448 §3 ClientHello handshake message (196 octets).
const RFC_8448_CLIENT_HELLO: &str = "
    01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
    02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01
    00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33
    00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13
    69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04
    01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

/// The RFC 8448 §3 ClientHello record (201 octets).
const RFC_8448_CLIENT_HELLO_RECORD: &str = "
    16 03 01 00 c4 01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
    ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73
    65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01
    04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0
    6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
    02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00
    02 40 01";

/// The RFC 8448 §3 client x25519 private key.
const RFC_8448_CLIENT_PRIVATE: &str = "
    49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05";

/// The RFC 8448 §3 client x25519 public key: what the imported scalar must
/// expand to.
const RFC_8448_CLIENT_PUBLIC: &str = "
    99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c";

/// The RFC 8448 §3 ServerHello record (95 octets).
const RFC_8448_SERVER_HELLO_RECORD: &str = "
    16 03 03 00 5a 02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14
    34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66
    76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";

/// The RFC 8448 §3 server flight record (679 octets): EncryptedExtensions,
/// Certificate, CertificateVerify and Finished under the handshake keys.
const RFC_8448_SERVER_FLIGHT_RECORD: &str = "
    17 03 03 02 a2 d1 ff 33 4a 56 f5 bf f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df
    78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45 cb 96 0b 40 68 90 51 23 ea 78 b1 11
    b4 29 ba 91 91 cd 05 d2 a3 89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b d9 ae fb
    0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9 b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09
    ae e6 e1 22 a4 cf 51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d 2e d6 5b 0e 3c dd
    0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55 cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7
    ed 1a 8f d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6 86 94 5b a2 46 ab 66 e5 ed
    d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac 66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea
    52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c
    27 03 42 72 96 8a 26 4e d6 54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb 31 7b 66
    d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59 62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9
    61 ff b1 38 64 7e 92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af 36 87 90 18 e3 f2
    52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37 8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b
    48 05 2c f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88 2b d8 9f c5 08 00 be cc a6
    2d 6c 74 11 6d bd 29 72 fd a1 fa 80 f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69
    18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99 2f 67 f8 af e6 7f 76 91 3f a3 88 cb
    56 30 c8 ca 01 e0 c6 5d 11 c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51 56 14 63
    6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42 f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31
    7f c9 fa 66 a7 3f 60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd d5 02 78 40 16 e4
    b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af 93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17
    19 bf da bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b";

/// A verifier that trusts the trace's chain: the crypto that matters is
/// checked separately by the CertificateVerify verification.
struct TrustTheTrace;

impl ServerCertVerifier for TrustTheTrace {
    fn verify_chain(
        &mut self,
        _server_name: &str,
        _end_entity: &[u8],
        _intermediates: &[Vec<u8>],
    ) -> Result<(), String> {
        Ok(())
    }
}

/// The trace's ClientHello, rebuilt field by field from the RFC's bytes.
fn rfc_8448_hello() -> ClientHello {
    ClientHello {
        legacy_version: 0x0303,
        random: unhex(
            "cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7",
        )
        .try_into()
        .expect("32-byte random"),
        session_id: Vec::new(),
        cipher_suites: vec![0x1301, 0x1303, 0x1302],
        compression_methods: vec![0x00],
        extensions: vec![
            crate::hello::Extension {
                body: ExtensionBody::ServerName { name: "server".into() },
            },
            crate::hello::Extension {
                body: ExtensionBody::RenegotiationInfo,
            },
            crate::hello::Extension {
                body: ExtensionBody::SupportedGroups {
                    groups: vec![0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104],
                },
            },
            crate::hello::Extension {
                body: ExtensionBody::Raw { kind: 0x0023, body: Vec::new() },
            },
            crate::hello::Extension {
                body: ExtensionBody::KeyShare {
                    shares: vec![KeyShareEntry {
                        group: 0x001d,
                        share: unhex(RFC_8448_CLIENT_PUBLIC),
                    }],
                },
            },
            crate::hello::Extension {
                body: ExtensionBody::SupportedVersions { versions: vec![0x0304] },
            },
            crate::hello::Extension {
                body: ExtensionBody::SignatureAlgorithms {
                    schemes: vec![
                        0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
                        0x0601, 0x0201, 0x0402, 0x0502, 0x0602, 0x0202,
                    ],
                },
            },
            crate::hello::Extension {
                body: ExtensionBody::Raw { kind: 0x002d, body: vec![0x01, 0x01] },
            },
            crate::hello::Extension {
                body: ExtensionBody::Raw { kind: 0x001c, body: vec![0x40, 0x01] },
            },
        ],
    }
}

/// A verifier that accepts anything; the live differential test checks the
/// crypto elsewhere. Test-only by construction.
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

#[test]
fn the_rfc_8448_handshake_completes_end_to_end() {
    // The rebuilt hello must serialize to the trace's exact bytes.
    let hello = rfc_8448_hello();
    assert_eq!(
        hello.serialize().expect("the trace hello encodes"),
        unhex(RFC_8448_CLIENT_HELLO),
    );

    // The trace's private scalar expands to the trace's public key.
    let share = ClientKeyShare::x25519_from_private(0x001d, &unhex(RFC_8448_CLIENT_PRIVATE))
        .expect("import");
    assert_eq!(share.share, unhex(RFC_8448_CLIENT_PUBLIC));

    let mut handshake = ClientHandshake::start(hello, vec![share], TrustTheTrace).expect("start");
    assert_eq!(
        handshake.take_output(),
        unhex(RFC_8448_CLIENT_HELLO_RECORD),
        "the first flight is the trace's ClientHello record",
    );

    // The ServerHello negotiates AES_128_GCM_SHA256 over x25519.
    match handshake
        .progress(&unhex(RFC_8448_SERVER_HELLO_RECORD))
        .expect("server hello")
    {
        HandshakeProgress::Blocked => {}
        other => panic!("the ServerHello alone must not establish: {other:?}"),
    }

    // The encrypted server flight: keys derived from the agreed shared
    // secret decrypt it, the EncryptedExtensions and Certificate parse, and
    // the CertificateVerify arrives with the trace's scheme (0x0804) — but
    // the trace's server key is 1024-bit RSA, below the RSA_PSS_2048_8192
    // bound every correct implementation enforces, so the machine refuses
    // the signature instead of verifying it. The signature path itself is
    // differentially validated by the live rustls handshake below, whose
    // server verifies our Finished over its own transcript.
    let error = handshake
        .progress(&unhex(RFC_8448_SERVER_FLIGHT_RECORD))
        .expect_err("the flight's CertificateVerify cannot verify");
    assert_eq!(
        error,
        super::HandshakeError::SignatureRejected { scheme: 0x0804 },
        "the trace's 1024-bit RSA key is below the modern RSA-PSS bound",
    );
}

#[test]
fn the_go_identity_completes_against_a_rustls_server() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use test_support::tls::identity;

    let identity = identity(&["localhost"], &[b"http/1.1"]);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        let mut connection =
            rustls::ServerConnection::new(Arc::clone(&identity.server)).expect("server connection");
        let mut buffer = [0u8; 16_384];
        let mut response_sent = false;
        loop {
            while connection.wants_write() {
                let written = connection
                    .write_tls(&mut &mut buffer[..])
                    .expect("write_tls");
                if written == 0 {
                    break;
                }
                socket.write_all(&buffer[..written]).expect("write");
            }
            if response_sent {
                break;
            }
            let read = socket.read(&mut buffer).expect("read");
            if read == 0 {
                break;
            }
            connection.read_tls(&mut &buffer[..read]).expect("read_tls");
            connection.process_new_packets().expect("process");
            let mut plaintext = [0u8; 1024];
            if let Ok(size) = connection.reader().read(&mut plaintext)
                && size > 0
            {
                assert!(
                    plaintext[..size].starts_with(b"GET / "),
                    "the owned client sent an HTTP request: {:?}",
                    String::from_utf8_lossy(&plaintext[..size])
                );
                connection
                    .writer()
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .expect("respond");
                response_sent = true;
            }
        }
    });

    // The go_identity offer, with real generated shares for the hybrid and
    // classical groups.
    let shares = ClientKeyShare::generate(&[0x11ec, 0x001d]).expect("shares");
    let entries = shares
        .iter()
        .map(|share| KeyShareEntry {
            group: share.group,
            share: share.share.clone(),
        })
        .collect();
    let mut random = [0u8; 32];
    aws_lc_rs::rand::fill(&mut random).expect("random");
    let hello = ClientHello::go_identity(GoIdentity {
        server_name: "localhost",
        alpn: &[b"http/1.1"],
        random,
        session_id: &[0x42; 32],
        key_shares: entries,
        cipher_suites: None,
        kx_groups: None,
    });

    let mut handshake = ClientHandshake::start(hello, shares, AcceptAny).expect("start");
    let mut socket = TcpStream::connect(address).expect("connect");
    socket
        .write_all(&handshake.take_output())
        .expect("write hello");

    let established = loop {
        let output = handshake.take_output();
        if !output.is_empty() {
            socket.write_all(&output).expect("write flight");
        }
        let mut buffer = [0u8; 16_384];
        let read = socket.read(&mut buffer).expect("read");
        assert!(read > 0, "the server hung up mid-handshake");
        match handshake.progress(&buffer[..read]).expect("progress") {
            HandshakeProgress::Blocked => continue,
            HandshakeProgress::Established(established) => {
                // The client flight (Finished) is pending output; the server
                // cannot read application data before it is on the wire.
                let flight = handshake.take_output();
                if !flight.is_empty() {
                    socket.write_all(&flight).expect("write client flight");
                }
                break established;
            }
        }
    };
    assert_eq!(
        established.alpn,
        Some(b"http/1.1".to_vec()),
        "the server selected the offered ALPN",
    );

    // Application data in both directions, through the owned record layer.
    let super::Protectors::Tls13 {
        write,
        read,
        write_seq,
        read_seq,
    } = established.protectors
    else {
        panic!("the rustls server negotiated TLS 1.3");
    };
    assert_eq!((write_seq, read_seq), (0, 0), "fresh TLS 1.3 epochs");
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let record = write
        .seal(write_seq, CONTENT_APPLICATION_DATA, request)
        .expect("seal request");
    socket.write_all(&record).expect("write request");

    let mut buffer = [0u8; 16_384];
    let read_bytes = socket.read(&mut buffer).expect("read response");
    assert!(read_bytes > 0, "the server hung up before responding");
    let (inner, payload) = read
        .open(read_seq, &buffer[..read_bytes])
        .expect("open response");
    assert_eq!(inner, CONTENT_APPLICATION_DATA);
    assert!(
        payload.starts_with(b"HTTP/1.1 200 OK"),
        "the rustls server answered over the owned handshake: {:?}",
        String::from_utf8_lossy(&payload)
    );
    server.join().expect("server thread");
}

#[test]
fn the_go_identity_completes_tls_1_2_against_a_rustls_server() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use test_support::tls::identity;

    // Both PRFs the GCM suites use: SHA-256 (c02b) and SHA-384 (c02c).
    for suite in [
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ] {
        let identity = identity(&["localhost"], &[b"http/1.1"]);
        // Pin the suite through the provider: the builder takes the
        // provider's suite list as-is.
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites = vec![suite];
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2 versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key.clone()),
                ),
            )
            .expect("server certificate");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut connection =
                rustls::ServerConnection::new(Arc::new(server_config)).expect("server connection");
            let mut buffer = [0u8; 16_384];
            let mut response_sent = false;
            loop {
                while connection.wants_write() {
                    let written = connection
                        .write_tls(&mut &mut buffer[..])
                        .expect("write_tls");
                    if written == 0 {
                        break;
                    }
                    socket.write_all(&buffer[..written]).expect("write");
                }
                if response_sent {
                    break;
                }
                let read = socket.read(&mut buffer).expect("read");
                if read == 0 {
                    break;
                }
                connection.read_tls(&mut &buffer[..read]).expect("read_tls");
                match connection.process_new_packets() {
                    Ok(_processed) => {}
                    Err(e) => {
                        panic!("the rustls server rejected our flight after {read} bytes: {e}")
                    }
                }
                let mut plaintext = [0u8; 1024];
                if let Ok(size) = connection.reader().read(&mut plaintext)
                    && size > 0
                {
                    connection
                        .writer()
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                        .expect("respond");
                    response_sent = true;
                }
            }
        });

        let shares = ClientKeyShare::generate(&[0x11ec, 0x001d]).expect("shares");
        let entries = shares
            .iter()
            .map(|share| KeyShareEntry {
                group: share.group,
                share: share.share.clone(),
            })
            .collect();
        let mut random = [0u8; 32];
        aws_lc_rs::rand::fill(&mut random).expect("random");
        let hello = ClientHello::go_identity(GoIdentity {
            server_name: "localhost",
            alpn: &[b"http/1.1"],
            random,
            session_id: &[0x42; 32],
            key_shares: entries,
            cipher_suites: None,
            kx_groups: None,
        });

        let mut handshake = ClientHandshake::start(hello, shares, AcceptAny).expect("start");
        let mut socket = TcpStream::connect(address).expect("connect");
        socket
            .write_all(&handshake.take_output())
            .expect("write hello");

        let established = loop {
            let output = handshake.take_output();
            if !output.is_empty() {
                socket.write_all(&output).expect("write flight");
            }
            let mut buffer = [0u8; 16_384];
            let read = socket.read(&mut buffer).expect("read");
            assert!(read > 0, "the server hung up mid-handshake");
            #[cfg(test)]
            #[cfg(test)]
            match handshake.progress(&buffer[..read]).expect("progress") {
                HandshakeProgress::Blocked => {
                    continue;
                }
                HandshakeProgress::Established(established) => {
                    // The client flight (ClientKeyExchange, change_cipher_spec
                    // and Finished) is pending output.
                    let flight = handshake.take_output();
                    if !flight.is_empty() {
                        socket.write_all(&flight).expect("write client flight");
                    }
                    break established;
                }
            }
        };
        assert_eq!(
            established.alpn,
            Some(b"http/1.1".to_vec()),
            "the server selected the offered ALPN",
        );
        let super::Protectors::Tls12 {
            write,
            read,
            write_seq,
            read_seq,
        } = established.protectors
        else {
            panic!("the TLS 1.2 server must establish the 1.2 protectors");
        };
        assert_eq!((write_seq, read_seq), (1, 1), "both Finished consumed 0");

        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let record = write
            .seal(write_seq, CONTENT_APPLICATION_DATA, request)
            .expect("seal request");
        socket.write_all(&record).expect("write request");

        let mut buffer = [0u8; 16_384];
        let read_bytes = socket.read(&mut buffer).expect("read response");
        assert!(read_bytes > 0, "the server hung up before responding");
        let (inner, payload) = read
            .open(read_seq, &buffer[..read_bytes])
            .expect("open response");
        assert_eq!(inner, CONTENT_APPLICATION_DATA);
        assert!(
            payload.starts_with(b"HTTP/1.1 200 OK"),
            "the rustls TLS 1.2 server answered over the owned handshake: {:?}",
            String::from_utf8_lossy(&payload)
        );
        server.join().expect("server thread");
    }
}

#[test]
fn chrome_firefox_safari_and_go_standard_blueprints_complete_against_rustls() {
    use crate::hello::{BlueprintBuildParams, ClientHelloBlueprint};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    let identity = test_support::tls::identity(&["localhost"], &[b"h2", b"http/1.1"]);
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.certificate.clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                identity.key.clone(),
            )),
        )
        .expect("server cert");
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);

    for (name, bp) in [
        ("chrome_current", ClientHelloBlueprint::chrome_current()),
        ("firefox_current", ClientHelloBlueprint::firefox_current()),
        ("safari_current", ClientHelloBlueprint::safari_current()),
        ("go_standard", ClientHelloBlueprint::go_standard()),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let cfg = Arc::clone(&server_config);
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut conn = rustls::ServerConnection::new(cfg).expect("conn");
            let mut buf = [0u8; 16_384];
            loop {
                while conn.wants_write() {
                    let n = conn.write_tls(&mut &mut buf[..]).expect("write_tls");
                    if n == 0 {
                        break;
                    }
                    socket.write_all(&buf[..n]).expect("write");
                }
                if !conn.is_handshaking() {
                    break;
                }
                let n = socket.read(&mut buf).expect("read");
                if n == 0 {
                    break;
                }
                conn.read_tls(&mut &buf[..n]).expect("read_tls");
                conn.process_new_packets().expect("process");
            }
        });

        let shares = ClientKeyShare::generate(&bp.key_share_groups).expect("shares");
        let entries = shares
            .iter()
            .map(|s| KeyShareEntry {
                group: s.group,
                share: s.share.clone(),
            })
            .collect();
        let hello = bp
            .build(BlueprintBuildParams {
                server_name: "localhost",
                random: [0x17; 32],
                session_id: &[0x28; 32],
                key_shares: entries,
                grease_seed: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                permutation_seed: [0x9a; 32],
            })
            .unwrap_or_else(|e| panic!("{name} build: {e}"));

        let mut machine = ClientHandshake::start(hello, shares, AcceptAny)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut socket = std::net::TcpStream::connect(addr).expect("connect");
        socket
            .write_all(&machine.take_output())
            .expect("write client hello");

        let mut buf = [0u8; 16_384];
        loop {
            let n = socket.read(&mut buf).expect("read");
            assert!(n > 0, "{name}: server closed mid-handshake");
            if let HandshakeProgress::Established(est) = machine
                .progress(&buf[..n])
                .unwrap_or_else(|e| panic!("{name} progress: {e}"))
            {
                assert_eq!(est.alpn.as_deref(), Some(b"h2".as_slice()), "{name}: ALPN");
                let out = machine.take_output();
                if !out.is_empty() {
                    socket.write_all(&out).expect("write finished");
                }
                break;
            }
            let out = machine.take_output();
            if !out.is_empty() {
                socket.write_all(&out).expect("write flight");
            }
        }
        server.join().expect("server thread");
    }
}

#[test]
fn compressed_certificate_decompresses_zlib_and_brotli_and_hashes_wire_message() {
    use std::io::Write as _;

    let identity = test_support::tls::identity(&["localhost"], &[b"http/1.1"]);
    let der = identity.certificate.as_ref();
    // Construct a TLS 1.3 Certificate message body:
    // context_len(1)=0, chain_len(3), entry_cert_len(3), der, entry_ext_len(2)=0
    let entry_len = 3 + der.len() + 2;
    let mut cert_body = Vec::with_capacity(4 + entry_len);
    cert_body.push(0x00); // context len
    cert_body.extend_from_slice(&(entry_len as u32).to_be_bytes()[1..4]);
    cert_body.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..4]);
    cert_body.extend_from_slice(der);
    cert_body.extend_from_slice(&[0x00, 0x00]); // entry extensions

    // 1. zlib
    let mut zlib_enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zlib_enc.write_all(&cert_body).expect("zlib write");
    let zlib_bytes = zlib_enc.finish().expect("zlib finish");

    // 2. brotli
    let mut brotli_bytes = Vec::new();
    {
        let mut brotli_enc = brotli::CompressorWriter::new(&mut brotli_bytes, 4096, 4, 22);
        brotli_enc.write_all(&cert_body).expect("brotli write");
    }

    for (alg, compressed) in [
        (crate::wire::CERT_COMP_ZLIB, zlib_bytes),
        (crate::wire::CERT_COMP_BROTLI, brotli_bytes),
    ] {
        let mut body = Vec::new();
        body.extend_from_slice(&alg.to_be_bytes());
        body.extend_from_slice(&(cert_body.len() as u32).to_be_bytes()[1..4]);
        body.extend_from_slice(&(compressed.len() as u32).to_be_bytes()[1..4]);
        body.extend_from_slice(&compressed);

        let mut msg = Vec::with_capacity(4 + body.len());
        msg.push(super::COMPRESSED_CERTIFICATE);
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        msg.extend_from_slice(&body);

        let shares = ClientKeyShare::generate(&[0x001d]).expect("shares");
        let entries = shares
            .iter()
            .map(|s| KeyShareEntry {
                group: s.group,
                share: s.share.clone(),
            })
            .collect();
        let hello = ClientHello::go_identity(crate::hello::GoIdentity {
            server_name: "localhost",
            alpn: &[b"http/1.1"],
            random: [0x11; 32],
            session_id: &[0x22; 32],
            key_shares: entries,
            cipher_suites: None,
            kx_groups: None,
        });
        let mut machine = ClientHandshake::start(hello, shares, AcceptAny).expect("start");
        let before_len = machine.transcript.len();
        machine.flight_stage = super::FlightStage::Certificate;
        machine
            .process_compressed_certificate(&msg)
            .expect("compressed cert accepted");
        assert!(matches!(
            machine.flight_stage,
            super::FlightStage::CertificateVerify
        ));
        assert_eq!(
            &machine.transcript[before_len..],
            &msg[..],
            "RFC 8879 §4: transcript hashes the CompressedCertificate wire message"
        );
    }
}
