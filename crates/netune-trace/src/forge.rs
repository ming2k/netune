//! Pure-data TLS ClientHello forge and assembly engine (ADR-0006).
//!
//! Standard TLS client engines (including rustls) randomize or strictly enforce
//! internal extension order, cipher suite lists, and GREASE placement.
//!
//! [`ClientHelloForge`] gives complete, deterministic, byte-for-byte control over
//! every field in the TLS ClientHello record:
//! - Exact extension sequencing (e.g. Chrome's GREASE first, ALPS, compress_cert).
//! - RFC 8701 GREASE injection (ciphers, extensions, supported groups, key shares).
//! - Chrome 130+, Safari 18+, and Firefox 132+ wire presets.
//! - Self-verifying: builds bytes that parse directly back into [`crate::ClientHello`]
//!   and produce the desired [`crate::Ja4`] fingerprint.

/// A raw TLS extension to encode on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExtension {
    pub ext_type: u16,
    pub payload: Vec<u8>,
}

/// A deterministic ClientHello constructor.
#[derive(Debug, Clone)]
pub struct ClientHelloForge {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<RawExtension>,
}

impl Default for ClientHelloForge {
    fn default() -> Self {
        Self {
            legacy_version: 0x0303, // TLS 1.2
            random: [0x42; 32],
            session_id: vec![0x01; 32],
            cipher_suites: Vec::new(),
            compression_methods: vec![0x00], // null compression
            extensions: Vec::new(),
        }
    }
}

impl ClientHelloForge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Modern Chromium baseline (Chrome ~130).
    pub fn chrome(server_name: &str) -> Self {
        let mut forge = Self::new();
        // Chrome 130 cipher suites (with GREASE 0x2a2a at head)
        forge.cipher_suites = vec![
            0x2a2a, // GREASE
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        ];

        // 1. GREASE extension (0x3a3a)
        forge.add_extension(0x3a3a, vec![0x00]);

        // 2. server_name (0x0000)
        forge.add_sni(server_name);

        // 3. extended_master_secret (0x0017)
        forge.add_extension(0x0017, vec![]);

        // 4. renegotiation_info (0xff01)
        forge.add_extension(0xff01, vec![0x00]);

        // 5. supported_groups (0x000a) with GREASE
        forge.add_supported_groups(&[0x2a2a, 0x001d, 0x0017, 0x0018]);

        // 6. ec_point_formats (0x000b)
        forge.add_ec_point_formats(&[0x00]);

        // 7. session_ticket (0x0023)
        forge.add_extension(0x0023, vec![]);

        // 8. alpn (0x0010) -> h2, http/1.1
        forge.add_alpn(&[b"h2", b"http/1.1"]);

        // 9. status_request (0x0005)
        forge.add_extension(0x0005, vec![0x01, 0x00, 0x00, 0x00, 0x00]);

        // 10. signature_algorithms (0x000d)
        forge.add_signature_algorithms(&[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]);

        // 11. signed_certificate_timestamp (0x0012)
        forge.add_extension(0x0012, vec![]);

        // 12. key_share (0x0033) with GREASE
        forge.add_key_share(&[(0x2a2a, &[0x00]), (0x001d, &[0x01; 32])]);

        // 13. psk_key_exchange_modes (0x002d)
        forge.add_extension(0x002d, vec![0x01, 0x01]);

        // 14. supported_versions (0x002b) with GREASE and TLS 1.3/1.2
        forge.add_supported_versions(&[0x3a3a, 0x0304, 0x0303]);

        // 15. compress_certificate (0x001b)
        forge.add_extension(0x001b, vec![0x02, 0x00, 0x02]);

        // 16. application_settings ALPS (0x4469)
        forge.add_extension(0x4469, vec![0x00, 0x03, 0x02, b'h', b'2']);

        // 17. GREASE extension (0x0a0a)
        forge.add_extension(0x0a0a, vec![]);

        forge
    }

    /// Modern Safari baseline (macOS / iOS Safari 18+).
    pub fn safari(server_name: &str) -> Self {
        let mut forge = Self::new();
        forge.cipher_suites = vec![
            0x1a1a, // GREASE
            0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009,
            0xc014, 0xc013,
        ];

        forge.add_extension(0x1a1a, vec![]); // GREASE
        forge.add_sni(server_name);
        forge.add_supported_groups(&[0x1a1a, 0x001d, 0x0017, 0x0018]);
        forge.add_ec_point_formats(&[0x00]);
        forge.add_signature_algorithms(&[0x0403, 0x0804, 0x0401, 0x0503, 0x0501, 0x0601]);
        forge.add_alpn(&[b"h2", b"http/1.1"]);
        forge.add_extension(0x0017, vec![]); // extended_master_secret
        forge.add_key_share(&[(0x1a1a, &[0x00]), (0x001d, &[0x02; 32])]);
        forge.add_extension(0x002d, vec![0x01, 0x01]); // psk_key_exchange_modes
        forge.add_supported_versions(&[0x1a1a, 0x0304, 0x0303]);

        forge
    }

    /// Modern Firefox baseline (Firefox 132+).
    pub fn firefox(server_name: &str) -> Self {
        let mut forge = Self::new();
        forge.cipher_suites = vec![
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];

        forge.add_sni(server_name);
        forge.add_extension(0x0017, vec![]); // extended_master_secret
        forge.add_extension(0xff01, vec![0x00]); // renegotiation_info
        forge.add_supported_groups(&[0x001d, 0x0017, 0x0018, 0x0100]);
        forge.add_ec_point_formats(&[0x00]);
        forge.add_extension(0x0023, vec![]); // session_ticket
        forge.add_alpn(&[b"h2", b"http/1.1"]);
        forge.add_signature_algorithms(&[
            0x0403, 0x0503, 0x0401, 0x0501, 0x0804, 0x0805, 0x0806, 0x0402, 0x0201,
        ]);
        forge.add_extension(0x002d, vec![0x01, 0x01]); // psk_key_exchange_modes
        forge.add_supported_versions(&[0x0304, 0x0303]);
        forge.add_extension(0x001b, vec![0x02, 0x00, 0x02]); // compress_certificate
        forge.add_key_share(&[(0x001d, &[0x03; 32])]);

        forge
    }

    /// Add an arbitrary extension with raw payload.
    pub fn add_extension(&mut self, ext_type: u16, payload: Vec<u8>) {
        self.extensions.push(RawExtension { ext_type, payload });
    }

    /// Add SNI (server_name, 0x0000).
    pub fn add_sni(&mut self, server_name: &str) {
        let name_bytes = server_name.as_bytes();
        let mut payload = Vec::with_capacity(5 + name_bytes.len());
        let list_len = (3 + name_bytes.len()) as u16;
        payload.extend_from_slice(&list_len.to_be_bytes());
        payload.push(0x00); // host_name
        payload.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(name_bytes);
        self.add_extension(0x0000, payload);
    }

    /// Add ALPN (0x0010).
    pub fn add_alpn(&mut self, protocols: &[&[u8]]) {
        let mut total_len = 0;
        for p in protocols {
            total_len += 1 + p.len();
        }
        let mut payload = Vec::with_capacity(2 + total_len);
        payload.extend_from_slice(&(total_len as u16).to_be_bytes());
        for p in protocols {
            payload.push(p.len() as u8);
            payload.extend_from_slice(p);
        }
        self.add_extension(0x0010, payload);
    }

    /// Add supported_groups (0x000a).
    pub fn add_supported_groups(&mut self, groups: &[u16]) {
        let mut payload = Vec::with_capacity(2 + groups.len() * 2);
        payload.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for &g in groups {
            payload.extend_from_slice(&g.to_be_bytes());
        }
        self.add_extension(0x000a, payload);
    }

    /// Add ec_point_formats (0x000b).
    pub fn add_ec_point_formats(&mut self, formats: &[u8]) {
        let mut payload = Vec::with_capacity(1 + formats.len());
        payload.push(formats.len() as u8);
        payload.extend_from_slice(formats);
        self.add_extension(0x000b, payload);
    }

    /// Add signature_algorithms (0x000d).
    pub fn add_signature_algorithms(&mut self, algs: &[u16]) {
        let mut payload = Vec::with_capacity(2 + algs.len() * 2);
        payload.extend_from_slice(&((algs.len() * 2) as u16).to_be_bytes());
        for &a in algs {
            payload.extend_from_slice(&a.to_be_bytes());
        }
        self.add_extension(0x000d, payload);
    }

    /// Add supported_versions (0x002b).
    pub fn add_supported_versions(&mut self, versions: &[u16]) {
        let mut payload = Vec::with_capacity(1 + versions.len() * 2);
        payload.push((versions.len() * 2) as u8);
        for &v in versions {
            payload.extend_from_slice(&v.to_be_bytes());
        }
        self.add_extension(0x002b, payload);
    }

    /// Add key_share (0x0033).
    pub fn add_key_share(&mut self, shares: &[(u16, &[u8])]) {
        let mut list_len = 0;
        for (_, val) in shares {
            list_len += 2 + 2 + val.len();
        }
        let mut payload = Vec::with_capacity(2 + list_len);
        payload.extend_from_slice(&(list_len as u16).to_be_bytes());
        for (group, val) in shares {
            payload.extend_from_slice(&group.to_be_bytes());
            payload.extend_from_slice(&(val.len() as u16).to_be_bytes());
            payload.extend_from_slice(val);
        }
        self.add_extension(0x0033, payload);
    }

    /// Build the complete ClientHello handshake message (type 0x01 + 3-byte length + body).
    pub fn build_client_hello(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(512);

        // legacy_version
        body.extend_from_slice(&self.legacy_version.to_be_bytes());
        // random
        body.extend_from_slice(&self.random);
        // session_id (1 byte len + data)
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        // cipher_suites (2 byte len + data)
        let c_len = (self.cipher_suites.len() * 2) as u16;
        body.extend_from_slice(&c_len.to_be_bytes());
        for &c in &self.cipher_suites {
            body.extend_from_slice(&c.to_be_bytes());
        }
        // compression_methods (1 byte len + data)
        body.push(self.compression_methods.len() as u8);
        body.extend_from_slice(&self.compression_methods);

        // extensions (2 byte len + data)
        let mut ext_bytes = Vec::new();
        for ext in &self.extensions {
            ext_bytes.extend_from_slice(&ext.ext_type.to_be_bytes());
            ext_bytes.extend_from_slice(&(ext.payload.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(&ext.payload);
        }
        body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_bytes);

        // Handshake header: type (1) + length (3)
        let body_len = body.len();
        let mut msg = Vec::with_capacity(4 + body_len);
        msg.push(0x01); // client_hello
        msg.push(((body_len >> 16) & 0xFF) as u8);
        msg.push(((body_len >> 8) & 0xFF) as u8);
        msg.push((body_len & 0xFF) as u8);
        msg.extend_from_slice(&body);
        msg
    }

    /// Build the full TLS Record (ContentType 22 + Legacy Version 0x0301 + 2-byte len + handshake).
    pub fn build_record(&self) -> Vec<u8> {
        let handshake = self.build_client_hello();
        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(0x16); // Handshake
        record.extend_from_slice(&0x0301u16.to_be_bytes()); // TLS 1.0 legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlsfp::{ClientHello, ja4};

    #[test]
    fn chrome_forge_produces_valid_client_hello_and_expected_ja4() {
        let forge = ClientHelloForge::chrome("api.openai.com");
        let record = forge.build_record();

        assert_eq!(record[0], 0x16, "TLS handshake record type");
        let hello_bytes = &record[5..];
        let parsed = ClientHello::parse(hello_bytes).expect("parse forged client hello");

        assert!(parsed.has_sni);
        assert_eq!(
            parsed.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(parsed.supported_versions_max, Some(0x0304)); // TLS 1.3

        let ja4_result = ja4(&parsed);
        println!("Chrome forged JA4: {}", ja4_result.fingerprint);

        // Chrome 130 JA4 characteristics:
        // t: TCP
        // 13: TLS 1.3
        // d: SNI present
        // 15: 15 non-GREASE ciphers (16 total - 1 GREASE)
        // 16: 15 non-GREASE extensions (17 total - 2 GREASE)
        // h2: ALPN h2 first
        assert!(ja4_result.fingerprint.starts_with("t13d1515h2_"));
    }

    #[test]
    fn safari_forge_produces_valid_client_hello_and_expected_ja4() {
        let forge = ClientHelloForge::safari("apple.com");
        let record = forge.build_record();

        let parsed = ClientHello::parse(&record[5..]).expect("parse forged safari");
        assert!(parsed.has_sni);
        assert_eq!(parsed.supported_versions_max, Some(0x0304));

        let ja4_result = ja4(&parsed);
        println!("Safari forged JA4: {}", ja4_result.fingerprint);
        assert!(ja4_result.fingerprint.starts_with("t13d"));
    }

    #[test]
    fn firefox_forge_produces_valid_client_hello_and_expected_ja4() {
        let forge = ClientHelloForge::firefox("mozilla.org");
        let record = forge.build_record();

        let parsed = ClientHello::parse(&record[5..]).expect("parse forged firefox");
        assert!(parsed.has_sni);
        assert_eq!(parsed.supported_versions_max, Some(0x0304));

        let ja4_result = ja4(&parsed);
        println!("Firefox forged JA4: {}", ja4_result.fingerprint);
        assert!(ja4_result.fingerprint.starts_with("t13d"));
    }
}
