use base64::Engine as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::error::WsError;

/// The standard RFC 6455 WebSocket GUID string.
pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0x4a9234857b29a10c);

/// Compute the SHA-1 digest of bytes according to RFC 3174.
///
/// Self-contained implementation without external C/OpenSSL or heavy crypto crates,
/// strictly adhering to `[INV-TRANSPORT-00]`.
pub fn sha1(bytes: &[u8]) -> [u8; 20] {
    const H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    let mut message = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = H0;
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, &w_i) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w_i);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Compute `Sec-WebSocket-Accept` value from a `Sec-WebSocket-Key` (RFC 6455 §1.3).
pub fn compute_accept_key(sec_key: &str) -> String {
    let mut input = String::with_capacity(sec_key.len() + WS_GUID.len());
    input.push_str(sec_key);
    input.push_str(WS_GUID);
    let digest = sha1(input.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Generate a fresh 16-byte random nonce for the client handshake.
pub fn generate_nonce() -> [u8; 16] {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = NONCE_COUNTER.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    let mut state = (now as u64) ^ count ^ 0x94d049bb133111eb;

    let mut rand64 = || {
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    };

    let r1 = rand64();
    let r2 = rand64();
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&r1.to_ne_bytes());
    out[8..16].copy_from_slice(&r2.to_ne_bytes());
    out
}

/// Generate a base64-encoded `Sec-WebSocket-Key` header value.
pub fn generate_key() -> String {
    base64::engine::general_purpose::STANDARD.encode(generate_nonce())
}

/// Verify that the server's `Sec-WebSocket-Accept` header matches the expected hash.
pub fn verify_handshake(sec_key: &str, accept_header: &str) -> Result<(), WsError> {
    let expected = compute_accept_key(sec_key);
    if expected == accept_header.trim() {
        Ok(())
    } else {
        Err(WsError::HandshakeFailed(format!(
            "Sec-WebSocket-Accept mismatch: expected {expected}, got {accept_header}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_official_vectors() {
        // RFC 3174 Test 1: "abc"
        let d1 = sha1(b"abc");
        assert_eq!(hex::encode(d1), "a9993e364706816aba3e25717850c26c9cd0d89d");

        // Test empty string
        let d0 = sha1(b"");
        assert_eq!(hex::encode(d0), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        // RFC 3174 Test 2: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let d2 = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(hex::encode(d2), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    #[test]
    fn test_rfc6455_handshake_example() {
        // RFC 6455 Section 1.3 example vector
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert!(verify_handshake(key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=").is_ok());
    }

    mod hex {
        pub fn encode(bytes: impl AsRef<[u8]>) -> String {
            bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
        }
    }
}
