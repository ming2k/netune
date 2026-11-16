//! TLS ClientHello parsing and JA3/JA4 fingerprints.
//!
//! **One honest caveat first.** JA3 is deprecated by its own authors; JA4 is
//! the successor. Both hash a *moving target*: a library's fingerprint
//! changes with every release of the browser being imitated and of the TLS
//! engine doing the imitating. This module's purpose is therefore not "we
//! have the right fingerprint" but "we can *see* our fingerprint at all" —
//! the prerequisite for any impersonation work, since a stock rustls
//! ClientHello cannot currently be shaped to a target profile.
//!
//! Everything here is pure: bytes in, structured view out, fingerprints as
//! strings. No socket, no clock — consistent with `netune-trace`'s no-I/O
//! discipline, and unit-tested against the published FoxIO worked example,
//! asserted exactly (not just in shape).
//!
//! # Spec notes baked into the implementation
//!
//! - JA4's TLS-version digit reports the *highest offered* version: a TLS
//!   1.3 hello whose `legacy_version` still says 0x0303 reports `13`
//!   because `supported_versions` offers 0x0304. A hello offering nothing
//!   above 1.2 reports its legacy field.
//! - JA4 counts and lists exclude GREASE (RFC 8701); JA3 keeps it (the
//!   original tooling hashed what was on the wire).
//! - JA4's extension hash omits SNI (0x0000) and ALPN (0x0010) — they are
//!   already in the `a` section — and appends the signature algorithms
//!   unsorted after an underscore.
//! - An empty extension list hashes to twelve zeroes rather than to the
//!   digest of nothing, so absence is visible instead of masquerading as a
//!   real hash.

use std::fmt::Write as _;

/// GREASE values (RFC 8701): both nibbles are `0xA` in the same positions.
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    (value & 0x0F0F) == 0x0A0A
}

/// The parts of a ClientHello that JA3 and JA4 read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Cipher suites in wire order, including GREASE if the sender sent it.
    pub cipher_suites: Vec<u16>,
    /// Extension types in wire order, including GREASE if sent.
    pub extensions: Vec<u16>,
    /// Supported groups in wire order (`supported_groups`, extension 0x000A).
    pub supported_groups: Vec<u16>,
    /// EC point formats (`ec_point_formats`, extension 0x000B) — JA3 hashes
    /// them, so the field exists even though JA4 ignores it.
    pub ec_point_formats: Vec<u16>,
    /// Signature algorithms in wire order (extension 0x000D).
    pub signature_algorithms: Vec<u16>,
    /// Protocols offered in ALPN (extension 0x0010), in order.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Highest version offered in `supported_versions` (0x002B), if present.
    pub supported_versions_max: Option<u16>,
    /// The ClientHello's `legacy_version` field.
    pub legacy_version: u16,
    /// Whether a `server_name` extension (0x0000) is present.
    pub has_sni: bool,
}

impl ClientHello {
    /// Parse a ClientHello from a TLS handshake message: the bytes starting
    /// at the one-byte handshake type (which must be `client_hello`).
    ///
    /// `None` for anything else — a different message type, or truncated
    /// bytes. Never a partial guess, mirroring the L2 packet parser's
    /// discipline of reporting `None` rather than inventing fields.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        // Handshake header: type (1) + 24-bit length (3).
        let rest = bytes.strip_prefix(&[0x01u8])?;
        let (length_bytes, body) = take::<3>(rest)?;
        if body.len() < read_u24(length_bytes) {
            return None;
        }

        // Body: legacy_version (2) + random (32) + session_id (1-byte
        // length) + cipher suites (2-byte length) + compression methods
        // (1-byte length) + extensions (2-byte length, TLS 1.2+).
        let (legacy_version, rest) = take_u16(body)?;
        let (_, rest) = take::<32>(rest)?;
        let (_, rest) = take_prefixed(rest)?; // session_id
        let (ciphers, rest) = take_prefixed_u16(rest)?;
        let (_, rest) = take_prefixed(rest)?; // compression methods

        let mut hello = Self {
            cipher_suites: words(ciphers),
            extensions: Vec::new(),
            supported_groups: Vec::new(),
            ec_point_formats: Vec::new(),
            signature_algorithms: Vec::new(),
            alpn_protocols: Vec::new(),
            supported_versions_max: None,
            legacy_version,
            has_sni: false,
        };

        // Extensions are optional; a TLS 1.0/1.1 hello ends here. The block
        // itself carries a 2-byte length, unlike the 1-byte vectors above.
        let Some((extension_bytes, _)) = take_prefixed_u16(rest) else {
            return Some(hello);
        };
        let mut extensions = extension_bytes;
        while let Some((extension_type, tail)) = take_u16(extensions) {
            let (data, tail) = take_prefixed_u16(tail)?;
            match extension_type {
                0x0000 => hello.has_sni = true,
                0x000A => hello.supported_groups = extension_words(data),
                0x000B => hello.ec_point_formats = ec_point_formats(data),
                0x000D => hello.signature_algorithms = extension_words(data),
                0x0010 => hello.alpn_protocols = alpn_protocols(data),
                0x002B => {
                    hello.supported_versions_max = supported_versions(data)
                        .filter(|versions| !versions.is_empty())
                        .and_then(|versions| versions.into_iter().filter(|&v| !is_grease(v)).max());
                }
                _ => {}
            }
            hello.extensions.push(extension_type);
            extensions = tail;
        }
        Some(hello)
    }
}

// ---- JA3 ----------------------------------------------------------------

/// The classic JA3 string and MD5 fingerprint.
///
/// `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
/// — fields comma-joined, the decimal values *within* each field
/// dash-joined, MD5 over the whole string. GREASE values are kept: the
/// original tooling hashed what was on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3 {
    /// Raw canonical JA3 fingerprint string before hashing.
    pub string: String,
    /// Lowercase hex MD5 digest of [`Ja3::string`].
    pub md5: String,
}

/// Compute the JA3 fingerprint.
///
/// `None` when a list the format demands is absent — the historical tooling
/// rendered an absent list as an empty field, which produces a fingerprint
/// indistinguishable from a real client that sent an empty list. An honest
/// absence beats a fabricated hash.
pub fn ja3(hello: &ClientHello) -> Option<Ja3> {
    // All four lists must have been present on the wire.
    let _ = hello.extensions.first()?;
    let _ = hello.supported_groups.first()?;
    let _ = hello.ec_point_formats.first()?;

    let string = [
        hello.legacy_version.to_string(),
        dashed_list(&hello.cipher_suites),
        dashed_list(&hello.extensions),
        dashed_list(&hello.supported_groups),
        dashed_list(&hello.ec_point_formats),
    ]
    .join(",");
    Some(Ja3 {
        md5: md5_hex(string.as_bytes()),
        string,
    })
}

// ---- JA4 ----------------------------------------------------------------

/// The JA4 fingerprint (`t13d1516h2_8daaf6152771_b186095e22b6` shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4 {
    /// Full JA4 fingerprint string (`a_b_c`).
    pub fingerprint: String,
    /// The TLS version the fingerprint reported (see the module notes).
    pub tls_version: u16,
    /// Whether SNI was present (`d`) or absent (`i`).
    pub has_sni: bool,
    /// Non-GREASE cipher-suite count.
    pub cipher_count: u16,
    /// Non-GREASE extension count (SNI and ALPN still counted).
    pub extension_count: u16,
    /// The `a` section's ALPN abbreviation (e.g. `h2`, `11`), if any.
    pub alpn_abbr: Option<String>,
}

/// Compute the JA4 fingerprint. Never fails on a parsed hello: `ja4` is a
/// pure function of the fields, and an unusual hello yields an unusual
/// (honest) fingerprint rather than an error.
pub fn ja4(hello: &ClientHello) -> Ja4 {
    // Highest offered version when that is TLS 1.3 or above; the legacy
    // field otherwise.
    let version = hello
        .supported_versions_max
        .filter(|&v| v >= 0x0304)
        .unwrap_or(hello.legacy_version);
    let version_text = match version {
        0x0304.. => "13", // 1.3+ all render as `13` per spec
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };

    let ciphers: Vec<u16> = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let extensions: Vec<u16> = hello
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();

    // First and last characters of the first ALPN value: `h2` → `h2`,
    // `http/1.1` → `h1`.
    let alpn_abbr = hello
        .alpn_protocols
        .first()
        .and_then(|first| Some((first.first()?, first.last()?)))
        .map(|(first, last)| {
            let mut text = String::new();
            text.push(*first as char);
            text.push(*last as char);
            text
        });

    let mut a = String::new();
    let _ = write!(
        a,
        "t{version_text}{}{:02}{:02}{}",
        if hello.has_sni { 'd' } else { 'i' },
        ciphers.len(),
        extensions.len(),
        alpn_abbr.as_deref().unwrap_or("00")
    );

    // Cipher hash: 4-hex codes, lower case, comma-delimited, sorted.
    let mut sorted_ciphers: Vec<String> = ciphers.iter().map(|c| format!("{c:04x}")).collect();
    sorted_ciphers.sort();
    let cipher_hash = sha256_hex_12(sorted_ciphers.join(",").as_bytes());

    // Extension hash: extensions sorted (SNI and ALPN removed), underscore,
    // signature algorithms in wire order.
    let mut sorted_extensions: Vec<String> = extensions
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .map(|e| format!("{e:04x}"))
        .collect();
    sorted_extensions.sort();
    let mut c_input = sorted_extensions.join(",");
    if !hello.signature_algorithms.is_empty() {
        c_input.push('_');
        let sigs: Vec<String> = hello
            .signature_algorithms
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect();
        c_input.push_str(&sigs.join(","));
    }
    // An empty extension list hashes to zeroes rather than to the digest of
    // nothing, so absence is visible instead of looking like a real hash.
    let extension_hash = if sorted_extensions.is_empty() {
        "000000000000".to_string()
    } else {
        sha256_hex_12(c_input.as_bytes())
    };

    Ja4 {
        fingerprint: format!("{a}_{cipher_hash}_{extension_hash}"),
        tls_version: version,
        has_sni: hello.has_sni,
        cipher_count: ciphers.len() as u16,
        extension_count: extensions.len() as u16,
        alpn_abbr,
    }
}

// ---- byte plumbing -------------------------------------------------------

const fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

const fn read_u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}

fn take_u16(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (head, rest) = take::<2>(bytes)?;
    Some((read_u16(head), rest))
}

/// Split off the first `N` bytes.
fn take<const N: usize>(bytes: &[u8]) -> Option<(&[u8; N], &[u8])> {
    let rest = bytes.get(N..)?;
    Some((bytes[..N].try_into().ok()?, rest))
}

/// Split off a length-prefixed vector (1-byte length).
fn take_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = bytes.split_first()?;
    rest.get(..len as usize)
        .map(|data| (data, &rest[len as usize..]))
}

/// Split off a 2-byte-length-prefixed vector — the extension block and each
/// extension's payload use this wider length.
fn take_prefixed_u16(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = take_u16(bytes)?;
    let len = len as usize;
    let (data, rest) = take_len(rest, len)?;
    Some((data, rest))
}

fn take_len(bytes: &[u8], len: usize) -> Option<(&[u8], &[u8])> {
    Some((bytes.get(..len)?, bytes.get(len..)?))
}

fn words(bytes: &[u8]) -> Vec<u16> {
    bytes.chunks_exact(2).map(read_u16).collect()
}

/// A `supported_groups` / `signature_algorithms` payload: a 2-byte length
/// followed by 16-bit words. A malformed payload yields an empty list — the
/// extension still counts (it was sent), its contents are just not readable.
fn extension_words(data: &[u8]) -> Vec<u16> {
    match take_u16(data) {
        Some((len, rest)) if rest.len() >= len as usize => words(&rest[..len as usize]),
        _ => Vec::new(),
    }
}

/// An ALPN payload (`ProtocolNameList`): a 2-byte list length of
/// **1-byte-length-prefixed** names — the entry prefix is `opaque<1..2^8-1>`,
/// not a second `u16` (confirmed against a live rustls hello).
fn alpn_protocols(data: &[u8]) -> Vec<Vec<u8>> {
    let Some((len, rest)) = take_u16(data) else {
        return Vec::new();
    };
    let Some(list) = rest.get(..len as usize) else {
        return Vec::new();
    };
    let mut remaining = list;
    let mut out = Vec::new();
    while let Some((&name_len, tail)) = remaining.split_first() {
        let Some(name) = tail.get(..name_len as usize) else {
            break;
        };
        out.push(name.to_vec());
        remaining = &tail[name_len as usize..];
    }
    out
}

/// An `ec_point_formats` payload: a 1-byte list length of 1-byte formats.
fn ec_point_formats(data: &[u8]) -> Vec<u16> {
    let Some((&len, rest)) = data.split_first() else {
        return Vec::new();
    };
    rest.get(..len as usize)
        .map(|formats| formats.iter().map(|f| u16::from(*f)).collect())
        .unwrap_or_default()
}

/// A `supported_versions` payload: a 1-byte list length of 16-bit versions.
fn supported_versions(data: &[u8]) -> Option<Vec<u16>> {
    let (&len, rest) = data.split_first()?;
    Some(words(rest.get(..len as usize)?))
}

// ---- digests -------------------------------------------------------------

/// MD5, implemented inline: this crate's dependency discipline (serde only)
/// is worth keeping, and the digest is deprecated anyway — a hundred lines
/// here instead of a dependency that would outlive its usefulness.
fn md5_hex(bytes: &[u8]) -> String {
    // Per-round rotation amounts and the standard sine-derived table.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut message = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());

    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    for chunk in message.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            // A 64-byte chunk's 4-byte windows are in-bounds by construction;
            // index arithmetic replaces `expect` (banned by the workspace lint).
            *word = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = temp;
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d]) {
            *word = word.wrapping_add(value);
        }
    }

    let mut out = String::with_capacity(32);
    // MD5's output is the little-endian encoding of each state word; the
    // standard hex digest spells those bytes in order, so each word is
    // printed bytewise reversed, not as a big-endian numeral.
    for word in state {
        for byte in word.to_le_bytes() {
            let _ = write!(out, "{byte:02x}");
        }
    }
    out
}

/// SHA-256, truncated to JA4's 12 hex characters — same reasoning as the MD5
/// above, but this one is load-bearing (JA4 is current).
fn sha256_hex_12(bytes: &[u8]) -> String {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut message = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = H0;
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            // In-bounds by construction; see the matching note in `md5_hex`.
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(value);
        }
    }

    let mut full = String::with_capacity(64);
    for word in state {
        let _ = write!(full, "{word:08x}");
    }
    full.chars().take(12).collect()
}

/// Dash-joined decimal list — the values *within* one JA3 field.
fn dashed_list(values: &[u16]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests;
