//! TLS 1.3 session ticket cache and `NewSessionTicket` parser (RFC 8446 §4.6.1).
//!
//! Tickets are keyed by `(server_name, profile_name, alpn)` so two identities
//! never share a resumption ticket ([`INV-TLS-09`]), and popped on use so
//! concurrent or sequential handshakes do not link connections via a reused
//! ticket.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::key_schedule::Hash;

/// Maximum number of distinct `(server_name, profile, alpn)` keys retained.
const MAX_CACHE_KEYS: usize = 64;
/// Maximum number of tickets retained per key.
const MAX_TICKETS_PER_KEY: usize = 4;
/// RFC 8446 §4.6.1: `ticket_lifetime` MUST NOT exceed 7 days (604,800 s).
const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

/// Isolation key for cached resumption tickets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// Target SNI `host_name`.
    pub server_name: String,
    /// Profile name that performed the initial handshake.
    pub profile_name: String,
    /// Offered ALPN list of that profile.
    pub alpn: Vec<Vec<u8>>,
}

/// A single-use TLS 1.3 resumption ticket and its derived PSK.
#[derive(Debug, Clone)]
pub struct ResumptionTicket {
    /// Opaque ticket bytes received from the server.
    pub ticket: Vec<u8>,
    /// Resumption PSK derived via `HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)`.
    pub psk: Vec<u8>,
    // The fields above are public for parsing and profile tests; the secret
    // half is still wiped when the ticket leaves the cache.
    /// Transcript hash of the cipher suite that issued this ticket.
    pub hash: Hash,
    /// Cipher suite negotiated when this ticket was issued.
    pub cipher_suite: u16,
    /// Random mask for `obfuscated_ticket_age` (RFC 8446 §4.6.1).
    pub ticket_age_add: u32,
    /// Server-declared lifetime in seconds.
    pub lifetime_secs: u32,
    /// Monotonic timestamp when the ticket was received.
    pub received_at: Instant,
}

impl Drop for ResumptionTicket {
    fn drop(&mut self) {
        self.psk.fill(0);
    }
}

impl ResumptionTicket {
    /// Compute the RFC 8446 §4.2.11.1 `obfuscated_ticket_age` in milliseconds.
    #[must_use]
    pub fn obfuscated_age_ms(&self, now: Instant) -> u32 {
        let elapsed_ms = now
            .saturating_duration_since(self.received_at)
            .as_millis()
            .min(u128::from(u32::MAX)) as u32;
        elapsed_ms.wrapping_add(self.ticket_age_add)
    }

    fn is_valid_at(&self, now: Instant) -> bool {
        self.lifetime_secs > 0
            && self.lifetime_secs <= MAX_TICKET_LIFETIME_SECS
            && now.saturating_duration_since(self.received_at)
                < Duration::from_secs(u64::from(self.lifetime_secs))
    }
}

/// Thread-safe, bounded, single-use TLS 1.3 session ticket store.
#[derive(Debug, Clone, Default)]
pub struct SessionCache {
    inner: Arc<Mutex<HashMap<SessionKey, VecDeque<ResumptionTicket>>>>,
}

impl SessionCache {
    /// Create an empty session cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a newly received ticket under `key`, evicting expired or oldest
    /// entries when bounds are reached.
    pub fn insert(&self, key: SessionKey, ticket: ResumptionTicket) {
        let now = Instant::now();
        if !ticket.is_valid_at(now) {
            return;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if !guard.contains_key(&key)
            && guard.len() >= MAX_CACHE_KEYS
            && let Some(evict_key) = guard.keys().next().cloned()
        {
            guard.remove(&evict_key);
        }
        let queue = guard.entry(key).or_default();
        queue.retain(|entry| entry.is_valid_at(now));
        while queue.len() >= MAX_TICKETS_PER_KEY {
            queue.pop_front();
        }
        queue.push_back(ticket);
    }

    /// Pop the most recent unexpired ticket for `key`, if any.
    #[must_use]
    pub fn take(&self, key: &SessionKey) -> Option<ResumptionTicket> {
        let now = Instant::now();
        let Ok(mut guard) = self.inner.lock() else {
            return None;
        };
        let queue = guard.get_mut(key)?;
        while let Some(ticket) = queue.pop_back() {
            if ticket.is_valid_at(now) {
                if queue.is_empty() {
                    guard.remove(key);
                }
                return Some(ticket);
            }
        }
        guard.remove(key);
        None
    }
}

/// Parsed fields of a TLS 1.3 `NewSessionTicket` handshake body (RFC 8446 §4.6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNewSessionTicket {
    /// Lifetime in seconds.
    pub lifetime_secs: u32,
    /// `ticket_age_add` mask.
    pub age_add: u32,
    /// Per-ticket nonce for PSK derivation.
    pub nonce: Vec<u8>,
    /// Opaque ticket bytes.
    pub ticket: Vec<u8>,
}

/// Parse the body of a TLS 1.3 `NewSessionTicket` message (excluding the 4-byte
/// handshake header). Returns `None` if malformed or violating RFC 8446 §4.6.1.
#[must_use]
pub fn parse_new_session_ticket(body: &[u8]) -> Option<ParsedNewSessionTicket> {
    let (lifetime_bytes, rest) = body.split_at_checked(4)?;
    let lifetime_secs = u32::from_be_bytes(lifetime_bytes.try_into().ok()?);
    if lifetime_secs > MAX_TICKET_LIFETIME_SECS {
        return None;
    }
    let (age_add_bytes, rest) = rest.split_at_checked(4)?;
    let age_add = u32::from_be_bytes(age_add_bytes.try_into().ok()?);
    let (&nonce_len_byte, rest) = rest.split_first()?;
    let (nonce, rest) = rest.split_at_checked(usize::from(nonce_len_byte))?;
    let (ticket_len_bytes, rest) = rest.split_at_checked(2)?;
    let ticket_len = usize::from(u16::from_be_bytes(ticket_len_bytes.try_into().ok()?));
    if ticket_len == 0 {
        return None;
    }
    let (ticket, rest) = rest.split_at_checked(ticket_len)?;
    let (ext_len_bytes, rest) = rest.split_at_checked(2)?;
    let ext_len = usize::from(u16::from_be_bytes(ext_len_bytes.try_into().ok()?));
    if rest.len() != ext_len {
        return None;
    }
    Some(ParsedNewSessionTicket {
        lifetime_secs,
        age_add,
        nonce: nonce.to_vec(),
        ticket: ticket.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_session_ticket_handles_valid_and_malformed_inputs_without_panicking() {
        let mut valid = Vec::new();
        valid.extend_from_slice(&3600u32.to_be_bytes());
        valid.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        valid.push(2);
        valid.extend_from_slice(&[0xaa, 0xbb]);
        valid.extend_from_slice(&3u16.to_be_bytes());
        valid.extend_from_slice(b"tkt");
        valid.extend_from_slice(&1u16.to_be_bytes());
        valid.push(0x99);
        let parsed = parse_new_session_ticket(&valid).expect("valid ticket");
        assert_eq!(parsed.lifetime_secs, 3600);
        assert_eq!(parsed.age_add, 0x1234_5678);
        assert_eq!(parsed.nonce, vec![0xaa, 0xbb]);
        assert_eq!(parsed.ticket, b"tkt");

        for len in 0..valid.len() {
            assert!(
                parse_new_session_ticket(&valid[..len]).is_none(),
                "truncated at {len} must return None"
            );
        }

        let mut over_lifetime = valid.clone();
        over_lifetime[..4].copy_from_slice(&(MAX_TICKET_LIFETIME_SECS + 1).to_be_bytes());
        assert!(parse_new_session_ticket(&over_lifetime).is_none());

        // Zero-length ticket is illegal per RFC 8446 §4.6.1.
        let mut zero_ticket = Vec::new();
        zero_ticket.extend_from_slice(&60u32.to_be_bytes());
        zero_ticket.extend_from_slice(&1u32.to_be_bytes());
        zero_ticket.push(0);
        zero_ticket.extend_from_slice(&0u16.to_be_bytes());
        zero_ticket.extend_from_slice(&0u16.to_be_bytes());
        assert!(parse_new_session_ticket(&zero_ticket).is_none());
    }
}
