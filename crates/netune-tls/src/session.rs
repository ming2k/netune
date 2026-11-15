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
    if body.len() < 9 {
        return None;
    }
    let lifetime_secs = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if lifetime_secs > MAX_TICKET_LIFETIME_SECS {
        return None;
    }
    let age_add = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let nonce_len = usize::from(body[8]);
    let rest = body.get(9..)?;
    if rest.len() < nonce_len + 2 {
        return None;
    }
    let (nonce, rest) = rest.split_at(nonce_len);
    let ticket_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
    let rest = rest.get(2..)?;
    if ticket_len == 0 || rest.len() < ticket_len + 2 {
        return None;
    }
    let (ticket, rest) = rest.split_at(ticket_len);
    let ext_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
    if rest.len() != 2 + ext_len {
        return None;
    }
    Some(ParsedNewSessionTicket {
        lifetime_secs,
        age_add,
        nonce: nonce.to_vec(),
        ticket: ticket.to_vec(),
    })
}
