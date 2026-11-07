//! Egress confinement policy for every outbound transport.
//!
//! This crate owns one question and answers it with no I/O, no clock and no
//! runtime dependency: **may this process open a socket to this address at
//! all?** (ADR-0002.)
//!
//! ```text
//! netune (TCP/DNS)      ──┐
//! netune (UDP datagram) ──┼──► netune-egress
//! netune-quic           ──┘        (pure predicate, no socket)
//! ```
//!
//! # Why this is a crate and not a module of `netune`
//!
//! Three separate outbound transports must refuse the same address classes:
//! `netune`'s TCP connector, `netune`'s datagram sessions, and `netune-quic`'s
//! QUIC connector. `netune-quic` is a leaf that may not depend on the egress
//! orchestrator (`[ARCH-003]`), so before this crate existed the QUIC path had
//! **no** confinement at all — the predicate lived only in `netune`, and a
//! copy in the QUIC crate would have been two definitions of a security rule
//! that could drift apart. A single pure leaf is the mechanism that keeps the
//! rule stated once (`AGENTS.md`: "Mechanisms over exhortations").
//!
//! # What it does not do
//!
//! It does not resolve names, does not open a socket, and does not decide
//! *when* the check runs — that ordering ("confinement strictly precedes
//! socket creation", `[INV-EGRESS-01]` / `[INV-QUIC-02]`) belongs to each
//! transport, which is the only layer that knows where its socket is created.
//! This crate supplies the predicate and the policy; the transport supplies the
//! ordering.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::net::IpAddr;

/// Egress confinement policy for connection establishment (ADR-0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressConfinement {
    /// Standard unrestricted egress (for configured LLM endpoints and proxies).
    #[default]
    Unrestricted,
    /// Strict public egress: rejects loopback, RFC 1918 private, link-local,
    /// carrier-grade NAT, cloud metadata, and multicast addresses.
    StrictPublic,
}

impl EgressConfinement {
    /// Refuse `ip` under this policy, or accept it.
    ///
    /// The single call site every transport uses, so the policy and the
    /// predicate cannot be wired up inconsistently.
    ///
    /// # Errors
    ///
    /// [`ConfinementRefused`] when the policy is [`EgressConfinement::StrictPublic`]
    /// and `ip` is not globally routable.
    pub fn check(self, ip: IpAddr) -> Result<(), ConfinementRefused> {
        match self {
            Self::Unrestricted => Ok(()),
            Self::StrictPublic if is_public_ip(ip) => Ok(()),
            Self::StrictPublic => Err(ConfinementRefused(ip)),
        }
    }
}

/// The address a [`EgressConfinement::StrictPublic`] policy refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfinementRefused(pub IpAddr);

impl std::fmt::Display for ConfinementRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "egress confinement refused non-public address {}",
            self.0
        )
    }
}

impl std::error::Error for ConfinementRefused {}

/// True only for globally-routable addresses. Rejects loopback, private RFC1918
/// ranges, link-local, cloud metadata, carrier-grade NAT, and unspecified/broadcast.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let [a, b, c, _d] = octets;
            // Cloud instance-metadata endpoint (AWS/Azure/GCP): link-local 169.254.169.254
            if octets == [169, 254, 169, 254] {
                return false;
            }
            if v4.is_loopback()        // 127.0.0.0/8
                || v4.is_private()     // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()  // 169.254/16
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast()
            // 255.255.255.255
            {
                return false;
            }
            // Carrier-grade NAT (100.64.0.0/10)
            if a == 100 && (b & 0xc0) == 64 {
                return false;
            }
            // Documentation/benchmarking networks (198.18.0.0/15, 198.51.100/24, 203.0.113/24)
            if a == 198 && (18..=19).contains(&b) {
                return false;
            }
            if a == 192 && b == 0 && (c == 0 || c == 2) {
                return false;
            }
            if a == 198 && b == 51 && c == 100 {
                return false;
            }
            if a == 203 && b == 0 && c == 113 {
                return false;
            }
            // Reserved / Class E
            if a >= 240 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let seg0 = v6.segments()[0];
            // Unique-local fc00::/7 (RFC 4193)
            if (seg0 & 0xfe00) == 0xfc00 {
                return false;
            }
            // Link-local fe80::/10 (RFC 4291)
            if (seg0 & 0xffc0) == 0xfe80 {
                return false;
            }
            // IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn non_public_v4_classes_are_refused() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.0.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
        ] {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
    }

    #[test]
    fn non_public_v6_classes_are_refused() {
        for s in ["::1", "fe80::1", "fc00::1", "fd00::1", "::", "ff02::1"] {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
    }

    #[test]
    fn ipv4_mapped_v6_inherits_the_v4_verdict() {
        assert!(!is_public_ip(ip("::ffff:127.0.0.1")));
        assert!(!is_public_ip(ip("::ffff:169.254.169.254")));
        assert!(is_public_ip(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn globally_routable_addresses_are_public() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(is_public_ip(ip(s)), "{s} must be public");
        }
    }

    #[test]
    fn unrestricted_policy_accepts_everything_it_is_given() {
        for s in ["127.0.0.1", "169.254.169.254", "8.8.8.8"] {
            assert_eq!(EgressConfinement::Unrestricted.check(ip(s)), Ok(()));
        }
    }

    #[test]
    fn strict_public_refuses_by_the_predicate() {
        assert!(EgressConfinement::StrictPublic.check(ip("8.8.8.8")).is_ok());
        assert_eq!(
            EgressConfinement::StrictPublic.check(ip("127.0.0.1")),
            Err(ConfinementRefused(ip("127.0.0.1")))
        );
    }
}
