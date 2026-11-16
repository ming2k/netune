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
//! # Example
//!
//! ```rust
//! use std::net::IpAddr;
//! use netune_egress::{EgressConfinement, is_public_ip};
//!
//! let public: IpAddr = "93.184.216.34".parse().unwrap();
//! let loopback: IpAddr = "127.0.0.1".parse().unwrap();
//! assert!(is_public_ip(public));
//! assert!(EgressConfinement::StrictPublic.check(loopback).is_err());
//! ```
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
#![deny(missing_docs)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Egress confinement policy for connection establishment (ADR-0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressConfinement {
    /// Standard unrestricted egress (for configured LLM endpoints and proxies).
    #[default]
    Unrestricted,
    /// Strict public egress: rejects loopback, RFC 1918 private, link-local,
    /// carrier-grade NAT, cloud metadata, and multicast addresses.
    ///
    /// The predicate covers the socket this process opens. A proxy that
    /// resolves and connects to the destination on our behalf is outside it:
    /// check the proxy's own reachability separately when that matters.
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
/// ranges, link-local, cloud metadata, carrier-grade NAT, multicast,
/// documentation/benchmarking ranges, and IPv6 transition forms that embed a
/// non-public IPv4 address.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
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
        || v4.is_broadcast()   // 255.255.255.255
        || v4.is_multicast()
    // 224.0.0.0/4
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
    // 6to4 relay anycast (192.88.99.0/24, deprecated by RFC 7526)
    if a == 192 && b == 88 && c == 99 {
        return false;
    }
    // Reserved / Class E
    if a >= 240 {
        return false;
    }
    true
}

fn is_public_v6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    let segments = v6.segments();
    let seg0 = segments[0];
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
        return is_public_v4(v4);
    }
    // IPv4-compatible ::/96 (deprecated by RFC 4291). It embeds an IPv4
    // address in the low 32 bits and is not globally routable.
    if segments[..6].iter().all(|segment| *segment == 0) {
        return false;
    }
    // 6to4 2002::/16 (RFC 3056) embeds an IPv4 address in bits 16..48. It is
    // only as public as the address it embeds, so a 6to4 form of loopback or
    // RFC 1918 space must not slip past the predicate.
    if seg0 == 0x2002 {
        return is_public_v4(embedded_v4(segments[1], segments[2]));
    }
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) embeds IPv4 in the low
    // 32 bits. The local-use prefix 64:ff9b:1::/48 (RFC 8215) is not global.
    if seg0 == 0x0064 && segments[1] == 0xff9b {
        if segments[2..6].iter().all(|segment| *segment == 0) {
            return is_public_v4(embedded_v4(segments[6], segments[7]));
        }
        // `64:ff9b:1::/48` is local-use and the remaining subprefixes are
        // unassigned; neither is globally routable.
        return false;
    }
    // Teredo 2001::/32 and the rest of the IETF protocol-assignment block
    // 2001::/23 (including benchmarking and ORCHID) are not public unicast.
    if seg0 == 0x2001 && segments[1] <= 0x01ff {
        return false;
    }
    // Documentation 2001:db8::/32 (RFC 3849) and 3fff::/20 (RFC 9637).
    if seg0 == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    if (seg0 & 0xfff0) == 0x3ff0 {
        return false;
    }
    // Discard-only 100::/64 (RFC 6666).
    if seg0 == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0) {
        return false;
    }
    // Segment-routing SIDs 5f00::/16 (RFC 9602) are not global unicast.
    if seg0 == 0x5f00 {
        return false;
    }
    true
}

const fn embedded_v4(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8)
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
            "192.88.99.1",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
        ] {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
    }

    #[test]
    fn non_public_v6_classes_are_refused() {
        for s in [
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "::",
            "ff02::1",
            "2001:db8::1",
            "2001:2::1",
            "2001:10::1",
            "3fff::1",
            "100::1",
            "5f00::1",
            "64:ff9b:1::1",
            "::127.0.0.1",
            // Transition forms that embed a non-public IPv4 address.
            "2002:7f00:1::1",
            "2002:0a00:1::1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
        ] {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
    }

    #[test]
    fn transition_forms_with_a_public_embedded_v4_are_public() {
        for s in ["2002:0808:0808::1", "64:ff9b::808:808"] {
            assert!(is_public_ip(ip(s)), "{s} must be public");
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
