//! Pure Ethernet/IPv4/TCP parsing. No sockets, no unsafe — so it can be tested
//! with hand-built frames.
//!
//! Only what the probe needs is parsed: the 4-tuple (to filter), and the TCP
//! header fields that describe the segment (flags, sequence, payload length).
//! Anything else — IPv6, IP options, VLAN tags, fragmentation — is reported as
//! `None` rather than guessed at.

/// `FIN`.
pub const FLAG_FIN: u8 = 0x01;
/// `SYN`.
pub const FLAG_SYN: u8 = 0x02;
/// `RST`.
pub const FLAG_RST: u8 = 0x04;
/// `PSH`.
pub const FLAG_PSH: u8 = 0x08;
/// `ACK`.
pub const FLAG_ACK: u8 = 0x10;

const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const ETH_HEADER_LEN: usize = 14;

/// A parsed TCP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    /// Source IPv4 address and TCP port.
    pub source: ([u8; 4], u16),
    /// Destination IPv4 address and TCP port.
    pub destination: ([u8; 4], u16),
    /// TCP sequence number.
    pub seq: u32,
    /// TCP acknowledgement number.
    pub ack: u32,
    /// TCP header flags byte.
    pub flags: u8,
    /// TCP payload byte length.
    pub payload_len: u32,
}

impl TcpSegment {
    /// Whether this segment carried application data.
    pub const fn carries_data(&self) -> bool {
        self.payload_len > 0
    }

    /// Whether this segment is a bare acknowledgement.
    pub const fn is_bare_ack(&self) -> bool {
        self.payload_len == 0 && self.flags & FLAG_ACK != 0
    }
}

/// Parse one Ethernet frame into a TCP segment.
///
/// `None` for anything the probe does not model: a non-IPv4 frame, a
/// non-TCP transport, a fragmented datagram, or a frame too short to contain
/// the headers it claims.
pub fn parse_ethernet_ipv4_tcp(frame: &[u8]) -> Option<TcpSegment> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }
    // A VLAN tag shifts the network header by 4 bytes.
    let mut offset = ETH_HEADER_LEN;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == 0x8100 || ethertype == 0x88A8 {
        if frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        offset += 4;
    }
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    if frame.len() < offset + 20 {
        return None;
    }
    let ip = &frame[offset..];
    let version = ip[0] >> 4;
    if version != 4 {
        return None;
    }
    let header_len = usize::from(ip[0] & 0x0F) * 4;
    if header_len < 20 || ip.len() < header_len {
        return None;
    }
    // Fragmented datagrams have no complete transport header in this frame.
    let fragment_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1FFF;
    if fragment_offset != 0 {
        return None;
    }
    if ip[9] != IPPROTO_TCP {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let source_ip = [ip[12], ip[13], ip[14], ip[15]];
    let destination_ip = [ip[16], ip[17], ip[18], ip[19]];

    let tcp = ip.get(header_len..)?;
    if tcp.len() < 20 {
        return None;
    }
    let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }
    let flags = tcp[13];

    // Trust the IP total length when it is consistent with the frame; a NIC can
    // pad a frame to the Ethernet minimum, and padding is not payload.
    let ip_available = ip.len().min(total_len.max(header_len));
    let payload_len = ip_available.saturating_sub(header_len + data_offset);

    Some(TcpSegment {
        source: (source_ip, source_port),
        destination: (destination_ip, destination_port),
        seq,
        ack,
        flags,
        payload_len: payload_len as u32,
    })
}

/// Whether `segment` belongs to the connection identified by `local` and
/// `remote` (either direction).
pub fn matches_flow(
    segment: &TcpSegment,
    local: ([u8; 4], u16),
    remote: ([u8; 4], u16),
) -> Option<bool> {
    if segment.source == local && segment.destination == remote {
        Some(true)
    } else if segment.source == remote && segment.destination == local {
        Some(false)
    } else {
        None
    }
}

// ---- construction (the injection half) -----------------------------------
//
// The parser's dual: bytes out, structured spec in. This is the first piece
// of the "change behaviour / forge" capability set: a pure frame builder
// that makes RST injection, forged seq/ack, and window manipulation
// *constructible and testable offline* (zero privileges, no socket). The
// privileged `send` path lives behind a feature — the default build of this
// crate stays receive-only, exactly as the daemon must never carry
// packet-sniffing authority.
//
// Invariants, chosen so `parse(build(spec)) == spec-ish` holds and so every
// field a fingerprint would read is the sender's own choice:
// - No IPv4 options, no TCP options (data offset 5): the minimum frame. A
//   forged segment does not need to look like any *other* sender's options;
//   it needs to be internally consistent.
// - The IPv4 checksum is computed and verified on parse (the parser currently
//   ignores it; the builder still writes a correct one, so a kernel or a
//   middlebox that does validate accepts the frame).
// - Nothing here invents values: every field of [`FrameSpec`] is explicit.

/// A minimal Ethernet+IPv4+TCP frame to construct, by field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSpec {
    /// Source MAC (6 bytes).
    pub source_mac: [u8; 6],
    /// Destination MAC (6 bytes).
    pub destination_mac: [u8; 6],
    /// Source IPv4 address and TCP port.
    pub source: ([u8; 4], u16),
    /// Destination IPv4 address and TCP port.
    pub destination: ([u8; 4], u16),
    /// TCP sequence number.
    pub seq: u32,
    /// TCP acknowledgement number.
    pub ack: u32,
    /// TCP header flags (`FLAG_*` ORed together).
    pub flags: u8,
    /// Advertised receive window.
    pub window: u16,
    /// Application payload.
    pub payload: &'static [u8],
}

/// Build an Ethernet + IPv4 + TCP frame from `spec`.
///
/// Pure: no allocation beyond the returned buffer, no clock, no socket. The
/// IPv4 checksum is computed over the header as built (header length 20, no
/// options).
pub fn build_ethernet_ipv4_tcp(spec: &FrameSpec) -> Vec<u8> {
    let tcp_len = 20 + spec.payload.len();
    let ip_total_len = 20 + tcp_len;

    let mut frame = Vec::with_capacity(ETH_HEADER_LEN + ip_total_len);
    frame.extend_from_slice(&spec.source_mac);
    frame.extend_from_slice(&spec.destination_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4 header, checksum computed after the fixed fields are placed.
    let ip_start = frame.len();
    frame.extend_from_slice(&[0x45, 0x00]); // version 4, IHL 5, DSCP/ECN 0
    frame.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // identification
    frame.extend_from_slice(&[0x40, 0x00]); // don't fragment, no offset
    frame.push(64); // TTL
    frame.push(IPPROTO_TCP);
    frame.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    frame.extend_from_slice(&spec.source.0);
    frame.extend_from_slice(&spec.destination.0);
    let checksum = ipv4_checksum(&frame[ip_start..]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&checksum.to_be_bytes());

    // TCP header.
    frame.extend_from_slice(&spec.source.1.to_be_bytes());
    frame.extend_from_slice(&spec.destination.1.to_be_bytes());
    frame.extend_from_slice(&spec.seq.to_be_bytes());
    frame.extend_from_slice(&spec.ack.to_be_bytes());
    frame.push(0x50); // data offset 5 words = 20 bytes
    frame.push(spec.flags);
    frame.extend_from_slice(&spec.window.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (optional on lo)
    frame.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    frame.extend_from_slice(spec.payload);
    frame
}

/// The IPv4 header checksum (RFC 1071): 16-bit one's-complement sum of the
/// header, folded, complemented. The checksum field itself must be zero
/// while summing — `header` is the full 20-byte header with the placeholder
/// in place.
fn ipv4_checksum(header: &[u8]) -> u16 {
    debug_assert!(header.len() >= 20, "an IPv4 header is at least 20 bytes");
    let mut sum = 0u32;
    for pair in header.chunks_exact(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    // Fold carries out of the high half, then complement. The checksum
    // placeholder was zero, so it contributed nothing and needs no clearing.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Verify an IPv4 header checksum. `true` for a header whose checksum field
/// is correct — the same RFC 1071 sum over the header *with* its checksum
/// yields zero.
pub fn ipv4_checksum_ok(header: &[u8]) -> bool {
    let mut sum = 0u32;
    for pair in header.chunks_exact(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16 == 0xFFFF
}

#[cfg(test)]
mod tests;
