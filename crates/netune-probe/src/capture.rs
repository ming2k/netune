//! The privileged part: an `AF_PACKET` capture loop.
//!
//! Deliberately thin. All parsing lives in [`crate::packet`], which is pure and
//! tested; this module only opens the socket, reads frames with their kernel
//! timestamps, and filters by 4-tuple.
//!
//! **Privileges**: `CAP_NET_RAW` (or root). That is why the probe is a separate
//! binary: the daemon must never hold this authority.
//!
//! **Filtering**: the 4-tuple filter runs in user space. A kernel BPF program
//! would be cheaper, but hand-written BPF is exactly the kind of thing that
//! silently drops the traffic you are trying to measure; the probe is a
//! short-window tool, so correctness beats efficiency here. The filter is
//! recorded in the output so a reader knows what was applied.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;

use crate::Segment;
use crate::packet;

/// A live capture on one interface.
pub struct Capture {
    fd: OwnedFd,
    started: Instant,
    local: ([u8; 4], u16),
    remote: ([u8; 4], u16),
    buffer: Vec<u8>,
}

impl Capture {
    /// Open a capture for the `local` ↔ `remote` flow on `interface`.
    ///
    /// Fails with `PermissionDenied` without `CAP_NET_RAW`, which is the
    /// expected outcome for an unprivileged run.
    pub fn open(
        interface: &str,
        local: ([u8; 4], u16),
        remote: ([u8; 4], u16),
    ) -> io::Result<Self> {
        // SAFETY: the arguments are the documented constants for an AF_PACKET
        // raw socket; the returned descriptor is checked before use.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(u16::to_be(libc::ETH_P_IP as u16)),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Bind to the interface so loopback and tunnels are visible.
        let mut sockaddr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sockaddr.sll_family = libc::AF_PACKET as u16;
        sockaddr.sll_protocol = u16::to_be(libc::ETH_P_IP as u16);
        sockaddr.sll_ifindex = Self::interface_index(interface)?;
        // SAFETY: `sockaddr` is a fully initialized `sockaddr_ll`.
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&sockaddr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if bound != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            started: Instant::now(),
            local,
            remote,
            buffer: vec![0u8; 65_536],
        })
    }

    /// Read one matching segment, blocking until it arrives.
    ///
    /// Non-matching frames are consumed and ignored; the probe is scoped to a
    /// single flow.
    pub fn next_segment(&mut self) -> io::Result<Segment> {
        loop {
            // SAFETY: `buffer` is a live, writable slice of the declared length.
            let read = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    self.buffer.as_mut_ptr().cast::<libc::c_void>(),
                    self.buffer.len(),
                    0,
                )
            };
            if read < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let frame = &self.buffer[..read as usize];
            let Some(segment) = packet::parse_ethernet_ipv4_tcp(frame) else {
                continue;
            };
            let Some(outbound) = packet::matches_flow(&segment, self.local, self.remote) else {
                continue;
            };
            return Ok(Segment {
                at_ns: self.started.elapsed().as_nanos() as u64,
                outbound,
                payload_len: segment.payload_len,
                flags: segment.flags,
                seq: segment.seq,
                ack: segment.ack,
            });
        }
    }

    /// The interface the capture is bound to, for reporting.
    pub fn interface_index(interface: &str) -> io::Result<i32> {
        let name = std::ffi::CString::new(interface)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has a NUL"))?;
        // SAFETY: `name` is a valid NUL-terminated C string.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(index as i32)
    }
}

/// Resolve an IPv4 literal, refusing names (the probe must not depend on DNS).
pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let address: std::net::Ipv4Addr = text.parse().ok()?;
    Some(address.octets())
}

/// Transmit one built frame out of the capture's interface.
///
/// **Feature-gated (`inject`) by construction, privileged by runtime.** The
/// default build of this crate has no transmit path at all — the same
/// privilege discipline that keeps the daemon from carrying
/// `CAP_NET_RAW`/packet-capture authority keeps injection out of it, and
/// injection is the stronger capability: it changes the network rather than
/// measuring it. A caller that opts in compiles with `--features inject`
/// and still needs the socket opened by [`Capture::open`] (raw sockets
/// cannot `send` on a filter-only bind without the same capability).
///
/// Deliberately unsophisticated: a blocking `sendto` of the exact bytes,
/// with a retry only on `EINTR`. No queueing, no retransmit logic — the
/// caller composes its own injection schedule (that is the point of the
/// capability).
#[cfg(all(target_os = "linux", feature = "inject"))]
impl Capture {
    /// Send `frame` (e.g. from [`crate::packet::build_ethernet_ipv4_tcp`])
    /// on this capture's interface.
    pub fn send_frame(&self, frame: &[u8]) -> io::Result<usize> {
        loop {
            // SAFETY: `fd` is an open AF_PACKET socket; `frame` is a live
            // slice of the declared length; the address is an Ethernet
            // link-level sockaddr for a raw send.
            let sent = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    frame.as_ptr().cast::<libc::c_void>(),
                    frame.len(),
                    0,
                )
            };
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}

#[allow(dead_code)]
fn _assert_maybe_uninit_is_used() {
    let _ = MaybeUninit::<u8>::uninit();
}
