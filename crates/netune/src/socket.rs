//! L3/L4 socket configuration and transport parameter tuning (ADR-0006).
//!
//! Standard OS defaults expose passive operating system fingerprints (p0f):
//! default TTLs (Linux=64, Windows=128), initial window sizes, and MSS limits.
//!
//! [`SocketConfig`] allows fine-tuning these parameters at the transport boundary
//! so the client can align its TCP stack characteristics with the claimed user agent.

use std::io;
use tokio::net::TcpStream;

/// L3/L4 transport tuning parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketConfig {
    /// Disable Nagle's algorithm (`TCP_NODELAY`). Default is `true`.
    pub nodelay: bool,
    /// Time-to-Live (`IP_TTL`) for outbound packets.
    ///
    /// Useful for passive OS fingerprint alignment:
    /// - Linux/Android: ~64
    /// - Windows: ~128
    /// - macOS/iOS: ~64
    pub ttl: Option<u32>,
    /// Socket receive buffer size (`SO_RCVBUF`).
    pub recv_buffer_size: Option<usize>,
    /// Socket send buffer size (`SO_SNDBUF`).
    pub send_buffer_size: Option<usize>,
    /// Maximum Segment Size (`TCP_MAXSEG`), where supported.
    pub mss: Option<u32>,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            nodelay: true,
            ttl: None,
            recv_buffer_size: None,
            send_buffer_size: None,
            mss: None,
        }
    }
}

impl SocketConfig {
    /// Standard stock configuration with Nagle disabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emulate a Windows TCP stack baseline (TTL = 128).
    pub fn windows_baseline() -> Self {
        Self {
            nodelay: true,
            ttl: Some(128),
            recv_buffer_size: Some(65_536),
            send_buffer_size: Some(65_536),
            mss: None,
        }
    }

    /// Emulate a Linux/macOS TCP stack baseline (TTL = 64).
    pub fn unix_baseline() -> Self {
        Self {
            nodelay: true,
            ttl: Some(64),
            recv_buffer_size: Some(131_072),
            send_buffer_size: Some(131_072),
            mss: None,
        }
    }

    /// Set `TCP_NODELAY`.
    pub fn with_nodelay(mut self, nodelay: bool) -> Self {
        self.nodelay = nodelay;
        self
    }

    /// Set IP Time-to-Live (`IP_TTL`).
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set socket receive buffer size (`SO_RCVBUF`).
    pub fn with_recv_buffer_size(mut self, bytes: usize) -> Self {
        self.recv_buffer_size = Some(bytes);
        self
    }

    /// Set socket send buffer size (`SO_SNDBUF`).
    pub fn with_send_buffer_size(mut self, bytes: usize) -> Self {
        self.send_buffer_size = Some(bytes);
        self
    }

    /// Set Maximum Segment Size (`TCP_MAXSEG`).
    pub fn with_mss(mut self, mss: u32) -> Self {
        self.mss = Some(mss);
        self
    }

    /// Apply these configuration knobs to a connected [`TcpStream`].
    pub fn apply(&self, stream: &TcpStream) -> Result<(), io::Error> {
        let _ = stream.set_nodelay(self.nodelay);

        if let Some(ttl) = self.ttl {
            let _ = stream.set_ttl(ttl);
        }

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = stream.as_raw_fd();

            if let Some(rcv) = self.recv_buffer_size {
                let size = rcv as libc::c_int;
                // SAFETY: valid socket fd and standard SOL_SOCKET option.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUF,
                        std::ptr::from_ref(&size).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }

            if let Some(snd) = self.send_buffer_size {
                let size = snd as libc::c_int;
                // SAFETY: valid socket fd and standard SOL_SOCKET option.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        std::ptr::from_ref(&size).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }

            #[cfg(target_os = "linux")]
            if let Some(mss) = self.mss {
                let val = mss as libc::c_int;
                // SAFETY: valid socket fd and IPPROTO_TCP option.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_MAXSEG,
                        std::ptr::from_ref(&val).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socket_config_applies_successfully() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let connect_fut = TcpStream::connect(addr);
        let accept_fut = listener.accept();

        let (client, server) = tokio::join!(connect_fut, accept_fut);
        let client = client.expect("connect");
        let (server, _) = server.expect("accept");

        let config = SocketConfig::windows_baseline()
            .with_ttl(128)
            .with_nodelay(true);

        assert!(config.apply(&client).is_ok());
        assert_eq!(client.ttl().ok(), Some(128));

        assert!(config.apply(&server).is_ok());
    }
}
