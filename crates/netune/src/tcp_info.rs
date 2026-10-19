//! `TCP_INFO` sampling: the only packet-adjacent signal available without
//! privileges.
//!
//! A client cannot see packets, but it can ask the kernel what the kernel knows
//! about the socket: the smoothed round-trip time and the retransmit counter.
//! Those two numbers turn "the network feels slow" into something falsifiable,
//! and they are the difference between "we cannot tell" and "the peer is 400 ms
//! away and this stream retransmitted twice".
//!
//! Sampling is deliberately sparse and change-driven: a 60-second turn at a
//! 1 ms cadence would push 60 000 near-identical records into the ring and bury
//! the events that matter. Only a *change* in `(rtt, retransmits)` is recorded,
//! so the trace holds the socket's story rather than its heartbeat.
//!
//! The sampler works on a *duplicated descriptor* of the connection's socket
//! ([`duplicate`]), so it never borrows the stream the HTTP path owns and can be
//! stopped at any time by dropping its handle.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune_trace::Recorder;

/// One `TCP_INFO` reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSample {
    /// Kernel-smoothed round-trip time, microseconds.
    pub rtt_us: u32,
    /// Cumulative retransmitted segments on this socket.
    pub retransmits: u32,
}

/// How often the socket is polled while a request is in flight.
pub const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// A live sampling task. Dropping this handle stops sampling.
#[derive(Debug)]
pub struct Sampler {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Start sampling `socket` into `recorder` until the returned handle is dropped.
pub fn start(
    socket: std::net::TcpStream,
    recorder: Arc<Mutex<Recorder>>,
    interval: Duration,
) -> Sampler {
    let handle = tokio::spawn(async move {
        let mut last: Option<TcpSample> = None;
        loop {
            if let Some(sample) = sample(&socket)
                && last != Some(sample)
            {
                recorder
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .tcp_info(sample.rtt_us, sample.retransmits);
                last = Some(sample);
            }
            tokio::time::sleep(interval).await;
        }
    });
    Sampler { handle }
}

/// Duplicate a socket's descriptor so sampling outlives any single borrow.
///
/// `None` when the platform refuses the duplicate, which costs only the
/// RTT/retransmit scopes — never a fabricated value.
#[cfg(unix)]
pub fn duplicate<S: std::os::fd::AsRawFd>(source: &S) -> Option<std::net::TcpStream> {
    use std::os::fd::{FromRawFd, RawFd};

    // SAFETY: `source` owns a live descriptor; `dup` returns a new one.
    let fd: RawFd = unsafe { libc::dup(source.as_raw_fd()) };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` is a fresh, owned descriptor that nothing else owns.
    Some(unsafe { std::net::TcpStream::from_raw_fd(fd) })
}

#[cfg(not(unix))]
pub fn duplicate<S>(_source: &S) -> Option<std::net::TcpStream> {
    None
}

/// Read `TCP_INFO` for `stream`.
///
/// `None` when the platform cannot answer, the socket has been closed, or the
/// option is unsupported — never a fabricated zero.
#[cfg(target_os = "linux")]
pub fn sample(stream: &std::net::TcpStream) -> Option<TcpSample> {
    use std::os::fd::AsRawFd;

    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    // SAFETY: `info` is a correctly sized, zeroed `tcp_info`, `length` describes
    // it, and the descriptor is owned by `stream` for the duration of the call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            std::ptr::from_mut(&mut info).cast::<libc::c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return None;
    }
    Some(TcpSample {
        rtt_us: info.tcpi_rtt,
        retransmits: info.tcpi_total_retrans,
    })
}

/// Non-Linux platforms have no portable `TCP_INFO`; the scope stays
/// `NotEstimable` there rather than pretending.
#[cfg(not(target_os = "linux"))]
pub fn sample(_stream: &std::net::TcpStream) -> Option<TcpSample> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connected_pair() -> (tokio::net::TcpStream, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            drop(socket);
        });
        let client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        (client, accept)
    }

    #[tokio::test]
    async fn a_connected_socket_yields_a_sample() {
        let (client, accept) = connected_pair().await;
        let duplicated = duplicate(&client).expect("duplicate");
        let sample = sample(&duplicated);
        if cfg!(target_os = "linux") {
            let sample = sample.expect("TCP_INFO available on Linux");
            assert_eq!(
                sample.retransmits, 0,
                "a clean loopback socket retransmits nothing"
            );
        } else {
            assert!(sample.is_none(), "no TCP_INFO off Linux");
        }
        accept.await.expect("join");
    }

    #[tokio::test]
    async fn sampling_records_at_least_one_sample_and_stops_on_drop() {
        let (client, accept) = connected_pair().await;
        let duplicated = duplicate(&client).expect("duplicate");
        let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
        let sampler = start(duplicated, Arc::clone(&recorder), Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(sampler);

        let count = || {
            recorder
                .lock()
                .expect("recorder")
                .log()
                .iter()
                .filter(|event| event.kind == netune_trace::EventKind::TcpInfo)
                .count()
        };
        let recorded = count();
        if cfg!(target_os = "linux") {
            assert!(recorded >= 1, "at least one sample recorded");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(count(), recorded, "dropping the sampler stops sampling");
        accept.await.expect("join");
    }
}
