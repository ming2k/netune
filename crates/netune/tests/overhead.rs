//! Tap overhead and fidelity, measured rather than assumed.
//!
//! ADR-0001's P0 gate has two empirical criteria this file can close hermetically:
//!
//! 1. **Overhead** — recording an event must cost microseconds, not milliseconds,
//!    or the tap changes the thing it measures.
//! 2. **Fidelity** — a read event's timestamp must mark when the bytes *arrived*,
//!    not when the read was issued. A tap that timestamps the wrong instant
//!    produces confident nonsense.
//!
//! The numbers are printed, so a regression shows up as a changed line, not just
//! a red test. The assertions are set well above the measured cost so a loaded
//! machine does not flake; the printed value is the real gate.
//!
//! What this file deliberately does *not* do: compare against `tcpdump`. That
//! needs a privileged capture and belongs in the CI cross-check job, not here.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use netune::TimedIo;
use netune_trace::{EventKind, Recorder, TimeSource};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// ADR-0001's per-event budget.
const PER_EVENT_BUDGET: Duration = Duration::from_micros(20);

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let connecting =
        tokio::spawn(async move { TcpStream::connect(address).await.expect("connect") });
    let (server, _) = listener.accept().await.expect("accept");
    let client = connecting.await.expect("join");
    client.set_nodelay(true).expect("nodelay client");
    server.set_nodelay(true).expect("nodelay server");
    (client, server)
}

#[test]
fn recording_an_event_costs_microseconds() {
    const EVENTS: usize = 200_000;
    let mut recorder = Recorder::start(EVENTS);
    let mut samples: Vec<Duration> = Vec::with_capacity(EVENTS);
    let started = Instant::now();
    for index in 0..EVENTS {
        let before = Instant::now();
        if index % 2 == 0 {
            recorder.read(1448, TimeSource::Syscall);
        } else {
            recorder.wrote(1448);
        }
        samples.push(before.elapsed());
    }
    let total = started.elapsed();
    samples.sort_unstable();
    let at = |per_mille: usize| samples[(EVENTS - 1) * per_mille / 1000];
    let (p50, p99, p999, worst) = (at(500), at(990), at(999), samples[EVENTS - 1]);
    println!(
        "recorder: {EVENTS} events in {total:?} → mean {:?}, p50 {p50:?}, p99 {p99:?}, \
         p99.9 {p999:?}, max {worst:?} (budget {PER_EVENT_BUDGET:?})",
        total / EVENTS as u32
    );
    // The budget governs the cost of *recording an event*. The maximum is an
    // amortized-allocation outlier (the ring doubles ~18 times over 200 000
    // pushes); the tail percentiles are what a stream actually pays.
    assert!(p99 < Duration::from_micros(5), "p99 {p99:?}");
    assert!(p999 < PER_EVENT_BUDGET, "p99.9 {p999:?}");
    assert_eq!(recorder.log().len(), EVENTS);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tap_timestamps_arrival_not_issue() {
    // The peer sends a burst after a known delay. The tap must place the event
    // at the arrival instant, not at the moment the read was issued. The
    // reference is the *actual* write instant (the sender's timer jitter is not
    // the tap's error), so the tolerance can be tight.
    const DELAY: Duration = Duration::from_millis(50);
    // The threshold is sized from the signal, not picked for tightness. The
    // failure this test exists for is a tap that stamps the *issue* instant,
    // which is DELAY away from the arrival instant — so a quarter of DELAY is
    // still unambiguous evidence (12.5 ms vs 50 ms), while leaving room for the
    // two scheduler preemptions that can land here: between the sender's clock
    // read and its write, and between arrival and the reader's syscall. Those are
    // host jitter, not tap error; the previous absolute 2 ms tolerance conflated
    // the two and flaked under parallel load, which says nothing about the tap.
    const TOLERANCE: Duration = Duration::from_millis(12);

    let (client, mut server) = loopback_pair().await;
    let recorder = Arc::new(Mutex::new(Recorder::start(64)));
    let origin = recorder.lock().expect("recorder").origin();
    let sent_at = Arc::new(Mutex::new(None));
    let sender_sent_at = Arc::clone(&sent_at);
    let sender = tokio::spawn(async move {
        tokio::time::sleep(DELAY).await;
        *sender_sent_at.lock().expect("sent_at") = Some(Instant::now());
        server.write_all(b"burst").await.expect("write");
        server.flush().await.expect("flush");
    });

    let mut timed = TimedIo::new(client, Arc::clone(&recorder));
    let mut buffer = [0u8; 32];
    let read = timed.read(&mut buffer).await.expect("read");
    assert_eq!(&buffer[..read], b"burst");
    sender.await.expect("join");

    let event = recorder
        .lock()
        .expect("recorder")
        .log()
        .first_of(EventKind::Read)
        .expect("read event");
    let recorded = Duration::from_nanos(event.at_ns);
    let wrote_at = sent_at
        .lock()
        .expect("sent_at")
        .expect("sender recorded its write instant");
    let expected = wrote_at.duration_since(origin);
    let error = recorded.abs_diff(expected);
    println!(
        "fidelity: wrote at {expected:?}, read event at {recorded:?}, error {error:?} \
         (tolerance {TOLERANCE:?})"
    );
    assert!(
        error < TOLERANCE,
        "read event landed {error:?} from the arrival instant"
    );
    assert_eq!(event.a, 5, "the event carries the byte count");
}

/// A sink that accepts every write immediately, so a measurement over it isolates the
/// tap's own bookkeeping from any network behaviour.
struct NullSink {
    written: usize,
}

impl NullSink {
    fn new() -> Self {
        Self { written: 0 }
    }
}

impl AsyncWrite for NullSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written += buffer.len();
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A source that yields `len` bytes once and then reports EOF.
struct FixedSource {
    remaining: usize,
}

impl AsyncRead for FixedSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let take = self.remaining.min(buffer.remaining());
        if take == 0 {
            return Poll::Ready(Ok(()));
        }
        buffer.initialize_unfilled_to(take);
        buffer.advance(take);
        self.remaining -= take;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tap_adds_no_delay_to_the_data_path() {
    // A tap that is correct but slow is not correct, and the instrument has to isolate
    // the tap from everything else.
    //
    // The earlier version of this test compared two end-to-end loopback round trips. That
    // is not a measurement of the tap: on a loaded machine a single trip drifted from
    // 20 µs to 111 µs (5×) while the tap added about 1 µs, so the test was reporting the
    // host's scheduler and failing in roughly a quarter of full parallel runs. No
    // threshold can fix that — the signal is smaller than the noise.
    //
    // So the transport is replaced by an in-memory sink: one write and one read through
    // `TimedIo`, versus the same calls on a bare sink. What remains is the tap: two
    // `Instant::now()` calls and two ring pushes. The measure is the *median* per-op cost
    // over many operations, which is a pure function of recorded events rather than of
    // elapsed wall time (docs/dev/testing.md §2), and the budget is ADR-0001's per-event
    // figure doubled to allow for the tap doing two events per operation.
    const OPERATIONS: usize = 20_000;
    const WRITE: usize = 1448;

    let recorder = Arc::new(Mutex::new(Recorder::start(2 * OPERATIONS + 64)));
    let mut tapped = TimedIo::new(NullSink::new(), Arc::clone(&recorder));

    let mut tapped_samples = Vec::with_capacity(OPERATIONS);
    for _ in 0..OPERATIONS {
        let before = Instant::now();
        tapped.write_all(&[0u8; WRITE]).await.expect("write");
        tapped_samples.push(before.elapsed());
    }

    let mut plain = NullSink::new();
    let mut plain_samples = Vec::with_capacity(OPERATIONS);
    for _ in 0..OPERATIONS {
        let before = Instant::now();
        plain.write_all(&[0u8; WRITE]).await.expect("write");
        plain_samples.push(before.elapsed());
    }

    tapped_samples.sort_unstable();
    plain_samples.sort_unstable();
    let median = |samples: &[Duration]| samples[samples.len() / 2];
    let tapped_median = median(&tapped_samples);
    let plain_median = median(&plain_samples);
    let added = tapped_median.saturating_sub(plain_median);
    println!(
        "data path (median of {OPERATIONS} writes through an in-memory sink): \
         plain {plain_median:?}, tapped {tapped_median:?}, added {added:?} \
         (two events per write, budget {PER_EVENT_BUDGET:?} each)"
    );

    // The tap records two events per write (a `Write` and its byte count), so the budget
    // for one operation is two events.
    let budget = PER_EVENT_BUDGET * 2;
    assert!(
        added < budget,
        "the tap added {added:?} per write, above the {budget:?} budget for two events"
    );

    // The sink really was written through the tap, so a passing measurement cannot be an
    // artefact of nothing happening.
    assert_eq!(tapped.into_inner().written, OPERATIONS * WRITE);
    assert_eq!(plain.written, OPERATIONS * WRITE);
    assert!(recorder.lock().expect("recorder").log().len() > OPERATIONS);

    // A read through the tap is measured the same way, so a regression in the read path is
    // not hidden behind the write path passing.
    let recorder = Arc::new(Mutex::new(Recorder::start(OPERATIONS + 64)));
    let mut reading = TimedIo::new(
        FixedSource {
            remaining: OPERATIONS * WRITE,
        },
        Arc::clone(&recorder),
    );
    let mut buffer = [0u8; WRITE];
    let mut read_samples = Vec::with_capacity(OPERATIONS);
    for _ in 0..OPERATIONS {
        let before = Instant::now();
        let read = reading.read(&mut buffer).await.expect("read");
        assert_eq!(read, WRITE);
        read_samples.push(before.elapsed());
    }
    read_samples.sort_unstable();
    let read_median = median(&read_samples);
    println!("data path: median read {read_median:?} through the tap");
    assert!(
        read_median < budget,
        "a tapped read cost {read_median:?}, above the {budget:?} budget"
    );
}
