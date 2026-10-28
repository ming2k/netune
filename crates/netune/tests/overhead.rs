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

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netune::TimedIo;
use netune_trace::{EventKind, Recorder, TimeSource};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// One round-trip measurement through a loopback echo, timed end to end.
///
/// `tapped` selects the path under test: `TimedIo` (with a recorder) or the bare
/// stream. The same function measures both, so the two sides cannot drift into
/// comparing different work.
async fn measure_round_trips(iterations: usize) -> Duration {
    let (client, mut server) = loopback_pair().await;
    let echo = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        loop {
            let read = match server.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            if server.write_all(&buffer[..read]).await.is_err() {
                return;
            }
        }
    });
    let started = Instant::now();
    let mut io = TimedIo::new(
        client,
        Arc::new(Mutex::new(Recorder::start(4 * iterations + 16))),
    );
    let mut buffer = [0u8; 64];
    for _ in 0..iterations {
        io.write_all(b"ping").await.expect("write");
        let read = io.read(&mut buffer).await.expect("read");
        assert_eq!(read, 4);
    }
    let elapsed = started.elapsed();
    drop(io);
    echo.abort();
    elapsed
}

/// The same loop with no tap: the baseline the tapped path is measured against.
async fn measure_round_trips_plain(iterations: usize) -> Duration {
    let (client, mut server) = loopback_pair().await;
    let echo = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        loop {
            let read = match server.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            if server.write_all(&buffer[..read]).await.is_err() {
                return;
            }
        }
    });
    let mut client = client;
    let mut buffer = [0u8; 64];
    let started = Instant::now();
    for _ in 0..iterations {
        client.write_all(b"ping").await.expect("write");
        let read = client.read(&mut buffer).await.expect("read");
        assert_eq!(read, 4);
    }
    let elapsed = started.elapsed();
    drop(client);
    echo.abort();
    elapsed
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tap_adds_no_delay_to_the_data_path() {
    // A tap that is correct but slow is not correct.
    //
    // One long wall-clock measurement per side is the wrong instrument here, and
    // it used to make this test flake under parallel load: a scheduler stall that
    // lands in the tapped sample is charged entirely to the tap, and with a
    // 20 µs/trip budget a single 2 ms preemption fails the assertion. Nothing in
    // the production path is being measured in that case — only the host's
    // willingness to schedule the test thread.
    //
    // So each side is sampled in interleaved batches (also removing the ordering
    // bias of measuring one path while the machine warms up) and the *minimum*
    // batch time per trip is compared. Contention can only add time, so the
    // minimum is the least-contaminated estimate of the true cost, which is what
    // the budget is about. The sample counts are printed so a regression still
    // shows up as a changed line rather than only as a red assertion.
    const BATCHES: usize = 9;
    const PER_BATCH: usize = 2_000;

    // Warm both paths, so the first batch does not pay for page faults or the
    // reactor's first registrations.
    let _ = measure_round_trips(500).await;
    let _ = measure_round_trips_plain(500).await;

    let mut tapped_min = Duration::MAX;
    let mut plain_min = Duration::MAX;
    for _ in 0..BATCHES {
        let tapped = measure_round_trips(PER_BATCH).await;
        let plain = measure_round_trips_plain(PER_BATCH).await;
        tapped_min = tapped_min.min(tapped);
        plain_min = plain_min.min(plain);
    }

    let per_trip_tapped = tapped_min / PER_BATCH as u32;
    let per_trip_plain = plain_min / PER_BATCH as u32;
    let added = per_trip_tapped.saturating_sub(per_trip_plain);
    println!(
        "data path (best of {BATCHES} batches of {PER_BATCH}): plain {per_trip_plain:?}/trip, \
         tapped {per_trip_tapped:?}/trip, added {added:?}/trip"
    );
    assert!(
        added < PER_EVENT_BUDGET,
        "the tap added {added:?} per round trip, above the {PER_EVENT_BUDGET:?} budget"
    );
}
