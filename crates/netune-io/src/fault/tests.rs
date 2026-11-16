use super::*;

#[test]
fn an_empty_script_admits_everything() {
    let mut script = FaultScript::empty();
    let now = Instant::now();
    for _ in 0..10 {
        assert_eq!(script.admit(now), Admit::Read(None));
        script.delivered(16);
    }
}

#[test]
fn a_delay_blocks_until_its_deadline_then_admits() {
    let mut script = FaultScript::new(vec![(0, Fault::Delay(Duration::from_millis(50)))]);
    let now = Instant::now();
    match script.admit(now) {
        Admit::Wait(deadline) => assert!(deadline > now, "the stall is in the future"),
        other => panic!("expected a wait, got {other:?}"),
    }
    // Still waiting before the deadline…
    assert!(matches!(
        script.admit(now + Duration::from_millis(10)),
        Admit::Wait(_)
    ));
    // …admitting after it, exactly once (the fault is retired).
    assert!(matches!(
        script.admit(now + Duration::from_millis(60)),
        Admit::Read(None)
    ));
    assert!(matches!(
        script.admit(now + Duration::from_millis(70)),
        Admit::Read(None)
    ));
}

#[test]
fn a_split_caps_reads_within_its_span() {
    let mut script = FaultScript::new(vec![(
        0,
        Fault::Split {
            span: 10,
            per_read: 4,
        },
    )]);
    let now = Instant::now();
    assert_eq!(script.admit(now), Admit::Read(Some(4)));
    script.delivered(4);
    assert_eq!(
        script.admit(now),
        Admit::Read(Some(4)),
        "still within the span"
    );
    script.delivered(4);
    assert_eq!(script.admit(now), Admit::Read(Some(4)));
    script.delivered(4);
    // 12 > span 10: the split is done, reads are uncapped.
    assert_eq!(script.admit(now), Admit::Read(None));
}

#[test]
fn truncate_reports_eof_at_its_offset() {
    let mut script = FaultScript::new(vec![(8, Fault::Truncate)]);
    let now = Instant::now();
    assert_eq!(
        script.admit(now),
        Admit::Read(Some(8)),
        "before the offset, a read stops at the offset"
    );
    script.delivered(8);
    assert_eq!(script.admit(now), Admit::Eof);
}

#[test]
fn reset_reports_a_connection_error_at_its_offset() {
    let mut script = FaultScript::new(vec![(16, Fault::Reset)]);
    let now = Instant::now();
    script.delivered(15);
    assert_eq!(script.admit(now), Admit::Read(Some(1)));
    script.delivered(1);
    assert!(matches!(script.admit(now), Admit::Reset));
}

#[test]
fn a_read_never_runs_past_the_next_fault() {
    // The whole payload is available at once. Without a cap the first read
    // would deliver all of it and the reset at byte 16 would never be seen.
    let mut script = FaultScript::new(vec![(16, Fault::Reset)]);
    let now = Instant::now();
    assert_eq!(script.admit(now), Admit::Read(Some(16)));
    script.delivered(16);
    assert!(matches!(script.admit(now), Admit::Reset));
    // With every fault spent, reads are uncapped.
    assert_eq!(script.admit(now), Admit::Read(None));
}

#[test]
fn faults_fire_in_offset_order() {
    let mut script = FaultScript::new(vec![
        (
            4,
            Fault::Split {
                span: 4,
                per_read: 2,
            },
        ),
        (12, Fault::Reset),
    ]);
    let now = Instant::now();
    // Before the split's offset, a read stops at that offset…
    assert_eq!(script.admit(now), Admit::Read(Some(4)));
    script.delivered(4);
    // …then the split caps reads for its 4-byte span…
    assert_eq!(script.admit(now), Admit::Read(Some(2)));
    script.delivered(2);
    assert_eq!(script.admit(now), Admit::Read(Some(2)));
    script.delivered(2);
    // (delivered = 8, past the span) …and then a read stops at the reset's
    // offset.
    assert_eq!(script.admit(now), Admit::Read(Some(4)));
    script.delivered(4);
    // …until the reset at offset 12.
    assert!(matches!(script.admit(now), Admit::Reset));
}

// -- end to end: the wrapper drives a real stream ----------------------
//
// The state machine is pure; these tests prove the `AsyncRead` impl
// actually enforces it against live bytes, over a tokio duplex pair.

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// A duplex stream that has `data` sitting in it, wrapped in `FaultIo`.
async fn faulted_stream(
    data: &'static [u8],
    faults: impl IntoIterator<Item = (usize, Fault)>,
) -> (FaultIo<DuplexStream>, tokio::task::JoinHandle<()>) {
    let (mut writer, reader) = tokio::io::duplex(64);
    let feeder = tokio::spawn(async move {
        writer.write_all(data).await.expect("feed");
    });
    (
        FaultIo::new(reader, Arc::new(Mutex::new(FaultScript::new(faults)))),
        feeder,
    )
}

#[tokio::test]
async fn an_empty_script_passes_every_byte_through() {
    let (mut stream, feeder) = faulted_stream(b"hello world", []).await;
    let mut got: Vec<u8> = Vec::new();
    stream.read_to_end(&mut got).await.expect("read");
    assert_eq!(got, b"hello world", "chaos off is a provable passthrough");
    feeder.await.expect("feeder");
}

#[tokio::test]
async fn a_split_is_enforced_as_a_cap_per_read() {
    let (mut stream, feeder) = faulted_stream(
        b"abcdefgh",
        [(
            0,
            Fault::Split {
                span: 8,
                per_read: 3,
            },
        )],
    )
    .await;
    let mut first = [0u8; 16];
    let read = stream.read(&mut first).await.expect("read");
    assert_eq!(
        read, 3,
        "the first read is capped at per_read, not the buffer"
    );
    let second = stream.read(&mut first).await.expect("read");
    assert_eq!(second, 3, "and the next one too");
    feeder.await.expect("feeder");
}

#[tokio::test]
async fn a_truncate_ends_the_stream_before_the_data_does() {
    let (mut stream, feeder) = faulted_stream(b"0123456789", [(4, Fault::Truncate)]).await;
    // A reader that wants everything gets EOF after 4 bytes.
    let mut chunk = [0u8; 64];
    let read = stream.read(&mut chunk).await.expect("read");
    assert!(read >= 4, "the first read carries the pre-offset bytes");
    let read = stream.read(&mut chunk).await.expect("read");
    assert_eq!(read, 0, "then EOF, though 6 more bytes were in flight");
    feeder.await.expect("feeder");
}

#[tokio::test]
async fn a_reset_is_a_connection_error_mid_stream() {
    let (mut stream, feeder) = faulted_stream(b"0123456789", [(4, Fault::Reset)]).await;
    let mut chunk = [0u8; 64];
    let read = stream.read(&mut chunk).await.expect("first read");
    assert!(read >= 4);
    let error = stream
        .read(&mut chunk)
        .await
        .expect_err("the next read is a reset");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    feeder.await.expect("feeder");
}

#[tokio::test]
async fn a_delay_stalls_the_reader_until_it_passes() {
    let (mut stream, feeder) =
        faulted_stream(b"abcdef", [(0, Fault::Delay(Duration::from_millis(80)))]).await;
    let started = Instant::now();
    let mut got: Vec<u8> = Vec::new();
    stream.read_to_end(&mut got).await.expect("read");
    assert_eq!(got, b"abcdef");
    assert!(
        started.elapsed() >= Duration::from_millis(70),
        "the read path really waited: {:?}",
        started.elapsed()
    );
    feeder.await.expect("feeder");
}
