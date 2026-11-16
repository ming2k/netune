use super::*;

fn kinds(log: &EventLog) -> Vec<(u64, EventKind)> {
    log.iter().map(|e| (e.at_ns, e.kind)).collect()
}

#[test]
fn the_encoded_event_stays_compact() {
    assert_eq!(std::mem::size_of::<EncodedEvent>(), 20);
}

#[test]
fn empty_log_has_no_events() {
    let log = EventLog::with_capacity(0);
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert_eq!(log.dropped(), 0);
    assert_eq!(log.iter().count(), 0);
    assert_eq!(log.first_of(EventKind::Read), None);
}

#[test]
fn deltas_round_trip_including_long_gaps() {
    let mut log = EventLog::with_capacity(64);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(1_500, EventKind::Read, 1448, 0);
    // 9.5 s of silence: exceeds one u32 nanosecond field (4.29 s).
    log.push_at(9_500_000_000, EventKind::Read, 100, 0);
    // 200 s: needs two high words.
    log.push_at(209_500_000_000, EventKind::Payload, 4, 0);

    let got = kinds(&log);
    assert_eq!(
        got,
        vec![
            (0, EventKind::Dispatch),
            (1_500, EventKind::Read),
            (9_500_000_000, EventKind::Read),
            (209_500_000_000, EventKind::Payload),
        ]
    );
    assert_eq!(log.last_ns(), 209_500_000_000);
    assert_eq!(log.bytes_read(), 1548);
}

#[test]
fn non_monotonic_offsets_are_clamped_not_corrupted() {
    let mut log = EventLog::with_capacity(8);
    log.push_at(1_000, EventKind::Read, 10, 0);
    log.push_at(500, EventKind::Read, 10, 0); // caller bug
    assert_eq!(
        kinds(&log),
        vec![(1_000, EventKind::Read), (1_000, EventKind::Read)]
    );
}

#[test]
fn exchange_filter_keeps_connection_events_and_one_stream() {
    let mut log = EventLog::with_capacity(16);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at_stream(100, 1, EventKind::H3StreamStart, 0, 0);
    log.push_at_stream(200, 2, EventKind::H3StreamStart, 0, 0);
    log.push_at_stream(300, 1, EventKind::H3HeadComplete, 200, 0);
    log.push_at_stream(400, 2, EventKind::H3HeadComplete, 201, 0);

    let exchange = log.for_exchange(1);
    let events: Vec<_> = exchange
        .iter()
        .map(|event| (event.stream, event.kind))
        .collect();
    assert_eq!(
        events,
        vec![
            (0, EventKind::Dispatch),
            (1, EventKind::H3StreamStart),
            (1, EventKind::H3HeadComplete),
        ]
    );
}

#[test]
fn merging_two_logs_keeps_absolute_order_and_drop_counts() {
    let mut control = EventLog::with_capacity(8);
    control.push_at(0, EventKind::Dispatch, 0, 0);
    control.push_at(200, EventKind::TcpStart, 0, 0);

    let mut byte = EventLog::with_capacity(8);
    byte.push_at(100, EventKind::Read, 10, 0);
    byte.push_at(300, EventKind::Write, 20, 0);

    control.merge(byte);
    let kinds: Vec<_> = control
        .iter()
        .map(|event| (event.at_ns, event.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (0, EventKind::Dispatch),
            (100, EventKind::Read),
            (200, EventKind::TcpStart),
            (300, EventKind::Write),
        ]
    );
    assert_eq!(control.dropped(), 0);
}

#[test]
fn ring_evicts_oldest_and_counts_drops() {
    let mut log = EventLog::with_capacity(3);
    for i in 0..5u64 {
        log.push_at(i * 1_000_000, EventKind::Read, 10, 0);
    }
    assert_eq!(log.len(), 3);
    assert_eq!(log.dropped(), 2);
    assert_eq!(
        kinds(&log),
        vec![
            (2_000_000, EventKind::Read),
            (3_000_000, EventKind::Read),
            (4_000_000, EventKind::Read),
        ]
    );
    // The window base moved with the evictions, so offsets stay absolute.
    assert_eq!(log.base_ns(), 1_000_000);
    assert_eq!(log.last_ns(), 4_000_000);
}

#[test]
fn eviction_of_a_time_jump_keeps_offsets_absolute() {
    let mut log = EventLog::with_capacity(3);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(10_000_000_000, EventKind::Read, 1, 0); // TimeJump + Read
    log.push_at(10_000_001_000, EventKind::Read, 2, 0);
    log.push_at(10_000_002_000, EventKind::Read, 3, 0); // evicts Dispatch
    log.push_at(10_000_003_000, EventKind::Read, 4, 0); // evicts the jump

    assert_eq!(
        kinds(&log),
        vec![
            (10_000_001_000, EventKind::Read),
            (10_000_002_000, EventKind::Read),
            (10_000_003_000, EventKind::Read),
        ]
    );
    assert_eq!(log.base_ns(), 10_000_000_000);
}

#[cfg(feature = "serde")]
#[test]
fn serde_round_trip_preserves_offsets_and_drops() {
    let mut log = EventLog::with_capacity(2);
    for i in 0..4u64 {
        log.push_at(i * 1_000, EventKind::Read, 7, 1);
    }
    let json = serde_json::to_string(&log).expect("serialize");
    let back: EventLog = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, log);
    assert_eq!(kinds(&back), kinds(&log));
    assert_eq!(back.dropped(), 2);
}

#[test]
fn first_and_last_of_a_kind_are_order_correct() {
    let mut log = EventLog::with_capacity(16);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(100, EventKind::ProtocolFrame, 1, 0);
    log.push_at(200, EventKind::Payload, 2, 0);
    log.push_at(300, EventKind::ProtocolFrame, 3, 0);
    log.push_at(400, EventKind::Payload, 5, 0);
    assert_eq!(
        log.first_of(EventKind::ProtocolFrame).map(|e| e.at_ns),
        Some(100)
    );
    assert_eq!(
        log.last_of(EventKind::ProtocolFrame).map(|e| e.at_ns),
        Some(300)
    );
    assert_eq!(log.last_of(EventKind::Payload).map(|e| e.a), Some(5));
}
