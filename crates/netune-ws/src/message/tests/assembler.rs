use crate::message::*;

#[test]
fn test_reassemble_fragmented_text_message() {
    let mut assembler = MessageAssembler::new(1024 * 1024);

    // Frame 1: Text, FIN=false
    let f1 = Frame::new(false, Opcode::Text, Bytes::from_static(b"Hello "));
    assert_eq!(assembler.process_frame(f1).unwrap(), None);

    // Interleaved Ping frame
    let f_ping = Frame::ping(Bytes::from_static(b"heartbeat"));
    let msg = assembler.process_frame(f_ping).unwrap();
    assert_eq!(msg, Some(Message::Ping(Bytes::from_static(b"heartbeat"))));

    // Frame 2: Continuation, FIN=false
    let f2 = Frame::new(false, Opcode::Continuation, Bytes::from_static(b"World"));
    assert_eq!(assembler.process_frame(f2).unwrap(), None);

    // Frame 3: Continuation, FIN=true
    let f3 = Frame::new(true, Opcode::Continuation, Bytes::from_static(b"!"));
    let final_msg = assembler.process_frame(f3).unwrap();
    assert_eq!(final_msg, Some(Message::Text("Hello World!".to_string())));
}

#[test]
fn test_unsolicited_continuation_rejected() {
    let mut assembler = MessageAssembler::new(1024);
    let f = Frame::new(true, Opcode::Continuation, Bytes::from_static(b"orphan"));
    let err = assembler.process_frame(f).unwrap_err();
    match err {
        WsError::Protocol { code, .. } => assert_eq!(code, CloseCode::PROTOCOL_ERROR),
        _ => panic!("Expected protocol error"),
    }
}

#[test]
fn test_close_payload_validation() {
    // 1-byte close payload must fail
    assert!(MessageAssembler::parse_close_payload(&[0x03]).is_err());

    // Valid close payload
    let mut valid = vec![0x03, 0xE8]; // 1000
    valid.extend_from_slice(b"normal closure");
    let res = MessageAssembler::parse_close_payload(&valid)
        .unwrap()
        .unwrap();
    assert_eq!(res.code, CloseCode::NORMAL);
    assert_eq!(res.description, "normal closure");

    // Illegal wire code (1005: No Status Received)
    let illegal = [0x03, 0xED]; // 1005
    assert!(MessageAssembler::parse_close_payload(&illegal).is_err());
}

#[test]
fn test_fragmented_text_invalid_utf8_fails_immediately() {
    let mut assembler = MessageAssembler::new(1024);

    // First frame: valid ASCII, no FIN
    let f1 = Frame::new(false, Opcode::Text, Bytes::from_static(b"good "));
    assert_eq!(assembler.process_frame(f1).unwrap(), None);

    // Continuation with a stray continuation byte (0x80): must fail NOW,
    // not after the message finishes.
    let f2 = Frame::new(false, Opcode::Continuation, Bytes::from_static(&[0x80]));
    let err = assembler.process_frame(f2).unwrap_err();
    match err {
        WsError::Protocol { code, .. } => assert_eq!(code, CloseCode::INVALID_PAYLOAD),
        _ => panic!("Expected invalid payload error"),
    }
}

#[test]
fn test_fragmented_text_split_utf8_sequence_accepts() {
    let mut assembler = MessageAssembler::new(1024);

    // "é" = C3 A9, split across frames
    let f1 = Frame::new(false, Opcode::Text, Bytes::from_static(&[0xC3]));
    assert_eq!(assembler.process_frame(f1).unwrap(), None);
    let f2 = Frame::new(true, Opcode::Continuation, Bytes::from_static(&[0xA9]));
    let msg = assembler.process_frame(f2).unwrap();
    assert_eq!(msg, Some(Message::Text("é".to_string())));
}

#[test]
fn test_fragmented_text_truncated_utf8_at_fin_fails() {
    let mut assembler = MessageAssembler::new(1024);

    let f1 = Frame::new(false, Opcode::Text, Bytes::from_static(&[0xC3]));
    assert_eq!(assembler.process_frame(f1).unwrap(), None);
    // FIN arrives, but the sequence never completed.
    let f2 = Frame::new(true, Opcode::Continuation, Bytes::new());
    let err = assembler.process_frame(f2).unwrap_err();
    match err {
        WsError::Protocol { code, .. } => assert_eq!(code, CloseCode::INVALID_PAYLOAD),
        _ => panic!("Expected invalid payload error"),
    }
}

#[test]
fn test_fragmented_binary_oversize_rejected() {
    let mut assembler = MessageAssembler::new(8);
    let f1 = Frame::new(false, Opcode::Binary, Bytes::from(vec![0u8; 6]));
    assert_eq!(assembler.process_frame(f1).unwrap(), None);
    let f2 = Frame::new(true, Opcode::Continuation, Bytes::from(vec![0u8; 6]));
    let err = assembler.process_frame(f2).unwrap_err();
    match err {
        WsError::PayloadTooLarge { .. } => {}
        _ => panic!("Expected payload too large"),
    }
}

#[test]
fn test_unfragmented_data_frame_during_fragment_is_rejected() {
    let mut assembler = MessageAssembler::new(1024);
    let f1 = Frame::new(false, Opcode::Text, Bytes::from_static(b"start"));
    assert_eq!(assembler.process_frame(f1).unwrap(), None);
    // An unfragmented text frame while a fragment is in flight: error.
    let f2 = Frame::new(true, Opcode::Text, Bytes::from_static(b"bad"));
    let err = assembler.process_frame(f2).unwrap_err();
    match err {
        WsError::Protocol { code, .. } => assert_eq!(code, CloseCode::PROTOCOL_ERROR),
        _ => panic!("Expected protocol error"),
    }
}
