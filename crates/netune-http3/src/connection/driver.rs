// SPDX-License-Identifier: MIT

//! The H3 connection driver: accepts streams, reads critical streams, and
//! serializes QPACK instruction writes.

use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use netune_quic::owned::{RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::proto::code::{error_code, frame_type, stream_type};
use crate::proto::frame::{self, Frame};
use crate::qpack::instructions::{decode_decoder_instruction, decode_encoder_instruction};

use super::IncomingBi;
use super::shared::{ControlCommand, Shared};

const CONTROL_FRAME_LIMIT: usize = 64 * 1024;

pub(crate) struct CriticalStreams {
    pub control: SendStream,
    pub encoder: SendStream,
    pub decoder: SendStream,
}

pub(crate) struct DriverChannels {
    pub control: mpsc::UnboundedReceiver<ControlCommand>,
    pub encoder: mpsc::UnboundedReceiver<bytes::Bytes>,
    pub decoder: mpsc::UnboundedReceiver<bytes::Bytes>,
}

pub(crate) async fn drive(
    shared: Arc<Shared>,
    streams: CriticalStreams,
    channels: DriverChannels,
    incoming_tx: Option<mpsc::Sender<IncomingBi>>,
) {
    let CriticalStreams {
        control: mut control_send,
        encoder: mut encoder_send,
        decoder: mut decoder_send,
    } = streams;
    let DriverChannels {
        control: mut control_rx,
        encoder: mut encoder_rx,
        decoder: mut decoder_rx,
    } = channels;
    let connection = shared.connection.clone();
    let datagram_connection = shared.connection.clone();
    let mut tasks = JoinSet::new();

    {
        let shared = shared.clone();
        tasks.spawn(async move {
            while let Some(bytes) = encoder_rx.recv().await {
                if let Err(error) = encoder_send.write_all(&bytes).await {
                    shared.set_error(
                        error_code::H3_CLOSED_CRITICAL_STREAM,
                        format!("QPACK encoder stream write failed: {error}"),
                    );
                    return;
                }
            }
            std::future::pending::<()>().await;
        });
    }
    {
        let shared = shared.clone();
        tasks.spawn(async move {
            while let Some(bytes) = decoder_rx.recv().await {
                if let Err(error) = decoder_send.write_all(&bytes).await {
                    shared.set_error(
                        error_code::H3_CLOSED_CRITICAL_STREAM,
                        format!("QPACK decoder stream write failed: {error}"),
                    );
                    return;
                }
            }
            std::future::pending::<()>().await;
        });
    }
    {
        let shared = shared.clone();
        tasks.spawn(async move {
            while let Some(command) = control_rx.recv().await {
                let ControlCommand::GoAway(stream_id) = command;
                if let Err(error) = frame::write_goaway(&mut control_send, stream_id).await {
                    shared.set_error(
                        error_code::H3_CLOSED_CRITICAL_STREAM,
                        format!("control stream write failed: {error}"),
                    );
                    return;
                }
            }
            std::future::pending::<()>().await;
        });
    }

    let mut closed = Box::pin(connection.closed());
    loop {
        tokio::select! {
            _ = &mut closed => break,
            datagram = datagram_connection.recv_datagram() => {
                if let Ok(data) = datagram {
                    if !shared.datagrams_enabled() {
                        shared.set_error(
                            error_code::H3_MESSAGE_ERROR,
                            "HTTP/3 datagram received without SETTINGS_H3_DATAGRAM",
                        );
                        break;
                    }
                    let mut cursor = data.as_ref();
                    if let Ok(quarter) = crate::proto::varint::decode(&mut cursor) {
                        shared.route_datagram(quarter.saturating_mul(4), Bytes::copy_from_slice(cursor));
                    }
                }
            }
            accepted = connection.accept_uni() => {
                match accepted {
                    Ok(recv) => {
                        tasks.spawn(handle_uni_stream(shared.clone(), recv));
                    }
                    Err(_) => break,
                }
            }
            accepted = connection.accept_bi() => {
                match accepted {
                    Ok((send, recv)) => {
                        let id = send.id();
                        if let Some(incoming) = &incoming_tx {
                            let accepted = IncomingBi { send, recv, id };
                            match incoming.try_send(accepted) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(mut rejected)) => {
                                    rejected.send.reset(error_code::H3_REQUEST_REJECTED);
                                    rejected.recv.stop(error_code::H3_REQUEST_REJECTED);
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        } else {
                            shared.set_error(
                                error_code::H3_ID_ERROR,
                                "server-initiated bidirectional stream without push support",
                            );
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn handle_uni_stream(shared: Arc<Shared>, mut recv: RecvStream) {
    let stream_type = match frame::read_varint(&mut recv).await {
        Ok(Some(stream_type)) => stream_type,
        Ok(None) | Err(_) => {
            shared.set_error(
                error_code::H3_STREAM_CREATION_ERROR,
                "unidirectional stream ended before its type",
            );
            return;
        }
    };

    match stream_type {
        stream_type::CONTROL => {
            if !shared.mark_control() {
                shared.set_error(
                    error_code::H3_STREAM_CREATION_ERROR,
                    "second control stream",
                );
                return;
            }
            read_control(shared, recv).await;
        }
        stream_type::QPACK_ENCODER => {
            if !shared.mark_encoder() {
                shared.set_error(
                    error_code::H3_STREAM_CREATION_ERROR,
                    "second QPACK encoder stream",
                );
                return;
            }
            read_qpack_encoder(shared, recv).await;
        }
        stream_type::QPACK_DECODER => {
            if !shared.mark_decoder() {
                shared.set_error(
                    error_code::H3_STREAM_CREATION_ERROR,
                    "second QPACK decoder stream",
                );
                return;
            }
            read_qpack_decoder(shared, recv).await;
        }
        stream_type::PUSH => {
            shared.set_error(
                error_code::H3_ID_ERROR,
                "push stream received without MAX_PUSH_ID",
            );
        }
        _ => {
            recv.stop(error_code::H3_NO_ERROR);
        }
    }
}

fn control_frame_error_code(error: &frame::FrameError) -> u64 {
    match error {
        frame::FrameError::Settings(_) => error_code::H3_SETTINGS_ERROR,
        _ => error_code::H3_FRAME_ERROR,
    }
}

async fn read_control(shared: Arc<Shared>, mut recv: RecvStream) {
    let first = match frame::read_frame(&mut recv, CONTROL_FRAME_LIMIT).await {
        Ok(Some(frame)) => frame,
        Ok(None) => {
            shared.set_error(
                error_code::H3_CLOSED_CRITICAL_STREAM,
                "control stream closed before SETTINGS",
            );
            return;
        }
        Err(error) => {
            shared.set_error(
                control_frame_error_code(&error),
                format!("control stream: {error}"),
            );
            return;
        }
    };
    match first {
        Frame::Settings(settings) => shared.update_peer_settings(settings),
        _ => {
            shared.set_error(
                error_code::H3_MISSING_SETTINGS,
                "first control-stream frame was not SETTINGS",
            );
            return;
        }
    }
    if shared.check_error().is_err() {
        return;
    }

    loop {
        let frame = match frame::read_frame(&mut recv, CONTROL_FRAME_LIMIT).await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                shared.set_error(
                    error_code::H3_CLOSED_CRITICAL_STREAM,
                    "control stream closed",
                );
                return;
            }
            Err(error) => {
                shared.set_error(
                    control_frame_error_code(&error),
                    format!("control stream: {error}"),
                );
                return;
            }
        };
        match frame {
            Frame::GoAway(stream_id) => shared.set_goaway(stream_id),
            Frame::Settings(_) => {
                shared.set_error(
                    error_code::H3_FRAME_UNEXPECTED,
                    "SETTINGS received more than once",
                );
                return;
            }
            Frame::CancelPush(_) | Frame::MaxPushId(_) => {}
            Frame::Unknown { ty, .. }
                if ty == frame_type::PUSH_PROMISE || ty == frame_type::DUPLICATE_PUSH =>
            {
                shared.set_error(
                    error_code::H3_FRAME_UNEXPECTED,
                    "push frame on the control stream",
                );
                return;
            }
            Frame::Unknown { .. } => {}
            _ => {
                shared.set_error(
                    error_code::H3_FRAME_UNEXPECTED,
                    "unexpected frame on the control stream",
                );
                return;
            }
        }
    }
}

async fn read_qpack_encoder(shared: Arc<Shared>, mut recv: RecvStream) {
    let limit = shared.max_qpack_instruction();
    let mut buffer = BytesMut::new();
    loop {
        let chunk = match recv.read(8192).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => {
                shared.set_error(
                    error_code::H3_CLOSED_CRITICAL_STREAM,
                    "QPACK encoder stream closed",
                );
                return;
            }
            Err(error) => {
                shared.set_error(
                    error_code::QPACK_ENCODER_STREAM_ERROR,
                    format!("QPACK encoder stream read failed: {error}"),
                );
                return;
            }
        };
        buffer.extend_from_slice(&chunk);

        loop {
            match decode_encoder_instruction(&buffer, limit) {
                Ok(Some((instruction, consumed))) => {
                    buffer.advance(consumed);
                    shared.apply_encoder_instruction(instruction);
                    if shared.check_error().is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    shared.set_error(
                        error_code::QPACK_ENCODER_STREAM_ERROR,
                        format!("QPACK encoder stream: {error}"),
                    );
                    return;
                }
            }
        }
        if buffer.len() > limit {
            shared.set_error(
                error_code::QPACK_ENCODER_STREAM_ERROR,
                "QPACK instruction exceeds the configured limit",
            );
            return;
        }
    }
}

async fn read_qpack_decoder(shared: Arc<Shared>, mut recv: RecvStream) {
    let mut buffer = BytesMut::new();
    loop {
        let chunk = match recv.read(8192).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => {
                shared.set_error(
                    error_code::H3_CLOSED_CRITICAL_STREAM,
                    "QPACK decoder stream closed",
                );
                return;
            }
            Err(error) => {
                shared.set_error(
                    error_code::QPACK_DECODER_STREAM_ERROR,
                    format!("QPACK decoder stream read failed: {error}"),
                );
                return;
            }
        };
        buffer.extend_from_slice(&chunk);

        loop {
            match decode_decoder_instruction(&buffer) {
                Ok(Some((instruction, consumed))) => {
                    buffer.advance(consumed);
                    shared.apply_decoder_instruction(instruction);
                    if shared.check_error().is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    shared.set_error(
                        error_code::QPACK_DECODER_STREAM_ERROR,
                        format!("QPACK decoder stream: {error}"),
                    );
                    return;
                }
            }
        }
        if buffer.len() > 64 * 1024 {
            shared.set_error(
                error_code::QPACK_DECODER_STREAM_ERROR,
                "QPACK decoder instruction exceeds the configured limit",
            );
            return;
        }
    }
}
