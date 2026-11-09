// SPDX-License-Identifier: MIT

//! The owned HTTP/3 connection machine and its per-stream adapters.

mod driver;
mod shared;
mod stream;

use std::sync::Arc;

use bytes::BytesMut;
use netune_quic::owned::{Connection as QuicConnection, RecvStream, SendStream};
use tokio::sync::mpsc;

use crate::error::H3Error;
use crate::profile::H3SettingsProfile;
use crate::proto::code::stream_type;
use crate::proto::frame;
use crate::proto::varint;

pub(crate) use shared::Shared;
pub(crate) use stream::H3Stream;

/// Which side of the H3 connection this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// A server-accepted request stream.
pub(crate) struct IncomingBi {
    pub send: SendStream,
    pub recv: RecvStream,
    pub id: u64,
}

/// A started HTTP/3 connection: shared state plus the driver task.
pub(crate) struct Connection {
    shared: Arc<Shared>,
    driver: tokio::task::JoinHandle<()>,
    incoming: Option<mpsc::Receiver<IncomingBi>>,
}

impl Connection {
    /// Open the critical streams, send SETTINGS, and start the driver.
    pub async fn start(
        quic: QuicConnection,
        settings: &H3SettingsProfile,
        role: Role,
    ) -> Result<Self, H3Error> {
        settings
            .validate()
            .map_err(|reason| H3Error::Profile(reason.to_string()))?;

        let mut control_send = quic
            .open_uni()
            .await
            .map_err(|error| H3Error::H3(format!("open control stream: {error}")))?;
        let mut encoder_send = quic
            .open_uni()
            .await
            .map_err(|error| H3Error::H3(format!("open QPACK encoder stream: {error}")))?;
        let mut decoder_send = quic
            .open_uni()
            .await
            .map_err(|error| H3Error::H3(format!("open QPACK decoder stream: {error}")))?;

        write_stream_type(&mut control_send, stream_type::CONTROL).await?;
        frame::write_settings(&mut control_send, &settings.to_settings()).await?;
        write_stream_type(&mut encoder_send, stream_type::QPACK_ENCODER).await?;
        write_stream_type(&mut decoder_send, stream_type::QPACK_DECODER).await?;

        let (encoder_tx, encoder_rx) = mpsc::unbounded_channel();
        let (decoder_tx, decoder_rx) = mpsc::unbounded_channel();
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (incoming_tx, incoming_rx) = if role == Role::Server {
            let (tx, rx) = mpsc::channel(32);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let shared = Arc::new(Shared::new(
            quic, settings, encoder_tx, decoder_tx, control_tx,
        )?);
        let driver = tokio::spawn(driver::drive(
            shared.clone(),
            driver::CriticalStreams {
                control: control_send,
                encoder: encoder_send,
                decoder: decoder_send,
            },
            driver::DriverChannels {
                control: control_rx,
                encoder: encoder_rx,
                decoder: decoder_rx,
            },
            incoming_tx,
        ));

        Ok(Self {
            shared,
            driver,
            incoming: incoming_rx,
        })
    }

    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Open a request stream and wrap it in the H3 stream state machine.
    pub async fn open_bi(&self) -> Result<H3Stream, H3Error> {
        self.shared.check_error()?;
        if self.shared.goaway().is_some() {
            return Err(H3Error::H3("connection received GOAWAY".to_string()));
        }
        let (send, recv) = self
            .shared
            .connection
            .open_bi()
            .await
            .map_err(|error| H3Error::H3(format!("open request stream: {error}")))?;
        let id = send.id();
        Ok(H3Stream::new(self.shared.clone(), id, send, recv))
    }

    /// Wait for the next server-accepted request stream.
    pub async fn next_incoming(&mut self) -> Result<Option<IncomingBi>, H3Error> {
        let Some(incoming) = self.incoming.as_mut() else {
            return Err(H3Error::H3(
                "next_incoming is only available on a server connection".to_string(),
            ));
        };
        self.shared.check_error()?;
        Ok(incoming.recv().await)
    }

    pub fn send_goaway(&self, stream_id: u64) {
        self.shared.send_goaway(stream_id);
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

async fn write_stream_type(send: &mut SendStream, stream_type: u64) -> Result<(), H3Error> {
    let mut header = BytesMut::new();
    varint::encode(&mut header, stream_type)
        .map_err(|_| H3Error::H3("invalid stream type".to_string()))?;
    send.write_all(&header)
        .await
        .map_err(|error| H3Error::H3(format!("write stream type: {error}")))
}
