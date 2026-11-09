// SPDX-License-Identifier: MIT

//! Client-side QUIC session metadata for 0-RTT.
//!
//! TLS tickets are owned by rustls' resumption store. This cache holds the
//! adjacent QUIC transport parameters a client needs before the handshake:
//! stream limits, receive windows and datagram capability. It is keyed by the
//! server name that produced the authenticated session.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::wire::transport_parameters::TransportParameters;

#[derive(Clone, Default)]
pub struct SessionCache {
    entries: Arc<Mutex<HashMap<String, TransportParameters>>>,
}

impl std::fmt::Debug for SessionCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionCache")
            .field(
                "entries",
                &self
                    .entries
                    .lock()
                    .map(|entries| entries.len())
                    .unwrap_or(0),
            )
            .finish()
    }
}

impl SessionCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, server_name: &str) -> Option<TransportParameters> {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(server_name)
            .cloned()
    }

    pub(crate) fn insert(&self, server_name: &str, parameters: TransportParameters) {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(server_name.to_string(), parameters);
    }
}
