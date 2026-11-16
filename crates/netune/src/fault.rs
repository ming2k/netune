//! Byte-level fault injection on real connections.
//!
//! [`FaultConnector`] wraps another [`Connector`] and runs every stream it
//! establishes through a [`FaultIo`] with a per-connection [`FaultScript`]:
//! delays, split reads, truncation and resets at chosen byte offsets. Where
//! it sits in the connector stack decides what the offsets count:
//!
//! ```text
//! FaultConnector(TlsRouterConnector(TcpConnector))   faults on decrypted bytes
//! TlsRouterConnector(FaultConnector(TcpConnector))   faults on the TLS records
//! ```
//!
//! This is the complement of [`crate::mock::Mock`]. A mock scripts *what the
//! peer answers*; a fault script disturbs *how the bytes arrive* while a real
//! peer and the real codecs do the talking.

use std::sync::{Arc, Mutex};

use netune_io::{FaultIo, FaultScript};
use netune_trace::TraceCollector;

use crate::connect::{Connector, Established, Target};
use crate::error::NetError;

type ScriptFor = Arc<dyn Fn(&Target) -> FaultScript + Send + Sync>;

/// A connector whose streams misbehave on a script.
pub struct FaultConnector<C: Connector> {
    inner: C,
    script_for: ScriptFor,
}

impl<C: Connector> FaultConnector<C> {
    /// Wrap `inner`; `script_for` is called once per established connection
    /// and returns the faults that connection's reads will suffer. Return
    /// [`FaultScript::empty`] to leave a connection undisturbed.
    pub fn new(
        inner: C,
        script_for: impl Fn(&Target) -> FaultScript + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner,
            script_for: Arc::new(script_for),
        }
    }
}

impl<C: Connector> Connector for FaultConnector<C> {
    fn socket_shape(&self) -> Option<String> {
        self.inner.socket_shape()
    }

    fn route_shape(&self) -> Option<String> {
        self.inner.route_shape()
    }

    fn egress_confinement(&self) -> Option<crate::connect::EgressConfinement> {
        self.inner.egress_confinement()
    }

    async fn connect(
        &self,
        target: &Target,
        recorder: &TraceCollector,
    ) -> Result<Established, NetError> {
        let mut established = self.inner.connect(target, recorder).await?;
        let script = Arc::new(Mutex::new((self.script_for)(target)));
        established.stream = Box::new(FaultIo::new(established.stream, script));
        Ok(established)
    }
}
