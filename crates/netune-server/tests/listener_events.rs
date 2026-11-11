//! Listener-scoped events are visible even when no connection trace exists.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use netune_server::{CollectingListenerObserver, ListenerEvent, ServerConfig};

#[tokio::test(flavor = "multi_thread")]
async fn a_bound_listener_and_a_drain_are_recorded() {
    let observer = Arc::new(CollectingListenerObserver::new(32));
    let config = ServerConfig::for_tests().with_listener_sink(Arc::clone(&observer) as _);
    let server = support::server_with(config, Arc::new(support::Echo)).await;
    let address = server.local_addr();
    let (shutdown, wait) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = wait.await;
            })
            .await;
    });

    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("drained")
        .expect("no panic");

    let events = observer.take();
    assert!(
        events.iter().any(|event| matches!(
            event,
            ListenerEvent::Bound { local, .. } if *local == address
        )),
        "the bound address is recorded: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, ListenerEvent::DrainStarted { .. })),
        "the drain start is recorded: {events:?}"
    );
}
