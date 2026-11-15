//! Failure evidence survives the observation tier.
//!
//! The point of these tests is not that a refused connection is interesting. It
//! is that the public failure boundary returns a registered diagnostic and a
//! trace id even when the caller selected `Observation::Off`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use http::Method;
use netune::{
    AttemptError, Client, ClientConfig, Observation, Pool, RequestHead, Target, TcpConnector,
    TraceConfig,
};
use netune_trace::Outcome;

fn expect_failure(result: Result<netune::Response, AttemptError>) -> AttemptError {
    match result {
        Ok(_) => panic!("the port is closed, so the attempt must fail"),
        Err(error) => error,
    }
}

fn closed_address() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
    let address = listener.local_addr().expect("local address");
    drop(listener);
    address.to_string()
}

#[tokio::test]
async fn a_failed_untraced_attempt_still_returns_evidence() {
    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(closed_address());
    let error = expect_failure(
        client
            .request_untraced(&target, RequestHead::new(Method::GET, "/"), None)
            .await,
    );

    assert_eq!(
        error.diagnostic().code,
        netune_trace::DiagnosticCode::EGRESS_TCP_FAILED
    );
    assert!(!error.trace().diagnostics.is_empty());
    assert!(
        error.trace().log.is_empty(),
        "Off records no event timeline"
    );
    assert_eq!(error.diagnosis().outcome, Outcome::Failed);
    assert!(!error.diagnosis().render_text().is_empty());
}

#[tokio::test]
async fn a_failed_traced_attempt_returns_its_timeline_and_diagnosis() {
    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(closed_address());
    let error = expect_failure(
        client
            .request_traced(
                &target,
                RequestHead::new(Method::GET, "/"),
                None,
                TraceConfig::new(64),
            )
            .await,
    );

    assert!(error.diagnostic().code.is_registered());
    assert!(!error.trace().diagnostics.is_empty());
    assert!(
        !error.trace().log.is_empty(),
        "Traced keeps the dispatch origin even when connect fails"
    );
    assert_eq!(error.diagnosis().outcome, Outcome::Failed);
}

#[tokio::test]
async fn a_configuration_failure_has_a_trace_id() {
    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let target = Target::plain(closed_address());
    let error = expect_failure(
        client
            .send(
                &target,
                RequestHead::new(Method::GET, "/"),
                None,
                Observation::Off,
            )
            .await,
    );
    assert!(!error.trace().meta.id.as_str().is_empty());
    assert_eq!(
        error.trace().meta.direction,
        netune_trace::Direction::Egress
    );
}
