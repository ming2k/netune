# Mock Requests at the Request Seam

This guide shows how to drive `netune::Client` against `netune::mock::Mock` so redirect chains, retry policies, timeouts, streaming decoders, and error traces are tested in-process without opening a socket.

`Client` is protocol-neutral over [`RoundTrip`](../adr/0050-request-level-exchange-seam-and-mock-transport.md): switching between `Wire` (real connections) and `Mock` keeps the exact same request planning, body decoding, trace recording, and error handling.

---

## Script one-shot and standing routes

Mount a `Mock` with `Client::with_transport`, match requests by method, path, header, or predicate, and inspect what reached the mock via `mock.calls()`:

```rust
use http::{Method, StatusCode};
use netune::{Client, ClientConfig, RequestHead, Target};
use netune::mock::{Matcher, Mock, MockResponse};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let mock = Mock::new();
mock.on(Matcher::get("/v1/models"))
    .reply_once(MockResponse::new(StatusCode::SERVICE_UNAVAILABLE))
    .reply(MockResponse::ok(r#"{"models":["m1"]}"#));

let client = Client::with_transport(mock.clone(), ClientConfig::default());
let target = Target::plain("api.example:80");

let first = client
    .request(&target, RequestHead::new(Method::GET, "/v1/models"), None)
    .await?;
assert_eq!(first.head.status, StatusCode::SERVICE_UNAVAILABLE);

let mut second = client
    .request(&target, RequestHead::new(Method::GET, "/v1/models"), None)
    .await?;
assert_eq!(second.head.status, StatusCode::OK);
assert_eq!(second.body.read_to_end().await?.as_ref(), br#"{"models":["m1"]}"#);
assert_eq!(mock.hits(&Matcher::get("/v1/models")), 2);
# Ok(())
# }
```

---

## Script delays, chunks, and mid-stream failures

Use `MockResponse::chunks`, `delay_head`, `delay_chunks`, `fail_before_head`, and `fail_after_chunks` to test `response_head_timeout`, `body_idle_timeout`, and terminal body trace preservation without sleep races or real TCP resets:

```rust
use std::io::ErrorKind;
use std::time::Duration;
use http::Method;
use netune::{Client, ClientConfig, RequestHead, Target, TraceConfig};
use netune::mock::{Matcher, Mock, MockResponse};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let mock = Mock::new();
mock.on(Matcher::get("/stream"))
    .reply(
        MockResponse::ok("")
            .chunks(["part-1-", "part-2"])
            .delay_chunks(Duration::from_millis(5))
            .fail_after_chunks(1, ErrorKind::ConnectionReset),
    );

let client = Client::with_transport(mock, ClientConfig::default());
let target = Target::plain("api.example:80");
let mut response = client
    .request_traced(
        &target,
        RequestHead::new(Method::GET, "/stream"),
        None,
        TraceConfig::default(),
    )
    .await?;

let err = response
    .body
    .read_to_end()
    .await
    .expect_err("mid-stream fault surfaces");
assert_eq!(err.io_error_kind(), Some(ErrorKind::ConnectionReset));
assert!(response.body.trace().is_some(), "trace survives stream failure");
# Ok(())
# }
```

---

## Fall back to the real wire for unmatched routes

Attach `Wire::new(...)` via `Mock::fallback` so only mocked paths are intercepted and everything else dials real connections:

```rust,no_run
use netune::{Client, ClientConfig, Pool, TcpConnector, Wire};
use netune::mock::{Matcher, Mock, MockResponse};

# fn build() -> Client {
let mock = Mock::new();
mock.on(Matcher::get("/healthz"))
    .reply(MockResponse::ok("ok"));
mock.fallback(Wire::new(TcpConnector::new(), Pool::default()));

Client::with_transport(mock, ClientConfig::default())
# }
```
