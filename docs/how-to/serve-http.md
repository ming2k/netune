# Serve HTTP/1.1 and HTTP/2

This guide builds an origin that answers both protocols behind one handler, streams a response, bounds
what a hostile peer can cost, and reports a per-exchange trace an operator can actually read.

The decision behind it is [ADR-0011](../adr/0011-server-side-ingress-transport.md) (ingress is its own
orchestrator) plus [ADR-0012](../adr/0012-http2-ingress.md) (one connection machine, two roles),
[ADR-0013](../adr/0013-response-writer-state-machine.md) (a response is a state machine) and
[ADR-0014](../adr/0014-request-validation-before-dispatch.md) (framing is validated before dispatch).

---

## 1. The smallest origin that is not a demo

```rust
use std::sync::Arc;

use netune_server::{Handler, HandlerFuture, RequestBody, Response, Server, ServerConfig};
use netune_server::IncomingRequest;

struct Echo;

impl Handler for Echo {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        mut body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            let bytes = body.read_to_end().await.unwrap_or_default();
            Response::ok(bytes)
        })
    }
}

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let server = Server::bind("127.0.0.1:0", ServerConfig::default(), Arc::new(Echo)).await?;
server.serve(async {}).await;
# Ok(())
# }
```

Two things are worth noticing before anything else:

- **There is no routing here, and that is deliberate.** A transport that decides which path maps to
  which function is a framework, and this crate is not one. `request.target_str()` is the bytes the peer
  sent, unmodified.
- **`ServerConfig::default()` is sized for a public port**, not for a laptop: 512 connections, 16 KiB
  heads, 64 headers, four separate phase timeouts, a 1 000-request reuse quota. See
  [§4](#4-the-bounds-and-what-each-one-stops) for what each one stops.

---

## 2. Both protocols, one handler

`ServerConfig::protocols` defaults to `Protocols::BOTH`. A connection is classified from its first
bytes — `PRI *` means prior-knowledge HTTP/2, anything else is HTTP/1.1 — and a TLS terminator in front
of the listener uses `Protocols::alpn()` to negotiate `h2`/`http/1.1` in that preference order.

```rust
use netune_server::{Protocols, ServerConfig};

// The default: both, with h2 preferred when ALPN is in play.
let both = ServerConfig::default().with_protocols(Protocols::BOTH);

// An internal health endpoint that must stay trivially debuggable.
let http1_only = ServerConfig::default().with_protocols(Protocols::HTTP1);
# let _ = (both, http1_only);
```

There is no in-place upgrade. A client that opens with the HTTP/2 preface against an
`HTTP1`-only listener gets `505 HTTP Version Not Supported` and a closed socket, rather than a silent
downgrade it cannot detect. That is `[INV-SERVER-09]`.

The handler does not know which protocol it is serving, and it does not need to. The request it
receives carries the same method, target, headers and body framing either way, and
`:authority`-without-`Host` (HTTP/2) and `Host`-without-`:authority` (HTTP/1.1) are translated so one
field always names the authority.

---

## 2.1 Terminating TLS

Without TLS the listener speaks HTTP directly; with it, the handshake happens inside the same
connection pipeline — same admission control, same drain, same trace. Turn the feature on to use it:

```toml
netune-server = { git = "https://github.com/ming2k/netune", tag = "v0.0.13", features = ["tls"] }
```

```rust
# #[cfg(feature = "tls")]
# mod __tls_example {
use std::sync::Arc;

use netune_server::{Protocols, ServerConfig, TlsTermination};

# fn build(config: Arc<tokio_rustls::rustls::ServerConfig>) -> ServerConfig {
// One certificate for every name.
let single = TlsTermination::single(Arc::clone(&config));

// Or one per SNI name, with a required fallback for a peer that sends none (an IP address, an old
// client). Serving the wrong certificate for a name is a silent security failure, which is why the
// selection is by name rather than by "whatever was configured first".
let per_name = TlsTermination::per_name(
    vec![("a.example".to_owned(), Arc::clone(&config))],
    config,
);

let config = ServerConfig::default()
    .with_protocols(Protocols::BOTH)
    .with_tls(single);
# config
# }
# }
```

Four things are true because the handshake is ours, and none of them are true of a fronting proxy:

- **The handshake is a recorded fact.** `IngressTlsEnd` is written when it completes and an `Error`
  carrying `ERROR_TLS_HANDSHAKE` when it fails, so a derivation separates "the identity cost this"
  from "the client was slow to speak" (`[INV-SERVER-18]`).
- **ALPN decides the protocol, once.** `h2` in the handshake means HTTP/2; anything else is HTTP/1.1;
  the HTTP/2 preface is still read inside the tunnel. No upgrade path exists (`[INV-SERVER-09]`).
- **A handshake is bounded by `head_timeout`.** Opening a socket and never speaking is the cheapest
  attack on a TLS listener, and nothing about a handshake is application code, so nothing else would
  bound it (`[INV-SERVER-20]`).
- **A mismatch is caught at bind time.** If the TLS configuration does not advertise every protocol
  `protocols` claims, `Server::bind` refuses, because that listener would negotiate something it then
  rejects on every connection (`[INV-SERVER-21]`).

`Protocols::alpn()` is the list to put in a *different* terminator's configuration if you choose to run
one; the rules above are what you give up by doing so.

---

## 3. A response that streams

`Response::stream` takes any `tokio::sync::mpsc::Receiver<Bytes>`, or any type implementing
`BodyStream`. The transport pulls from it and writes each chunk as it arrives: chunked framing on
HTTP/1.1, `DATA` frames on HTTP/2.

```rust
use netune_server::{Handler, HandlerFuture, RequestBody, Response};
use netune_server::IncomingRequest;

struct Tokens;

impl Handler for Tokens {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        _body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                for token in ["the ", "answer ", "is ", "42"] {
                    if tx.send(bytes::Bytes::from_static(token.as_bytes())).await.is_err() {
                        // The peer went away; stop producing.
                        return;
                    }
                }
            });
            Response::stream(http::StatusCode::OK, rx)
        })
    }
}
# let _ = std::sync::Arc::new(Tokens);
```

Three properties come with it, and they are structural rather than conventional:

- **`HEAD` costs nothing.** The transport writes the head and drops the stream, and the writer refuses
  any body byte under a `HEAD` response — so a streaming endpoint answers `HEAD` without generating a
  token.
- **A status that forbids a body keeps forbidding it.** `Response::stream(204, rx)` drops the stream and
  sends a head-only message, because a byte under `204` becomes the next response's status line.
- **The terminator is written once, by the writer.** A zero-length chunk from a handler is a no-op, not
  an early end of body.

---

## 4. The bounds, and what each one stops

```rust
use std::time::Duration;
use netune_server::{H2Ingress, ServerConfig};

let config = ServerConfig::default()
    .with_max_connections(2_000)                       // burst → shed, not OOM
    .with_max_requests_per_connection(200)             // keep-alive is not forever
    .with_head_timeout(Duration::from_secs(5))         // slow loris
    .with_body_timeout(Duration::from_secs(30))        // slow upload
    .with_handler_timeout(Duration::from_secs(60))     // a handler that never returns
    .with_write_timeout(Duration::from_secs(15))       // a peer that stops reading
    .with_http2(H2Ingress::for_ingress());             // h2 SETTINGS, advertised and enforced
# let _ = config;
```

| Bound | Stops | Answers with |
| :--- | :--- | :--- |
| `max_connections` | a burst turning one listener into an OOM | immediate close (shedding is explicit) |
| `max_requests_per_connection` | one client pinning a slot forever | `Connection: close` on the last response |
| `head_timeout` | slow loris (open, then whisper) | `408` where it can be written |
| `body_timeout` | slow upload holding a worker | connection close |
| `handler_timeout` | an application bug that never returns | `500`, connection closed |
| `write_timeout` | slow *read*: a peer that opens its window a byte at a time | connection close |
| `write_timeout` (again) | a streaming handler that returns and then never produces a chunk | connection close |
| `limits.max_body_bytes` | a body larger than the operator granted | `413`, or the codec's limit error |

`max_body_bytes` is cumulative across every `next_chunk`, and a declared `Content-Length` beyond it is
refused **before** the first body byte is read — so a peer cannot make the server read toward a size the
operator never granted (`[INV-SERVER-15]`). A handler that wants a tighter ceiling than the transport's
says so itself:

```rust
use netune_server::{Handler, HandlerFuture, RequestBody, Response};
use netune_server::IncomingRequest;

struct SmallJson;

impl Handler for SmallJson {
    fn handle<'a>(
        &'a self,
        _request: IncomingRequest,
        mut body: RequestBody<'a>,
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            match body.read_to_end_within(64 * 1024).await {
                Ok(bytes) => Response::ok(bytes),
                Err(_) => Response::content_too_large(),
            }
        })
    }
}
# let _ = SmallJson;
```

---

## 5. What never reaches a handler

Four classes of request are refused before application code runs, each with a status line rather than a
reset socket (`[INV-SERVER-14]`, `[INV-SERVER-16]`):

| Request | Refused because | Status |
| :--- | :--- | :--- |
| `GET /a b HTTP/1.1` | a space in a target splits three ways; there is no safe normalisation | `400` |
| `GET /page#frag` | a fragment is never sent on the wire, and it is a cache-key primitive | `400` |
| `GET /x` with no `Host` | RFC 9112 §3.2 makes it mandatory for HTTP/1.1 | `400` |
| `GET /x` with two `Host` | merging them is choosing an origin on the peer's behalf | `400` |
| `POST` with `Content-Length` and `Transfer-Encoding` | the canonical CL.TE desync | `400` |
| a line terminated by a bare LF | a hop that only knows CRLF reads the difference as payload | `400` |

`ServerConfig::with_host_requirement(false)` exists for the one legitimate case — a listener behind a
proxy that has already validated it — and is a named switch so that turning off an RFC requirement is
visible in review rather than silent.

---

## 6. What the trace tells you

Install an observer and every finished connection arrives as one `IngressTrace`, tagged with the
protocol that served it and with each event carrying its stream identity:

```rust
use std::sync::Arc;
use netune_server::{CollectingObserver, Server, ServerConfig};

# async fn run(handler: Arc<dyn netune_server::Handler>) -> Result<(), Box<dyn std::error::Error>> {
let observer = Arc::new(CollectingObserver::default());
let config = ServerConfig::default().with_trace_sink(Arc::clone(&observer) as _);
let server = Server::bind("127.0.0.1:0", config, handler).await?;
# drop(server);
// Later, for one finished connection:
for trace in observer.take() {
    println!("{} exchanges over {}", trace.exchanges, trace.protocol.label());
}
# Ok(())
# }
```

Derive the spans. A connection that served one exchange derives directly; one that served several
derives per exchange, and one that multiplexed HTTP/2 streams derives per stream rather than by
position:

```rust
use netune_trace::{RequestTrace, derive_ingress, derive_ingress_exchanges};

# fn derive(trace: &RequestTrace) {
// One exchange: every span is a number or a verdict.
let single = derive_ingress(trace);
println!("handler took {:?} µs", single.handler_us.value());

// Several exchanges on one connection, concurrent or not: one derivation each.
for exchange in derive_ingress_exchanges(trace) {
    println!("status {:?}", exchange.status.value());
}
# }
```

The distinction that matters is the one a handler-duration metric cannot make: **`handler_us` and
`write_us` separate "the handler was slow" from "the peer would not read"**, and `request_read_us`
separates both from "the client was slow to speak". Three failures, one symptom otherwise, three
different responses.

---

## 7. Boundaries to state up front

- **Not a framework.** No routing table, no extractors, no middleware, no JSON.
- **No dialing.** `netune-server` never opens an outbound connection; a handler that calls another
  service depends on `netune` from your *application*, not from this transport.
- **No client certificates, session-resumption tuning, or cipher policy.** TLS termination is here
  ([ADR-0015](../adr/0015-self-terminated-tls.md)); mTLS and resumption bounds are deployment decisions
  whose right answer depends on your client population, so this crate takes a `rustls::ServerConfig` and
  uses it as given.
- **One protocol per connection, and only the ones you offer.** `Protocols` defaults to what the build
  can serve; asking for `HTTP2` in a build without the `http2` feature fails at bind time, and a
  listener refuses any protocol it does not offer in either direction rather than downgrading.
- **No WebSocket upgrade.** The codec's server role is complete, but wiring it to a listener is its own
  decision with its own liveness questions.
- **One protocol per connection.** No `h2c` upgrade, ever.
- **Full-duplex streaming** needs the application to buffer or spawn: the transport is the only writer of
  a connection, which is what lets it enforce framing and flow control at all.

---

See the [Crates Reference](../reference/crates.md) for the full type list, or
[Two Orchestrators](../explanation/two-orchestrators.md) for why ingress is a separate crate.
