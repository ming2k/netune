# Diagnose a Failed Request

A `netune` failure is evidence, not just an error string. The public attempt methods return an `AttemptError` that carries the original error, a real trace id, a diagnostic table, and — for traced attempts — the event timeline. This guide shows how to read it and how to preserve it for review.

## 1. Read the failure at the call site

```rust,no_run
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new(TcpConnector::new(), Pool::default(), ClientConfig::default());
let target = Target::plain("127.0.0.1:8080");
let head = RequestHead::new(Method::GET, "/health");

match client.request_untraced(&target, head, None).await {
    Ok(mut response) => {
        let body = response.body.read_to_end().await?;
        println!("status {}, {} bytes", response.head.status, body.len());
    }
    Err(error) => {
        // The code is stable; the message is context.
        let diagnostic = error.diagnostic();
        eprintln!("{}: {}", diagnostic.code, diagnostic.message);
        // `diagnose` names the phase, retry verdict and next checks.
        eprintln!("{}", error.diagnosis());
        // The trace id joins this failure to an ingress record when propagation is on.
        eprintln!("trace {}", error.trace().meta.id);
    }
}
# Ok(())
# }
```

`Observation::Off` still produces a diagnostic table. It does not produce a byte timeline; the diagnosis says so through `fidelity` and the empty log rather than pretending a missing phase was fast.

## 2. Read a traced failure

```rust,no_run
use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TraceConfig};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new(TcpConnector::new(), Pool::default(), ClientConfig::default());
let target = Target::plain("127.0.0.1:8080");
let head = RequestHead::new(Method::GET, "/health");

if let Err(error) = client
    .request_traced(&target, head, None, TraceConfig::new(4096))
    .await
{
    let diagnosis = error.diagnosis();
    println!("outcome: {:?}", diagnosis.outcome);
    println!("terminal: {:?}", diagnosis.terminal);
    println!("last phase: {:?}", diagnosis.last_phase);
    println!("dropped events: {}", diagnosis.dropped_events);
}
# Ok(())
# }
```

## 3. Write a review bundle

`netune-diagnostics` owns the presentation and file I/O. The transport never writes a file by itself.

```rust,no_run
use netune_diagnostics::{RedactionPolicy, TraceBundle};

# fn write(error: &netune::AttemptError) -> std::io::Result<()> {
let directory = std::path::PathBuf::from("/tmp/netune-review");
let bundle = TraceBundle::write(
    directory,
    error.trace(),
    &error.diagnosis(),
    Some("reproduced with a closed port"),
    RedactionPolicy::default(),
)?;
println!("bundle: {}", bundle.directory.display());
# Ok(())
# }
```

The bundle contains `manifest.json`, `trace.json`, `diagnosis.json`, `diagnosis.txt`, and optional `notes.md`. `RedactionPolicy::default()` is production-safe: only `Public` fields and text survive. Use `RedactionPolicy::internal()` for a local investigation where internal fields and messages are wanted; `Secret` text is removed under both policies.

## 4. Add a regression test

A bug fix starts with a failing test named for the diagnostic code, for example `diag_egress_tls_failed_keeps_the_retry_verdict`. When the failure is reproducible through `FaultIo`, assert both the error code and the recorded diagnostic. Then link the test from the postmortem action item.

## 5. What not to do

- Do not parse the `Display` string to classify a failure. Use `DiagnosticCode`.
- Do not treat an empty event log under `Observation::Off` as “nothing happened”. Read the diagnostic table.
- Do not attach a trace with secret fields. Use the bundle redaction policy.
