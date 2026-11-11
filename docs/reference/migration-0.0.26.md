# Migrating to 0.0.26

`0.0.26` is a deliberate breaking release. The diagnostic model is now part of the trace, and failure boundaries carry evidence. There is no compatibility shim. `0.0.27` is a documentation-only correction and keeps the same API.

## Trace envelope

`RequestTrace` no longer has a bare `id`:

```rust
// 0.0.25
let id = &trace.id;

// 0.0.26
let id = &trace.meta.id;
let diagnostics = &trace.diagnostics;
```

`RequestTrace` and `IngressTrace` now carry `TraceMeta` and `DiagnosticTable`. `TRACE_SCHEMA_VERSION` is `2`; v1 traces are not silently reinterpreted.

## Sink contract

`TraceSink` v2:

```rust
trait TraceSink {
    fn trace_started(&self, meta: &TraceMeta) {}
    fn event(&self, meta: &TraceMeta, event: Event) -> Flow;
    fn trace_finished(&self, meta: &TraceMeta, summary: &TraceSummary) {}
}
```

A v1 sink that only implemented `event(Event)` must add the envelope parameter and may implement the lifecycle methods. The envelope is what lets one sink serve egress and ingress without flattening the record.

## Failure boundary

`netune` request methods return `AttemptError`, not `NetError`:

```rust
match client.request_traced(&target, head, None, config).await {
    Ok(response) => { /* ... */ }
    Err(error) => {
        let code = error.diagnostic().code;
        let trace = error.trace();
        let diagnosis = error.diagnosis();
        // ... attach the evidence
    }
}
```

`AttemptError` dereferences to `NetError`, so `class()`, `is_retryable()` and `is_stale_connection()` still work. Pattern matches must use `error.error()` or `*error` where a `NetError` value is required.

`H3Client::connect*` and `H3Client::execute` return `H3AttemptError` with the same `error()` / `trace()` / `diagnostic()` / `diagnosis()` shape.

## Server error constants

The public `netune_server::ERROR_*` constants are removed. Use the stable registry:

```rust
use netune_trace::DiagnosticCode;

assert_eq!(error.code, DiagnosticCode::SERVER_HANDLER_TIMEOUT);
```

## Configuration

- `ServerConfig` gains `listener_sink` and `trace_propagation`; use
  `with_listener_sink` and `with_trace_propagation`.
- `TraceConfig` gains `propagation`; use `with_propagation`.
- `IngressTrace` gains `meta` and `diagnostics`.

## Bundles

`netune-diagnostics` is the presentation leaf. Its default redaction is
production-safe (public fields/text only); use `RedactionPolicy::internal()` for
a local investigation. `netune-diagnose inspect|diff` reads the resulting bundle
offline.
