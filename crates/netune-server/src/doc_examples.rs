//! Compile-and-run guard for every Rust example in the ingress documentation.
//!
//! `netune-server` is the peer orchestrator to `netune`, so its guides live in their
//! own crate: a `netune` doctest that pulled in `docs/how-to/serve-http.md` would
//! need `netune-server` as a dev-dependency, which is the inversion
//! `[INV-SERVER-01]` forbids and the reason `crates/netune-server/tests/interop.rs`
//! is the only suite allowed to see both.
//!
//! The mechanism is the same one `netune` uses, and for the same reason: a guide is
//! consumed by people who copy it, so a snippet that no longer compiles must fail the
//! build rather than mislead a reader.
//!
//! Two rules make the fencing meaningful:
//!
//! - A block that must not be *run* (it would block on a real signal, or bind a fixed
//!   port) is annotated ```` ```rust,no_run ```` in the document itself, where a
//!   reader can see why.
//! - A block that is a fragment is wrapped by the document in a function so it is
//!   still type-checked. It is never `ignore`d, because an ignored block is a block
//!   nobody checks.
//!
//! `crates/netune-server/tests/guide_examples.rs` additionally *executes* verbatim
//! transcriptions and asserts the behavioural claims. That duplication is deliberate:
//! this module proves the text compiles, that suite proves the text is true.
//!
//! Gated on `cfg(doctest)`, so this contributes nothing to a normal build.

#[doc = include_str!("../../../docs/how-to/serve-http.md")]
pub struct ServeHttp1Examples;

#[doc = include_str!("../../../docs/explanation/two-orchestrators.md")]
pub struct TwoOrchestratorsExamples;
