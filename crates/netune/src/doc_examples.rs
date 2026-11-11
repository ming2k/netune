//! Compile-and-run guard for every Rust example in the documentation.
//!
//! The repository's guides are consumed by people who copy them. A guide that
//! drifts from the API is worse than no guide, and nothing about Markdown makes
//! a stale snippet fail — so this module is the mechanism: each documented
//! example is pulled out of its source document at compile time and compiled as
//! a real program.
//!
//! The mechanism is `#[doc = include_str!]`. The document is parsed as rustdoc
//! input, so its ```` ```rust ```` blocks become doctests: they are
//! type-checked, and — for blocks that are complete programs — executed.
//! Editing a guide into a state that no longer compiles is therefore a build
//! failure, not a review accident.
//!
//! Two rules make the fencing meaningful:
//!
//! - A block that must not be *run* (it dials a real host, or blocks on stdin)
//!   is annotated ```` ```rust,no_run ```` in the document itself, where a
//!   reader can see why.
//! - A block that is a fragment — a struct literal, a single call — is wrapped
//!   by the document in a function so it is still type-checked. It is never
//!   `ignore`d, because an ignored block is a block nobody checks.
//!
//! `docs/how-to/websocket-client.md` additionally has an executed transcription
//! in `tests/guide_examples.rs`. That duplication is deliberate: this module
//! proves the *text* compiles, that test proves the *behaviour* is what the
//! text says.
//!
//! Gated on `cfg(doctest)`, so this contributes nothing to a normal build.

#[doc = include_str!("../../../README.md")]
pub struct ReadmeExamples;

#[doc = include_str!("../../../docs/tutorials/getting-started.md")]
pub struct GettingStartedExamples;

#[doc = include_str!("../../../docs/how-to/configure-proxies.md")]
pub struct ProxyExamples;

#[doc = include_str!("../../../docs/how-to/configure-tls-profiles.md")]
pub struct TlsProfileExamples;

#[doc = include_str!("../../../docs/how-to/fault-injection.md")]
pub struct FaultInjectionExamples;

#[doc = include_str!("../../../docs/how-to/websocket-client.md")]
pub struct WebSocketExamples;

#[doc = include_str!("../../../docs/how-to/diagnose-failures.md")]
pub struct DiagnoseFailuresExamples;
