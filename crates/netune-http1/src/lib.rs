//! A client-side HTTP/1.1 codec we own.
//!
//! ADR-0200 removes every third-party HTTP implementation from the production
//! path because the request trace must map *bytes* to *frames* without a foreign
//! buffer in between. This crate is that codec: it serializes a request, parses
//! a response head, and decodes the body framing — nothing else. It holds no
//! connection, no pool, no policy and no clock.
//!
//! # Scope, stated exactly
//!
//! Supported (RFC 9112, client side):
//!
//! - request line + header serialization with a length-delimited body;
//! - response status line and header parsing (case-insensitive names, duplicate
//!   headers preserved, obsolete line folding rejected);
//! - body framing: `Content-Length`, `Transfer-Encoding: chunked` (chunk
//!   extensions and trailers), close-delimited bodies, and the no-body cases
//!   (`HEAD`, `1xx`, `204`, `304`);
//! - hard limits on head size, header count and chunk size, with typed errors
//!   and no panics.
//!
//! Deliberately out of scope: HTTP/2 and above, server-side parsing, content
//! negotiation, redirects, compression, and connection pooling — those live in
//! `netune` (policy) or are simply not needed.
//!
//! # Why `http` is still a dependency
//!
//! `http` is a *data-type* crate: `Method`, `StatusCode`, `HeaderMap`. It carries
//! no parsing, no I/O and no policy, so keeping it does not put foreign
//! behaviour in the measurement path. Everything that turns bytes into state is
//! here.
//!
//! # Correctness posture
//!
//! The parser is accepted against a differential oracle (hyper) over a recorded
//! corpus, fuzzed for panics, and bounded by [`Limits`]. See
//! `tests/differential.rs`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod head;
mod reader;
mod writer;

pub use error::HttpError;
pub use head::{BodyKind, RequestHead, ResponseHead};
pub use reader::{Http1Reader, Limits};
pub use writer::write_request;
