# Vendored h3 patch

Upstream: `h3` 0.0.8 (MIT), copied from the crates.io package already used by
the workspace. See `LICENSE` for the upstream license.

This is a **narrow, audited fork** for ADR-0023 and ADR-0026. It is linked
through `[patch.crates-io]` in the workspace root, so `h3-quinn`,
`netune-http3` and `netune-server` resolve the same package.

## Behavioural diff

1. `src/proto/headers.rs`
   - adds `RequestHeaderOrder { pseudo, regular }`;
   - adds `Header::request_with_order`;
   - makes `HeaderIter` emit pseudo-headers in the selected order, then regular
     headers in the selected order, with unlisted fields stable-appended;
   - the default order preserves upstream behaviour.
2. `src/client/connection.rs`
   - adds `SendRequest::send_request_with_order`;
   - `send_request` delegates with the default order;
   - request head blocks are encoded by the shared dynamic QPACK encoder;
   - QPACK encoder instructions are queued for the encoder critical stream.
3. `src/server/stream.rs` and `src/connection.rs`
   - response head and request/response trailer blocks use the shared dynamic encoder;
   - receiving trailers has an asynchronous dynamic-decoder path alongside the
     compatibility stateless `poll_recv_trailers`;
   - sending trailers finishes the send side, so a peer does not wait for END_STREAM after decoding them.
4. `src/shared_state.rs`
   - owns the connection's `qpack::Encoder` and `qpack::Decoder` behind one
     short-held mutex;
   - provides decoder-instruction and encoder-instruction channels;
   - exposes `decode_headers`, which waits for missing dynamic insertions and
     sends a Section Acknowledgement after a successful decode.
5. `src/connection.rs`
   - drives both QPACK critical streams: drains outgoing instruction channels,
     reads peer encoder/decoder streams synchronously in `poll_control`, buffers
     partial instructions across QUIC chunks, bounds the buffer, and applies peer
     SETTINGS capacities to the encoder.
6. `src/config.rs` and both builders
   - add `qpack_max_table_capacity` and `qpack_blocked_streams` to `Settings`;
   - emit and parse both SETTINGS parameters;
   - expose matching builder methods.
7. `src/qpack/{encoder,decoder}.rs`
   - expose the existing dynamic encoder/decoder, capacity setters and
     `encode_with_size` (required reference plus header-section memory size).
8. `src/quic.rs`
   - requires `OpenStreams::SendStream: SendStreamUnframed` so QPACK instruction
     bytes can be written without HTTP frame headers.
9. `src/client/stream.rs`, `src/server/request.rs` and `src/server/stream.rs`
   - response/request head and trailer decoding uses `SharedState::decode_headers`;
   - stream identity is carried into the decoder for acknowledgements.
10. `src/error/error.rs`
    - adds `StreamError::is_connection_error` so the server adapter can tell a
      stream-local refusal from a connection-fatal one.
11. `src/lib.rs`
    - re-exports `RequestHeaderOrder`;
    - gates upstream integration tests behind `upstream-tests` because their
      `../../../h3-quinn` relative import is not present in this layout.
12. `Cargo.toml`
    - adds the `upstream-tests` feature (off by default);
    - adds the empty `[workspace]` table so the fork can be tested with
      `--manifest-path` without becoming a workspace member.

No change is made to QUIC ownership, the H3 frame loop, control-stream
semantics, response semantics or error types.

## Upgrade procedure

1. Copy the new upstream `h3` source over this directory.
2. Re-apply the diffs above.
3. Run:
   - `cargo test --manifest-path vendor/h3/Cargo.toml`
   - `cargo test -p netune-http3 --all-features`
   - `cargo test -p netune-server --all-features --test http3_ingress`
4. If upstream exposes native header-order and QPACK-stream hooks, delete this
   fork and remove the `[patch.crates-io]` entry; keep the public
   `netune-http3` profile types.

## Why not a full owned H3/QPACK implementation

The control points are pre-QPACK request-header order and dynamic-table
connection state. The fork finishes the dynamic encoder/decoder wiring already
present upstream; it does not duplicate the H3 state machine, QUIC integration,
frame loop or error model. A full owned H3 implementation is a separate
capability and is not required to make the current surfaces enforceable.
