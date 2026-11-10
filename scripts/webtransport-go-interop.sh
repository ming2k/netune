#!/usr/bin/env bash
# Independent non-Rust WebTransport interop gate (ADR-0037, Gate 4).
#
# The Go peer is quic-go/webtransport-go, an implementation independent of the
# Rust workspace. It exercises a bidirectional stream, a unidirectional stream
# and a datagram in both directions against `netune-webtransport`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

cargo build --quiet -p netune-webtransport --example interop_server
"$ROOT/target/debug/examples/interop_server" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 100); do
    grep -q '^PORT=' "$TMP/server.log" && break
    sleep 0.1
done
PORT="$(sed -n 's/^PORT=//p' "$TMP/server.log" | head -1)"
if [[ -z "$PORT" ]]; then
    echo "WebTransport interop origin did not publish a port" >&2
    cat "$TMP/server.log" >&2
    exit 1
fi

(
    cd "$ROOT/interop/webtransport-go"
    timeout 120 go run . "https://127.0.0.1:${PORT}/interop"
) | tee "$TMP/client.log"

for expected in \
    'STATUS=200' \
    'GOT=pong from netune' \
    'UNI=pong uni from netune' \
    'DATAGRAM=pong datagram from netune'; do
    if ! grep -Fq "$expected" "$TMP/client.log"; then
        echo "missing Go interop result: $expected" >&2
        cat "$TMP/server.log" >&2
        exit 1
    fi
done

wait "$SERVER_PID"
SERVER_PID=""
for expected in \
    'GOT=hello from go' \
    'UNI=hello uni from go' \
    'DATAGRAM=hello datagram from go'; do
    if ! grep -Fq "$expected" "$TMP/server.log"; then
        echo "missing origin interop result: $expected" >&2
        cat "$TMP/server.log" >&2
        exit 1
    fi
done

echo "WebTransport Go interop: ok"
