# WebTransport Browser Interoperability

WebTransport is **Experimental** until at least two independent browser engines
pass a pinned interoperability matrix. This page records the matrix, the
harness contract, and the current blocking evidence. It is not a stability
claim.

---

## 1. Pinned matrix

Browsers are pinned by exact version; "latest" is not a gate.

| Engine | Browser | Version | WT draft observed | reset_stream_at | Extended CONNECT | Datagrams | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Chromium | Chrome/Edge | 157.0.8103.78 | draft-02 legacy setting | no | — | — | **blocked** |
| Firefox | Firefox | not installed | — | — | — | — | not run |
| WebKit | Safari/WebKitGTK | not installed | — | — | — | — | not run |

A browser that does not advertise `reset_stream_at` is not a draft-17
WebTransport peer. The server must reject it with a typed settings error, which
is what `WebTransportClient` / `WebTransportServer` do today.

---

## 2. Harness contract

The browser harness must be executable, not a checked-in screenshot:

1. Start a local `netune-webtransport` server over QUIC/H3 with a test
   certificate.
2. Serve a secure-context HTML page from a TLS listener that advertises the
   WebTransport endpoint (Alt-Svc or a direct H3 URL).
3. Launch each pinned browser through Playwright with
   `ignoreHTTPSErrors` for the page and `serverCertificateHashes` for the
   WebTransport connection (or a locally trusted test CA).
4. Exercise:
   - `new WebTransport(url)`, `ready`, `closed`;
   - bidirectional streams in both directions;
   - unidirectional streams in both directions;
   - datagrams;
   - `close()` with an application error code;
   - drain / GOAWAY;
   - reliable reset (`reset_reliable` / browser equivalent);
   - concurrent streams and flow-control limits;
   - `Origin` handling.
5. Save browser console, page errors, network trace, server trace bundle and a
   screenshot on failure.
6. Fail the job if a browser is missing a pinned version; do not silently skip
   an engine.

A minimal Playwright driver:

```text
import { chromium } from "playwright";

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();
page.on("console", (message) => console.log("browser:", message.text()));
await page.goto(process.env.WT_PAGE_URL, { waitUntil: "load" });
const result = await page.evaluate(async () => {
  const wt = new WebTransport(window.WT_URL, {
    serverCertificateHashes: [
      { algorithm: "sha-256", value: window.WT_CERT_HASH },
    ],
  });
  await wt.ready;
  const stream = await wt.createBidirectionalStream();
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();
  await writer.write(new TextEncoder().encode("hello"));
  await writer.close();
  const { value } = await reader.read();
  wt.close({ closeCode: 0, reason: "done" });
  return new TextDecoder().decode(value);
});
if (result !== "hello") throw new Error(`unexpected echo: ${result}`);
```

The Rust side is an ignored `browser` test target so nextest does not attempt
to launch a browser in the default PR matrix. The CI job installs the pinned
browsers explicitly and runs that target.

---

## 3. Closing the gate

The gate closes only when:

- the matrix has at least two independent engines in `pass`, with exact
  versions;
- each browser advertises the QUIC `reset_stream_at` transport parameter;
- draft-16/draft-17 negotiation is exercised end to end;
- WPT/external differential scenarios are part of CI;
- the same matrix is green for two consecutive releases.

Until then, `netune-webtransport` stays feature-gated, Experimental, and
excluded from the default production build.
