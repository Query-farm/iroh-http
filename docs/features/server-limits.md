# Server Limits

All resource limits are configured at **`serve(options, handler)`** and enforced
in Rust before any JavaScript handler runs. They protect the serve loop
against misbehaving or hostile peers at the transport level.

## Options

```ts
node.serve({
  /** Maximum simultaneous in-flight requests across all peers. Default: 1024. */
  maxConcurrency: 1024,

  /** Maximum simultaneous connections from a single peer. Default: 8. */
  maxConnectionsPerPeer: 8,

  /** Optional application execution timeout. Disabled by default. */
  requestTimeout: 10 * 60_000,

  /** Time allowed to receive a complete request head. Default: 15 000. */
  requestHeadTimeout: 15_000,

  /** Maximum no-progress interval while consuming a body. Default: 30 000. */
  bodyIdleTimeout: 30_000,

  /** Reject request bodies larger than this many wire (compressed) bytes,
   *  while the body is streamed. Optional and unlimited by default. */
  maxRequestBodyWireBytes: 10 * 1024 * 1024,  // 10 MB example

  /** Reject request bodies larger than this many decoded bytes (after
   *  decompression). Optional and unlimited by default. */
  maxRequestBodyDecodedBytes: 10 * 1024 * 1024,  // 10 MB example

  /** Drain timeout in ms after shutdown signal. Default: 30 000. */
  drainTimeout: 30_000,
}, handler);

// Header size is configured at node level:
const node = await createNode({
  limits: {
    /** Maximum request header block size in bytes. Default: 64 KB. */
    maxHeaderBytes: 64 * 1024,
  },
});
```

All limits are optional. Omitting a size limit leaves it unlimited; applications
should enforce and advertise their own semantic request budget.

## Why at the Rust layer

These limits intercept bytes or connections before they reach the FFI
boundary. A JS handler never runs for a rejected request, so no user code
needs to handle the overflow cases.

Bodies are streamed with backpressure and are not accumulated by the HTTP
runtime. A total body limit is therefore a coarse application or transport
ceiling, not the primary memory bound. The body-idle timeout and concurrency
limits protect finite transport resources while preserving large streaming
requests.

Request bodies are capped by two independent limits. `maxRequestBodyWireBytes`
bounds the **wire** (compressed) size: a declared `Content-Length` larger than
the limit is rejected up front (before the body is read), and the wire stream
is capped as bytes arrive so a chunked upload that omits or understates
`Content-Length` still stops at the limit. `maxRequestBodyDecodedBytes` bounds
the **decoded** size (after decompression), so a small compressed payload that
inflates past the limit once decompressed is stopped as it expands. Both
surface the same `413`; the decoded cap is what protects against
compression bombs.

## What each limit protects against

| Option | Attack vector | Behavior |
|---|---|---|
| `maxConcurrency` | Request flood from many peers | Excess requests are rejected with 503 when load shedding is enabled |
| `maxConnectionsPerPeer` | Connection flood from one peer | Excess connections are closed at the QUIC level (transport close, not an HTTP response) |
| `requestHeadTimeout` | Incomplete or trickled request head | Stream is closed |
| `bodyIdleTimeout` | Stalled body while it is being consumed | Body fails and the stream is closed |
| `requestTimeout` | Application execution exceeding an explicit operator deadline | 408 Request Timeout |
| `maxRequestBodyWireBytes` | Oversized/compressed body exhausting bandwidth | 413 Content Too Large |
| `maxRequestBodyDecodedBytes` | Compression bomb exhausting memory | 413 Content Too Large |
| `maxHeaderBytes` | Header flood exhausting memory | 431 Request Header Fields Too Large |
