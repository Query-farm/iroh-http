# query-farm-iroh-http-core

Query Farm's maintained packaging of `iroh-http-core`, based on Momics
`iroh-http` 0.6.2.

This package adds a reusable `ConnectionServeRuntime` for serving HTTP on Iroh
connections that were accepted and ALPN-routed by an external router. It also
provides typed authenticated endpoint identity, shared connection admission,
streaming request-body idle protection, and graceful connection draining.

It does not define a Query Farm or VGI wire protocol. Existing Rust source can
retain the conventional crate name with a dependency alias:

```toml
iroh-http-core = { package = "query-farm-iroh-http-core", version = "0.6.3" }
```

The source repository preserves the upstream history and license. The
connection-serving changes are intentionally general-purpose and suitable for
upstreaming.

Runs HTTP/1.1 over [Iroh](https://iroh.computer) QUIC bidirectional streams via
[hyper](https://hyper.rs). Nodes are addressed by Ed25519 public key.

This is the runtime-independent Rust API and transport engine. JavaScript
application developers should normally use the upstream higher-level adapters:

- **Node.js** → [`@momics/iroh-http-node`](https://www.npmjs.com/package/@momics/iroh-http-node)
- **Deno** → [`@momics/iroh-http-deno`](https://jsr.io/@momics/iroh-http-deno)
- **Tauri** → [`@momics/iroh-http-tauri`](https://www.npmjs.com/package/@momics/iroh-http-tauri)

## Usage

```rust
use std::convert::Infallible;

use iroh_http_core::{serve, Body, IrohEndpoint, NodeOptions, ServeOptions};
use tower::service_fn;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint = IrohEndpoint::bind(NodeOptions::default()).await?;
    println!("Node ID: {}", endpoint.node_id());

    let handle = serve(
        endpoint.clone(),
        ServeOptions::default(),
        service_fn(|request| async move {
            let body = format!("hello from {}", request.uri().path());
            Ok::<_, Infallible>(hyper::Response::new(Body::full(body)))
        }),
    );

    handle.drain().await;
    Ok(())
}
```

## Features

- **Externally routed connections**: serve an already-negotiated Iroh
  connection after a shared router selects the ALPN
- **Typed peer identity**: attach the authenticated `EndpointId` to requests
- **Connection reuse**: pool and multiplex QUIC connections to the same peer
- **Streaming bodies**: forward request and response bodies with backpressure
- **Progress timeouts**: protect request heads and stalled bodies independently
  of optional application execution deadlines
- **Optional body ceilings**: configure coarse wire and decoded byte limits
  without imposing a hidden default maximum
- **Fetch cancellation**: abort in-flight requests via cancellation tokens
- **Bidirectional streams**: full-duplex streaming via QUIC bidi streams
- **Trailer support**: HTTP/1.1 chunked trailers for streaming metadata
- **Runtime-opt-in compression**: zstd request/response compression is compiled
  in and enabled per node through `NodeOptions`

## License

`MIT OR Apache-2.0`
