//! Incoming HTTP request — pure-Rust `serve()` implementation.
//!
//! Each accepted QUIC bidirectional stream is driven by hyper's HTTP/1.1
//! server connection. The user supplies a `tower::Service<Request<Body>,
//! Response = Response<Body>, Error = Infallible>`; the per-connection
//! `AddExtensionLayer` makes the authenticated peer id available as a
//! legacy [`RemoteNodeId`] and typed [`RemoteEndpointId`] request extensions.
//!
//! The accept loop body lives in [`accept`]; this file is the public
//! surface and option-resolution glue, kept close to the axum reference
//! shape. Sub-modules: [`options`] (`ServeOptions` + defaults), [`handle`]
//! (`ServeHandle`), [`error_layer`] (tower → HTTP error converter),
//! [`pipeline`] / [`stack`] / [`lifecycle`] (per-bistream chain and RAII
//! guards).
//!
//! The FFI-shaped callback API ([`crate::ffi::dispatcher::ffi_serve_with_callback`])
//! is one specific consumer of this entry — it constructs an
//! `IrohHttpService` around the JS callback and hands it in like any
//! other service.

pub(crate) mod accept;
pub(crate) mod connection;
pub(crate) mod error_layer;
pub(crate) mod handle;
pub(crate) mod lifecycle;
pub(crate) mod options;
pub(crate) mod pipeline;
pub(crate) mod stack;

use std::{sync::Arc, time::Duration};

use tower::Service;

use crate::{Body, ConnectionEvent, IrohEndpoint};

use self::accept::{accept_loop, AcceptConfig};
use self::options::{
    DEFAULT_BODY_IDLE_TIMEOUT_MS, DEFAULT_CONCURRENCY, DEFAULT_CONNECTION_IDLE_TIMEOUT_MS,
    DEFAULT_DRAIN_TIMEOUT_MS, DEFAULT_MAX_CONNECTIONS_PER_PEER, DEFAULT_MAX_TOTAL_CONNECTIONS,
    DEFAULT_REQUEST_HEAD_TIMEOUT_MS,
};

// Re-exported from sub-modules so external paths
// (`crate::http::server::ServeOptions`, `…::ServeHandle`,
// `…::HandleLayerErrorLayer`, `…::DEFAULT_MAX_RESPONSE_BODY_BYTES`) stay
// unchanged after Slice C.7 split.
pub use self::connection::{
    serve_connection, ConnectionServeEnd, ConnectionServeError, ConnectionServeOptions,
    ConnectionServeResult, ConnectionServeRuntime,
};
pub(crate) use self::error_layer::HandleLayerErrorLayer;
pub use self::handle::ServeHandle;
pub use self::options::{
    ServeOptions, DEFAULT_MAX_REQUEST_BODY_BYTES, DEFAULT_MAX_RESPONSE_BODY_BYTES,
};

// ── Connection-event callback type ───────────────────────────────────────────

pub(crate) type ConnectionEventFn = Arc<dyn Fn(ConnectionEvent) + Send + Sync>;

/// Authenticated peer node id of the QUIC connection a request arrived on,
/// encoded as lowercase, unpadded RFC 4648 base32 for compatibility. Inserted
/// as a request extension by the per-connection
/// [`tower_http::add_extension::AddExtensionLayer`] in
/// [`serve_with_events`].
///
/// Existing pure-Rust services consume it with
/// `req.extensions().get::<RemoteNodeId>()`. New bridges should prefer
/// [`RemoteEndpointId`] so they never have to reverse-decode this string.
/// Closes #177.
#[derive(Clone, Debug)]
pub struct RemoteNodeId(pub Arc<String>);

/// Authenticated raw endpoint identity of the QUIC connection a request
/// arrived on.
///
/// Bridges that need a canonical machine identity should encode
/// `value.0.as_bytes()` directly as 64 lowercase hexadecimal characters.
/// They must not recover raw bytes by decoding [`RemoteNodeId`], whose RFC
/// 4648 base32 representation is retained for compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteEndpointId(pub iroh::EndpointId);

/// Pure-Rust serve entry — convenience 3-arg wrapper that omits the
/// connection-event callback. Equivalent to `serve_with_events(ep,
/// opts, svc, None)`. The endpoint owns the returned serve cycle immediately,
/// so [`IrohEndpoint::stop_serve`] works without a separate handle-registration
/// call.
pub fn serve<S>(endpoint: IrohEndpoint, options: ServeOptions, svc: S) -> ServeHandle
where
    S: Service<
            hyper::Request<Body>,
            Response = hyper::Response<Body>,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    serve_with_events(endpoint, options, svc, None)
}

/// Pure-Rust serve entry — the canonical inbound API.
///
/// Accepts any `tower::Service<Request<Body>, Response = Response<Body>,
/// Error = Infallible>` (`Clone + Send + Sync + 'static`, with `Send`
/// futures). Each accepted QUIC bidirectional stream is driven by
/// hyper's HTTP/1.1 server connection through the per-connection tower
/// stack composed in [`stack::build_stack`]; the user service sees
/// requests with the authenticated peer id available as a typed
/// [`RemoteNodeId`] and [`RemoteEndpointId`] request extensions.
///
/// `on_connection_event` is called on 0→1 (first connection from a peer)
/// and 1→0 (last connection from a peer closed) count transitions.
/// The cycle is installed in `endpoint` before this function returns; adapter
/// code may retain the returned handle, but need not register it for endpoint
/// lifecycle methods to reach the server.
///
/// # Security
///
/// Calling this opens a **public endpoint** on the Iroh overlay network.
/// Any peer that knows or discovers your node's public key can connect
/// and send requests. Iroh QUIC authenticates the peer's *identity*
/// cryptographically, but does not enforce *authorization*. Inspect
/// [`RemoteEndpointId`] (or the compatible [`RemoteNodeId`] string) in your
/// service and reject untrusted peers.
pub fn serve_with_events<S>(
    endpoint: IrohEndpoint,
    options: ServeOptions,
    svc: S,
    on_connection_event: Option<ConnectionEventFn>,
) -> ServeHandle
where
    S: Service<
            hyper::Request<Body>,
            Response = hyper::Response<Body>,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let cfg = AcceptConfig {
        connection: ConnectionServeOptions {
            max_connections_per_peer: options
                .max_connections_per_peer
                .unwrap_or(DEFAULT_MAX_CONNECTIONS_PER_PEER),
            max_total_connections: options
                .max_total_connections
                .unwrap_or(DEFAULT_MAX_TOTAL_CONNECTIONS),
            connection_idle_timeout: Duration::from_millis(
                options
                    .connection_idle_timeout_ms
                    .unwrap_or(DEFAULT_CONNECTION_IDLE_TIMEOUT_MS),
            ),
            max_concurrency: options.max_concurrency.unwrap_or(DEFAULT_CONCURRENCY),
            // Preserve the endpoint API's established zero-means-disabled
            // convention while the connection API expresses that as `None`.
            request_timeout: match options.request_timeout_ms {
                Some(0) => None,
                Some(milliseconds) => Some(Duration::from_millis(milliseconds)),
                None => None,
            },
            request_head_timeout: match options.request_head_timeout_ms {
                Some(0) => None,
                Some(milliseconds) => Some(Duration::from_millis(milliseconds)),
                None => Some(Duration::from_millis(DEFAULT_REQUEST_HEAD_TIMEOUT_MS)),
            },
            body_idle_timeout: match options.body_idle_timeout_ms {
                Some(0) => None,
                Some(milliseconds) => Some(Duration::from_millis(milliseconds)),
                None => Some(Duration::from_millis(DEFAULT_BODY_IDLE_TIMEOUT_MS)),
            },
            max_request_body_wire_bytes: options.max_request_body_wire_bytes,
            max_request_body_decoded_bytes: options.max_request_body_decoded_bytes,
            drain_timeout: Duration::from_millis(
                options.drain_timeout_ms.unwrap_or(DEFAULT_DRAIN_TIMEOUT_MS),
            ),
            load_shed: options.load_shed.unwrap_or(true),
            // Hyper cannot enforce a receive buffer below 8192 bytes. The
            // endpoint/FFI dispatcher retains and enforces its exact smaller
            // post-parse budget; this transport option must represent the
            // distinct Hyper framing bound accepted by ConnectionServeOptions.
            max_header_size: endpoint.max_header_size().max(8192),
            compression: endpoint.compression().cloned(),
            decompression: options.decompression.unwrap_or(true),
        },
    };

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let close_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let close_connections = Arc::new(tokio::sync::Notify::new());
    let drain_dur = cfg.connection.drain_timeout;
    let (done_tx, done_rx) = tokio::sync::watch::channel(false);

    // Register the cycle before spawning it. A stop racing after this point
    // targets this exact token; Notify retains the shutdown permit if the task
    // has not begun polling yet. The returned handle is a clone of the one in
    // the endpoint slot, so adapter-side `set_serve_handle` is idempotent.
    let handle = ServeHandle::pending(
        endpoint.next_serve_token(),
        shutdown_notify.clone(),
        close_flag.clone(),
        close_connections.clone(),
        drain_dur,
        done_rx,
    );
    endpoint.register_serve_handle(handle.clone());

    let join = tokio::spawn(accept_loop(
        endpoint,
        cfg,
        svc,
        on_connection_event,
        shutdown_notify.clone(),
        close_flag.clone(),
        close_connections.clone(),
        done_tx,
    ));
    handle.attach_join(join);
    handle
}
