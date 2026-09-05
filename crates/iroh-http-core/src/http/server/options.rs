//! `ServeOptions` and the default tunables consumed by
//! [`crate::http::server::serve_with_events`].
//!
//! Split out of `mod.rs` per Slice C.7 of #182 so the accept loop in
//! `mod.rs` stays close to the axum reference shape (≤ 200 LoC).

/// Options for the HTTP serve loop.
///
/// Passed directly to [`crate::http::server::serve`] or
/// [`crate::http::server::serve_with_events`]. These govern
/// per-request middleware (Tower layers), inbound connection caps, and
/// serve-loop lifecycle — they do **not** affect outgoing fetch calls.
#[derive(Debug, Clone, Default)]
pub struct ServeOptions {
    /// Maximum simultaneous in-flight requests.  Default: 1024.
    pub max_concurrency: Option<usize>,
    /// Application execution timeout in milliseconds. Default: disabled.
    /// Zero also disables the timeout.
    pub request_timeout_ms: Option<u64>,
    /// Maximum time to receive a complete HTTP request head. Default: 15 000
    /// milliseconds. Zero disables the timeout.
    pub request_head_timeout_ms: Option<u64>,
    /// Maximum time a polled request body may make no progress. Default:
    /// 30 000 milliseconds. Zero disables the timeout.
    pub body_idle_timeout_ms: Option<u64>,
    /// Maximum time an otherwise-idle accepted HTTP connection may wait for
    /// its next bidirectional request stream. Default: 60 000 milliseconds.
    pub connection_idle_timeout_ms: Option<u64>,
    /// Maximum connections from a single peer.  Default: 8.
    pub max_connections_per_peer: Option<usize>,
    /// Reject request bodies larger than this many **wire** bytes (compressed).
    /// Default: unlimited. This is an optional coarse transport ceiling; the
    /// application remains responsible for its semantic request-size limit.
    pub max_request_body_wire_bytes: Option<usize>,
    /// Reject request bodies larger than this many **decoded** bytes (after
    /// decompression). This is the primary compression-bomb guard.
    /// Default: unlimited. Enable this when this server decompresses request
    /// bodies and the application does not enforce its own decoded limit.
    pub max_request_body_decoded_bytes: Option<usize>,
    /// Graceful shutdown drain window in milliseconds.  Default: 30 000.
    pub drain_timeout_ms: Option<u64>,
    /// Maximum total QUIC connections the server will accept. Default: 1024.
    pub max_total_connections: Option<usize>,
    /// When `true` (the default), reject new requests immediately with `503
    /// Service Unavailable` when `max_concurrency` is already reached rather
    /// than queuing them.  Prevents thundering-herd on recovery.
    pub load_shed: Option<bool>,
    /// When `true` (the default), automatically decompress compressed request
    /// bodies before handing them to the handler.  Set to `false` to receive
    /// the raw wire bytes (e.g. for relay/proxy use-cases that forward the
    /// body downstream without inspecting it).
    pub decompression: Option<bool>,
}

pub(crate) const DEFAULT_CONCURRENCY: usize = 1024;
pub(crate) const DEFAULT_REQUEST_HEAD_TIMEOUT_MS: u64 = 15_000;
pub(crate) const DEFAULT_BODY_IDLE_TIMEOUT_MS: u64 = 30_000;
pub(crate) const DEFAULT_CONNECTION_IDLE_TIMEOUT_MS: u64 = 60_000;
pub(crate) const DEFAULT_MAX_CONNECTIONS_PER_PEER: usize = 8;
pub(crate) const DEFAULT_MAX_TOTAL_CONNECTIONS: usize = 1024;
pub(crate) const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 30_000;
/// 16 MiB convenience value for applications that want the historical
/// bounded-body profile. It is no longer applied implicitly by the server.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
/// 256 MiB — applied when `max_response_body_bytes` is not explicitly set.
/// Prevents memory exhaustion from a malicious server sending a compressed
/// response that expands to an unbounded size (compression bomb).
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 256 * 1024 * 1024;
