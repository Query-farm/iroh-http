//! HTTP serving for already-negotiated Iroh connections.
//!
//! [`ConnectionServeRuntime`] owns the state that must be shared when an
//! external Iroh router dispatches more than one HTTP connection: request
//! concurrency, connection admission, request/delivery tracking, and graceful
//! shutdown.

use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use hyper_util::rt::TokioIo;
use tower::{limit::GlobalConcurrencyLimitLayer, Service, ServiceBuilder, ServiceExt};

use crate::{base32_encode, http::transport::io::IrohStream, Body, ALPN};

use super::lifecycle::{
    ConnectionAdmission, ConnectionAdmissionError, DeliveryTracker, RequestTracker,
};
use super::pipeline::ServeService;
use super::stack::{CompressionOptions, StackConfig};
use super::{RemoteEndpointId, RemoteNodeId};

/// Options for HTTP requests served on already-negotiated Iroh connections.
///
/// A single [`ConnectionServeRuntime`] shares these limits across every
/// connection passed to it. Construct one runtime per external router or
/// listener; constructing one runtime per connection makes `max_concurrency`
/// a per-connection limit instead.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConnectionServeOptions {
    /// Maximum simultaneous connections from one authenticated peer. Default: 8.
    pub max_connections_per_peer: usize,
    /// Maximum simultaneous connections across this runtime. Default: 1024.
    pub max_total_connections: usize,
    /// Maximum time an otherwise-idle connection may wait for its next
    /// bidirectional request stream. Default: 60 seconds.
    pub connection_idle_timeout: Duration,
    /// Maximum simultaneous requests across this runtime. Default: 1024.
    pub max_concurrency: usize,
    /// Per-request and request-head timeout. `None` disables both.
    pub request_timeout: Option<Duration>,
    /// Maximum compressed request-body bytes. Default: 16 MiB.
    pub max_request_body_wire_bytes: Option<usize>,
    /// Maximum decoded request-body bytes. Default: 16 MiB.
    pub max_request_body_decoded_bytes: Option<usize>,
    /// Maximum graceful delivery drain. Default: 30 seconds.
    pub drain_timeout: Duration,
    /// Reject rather than queue requests when the concurrency gate is full.
    pub load_shed: bool,
    /// Maximum parsed request-head bytes. Zero selects the 64 KiB default.
    pub max_header_size: usize,
    /// Optional response compression configuration.
    pub compression: Option<CompressionOptions>,
    /// Automatically decompress request bodies. Default: true.
    pub decompression: bool,
}

impl Default for ConnectionServeOptions {
    fn default() -> Self {
        Self {
            max_connections_per_peer: super::options::DEFAULT_MAX_CONNECTIONS_PER_PEER,
            max_total_connections: super::options::DEFAULT_MAX_TOTAL_CONNECTIONS,
            connection_idle_timeout: Duration::from_millis(
                super::options::DEFAULT_CONNECTION_IDLE_TIMEOUT_MS,
            ),
            max_concurrency: super::options::DEFAULT_CONCURRENCY,
            request_timeout: Some(Duration::from_millis(
                super::options::DEFAULT_REQUEST_TIMEOUT_MS,
            )),
            max_request_body_wire_bytes: Some(super::options::DEFAULT_MAX_REQUEST_BODY_BYTES),
            max_request_body_decoded_bytes: Some(super::options::DEFAULT_MAX_REQUEST_BODY_BYTES),
            drain_timeout: Duration::from_millis(super::options::DEFAULT_DRAIN_TIMEOUT_MS),
            load_shed: true,
            max_header_size: 64 * 1024,
            compression: None,
            decompression: true,
        }
    }
}

impl ConnectionServeOptions {
    fn validate(&self) -> Result<(), ConnectionServeError> {
        if self.max_connections_per_peer == 0 {
            return Err(ConnectionServeError::InvalidOptions {
                option: "max_connections_per_peer",
                reason: "must be greater than zero",
            });
        }
        if self.max_total_connections == 0 {
            return Err(ConnectionServeError::InvalidOptions {
                option: "max_total_connections",
                reason: "must be greater than zero",
            });
        }
        if self.max_connections_per_peer > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConnectionServeError::InvalidOptions {
                option: "max_connections_per_peer",
                reason: "exceeds Tokio's supported admission limit",
            });
        }
        if self.max_total_connections > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConnectionServeError::InvalidOptions {
                option: "max_total_connections",
                reason: "exceeds Tokio's supported admission limit",
            });
        }
        if self.connection_idle_timeout.is_zero() {
            return Err(ConnectionServeError::InvalidOptions {
                option: "connection_idle_timeout",
                reason: "must be greater than zero",
            });
        }
        if self.max_concurrency == 0 {
            return Err(ConnectionServeError::InvalidOptions {
                option: "max_concurrency",
                reason: "must be greater than zero",
            });
        }
        if self.max_concurrency > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConnectionServeError::InvalidOptions {
                option: "max_concurrency",
                reason: "exceeds Tokio's semaphore permit limit",
            });
        }
        if self.max_header_size != 0 && self.max_header_size < 8192 {
            return Err(ConnectionServeError::InvalidOptions {
                option: "max_header_size",
                reason: "must be zero or at least Hyper's 8192-byte floor",
            });
        }
        Ok(())
    }
}

/// Why serving one already-negotiated connection ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectionServeEnd {
    /// The peer closed the connection or QUIC stopped yielding streams.
    PeerClosed,
    /// No request was in flight and the peer opened no new stream before the
    /// configured connection idle timeout.
    IdleTimeout,
    /// The owning runtime was shut down.
    Shutdown,
}

/// Completion details for one already-negotiated connection.
///
/// When this is returned, this call no longer accepts streams and all request
/// tasks it spawned have either completed or been aborted after drain expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionServeResult {
    /// Terminal condition observed by this connection task.
    pub end: ConnectionServeEnd,
    /// Whether response delivery completed inside the configured drain budget.
    pub drained: bool,
}

/// Errors that reject an already-negotiated connection before HTTP dispatch.
///
/// The connection handle passed to the serving call is consumed on error. An
/// unexpected-ALPN connection is explicitly closed before the error returns.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectionServeError {
    #[error("invalid connection serve option {option}: {reason}")]
    /// A runtime option could not be enforced safely.
    InvalidOptions {
        /// Name of the invalid option.
        option: &'static str,
        /// Stable explanation of the rejected value.
        reason: &'static str,
    },
    #[error("connection negotiated an unexpected ALPN: {actual:?}")]
    /// The connection did not negotiate [`crate::ALPN`].
    UnexpectedAlpn {
        /// Raw negotiated ALPN bytes, which need not be UTF-8.
        actual: Vec<u8>,
    },
    #[error("total connection limit reached ({maximum})")]
    /// The shared runtime reached its total connection bound.
    TotalConnectionLimitReached {
        /// Configured total connection maximum.
        maximum: usize,
    },
    #[error("per-peer connection limit reached ({maximum})")]
    /// The authenticated peer reached its per-peer connection bound.
    PeerConnectionLimitReached {
        /// Configured maximum for the rejected scope.
        maximum: usize,
    },
}

struct ConnectionServeInner {
    options: ConnectionServeOptions,
    service: Mutex<ServeService>,
    concurrency: GlobalConcurrencyLimitLayer,
    admission: Arc<ConnectionAdmission>,
    requests: Arc<AtomicUsize>,
    deliveries: Arc<AtomicUsize>,
    drain_notify: Arc<tokio::sync::Notify>,
    stream_admission: StreamAdmissionBarrier,
    close_flag: Arc<AtomicBool>,
    close_connections: Arc<tokio::sync::Notify>,
    drained: AtomicBool,
    shutdown: tokio::sync::OnceCell<bool>,
}

/// Serializes stream counter acquisition with the transition to draining.
///
/// The lock is held only for one flag check and two atomic increments. It
/// closes the window where shutdown could observe zero deliveries after a
/// stream had been accepted but before that stream became visible to drain.
struct StreamAdmissionBarrier {
    gate: Mutex<()>,
    stopped: AtomicBool,
}

impl StreamAdmissionBarrier {
    fn new() -> Self {
        Self {
            gate: Mutex::new(()),
            stopped: AtomicBool::new(false),
        }
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    fn try_admit(&self, requests: &AtomicUsize, deliveries: &AtomicUsize) -> bool {
        let _gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        requests.fetch_add(1, Ordering::Relaxed);
        deliveries.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn stop(&self) {
        let _gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.stopped.store(true, Ordering::Release);
    }
}

/// Reusable owner for serving HTTP on connections accepted by an external
/// Iroh endpoint/router.
///
/// Clone this value into every protocol-handler invocation. Doing so keeps
/// request admission and graceful drain global to that router. Call
/// [`Self::shutdown`] to stop all clones from accepting streams, drain
/// transport delivery, and close their owned connections.
#[derive(Clone)]
pub struct ConnectionServeRuntime {
    inner: Arc<ConnectionServeInner>,
}

impl std::fmt::Debug for ConnectionServeRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionServeRuntime")
            .field("options", &self.inner.options)
            .finish_non_exhaustive()
    }
}

impl ConnectionServeRuntime {
    /// Build a reusable runtime around a Tower HTTP service.
    pub fn new<S>(options: ConnectionServeOptions, service: S) -> Result<Self, ConnectionServeError>
    where
        S: Service<hyper::Request<Body>, Response = hyper::Response<Body>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        Self::with_runtime_state(
            options,
            service,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            None,
            Arc::new(AtomicBool::new(false)),
            Arc::new(tokio::sync::Notify::new()),
        )
    }

    pub(super) fn with_runtime_state<S>(
        options: ConnectionServeOptions,
        service: S,
        requests: Arc<AtomicUsize>,
        connections: Arc<AtomicUsize>,
        on_connection_event: Option<super::ConnectionEventFn>,
        close_flag: Arc<AtomicBool>,
        close_connections: Arc<tokio::sync::Notify>,
    ) -> Result<Self, ConnectionServeError>
    where
        S: Service<hyper::Request<Body>, Response = hyper::Response<Body>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        options.validate()?;
        let max_concurrency = options.max_concurrency;
        let admission = ConnectionAdmission::new(
            options.max_connections_per_peer,
            options.max_total_connections,
            connections,
            on_connection_event,
        );
        Ok(Self {
            inner: Arc::new(ConnectionServeInner {
                options,
                service: Mutex::new(service.boxed_clone()),
                concurrency: GlobalConcurrencyLimitLayer::new(max_concurrency),
                admission,
                requests,
                deliveries: Arc::new(AtomicUsize::new(0)),
                drain_notify: Arc::new(tokio::sync::Notify::new()),
                stream_admission: StreamAdmissionBarrier::new(),
                close_flag,
                close_connections,
                drained: AtomicBool::new(false),
                shutdown: tokio::sync::OnceCell::new(),
            }),
        })
    }

    /// Serve one connection already authenticated and negotiated by Iroh.
    ///
    /// This function consumes the supplied connection handle (but cannot
    /// revoke clones held elsewhere), verifies its negotiated ALPN, injects
    /// both its typed cryptographic endpoint ID and the compatible base32 node
    /// ID into every request, and closes it when the runtime shuts down. A
    /// malformed HTTP stream is isolated from later streams on the same
    /// connection. Cancelling this future aborts its local request tasks; call
    /// [`Self::shutdown`] for graceful global teardown. The connection is
    /// rejected when either shared connection limit is already full, and an
    /// otherwise-idle connection is closed after `connection_idle_timeout`.
    pub async fn serve_connection(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<ConnectionServeResult, ConnectionServeError> {
        let identity = validate_http_connection(&connection)?;
        self.serve_validated(connection, identity).await
    }

    pub(super) async fn serve_validated(
        &self,
        connection: iroh::endpoint::Connection,
        identity: ValidatedRemoteIdentity,
    ) -> Result<ConnectionServeResult, ConnectionServeError> {
        let _connection = match self
            .inner
            .admission
            .acquire(identity.endpoint_id, identity.legacy_node_id.clone())
        {
            Ok(connection) => connection,
            Err(ConnectionAdmissionError::Total) => {
                connection.close(0u32.into(), b"server at capacity");
                return Err(ConnectionServeError::TotalConnectionLimitReached {
                    maximum: self.inner.options.max_total_connections,
                });
            }
            Err(ConnectionAdmissionError::Peer) => {
                connection.close(0u32.into(), b"too many peer connections");
                return Err(ConnectionServeError::PeerConnectionLimitReached {
                    maximum: self.inner.options.max_connections_per_peer,
                });
            }
        };
        let service = self
            .inner
            .service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let connection_service: ServeService = ServiceBuilder::new()
            // Unlike `ConcurrencyLimitLayer`, this layer's clones share one
            // semaphore, so the limit remains global across connections.
            .layer(self.inner.concurrency.clone())
            .layer(tower_http::add_extension::AddExtensionLayer::new(
                RemoteEndpointId(identity.endpoint_id),
            ))
            .layer(tower_http::add_extension::AddExtensionLayer::new(
                RemoteNodeId(Arc::new(identity.legacy_node_id)),
            ))
            .service(service)
            .boxed_clone();
        let stack = super::stack::build_stack(
            connection_service,
            &StackConfig {
                timeout: self.inner.options.request_timeout,
                max_request_body_wire_bytes: self.inner.options.max_request_body_wire_bytes,
                max_request_body_decoded_bytes: self.inner.options.max_request_body_decoded_bytes,
                load_shed: self.inner.options.load_shed,
                compression: self.inner.options.compression.clone(),
                decompression: self.inner.options.decompression,
            },
        );
        let effective_header_limit = if self.inner.options.max_header_size == 0 {
            64 * 1024
        } else {
            self.inner.options.max_header_size
        };
        let mut requests = tokio::task::JoinSet::new();

        let mut end = ConnectionServeEnd::PeerClosed;
        loop {
            // Register before loading `close_flag`: `notify_waiters` stores no
            // permit, so registering later would leave a lost-wakeup window.
            let close = self.inner.close_connections.notified();
            tokio::pin!(close);
            close.as_mut().enable();

            if self.inner.close_flag.load(Ordering::Acquire) {
                connection.close(0u32.into(), b"HTTP serve runtime stopped");
                break;
            }
            if self.inner.stream_admission.is_stopped() {
                close.as_mut().await;
                continue;
            }

            let idle = tokio::time::sleep(self.inner.options.connection_idle_timeout);
            tokio::pin!(idle);
            let accepted = tokio::select! {
                biased;
                _ = &mut close => None,
                completed = requests.join_next(), if !requests.is_empty() => {
                    report_request_join(completed);
                    continue;
                }
                stream = connection.accept_bi() => Some(stream),
                _ = &mut idle, if requests.is_empty() => {
                    end = ConnectionServeEnd::IdleTimeout;
                    connection.close(0u32.into(), b"HTTP connection idle timeout");
                    break;
                }
            };
            let (send, recv) = match accepted {
                None => continue,
                Some(Ok(stream)) => {
                    // Counter acquisition and shutdown's transition to drain
                    // share one short gate. The stream is therefore either
                    // visible to drain or rejected; it cannot land between
                    // the stop flag and drain's first zero observation.
                    if !self
                        .inner
                        .stream_admission
                        .try_admit(&self.inner.requests, &self.inner.deliveries)
                    {
                        drop(stream);
                        continue;
                    }
                    stream
                }
                Some(Err(_)) => break,
            };

            // Hyper completion means bytes and FIN were queued, not that the
            // peer received them. Track the transport ACK boundary before
            // handing the stream to Hyper so shutdown cannot discard a queued
            // response on a pooled connection.
            let response_stopped = send.stopped();
            let io = TokioIo::new(IrohStream::new(send, recv));
            let request_counter = Arc::clone(&self.inner.requests);
            let delivery_counter = Arc::clone(&self.inner.deliveries);
            let drain_notify = Arc::clone(&self.inner.drain_notify);
            let request_stack = stack.clone();
            let header_read_timeout = self.inner.options.request_timeout;

            requests.spawn(async move {
                let _delivery = DeliveryTracker::new(delivery_counter, drain_notify);
                {
                    let _request = RequestTracker::new(request_counter);
                    super::pipeline::serve_bistream(
                        io,
                        request_stack,
                        effective_header_limit,
                        header_read_timeout,
                    )
                    .await;
                }
                if let Err(error) = response_stopped.await {
                    tracing::debug!(%error, "iroh-http: response stream ended before delivery acknowledgement");
                }
            });
        }

        if self.inner.close_flag.load(Ordering::Acquire)
            && !self.inner.drained.load(Ordering::Acquire)
        {
            requests.abort_all();
        }
        while let Some(completed) = requests.join_next().await {
            report_request_join(Some(completed));
        }

        let shutdown = self.inner.close_flag.load(Ordering::Acquire);
        Ok(ConnectionServeResult {
            end: if shutdown {
                ConnectionServeEnd::Shutdown
            } else {
                end
            },
            drained: !shutdown || self.inner.drained.load(Ordering::Acquire),
        })
    }

    /// Stop accepting new streams across every runtime clone, wait for
    /// response delivery up to `drain_timeout`, then close the connections.
    /// Returns `true` when tracked deliveries drained and every admitted
    /// connection handler exited before the shared deadline.
    pub async fn shutdown(&self) -> bool {
        *self
            .inner
            .shutdown
            .get_or_init(|| async {
                self.inner.stream_admission.stop();
                let deadline = drain_deadline(self.inner.options.drain_timeout);
                let drained =
                    wait_for_zero_until(&self.inner.deliveries, &self.inner.drain_notify, deadline)
                        .await;
                self.inner.drained.store(drained, Ordering::Release);
                self.inner.close_flag.store(true, Ordering::Release);
                self.inner.close_connections.notify_waiters();
                let connections_closed = wait_for_zero_until(
                    self.inner.admission.total(),
                    self.inner.admission.released(),
                    deadline,
                )
                .await;
                drained && connections_closed
            })
            .await
    }
}

/// Serve a single already-negotiated connection with a one-connection runtime.
///
/// Use [`ConnectionServeRuntime`] directly when an external router accepts
/// multiple connections, so concurrency and shutdown state are shared. This
/// convenience function runs until the peer closes; cancelling its future is
/// an immediate, non-draining cancellation.
pub async fn serve_connection<S>(
    connection: iroh::endpoint::Connection,
    options: ConnectionServeOptions,
    service: S,
) -> Result<ConnectionServeResult, ConnectionServeError>
where
    S: Service<hyper::Request<Body>, Response = hyper::Response<Body>, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    ConnectionServeRuntime::new(options, service)?
        .serve_connection(connection)
        .await
}

pub(super) struct ValidatedRemoteIdentity {
    pub(super) endpoint_id: iroh::EndpointId,
    pub(super) legacy_node_id: String,
}

pub(super) fn validate_http_connection(
    connection: &iroh::endpoint::Connection,
) -> Result<ValidatedRemoteIdentity, ConnectionServeError> {
    if connection.alpn() != ALPN {
        let actual = connection.alpn().to_vec();
        connection.close(0u32.into(), b"unexpected ALPN");
        return Err(ConnectionServeError::UnexpectedAlpn { actual });
    }
    let endpoint_id = connection.remote_id();
    Ok(ValidatedRemoteIdentity {
        endpoint_id,
        legacy_node_id: base32_encode(endpoint_id.as_bytes()),
    })
}

fn drain_deadline(timeout: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400))
}

async fn wait_for_zero_until(
    in_flight: &AtomicUsize,
    notify: &tokio::sync::Notify,
    deadline: tokio::time::Instant,
) -> bool {
    loop {
        // Register before inspecting the count for the same lost-wakeup
        // reason as the connection close waiter above.
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if in_flight.load(Ordering::Acquire) == 0 {
            return true;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::select! {
            _ = &mut notified => {}
            _ = tokio::time::sleep(remaining) => {}
        }
    }
}

fn report_request_join(completed: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(_)) = completed {
        tracing::warn!("iroh-http: request task failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_barrier_rejects_a_stream_after_its_early_observation() {
        let barrier = Arc::new(StreamAdmissionBarrier::new());
        let requests = Arc::new(AtomicUsize::new(0));
        let deliveries = Arc::new(AtomicUsize::new(0));
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();

        let late_barrier = Arc::clone(&barrier);
        let late_requests = Arc::clone(&requests);
        let late_deliveries = Arc::clone(&deliveries);
        let late = tokio::spawn(async move {
            // This is the old pre-increment observation that raced with
            // shutdown. Pause here so shutdown deterministically wins the
            // shared gate before the stream attempts counter acquisition.
            assert!(!late_barrier.is_stopped());
            observed_tx.send(()).expect("signal early observation");
            resume_rx.await.expect("resume late stream");
            late_barrier.try_admit(&late_requests, &late_deliveries)
        });

        observed_rx.await.expect("late stream reached race window");
        barrier.stop();
        resume_tx.send(()).expect("release late stream");

        assert!(!late.await.expect("late admission task joined"));
        assert_eq!(requests.load(Ordering::Acquire), 0);
        assert_eq!(deliveries.load(Ordering::Acquire), 0);
    }

    #[test]
    fn options_reject_zero_concurrency_without_panicking() {
        let error = ConnectionServeOptions {
            max_concurrency: 0,
            ..ConnectionServeOptions::default()
        }
        .validate()
        .expect_err("zero concurrency must be rejected before tower construction");
        assert!(matches!(
            error,
            ConnectionServeError::InvalidOptions {
                option: "max_concurrency",
                ..
            }
        ));
    }

    #[test]
    fn options_reject_unbounded_connection_configuration() {
        for (option, options) in [
            (
                "max_connections_per_peer",
                ConnectionServeOptions {
                    max_connections_per_peer: 0,
                    ..ConnectionServeOptions::default()
                },
            ),
            (
                "max_total_connections",
                ConnectionServeOptions {
                    max_total_connections: 0,
                    ..ConnectionServeOptions::default()
                },
            ),
            (
                "connection_idle_timeout",
                ConnectionServeOptions {
                    connection_idle_timeout: Duration::ZERO,
                    ..ConnectionServeOptions::default()
                },
            ),
        ] {
            let error = options
                .validate()
                .expect_err("unsafe connection option must be rejected");
            assert!(matches!(
                error,
                ConnectionServeError::InvalidOptions {
                    option: rejected,
                    ..
                } if rejected == option
            ));
        }
    }

    #[test]
    fn options_reject_admission_counts_above_tokio_limit_without_panicking() {
        for (option, options) in [
            (
                "max_connections_per_peer",
                ConnectionServeOptions {
                    max_connections_per_peer: usize::MAX,
                    ..ConnectionServeOptions::default()
                },
            ),
            (
                "max_total_connections",
                ConnectionServeOptions {
                    max_total_connections: usize::MAX,
                    ..ConnectionServeOptions::default()
                },
            ),
            (
                "max_concurrency",
                ConnectionServeOptions {
                    max_concurrency: usize::MAX,
                    ..ConnectionServeOptions::default()
                },
            ),
        ] {
            let error = options
                .validate()
                .expect_err("oversized admission count must be rejected");
            assert!(matches!(
                error,
                ConnectionServeError::InvalidOptions {
                    option: rejected,
                    ..
                } if rejected == option
            ));
        }
    }

    #[test]
    fn options_reject_header_limits_below_hyper_floor() {
        let error = ConnectionServeOptions {
            max_header_size: 8191,
            ..ConnectionServeOptions::default()
        }
        .validate()
        .expect_err("misleading sub-Hyper header limit must be rejected");
        assert!(matches!(
            error,
            ConnectionServeError::InvalidOptions {
                option: "max_header_size",
                ..
            }
        ));
        assert!(ConnectionServeOptions {
            max_header_size: 0,
            ..ConnectionServeOptions::default()
        }
        .validate()
        .is_ok());
        assert!(ConnectionServeOptions {
            max_header_size: 8192,
            ..ConnectionServeOptions::default()
        }
        .validate()
        .is_ok());
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn drain_deadline_saturates_on_huge_timeout() {
        let now = tokio::time::Instant::now();
        let deadline = now
            .checked_add(Duration::from_millis(u64::MAX))
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
        assert!(deadline > now);
    }
}
