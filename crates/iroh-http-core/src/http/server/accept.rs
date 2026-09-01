//! Whole-endpoint accept loop.
//!
//! Endpoint ownership, connection caps/statistics, and connection events live
//! here. Once a connection is admitted, the same [`ConnectionServeRuntime`]
//! used by the public already-negotiated connection API owns its HTTP streams,
//! request limits, identity injection, and drain behavior.

use std::sync::{atomic::AtomicBool, Arc};

use tower::Service;

use crate::{Body, IrohEndpoint};

use super::connection::{validate_http_connection, ConnectionServeOptions, ConnectionServeRuntime};
use super::ConnectionEventFn;

/// Endpoint-only admission plus the shared per-connection HTTP configuration.
pub(super) struct AcceptConfig {
    pub connection: ConnectionServeOptions,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn accept_loop<S>(
    endpoint: IrohEndpoint,
    cfg: AcceptConfig,
    service: S,
    on_connection_event: Option<ConnectionEventFn>,
    shutdown_listen: Arc<tokio::sync::Notify>,
    close_flag: Arc<AtomicBool>,
    close_connections: Arc<tokio::sync::Notify>,
    done_tx: tokio::sync::watch::Sender<bool>,
) where
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
    let total_connections = endpoint.active_connections_arc();
    let total_requests = endpoint.active_requests_arc();
    let endpoint_closed_tx = endpoint.connection_closed_tx();
    let raw_endpoint = endpoint.raw().clone();
    let runtime = match ConnectionServeRuntime::with_runtime_state(
        cfg.connection,
        service,
        total_requests,
        total_connections,
        on_connection_event,
        close_flag,
        close_connections,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "iroh-http: invalid serve configuration");
            let _ = done_tx.send(true);
            return;
        }
    };

    loop {
        let incoming = tokio::select! {
            biased;
            _ = shutdown_listen.notified() => {
                tracing::info!("iroh-http: serve loop shutting down");
                break;
            }
            incoming = raw_endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => {
                    tracing::info!("iroh-http: endpoint closed (accept returned None)");
                    let _ = endpoint_closed_tx.send(true);
                    break;
                }
            }
        };

        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::debug!(%error, "iroh-http: connection handshake error");
                continue;
            }
        };

        // The public connection API and whole-endpoint path use this exact
        // protocol-confusion check. Validate before endpoint counters/events.
        let identity = match validate_http_connection(&connection) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::debug!(%error, "iroh-http: rejecting non-HTTP connection");
                continue;
            }
        };

        let connection_runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = connection_runtime
                .serve_validated(connection, identity)
                .await
            {
                tracing::debug!(%error, "iroh-http: connection rejected");
            }
        });
    }

    let drained = runtime.shutdown().await;
    if drained {
        tracing::info!("iroh-http: all in-flight requests drained");
    } else {
        tracing::warn!("iroh-http: response delivery drain timed out");
    }
    let _ = done_tx.send(true);
}
