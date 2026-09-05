//! Real-QUIC coverage for the already-negotiated connection server API.

mod common;

use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use iroh_http_core::{
    fetch_request, Body, ConnectionServeEnd, ConnectionServeError, ConnectionServeOptions,
    ConnectionServeRuntime, IrohEndpoint, NetworkingOptions, NodeOptions, RemoteEndpointId,
    RemoteNodeId, StackConfig, ALPN, ALPN_DUPLEX,
};

fn server_addr(endpoint: &iroh_http_core::IrohEndpoint) -> iroh::EndpointAddr {
    let mut addr = iroh::EndpointAddr::new(endpoint.raw().id());
    for socket in common::server_addrs(endpoint) {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

async fn loopback_endpoint() -> IrohEndpoint {
    IrohEndpoint::bind(NodeOptions {
        networking: NetworkingOptions {
            disabled: true,
            bind_addrs: vec!["127.0.0.1:0".into()],
            ..NetworkingOptions::default()
        },
        ..NodeOptions::default()
    })
    .await
    .expect("bind loopback endpoint")
}

#[tokio::test]
async fn negotiated_connection_uses_full_http_stack_and_graceful_drain() {
    let (server_endpoint, client_endpoint) = common::make_pair().await;
    let expected_peer = Arc::new(common::node_id(&client_endpoint));
    let expected_endpoint_id = client_endpoint.raw().id();
    let expected_peer_service = Arc::clone(&expected_peer);
    let runtime = ConnectionServeRuntime::new(
        ConnectionServeOptions::default(),
        tower::service_fn(move |request: hyper::Request<Body>| {
            let expected_peer = Arc::clone(&expected_peer_service);
            async move {
                let peer = request
                    .extensions()
                    .get::<RemoteNodeId>()
                    .map(|identity| Arc::clone(&identity.0));
                assert_eq!(peer.as_deref(), Some(expected_peer.as_ref()));
                assert_eq!(
                    request
                        .extensions()
                        .get::<RemoteEndpointId>()
                        .map(|identity| identity.0),
                    Some(expected_endpoint_id),
                );
                let body = format!("{} {}", request.method(), request.uri().path());
                Ok::<_, Infallible>(hyper::Response::new(Body::full(Bytes::from(body))))
            }
        }),
    )
    .expect("valid runtime");

    let raw_server = server_endpoint.raw().clone();
    let connection_runtime = runtime.clone();
    let server = tokio::spawn(async move {
        let incoming = raw_server.accept().await.expect("incoming connection");
        let connection = incoming.await.expect("completed handshake");
        connection_runtime.serve_connection(connection).await
    });

    let address = server_addr(&server_endpoint);
    for path in ["/one", "/two"] {
        let request = hyper::Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .expect("valid request");
        let response = fetch_request(&client_endpoint, &address, request, &StackConfig::default())
            .await
            .expect("HTTP request over supplied connection");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        assert_eq!(body.as_ref(), format!("GET {path}").as_bytes());
    }

    assert!(
        runtime.shutdown().await,
        "responses should drain before close"
    );
    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("connection server stopped")
        .expect("connection task joined")
        .expect("connection serve succeeded");
    assert_eq!(result.end, ConnectionServeEnd::Shutdown);
    assert!(result.drained);
}

#[tokio::test]
async fn negotiated_connection_rejects_protocol_confusion() {
    let (server_endpoint, client_endpoint) = common::make_pair().await;
    let runtime = ConnectionServeRuntime::new(
        ConnectionServeOptions::default(),
        tower::service_fn(|_request: hyper::Request<Body>| async {
            Ok::<_, Infallible>(hyper::Response::new(Body::empty()))
        }),
    )
    .expect("valid runtime");
    let raw_server = server_endpoint.raw().clone();
    let server = tokio::spawn(async move {
        let incoming = raw_server.accept().await.expect("incoming connection");
        let connection = incoming.await.expect("completed handshake");
        runtime.serve_connection(connection).await
    });

    let connection = client_endpoint
        .raw()
        .connect(server_addr(&server_endpoint), ALPN_DUPLEX)
        .await
        .expect("duplex ALPN is advertised");
    let error = server
        .await
        .expect("connection task joined")
        .expect_err("duplex connection must not enter HTTP dispatch");
    assert!(matches!(
        error,
        ConnectionServeError::UnexpectedAlpn { actual } if actual == ALPN_DUPLEX
    ));
    tokio::time::timeout(Duration::from_secs(5), connection.closed())
        .await
        .expect("rejected connection closed promptly");
}

#[tokio::test]
async fn reusable_runtime_closes_idle_connections() {
    let (server_endpoint, client_endpoint) = common::make_pair().await;
    let mut options = ConnectionServeOptions::default();
    options.connection_idle_timeout = Duration::from_millis(50);
    let runtime = ConnectionServeRuntime::new(
        options,
        tower::service_fn(|_request: hyper::Request<Body>| async {
            Ok::<_, Infallible>(hyper::Response::new(Body::empty()))
        }),
    )
    .expect("valid runtime");
    let raw_server = server_endpoint.raw().clone();
    let server = tokio::spawn(async move {
        let incoming = raw_server.accept().await.expect("incoming connection");
        let connection = incoming.await.expect("completed handshake");
        runtime.serve_connection(connection).await
    });

    let connection = client_endpoint
        .raw()
        .connect(server_addr(&server_endpoint), ALPN)
        .await
        .expect("HTTP ALPN negotiates");
    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("idle connection server stopped")
        .expect("connection task joined")
        .expect("connection serve succeeded");
    assert_eq!(result.end, ConnectionServeEnd::IdleTimeout);
    tokio::time::timeout(Duration::from_secs(5), connection.closed())
        .await
        .expect("idle connection closed promptly");
}

#[tokio::test]
async fn reusable_runtime_shares_total_connection_admission() {
    let (server_endpoint, first_client) = common::make_pair().await;
    let second_client = loopback_endpoint().await;
    let mut options = ConnectionServeOptions::default();
    options.max_total_connections = 1;
    let runtime = ConnectionServeRuntime::new(
        options,
        tower::service_fn(|_request: hyper::Request<Body>| async {
            Ok::<_, Infallible>(hyper::Response::new(Body::empty()))
        }),
    )
    .expect("valid runtime");

    let raw_server = server_endpoint.raw().clone();
    let server_runtime = runtime.clone();
    let server = tokio::spawn(async move {
        let first = raw_server.accept().await.expect("first incoming");
        let first = first.await.expect("first handshake");
        let runtime = server_runtime.clone();
        let first = tokio::spawn(async move { runtime.serve_connection(first).await });

        let second = raw_server.accept().await.expect("second incoming");
        let second = second.await.expect("second handshake");
        let rejected = server_runtime.serve_connection(second).await;
        (first, rejected)
    });

    let address = server_addr(&server_endpoint);
    let first_response = fetch_request(
        &first_client,
        &address,
        hyper::Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("first request"),
        &StackConfig::default(),
    )
    .await
    .expect("first admitted request");
    first_response
        .into_body()
        .collect()
        .await
        .expect("first response body");
    let rejected_fetch = tokio::spawn(async move {
        fetch_request(
            &second_client,
            &address,
            hyper::Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("second request"),
            &StackConfig::default(),
        )
        .await
    });
    let (first_task, rejected) = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("second admission resolved")
        .expect("server task joined");
    assert!(matches!(
        rejected,
        Err(ConnectionServeError::TotalConnectionLimitReached { maximum: 1 })
    ));
    let rejected_fetch = tokio::time::timeout(Duration::from_secs(5), rejected_fetch)
        .await
        .expect("rejected client request stopped")
        .expect("rejected client task joined");
    assert!(rejected_fetch.is_err());

    assert!(runtime.shutdown().await);
    first_task
        .await
        .expect("first connection task joined")
        .expect("first connection served");
}

#[tokio::test]
async fn reusable_runtime_shares_admission_across_connections() {
    let (server_endpoint, first_client) = common::make_pair().await;
    let second_client = loopback_endpoint().await;
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let service_calls = Arc::new(AtomicUsize::new(0));
    let mut options = ConnectionServeOptions::default();
    options.max_concurrency = 1;
    let runtime = ConnectionServeRuntime::new(
        options,
        tower::service_fn({
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            let service_calls = Arc::clone(&service_calls);
            move |request: hyper::Request<Body>| {
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                let service_calls = Arc::clone(&service_calls);
                async move {
                    service_calls.fetch_add(1, Ordering::SeqCst);
                    if request.uri().path() == "/hold" {
                        started.notify_one();
                        release.notified().await;
                    }
                    Ok::<_, Infallible>(hyper::Response::new(Body::empty()))
                }
            }
        }),
    )
    .expect("valid runtime");

    let raw_server = server_endpoint.raw().clone();
    let server_runtime = runtime.clone();
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let incoming = raw_server.accept().await.expect("incoming connection");
            let connection = incoming.await.expect("completed handshake");
            let runtime = server_runtime.clone();
            connections.spawn(async move { runtime.serve_connection(connection).await });
        }
        while let Some(result) = connections.join_next().await {
            result.expect("connection task joined").expect("HTTP serve");
        }
    });

    let address = server_addr(&server_endpoint);
    let first_address = address.clone();
    let first = tokio::spawn(async move {
        fetch_request(
            &first_client,
            &first_address,
            hyper::Request::builder()
                .uri("/hold")
                .body(Body::empty())
                .expect("valid request"),
            &StackConfig::default(),
        )
        .await
        .expect("first request")
    });
    started.notified().await;

    let shed = fetch_request(
        &second_client,
        &address,
        hyper::Request::builder()
            .uri("/shed")
            .body(Body::empty())
            .expect("valid request"),
        &StackConfig::default(),
    )
    .await
    .expect("load-shed response");
    assert_eq!(shed.status(), hyper::StatusCode::SERVICE_UNAVAILABLE);
    shed.into_body()
        .collect()
        .await
        .expect("load-shed response body");
    assert_eq!(service_calls.load(Ordering::SeqCst), 1);

    release.notify_one();
    first
        .await
        .expect("first request task")
        .into_body()
        .collect()
        .await
        .expect("first response body");
    assert!(runtime.shutdown().await);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("connection tasks stopped")
        .expect("server task joined");
}
