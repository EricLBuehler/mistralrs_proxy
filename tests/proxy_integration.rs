use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{StatusCode, Uri, header},
    response::Response,
};
use http_body_util::BodyExt;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use mistralrs_proxy::{logging, proxy};
use serde_json::Value;
use tokio::{sync::mpsc, task::JoinHandle};
use uuid::Uuid;

#[derive(Debug)]
struct ObservedRequest {
    uri: Uri,
    host: String,
    authorization: String,
    body: String,
}

async fn upstream(
    State(observed): State<mpsc::UnboundedSender<ObservedRequest>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    observed
        .send(ObservedRequest {
            uri: parts.uri,
            host: parts.headers[header::HOST].to_str().unwrap().to_owned(),
            authorization: parts.headers[header::AUTHORIZATION]
                .to_str()
                .unwrap()
                .to_owned(),
            body: String::from_utf8(body.to_vec()).unwrap(),
        })
        .unwrap();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from("data: one\n\ndata: two\n\n"))
        .unwrap()
}

fn http_client() -> Client<HttpConnector, Body> {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

async fn stop_server(shutdown: tokio::sync::oneshot::Sender<()>, task: JoinHandle<()>) {
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("server did not shut down")
        .expect("server task panicked");
}

#[tokio::test]
async fn proxies_authenticates_and_correlates_jsonl_records() {
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_app = Router::new().fallback(upstream).with_state(observed_tx);
    let (upstream_shutdown_tx, upstream_shutdown_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_app)
            .with_graceful_shutdown(async move {
                let _ = upstream_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let log_path = std::env::temp_dir().join(format!("proxy-e2e-{}.jsonl", Uuid::new_v4()));
    let (logger, log_worker) = logging::start(&log_path).unwrap();
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let state = Arc::new(proxy::AppState::new(
        http_client(),
        format!("http://{upstream_addr}/internal").parse().unwrap(),
        logger,
    ));
    let app = proxy::router(state);
    let (proxy_shutdown_tx, proxy_shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        axum::serve(
            proxy_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = proxy_shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/v1/responses?stream=true"))
        .header(header::HOST, "api.client.example")
        .header(header::AUTHORIZATION, "Bearer foobar")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"input":"hello"}"#))
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let valid_id = response.headers()["x-proxy-request-id"]
        .to_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let response_body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(response_body, "data: one\n\ndata: two\n\n");

    let observed = tokio::time::timeout(Duration::from_secs(2), observed_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed.uri, "/internal/v1/responses?stream=true");
    assert_eq!(observed.host, upstream_addr.to_string());
    assert_eq!(observed.authorization, "Bearer foobar");
    assert_eq!(observed.body, r#"{"input":"hello"}"#);

    let rejected_request = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/v1/responses"))
        .header(header::HOST, "api.client.example")
        .header(header::AUTHORIZATION, "Bearer not-allowed")
        .body(Body::from("not read"))
        .unwrap();
    let rejected_response = client.request(rejected_request).await.unwrap();
    assert_eq!(rejected_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejected_response.headers()[header::WWW_AUTHENTICATE],
        "Bearer"
    );
    let rejected_id = rejected_response.headers()["x-proxy-request-id"]
        .to_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    assert_ne!(valid_id, rejected_id);
    let error: Value = serde_json::from_slice(
        &rejected_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(error["error"]["code"], "invalid_api_key");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), observed_rx.recv())
            .await
            .is_err(),
        "rejected request unexpectedly reached the upstream"
    );

    drop(client);
    stop_server(proxy_shutdown_tx, proxy_task).await;
    log_worker.join().unwrap();
    stop_server(upstream_shutdown_tx, upstream_task).await;

    let log = std::fs::read_to_string(&log_path).unwrap();
    std::fs::remove_file(&log_path).unwrap();
    let records: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    let valid_id = valid_id.to_string();
    let valid_records: Vec<&Value> = records
        .iter()
        .filter(|record| record["request_id"] == valid_id)
        .collect();
    let valid_request = valid_records
        .iter()
        .find(|record| record["event"] == "request")
        .unwrap();
    assert_eq!(valid_request["client_ip"], "127.0.0.1");
    assert_eq!(valid_request["host"], "api.client.example");
    assert_eq!(valid_request["api_key"], "foobar");
    assert_eq!(valid_request["authorized"], true);
    assert_eq!(valid_request["body"], r#"{"input":"hello"}"#);
    assert_eq!(valid_request["complete"], true);
    assert!(
        valid_records
            .iter()
            .any(|record| record["event"] == "response_start" && record["status"] == 200)
    );
    assert!(
        valid_records
            .iter()
            .any(|record| record["event"] == "response_body")
    );
    assert_eq!(valid_records.last().unwrap()["event"], "response_end");

    let rejected_id = rejected_id.to_string();
    let rejected_records: Vec<&Value> = records
        .iter()
        .filter(|record| record["request_id"] == rejected_id)
        .collect();
    let rejected_request = rejected_records
        .iter()
        .find(|record| record["event"] == "request")
        .unwrap();
    assert_eq!(rejected_request["api_key"], "not-allowed");
    assert_eq!(rejected_request["authorized"], false);
    assert_eq!(rejected_request["body"], "not read");
    assert_eq!(rejected_request["termination"], "complete");
    let rejected_start = rejected_records
        .iter()
        .find(|record| record["event"] == "response_start")
        .unwrap();
    assert_eq!(rejected_start["status"], 401);
    assert!(
        rejected_start["headers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|header| header["name"] == "www-authenticate")
    );
}

#[tokio::test]
async fn upstream_connection_failure_is_a_logged_bad_gateway() {
    let unused_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_addr = unused_listener.local_addr().unwrap();
    drop(unused_listener);

    let log_path = std::env::temp_dir().join(format!("proxy-e2e-{}.jsonl", Uuid::new_v4()));
    let (logger, log_worker) = logging::start(&log_path).unwrap();
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let state = Arc::new(proxy::AppState::new(
        http_client(),
        format!("http://{unused_addr}").parse().unwrap(),
        logger,
    ));
    let app = proxy::router(state);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        axum::serve(
            proxy_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/v1/responses"))
        .header(header::AUTHORIZATION, "Bearer foobar")
        .body(Body::from("hello"))
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let request_id = response.headers()["x-proxy-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let error: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error["error"]["code"], "upstream_connection_error");

    drop(client);
    stop_server(shutdown_tx, proxy_task).await;
    log_worker.join().unwrap();

    let log = std::fs::read_to_string(&log_path).unwrap();
    std::fs::remove_file(&log_path).unwrap();
    let records: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        records
            .iter()
            .all(|record| record["request_id"] == request_id)
    );
    assert!(
        records
            .iter()
            .any(|record| record["event"] == "response_start" && record["status"] == 502)
    );
    let request = records
        .iter()
        .find(|record| record["event"] == "request")
        .unwrap();
    assert_eq!(request["body"], "hello");
    assert_eq!(request["complete"], true);
    assert!(
        records
            .iter()
            .any(|record| record["event"] == "response_end" && record["complete"] == true)
    );
}
