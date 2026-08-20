mod support;

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{StatusCode, Uri, header},
    response::Response,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use uuid::Uuid;

use support::{Proxy, Upstream, http_client, key_store, one_key, record_for, unbound_addr};

const UPSTREAM_BODY: &str = concat!(
    "data: {\"choices\":[{\"delta\":{\"content\":\"one\"}}],\"usage\":null}\n\n",
    "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":31,\"completion_tokens\":7,\"total_tokens\":38}}\n\n",
    "data: [DONE]\n\n",
);

#[derive(Debug)]
struct ObservedRequest {
    uri: Uri,
    host: String,
    authorization: String,
    accept_encoding: Option<String>,
    body: String,
}

async fn upstream_handler(
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
            accept_encoding: parts
                .headers
                .get(header::ACCEPT_ENCODING)
                .map(|value| value.to_str().unwrap().to_owned()),
            body: String::from_utf8(body.to_vec()).unwrap(),
        })
        .unwrap();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from(UPSTREAM_BODY))
        .unwrap()
}

fn request_id(response: &Response<hyper::body::Incoming>) -> String {
    response.headers()["x-proxy-request-id"]
        .to_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn proxies_an_authorized_request_and_logs_one_record_with_token_counts() {
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let upstream = Upstream::start(
        Router::new()
            .fallback(upstream_handler)
            .with_state(observed_tx),
    )
    .await;
    let (keys, key) = one_key();
    let proxy = Proxy::start(upstream.uri("/internal"), keys).await;

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(proxy.url("/v1/chat/completions?stream=true"))
        .header(header::HOST, "api.client.example")
        .header(header::AUTHORIZATION, format!("Bearer {}", key.secret))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "openai-python/1.2.3")
        .body(Body::from(
            r#"{"messages":[{"role":"user","content":"hi"}]}"#,
        ))
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let id = request_id(&response);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, UPSTREAM_BODY);

    let observed = tokio::time::timeout(Duration::from_secs(2), observed_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed.uri, "/internal/v1/chat/completions?stream=true");
    assert_eq!(observed.host, upstream.addr.to_string());
    assert_eq!(observed.authorization, format!("Bearer {}", key.secret));
    assert_eq!(
        observed.body,
        r#"{"messages":[{"role":"user","content":"hi"}]}"#
    );
    // Compressed responses could not be scanned for usage.
    assert_eq!(observed.accept_encoding.as_deref(), Some("identity"));

    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;

    let record = record_for(&records, &id);
    assert_eq!(record["event"], "request");
    assert_eq!(record["client_ip"], "127.0.0.1");
    assert_eq!(record["host"], "api.client.example");
    assert_eq!(record["user_agent"], "openai-python/1.2.3");
    assert_eq!(record["method"], "POST");
    assert_eq!(record["uri"], "/v1/chat/completions?stream=true");
    assert_eq!(record["authorized"], true);
    assert_eq!(record["auth_error"], Value::Null);
    assert_eq!(record["key_name"], "alice");
    assert_eq!(record["key_identifier"], key.identifier);
    assert_eq!(record["key_sha256"], key.sha256);
    assert_eq!(record["key_admin"], true);
    assert_eq!(record["status"], 200);
    assert_eq!(record["input_tokens"], 31);
    assert_eq!(record["output_tokens"], 7);
    assert_eq!(record["total_tokens"], 38);
    assert_eq!(record["response_bytes"], UPSTREAM_BODY.len());
    assert_eq!(record["complete"], true);
    assert_eq!(record["termination"], "complete");
    assert_eq!(
        record["request_content_length"],
        r#"{"messages":[{"role":"user","content":"hi"}]}"#.len()
    );
}

#[tokio::test]
async fn neither_keys_nor_bodies_appear_in_the_log() {
    let (observed_tx, _observed_rx) = mpsc::unbounded_channel();
    let upstream = Upstream::start(
        Router::new()
            .fallback(upstream_handler)
            .with_state(observed_tx),
    )
    .await;
    let (keys, key) = one_key();
    let proxy = Proxy::start(upstream.uri(""), keys).await;

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(proxy.url("/v1/chat/completions"))
        .header(header::AUTHORIZATION, format!("Bearer {}", key.secret))
        .body(Body::from(
            r#"{"messages":[{"content":"my private prompt"}]}"#,
        ))
        .unwrap();
    let response = client.request(request).await.unwrap();
    response.into_body().collect().await.unwrap();

    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;

    let log = serde_json::to_string(&records).unwrap();
    assert!(!log.contains(&key.secret), "the log contains the API key");
    assert!(
        !log.contains("my private prompt"),
        "the log contains the prompt"
    );
    assert!(!log.contains("delta"), "the log contains response content");
}

#[tokio::test]
async fn an_unknown_key_is_rejected_before_the_upstream_and_logged_by_digest() {
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let upstream = Upstream::start(
        Router::new()
            .fallback(upstream_handler)
            .with_state(observed_tx),
    )
    .await;
    let (keys, _) = one_key();
    let proxy = Proxy::start(upstream.uri(""), keys).await;

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(proxy.url("/v1/responses"))
        .header(
            header::AUTHORIZATION,
            "Bearer eb_AAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )
        .body(Body::from("not read"))
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    let id = request_id(&response);
    let error: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error["error"]["code"], "invalid_api_key");

    assert!(
        tokio::time::timeout(Duration::from_millis(100), observed_rx.recv())
            .await
            .is_err(),
        "the rejected request reached the upstream"
    );

    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;

    let record = record_for(&records, &id);
    assert_eq!(record["authorized"], false);
    assert_eq!(record["auth_error"], "invalid_api_key");
    assert_eq!(record["status"], 401);
    assert_eq!(record["key_name"], Value::Null);
    // The digest of an unknown key is still recorded, so repeats are visible.
    assert_eq!(record["key_sha256"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn a_disabled_key_is_named_in_the_log_and_refused_with_403() {
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let upstream = Upstream::start(
        Router::new()
            .fallback(upstream_handler)
            .with_state(observed_tx),
    )
    .await;
    let (keys, issued) = key_store(&[("alice", true, false), ("retired", false, true)]);
    let retired = &issued[1];
    let proxy = Proxy::start(upstream.uri(""), keys).await;

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(proxy.url("/v1/responses"))
        .header(header::AUTHORIZATION, format!("Bearer {}", retired.secret))
        .body(Body::empty())
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let id = request_id(&response);
    let error: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error["error"]["code"], "api_key_disabled");

    assert!(
        tokio::time::timeout(Duration::from_millis(100), observed_rx.recv())
            .await
            .is_err(),
        "the disabled key reached the upstream"
    );

    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;

    let record = record_for(&records, &id);
    assert_eq!(record["authorized"], false);
    assert_eq!(record["auth_error"], "api_key_disabled");
    assert_eq!(record["status"], 403);
    assert_eq!(record["key_name"], "retired");
    assert_eq!(record["key_identifier"], retired.identifier);
}

#[tokio::test]
async fn a_missing_authorization_header_is_logged_without_a_digest() {
    let (observed_tx, _observed_rx) = mpsc::unbounded_channel();
    let upstream = Upstream::start(
        Router::new()
            .fallback(upstream_handler)
            .with_state(observed_tx),
    )
    .await;
    let (keys, _) = one_key();
    let proxy = Proxy::start(upstream.uri(""), keys).await;

    let client = http_client();
    let request = Request::builder()
        .uri(proxy.url("/v1/models"))
        .body(Body::empty())
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let id = request_id(&response);
    response.into_body().collect().await.unwrap();

    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;

    let record = record_for(&records, &id);
    assert_eq!(record["authorized"], false);
    assert_eq!(record["auth_error"], "invalid_api_key");
    assert_eq!(record["key_sha256"], Value::Null);
    assert_eq!(record["key_name"], Value::Null);
}

#[tokio::test]
async fn upstream_connection_failure_is_a_logged_bad_gateway() {
    let (keys, key) = one_key();
    let unreachable = format!("http://{}", unbound_addr().await);
    let proxy = Proxy::start(unreachable.parse().unwrap(), keys).await;

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(proxy.url("/v1/responses"))
        .header(header::AUTHORIZATION, format!("Bearer {}", key.secret))
        .body(Body::from("hello"))
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let id = request_id(&response);
    let error: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error["error"]["code"], "upstream_connection_error");

    drop(client);
    let records = proxy.stop().await;

    let record = record_for(&records, &id);
    assert_eq!(record["status"], 502);
    assert_eq!(record["authorized"], true);
    assert_eq!(record["key_name"], "alice");
    assert_eq!(record["complete"], true);
    assert_eq!(record["input_tokens"], Value::Null);
    assert_eq!(record["output_tokens"], Value::Null);
}

#[tokio::test]
async fn a_client_that_disconnects_before_the_response_is_still_recorded() {
    // An upstream that accepts the request and never answers.
    let upstream = Upstream::start(
        Router::new().fallback(|| async { std::future::pending::<Response>().await }),
    )
    .await;
    let (keys, key) = one_key();
    let proxy = Proxy::start(upstream.uri(""), keys).await;

    // A raw socket, so the connection can be dropped mid-request.
    let mut socket = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: 2\r\n\r\n{{}}",
        proxy.addr, key.secret,
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
    // Give the proxy time to reach the upstream, which never replies.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(socket);

    let records = proxy.stop().await;
    upstream.stop().await;

    assert_eq!(records.len(), 1, "{records:?}");
    let record = &records[0];
    assert_eq!(record["key_name"], "alice");
    assert_eq!(record["status"], Value::Null);
    assert_eq!(record["complete"], false);
    assert_eq!(record["termination"], "client_disconnected");
}
