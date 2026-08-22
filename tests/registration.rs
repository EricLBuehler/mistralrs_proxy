mod support;

use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use mistralrs_proxy::{
    keys::{KeyFile, digest, hex_encode, identifier_of},
    register::BODY_LIMIT,
    runtime::RegistrationConfig,
};
use serde_json::{Value, json};

use support::{Proxy, Upstream, http_client};

const UNAVAILABLE_MESSAGE: &str = "Key registration unavailable.";
const DUPLICATE_NAME_MESSAGE: &str = "That name is already registered.";

async fn counting_upstream(State(count): State<Arc<AtomicUsize>>) -> &'static str {
    count.fetch_add(1, Ordering::SeqCst);
    "upstream"
}

async fn start_counting_upstream() -> (Upstream, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let upstream = Upstream::start(
        Router::new()
            .fallback(counting_upstream)
            .with_state(Arc::clone(&count)),
    )
    .await;

    (upstream, count)
}

fn registration(enabled: bool, max_keys: Option<usize>) -> RegistrationConfig {
    RegistrationConfig { enabled, max_keys }
}

fn json_post(proxy: &Proxy, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(proxy.url("/register"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

fn assert_secure_headers(headers: &HeaderMap) {
    assert_eq!(headers[header::CACHE_CONTROL], "no-store, max-age=0");
    assert_eq!(headers[header::PRAGMA], "no-cache");
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["permissions-policy"], "clipboard-write=(self)");
    let policy = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(policy.contains("default-src 'none'"));
    assert!(policy.contains("connect-src 'self'"));
    assert!(policy.contains("frame-ancestors 'none'"));
    assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

async fn body_text(response: Response<hyper::body::Incoming>) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn body_json(response: Response<hyper::body::Incoming>) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn assert_unavailable(
    response: Response<hyper::body::Incoming>,
    expected_status: StatusCode,
) {
    assert_eq!(response.status(), expected_status);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_secure_headers(response.headers());
    assert_eq!(
        body_json(response).await,
        json!({
            "error": {
                "message": UNAVAILABLE_MESSAGE,
                "type": "api_error",
                "param": null,
                "code": "registration_unavailable"
            }
        })
    );
}

async fn assert_duplicate(response: Response<hyper::body::Incoming>) {
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_secure_headers(response.headers());
    assert_eq!(
        body_json(response).await,
        json!({
            "error": {
                "message": DUPLICATE_NAME_MESSAGE,
                "type": "invalid_request_error",
                "param": "name",
                "code": "name_already_registered"
            }
        })
    );
}

#[tokio::test]
async fn unauthenticated_get_serves_the_local_registration_page_securely() {
    let (upstream, count) = start_counting_upstream().await;
    let (proxy, _) = Proxy::start_file_backed(
        upstream.uri(""),
        registration(true, None),
        &[("admin", true, false)],
    )
    .await;
    let client = http_client();

    let response = client
        .request(
            Request::builder()
                .uri(proxy.url("/register"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_secure_headers(response.headers());
    let page = body_text(response).await;
    assert!(page.contains("data-registration-available=\"true\""));
    assert!(page.contains("mistral.rs key registration"));
    assert!(page.contains("Your name"));
    assert!(page.contains("Create API key"));
    assert_eq!(count.load(Ordering::SeqCst), 0);

    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;
    assert!(records.is_empty(), "registration GET was audit logged");
}

#[tokio::test]
async fn disabled_or_capped_registration_renders_the_same_unavailable_page() {
    let (upstream, count) = start_counting_upstream().await;

    for config in [registration(false, None), registration(true, Some(1))] {
        let (proxy, _) =
            Proxy::start_file_backed(upstream.uri(""), config, &[("admin", true, false)]).await;
        let client = http_client();
        let response = client
            .request(
                Request::builder()
                    .uri(proxy.url("/register"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_secure_headers(response.headers());
        let page = body_text(response).await;
        assert!(page.contains("data-registration-available=\"false\""));
        assert!(page.contains(UNAVAILABLE_MESSAGE));

        drop(client);
        assert!(proxy.stop().await.is_empty());
    }

    assert_eq!(count.load(Ordering::SeqCst), 0);
    upstream.stop().await;
}

#[tokio::test]
async fn a_created_key_is_persisted_once_and_authenticates_immediately() {
    let (upstream, count) = start_counting_upstream().await;
    let (proxy, _) = Proxy::start_file_backed(
        upstream.uri(""),
        registration(true, Some(2)),
        &[("admin", true, false)],
    )
    .await;
    let client = http_client();

    let response = client
        .request(json_post(&proxy, r#"{"name":"  Bob  "}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_secure_headers(response.headers());
    let payload = body_json(response).await;
    assert_eq!(payload.as_object().unwrap().len(), 1);
    let api_key = payload["api_key"].as_str().unwrap().to_owned();
    assert!(identifier_of(&api_key).is_some());

    let raw_file = fs::read_to_string(proxy.keys_path()).unwrap();
    assert!(!raw_file.contains(&api_key), "plaintext key was persisted");
    let file = KeyFile::load(proxy.keys_path()).unwrap();
    assert_eq!(file.keys.len(), 2);
    let registered = file.keys.iter().find(|key| key.name == "Bob").unwrap();
    assert!(!registered.admin);
    assert!(!registered.disabled);
    assert_eq!(registered.key_sha256, hex_encode(&digest(&api_key)));
    assert_eq!(
        identifier_of(&api_key),
        Some(registered.identifier.as_str())
    );

    let response = client
        .request(
            Request::builder()
                .uri(proxy.url("/v1/models"))
                .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, "upstream");
    assert_eq!(count.load(Ordering::SeqCst), 1);

    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;
    assert_eq!(
        records.len(),
        1,
        "registration should not add an audit record"
    );
    assert_eq!(records[0]["uri"], "/v1/models");
    assert_eq!(records[0]["key_name"], "Bob");
    let audit_json = serde_json::to_string(&records).unwrap();
    assert!(!audit_json.contains(&api_key));
    assert!(!audit_json.contains("/register"));
}

#[tokio::test]
async fn registration_failures_are_safe_and_never_mutate_the_key_file() {
    let (upstream, count) = start_counting_upstream().await;
    let (proxy, _) = Proxy::start_file_backed(
        upstream.uri(""),
        registration(true, None),
        &[("admin", true, false)],
    )
    .await;
    let original = fs::read(proxy.keys_path()).unwrap();
    let client = http_client();

    let duplicate = client
        .request(json_post(&proxy, r#"{"name":"admin"}"#))
        .await
        .unwrap();
    assert_duplicate(duplicate).await;
    assert_eq!(fs::read(proxy.keys_path()).unwrap(), original);

    let invalid = client
        .request(json_post(&proxy, r#"{"name":"   "}"#))
        .await
        .unwrap();
    assert_unavailable(invalid, StatusCode::BAD_REQUEST).await;
    assert_eq!(fs::read(proxy.keys_path()).unwrap(), original);

    let cross_site = Request::builder()
        .method(Method::POST)
        .uri(proxy.url("/register"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("sec-fetch-site", "cross-site")
        .body(Body::from(r#"{"name":"mallory"}"#))
        .unwrap();
    let cross_site = client.request(cross_site).await.unwrap();
    assert_unavailable(cross_site, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(fs::read(proxy.keys_path()).unwrap(), original);

    let oversized_name = "x".repeat(BODY_LIMIT * 2);
    let oversized = client
        .request(json_post(
            &proxy,
            serde_json::to_vec(&json!({ "name": oversized_name })).unwrap(),
        ))
        .await
        .unwrap();
    assert_unavailable(oversized, StatusCode::PAYLOAD_TOO_LARGE).await;
    assert_eq!(fs::read(proxy.keys_path()).unwrap(), original);

    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(client);
    assert!(proxy.stop().await.is_empty());
    upstream.stop().await;
}

#[tokio::test]
async fn trailing_slash_and_unsupported_registration_methods_never_reach_upstream() {
    let (upstream, count) = start_counting_upstream().await;
    let (proxy, _) = Proxy::start_file_backed(
        upstream.uri(""),
        registration(true, None),
        &[("admin", true, false)],
    )
    .await;
    let client = http_client();

    let slash = client
        .request(
            Request::builder()
                .uri(proxy.url("/register/"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(slash.status(), StatusCode::OK);
    assert!(
        body_text(slash)
            .await
            .contains("mistral.rs key registration")
    );

    for path in ["/register", "/register/"] {
        let response = client
            .request(
                Request::builder()
                    .method(Method::PUT)
                    .uri(proxy.url(path))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        response.into_body().collect().await.unwrap();
    }

    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(client);
    assert!(proxy.stop().await.is_empty());
    upstream.stop().await;
}
