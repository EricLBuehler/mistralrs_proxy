mod support;

use std::{path::PathBuf, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use mistralrs_proxy::{
    backend::BackendId,
    runtime::{Backend, RegistrationConfig, RuntimeState},
};
use serde_json::Value;
use tokio::sync::mpsc;
use uuid::Uuid;

use support::{Proxy, Upstream, http_client, one_key, record_for};

fn authorized_request(proxy: &Proxy, secret: &str) -> Request<Body> {
    Request::builder()
        .uri(proxy.url("/v1/models"))
        .header(header::AUTHORIZATION, format!("Bearer {secret}"))
        .body(Body::empty())
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

fn temp_runtime_path() -> PathBuf {
    std::env::temp_dir().join(format!("proxy-runtime-{}.toml", Uuid::new_v4()))
}

fn runtime_toml(id: &str, url: &axum::http::Uri) -> String {
    format!("schema_version = 1\n\n[[backends]]\nid = {id:?}\nurl = \"{url}\"\n")
}

fn runtime_toml_with_registration(
    id: &str,
    url: &axum::http::Uri,
    registration: &RegistrationConfig,
) -> String {
    let max_keys = registration
        .max_keys
        .map(|limit| format!("max_keys = {limit}\n"))
        .unwrap_or_default();
    format!(
        "{}\n[registration]\nenabled = {}\n{max_keys}",
        runtime_toml(id, url),
        registration.enabled,
    )
}

async fn observed_upstream(State(observed): State<mpsc::UnboundedSender<()>>) -> &'static str {
    observed.send(()).unwrap();
    "unexpected"
}

#[tokio::test]
async fn a_disabled_backend_returns_a_logged_503_without_contacting_upstream() {
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let upstream = Upstream::start(
        Router::new()
            .fallback(observed_upstream)
            .with_state(observed_tx),
    )
    .await;
    let backends = RuntimeState::new(vec![Backend::new("disabled", upstream.uri(""))]);
    backends
        .registry()
        .get(&BackendId::from("disabled"))
        .unwrap()
        .disable();
    let (keys, key) = one_key();
    let proxy = Proxy::start_with_backends(backends, keys).await;

    let client = http_client();
    let response = client
        .request(authorized_request(&proxy, &key.secret))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    let id = request_id(&response);
    let error: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error["error"]["type"], "api_error");
    assert_eq!(error["error"]["code"], "service_unavailable");
    assert_eq!(
        error["error"]["message"],
        "The service is temporarily unavailable. Please retry shortly."
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), observed_rx.recv())
            .await
            .is_err(),
        "a request reached the disabled backend"
    );

    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;

    let record = record_for(&records, &id);
    assert_eq!(record["status"], 503);
    assert_eq!(record["authorized"], true);
    assert_eq!(record["key_name"], "alice");
    assert_eq!(record["complete"], true);
}

async fn named_upstream(State(name): State<&'static str>) -> &'static str {
    name
}

#[tokio::test]
async fn explicit_reload_switches_a_disabled_backend_to_its_new_endpoint() {
    let first = Upstream::start(Router::new().fallback(named_upstream).with_state("first")).await;
    let second = Upstream::start(Router::new().fallback(named_upstream).with_state("second")).await;
    let first_uri = first.uri("");
    let second_uri = second.uri("");
    let runtime_path = temp_runtime_path();
    std::fs::write(&runtime_path, runtime_toml("backend", &first_uri)).unwrap();

    let (keys, key) = one_key();
    let proxy = Proxy::start_with_runtime(runtime_path.clone(), keys).await;
    let client = http_client();

    let initial = client
        .request(authorized_request(&proxy, &key.secret))
        .await
        .unwrap();
    assert_eq!(initial.status(), StatusCode::OK);
    assert_eq!(
        initial.into_body().collect().await.unwrap().to_bytes(),
        "first"
    );

    // Endpoint replacement is deliberately fenced: the backend must be
    // disabled and idle before an explicit control-plane reload can apply it.
    proxy.disable_backend("backend");
    std::fs::write(&runtime_path, runtime_toml("backend", &second_uri)).unwrap();
    let report = proxy.reload_runtime().await;
    assert_eq!(report.revision, 2);
    assert_eq!(proxy.configured_backend().url, second_uri);
    proxy.activate_backend("backend");

    let reloaded = client
        .request(authorized_request(&proxy, &key.secret))
        .await
        .unwrap();
    assert_eq!(reloaded.status(), StatusCode::OK);
    assert_eq!(
        reloaded.into_body().collect().await.unwrap().to_bytes(),
        "second"
    );

    drop(client);
    proxy.stop().await;
    first.stop().await;
    second.stop().await;
}

#[tokio::test]
async fn reload_updates_the_live_registration_controls() {
    let upstream =
        Upstream::start(Router::new().fallback(named_upstream).with_state("ready")).await;
    let runtime_path = temp_runtime_path();
    std::fs::write(&runtime_path, runtime_toml("backend", &upstream.uri(""))).unwrap();

    let (keys, _) = one_key();
    let proxy = Proxy::start_with_runtime(runtime_path.clone(), keys).await;
    assert_eq!(proxy.registration_config(), RegistrationConfig::default());

    let reloaded = RegistrationConfig {
        enabled: true,
        max_keys: Some(12),
    };
    std::fs::write(
        &runtime_path,
        runtime_toml_with_registration("backend", &upstream.uri(""), &reloaded),
    )
    .unwrap();

    let report = proxy.reload_runtime().await;
    assert_eq!(report.revision, 2);
    assert_eq!(proxy.registration_config(), reloaded);

    proxy.stop().await;
    upstream.stop().await;
}
