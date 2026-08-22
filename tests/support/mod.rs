#![allow(dead_code)]

//! Shared harness: an in-process upstream, an in-process proxy, and helpers
//! for building key stores and reading back the JSONL audit log.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{Router, body::Body, http::Uri};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use mistralrs_proxy::{
    auth::KeyStore,
    backend::BackendId,
    keys::{KeyFile, KeyRecord, SCHEMA_VERSION},
    logging::{self, LogWorker},
    proxy,
    routing::RoutingState,
    runtime::{Backend, RegistrationConfig, RuntimeConfig, RuntimeReloadReport, RuntimeState},
};
use serde_json::Value;
use tokio::{sync::oneshot, task::JoinHandle};
use uuid::Uuid;

pub fn http_client() -> Client<HttpConnector, Body> {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

/// One issued key: the plaintext to present and the digest that will appear in
/// the log.
pub struct TestKey {
    pub name: String,
    pub identifier: String,
    pub secret: String,
    pub sha256: String,
}

/// Build a key store from `(name, admin, disabled)` specs.
pub fn key_store(specs: &[(&str, bool, bool)]) -> (KeyStore, Vec<TestKey>) {
    let (records, issued) = key_records(specs);

    (KeyStore::from_records(records).unwrap(), issued)
}

fn key_records(specs: &[(&str, bool, bool)]) -> (Vec<KeyRecord>, Vec<TestKey>) {
    let mut records = Vec::new();
    let mut issued = Vec::new();
    for (name, admin, disabled) in specs {
        let (mut record, secret) = KeyRecord::generate(*name, *admin).unwrap();
        record.disabled = *disabled;
        issued.push(TestKey {
            name: record.name.clone(),
            identifier: record.identifier.clone(),
            secret,
            sha256: record.key_sha256.clone(),
        });
        records.push(record);
    }

    (records, issued)
}

/// A single enabled admin key named `alice`.
pub fn one_key() -> (KeyStore, TestKey) {
    let (store, mut issued) = key_store(&[("alice", true, false)]);

    (store, issued.remove(0))
}

pub struct Upstream {
    pub addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Upstream {
    pub async fn start(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        Self {
            addr,
            shutdown,
            task,
        }
    }

    /// Base URL, optionally with a path prefix.
    pub fn uri(&self, prefix: &str) -> Uri {
        format!("http://{}{prefix}", self.addr).parse().unwrap()
    }

    pub async fn stop(self) {
        stop(self.shutdown, self.task).await;
    }
}

/// An address nothing is listening on, for connection-failure tests.
pub async fn unbound_addr() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    addr
}

pub struct Proxy {
    pub addr: SocketAddr,
    backends: RuntimeState,
    routing: RoutingState,
    log_path: PathBuf,
    keys_path: Option<PathBuf>,
    runtime_path: Option<PathBuf>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
    worker: LogWorker,
}

impl Proxy {
    pub async fn start(upstream: Uri, keys: KeyStore) -> Self {
        Self::start_with_backends(
            RuntimeState::new(vec![Backend::new("test", upstream)]),
            keys,
        )
        .await
    }

    pub async fn start_with_backends(backends: RuntimeState, keys: KeyStore) -> Self {
        Self::start_inner(backends, keys, None, None).await
    }

    /// Start with a persistent key database so `/register` can issue keys.
    /// Returns the proxy plus the plaintexts for the initial test records.
    pub async fn start_file_backed(
        upstream: Uri,
        registration: RegistrationConfig,
        specs: &[(&str, bool, bool)],
    ) -> (Self, Vec<TestKey>) {
        let path = std::env::temp_dir().join(format!("proxy-keys-{}.json", Uuid::new_v4()));
        let (records, issued) = key_records(specs);
        KeyFile {
            version: SCHEMA_VERSION,
            keys: records,
        }
        .save(&path)
        .unwrap();
        let keys = KeyStore::from_file(&path).unwrap();
        let mut config = RuntimeConfig::new(vec![Backend::new("test", upstream)]);
        config.registration = registration;
        let runtime = RuntimeState::from_config(config);
        let proxy = Self::start_inner(runtime, keys, Some(path), None).await;

        (proxy, issued)
    }

    pub async fn start_with_runtime(runtime_path: PathBuf, keys: KeyStore) -> Self {
        let config = RuntimeConfig::load(&runtime_path).await.unwrap();
        let backends = RuntimeState::from_config(config);

        Self::start_inner(backends, keys, None, Some(runtime_path)).await
    }

    async fn start_inner(
        backends: RuntimeState,
        keys: KeyStore,
        keys_path: Option<PathBuf>,
        runtime_path: Option<PathBuf>,
    ) -> Self {
        let log_path = std::env::temp_dir().join(format!("proxy-test-{}.jsonl", Uuid::new_v4()));
        let (logger, worker) = logging::start(&log_path, false).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let routing = RoutingState::new_assume_ready(backends.clone());
        let app = proxy::router(Arc::new(proxy::AppState::with_routing(
            http_client(),
            backends.clone(),
            routing.clone(),
            logger,
            keys,
        )));
        let (shutdown, rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
        });

        Self {
            addr,
            backends,
            routing,
            log_path,
            keys_path,
            runtime_path,
            shutdown,
            task,
            worker,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    pub fn configured_backend(&self) -> Backend {
        self.backends.configured()
    }

    /// Apply the current runtime file immediately, as the control plane does.
    pub async fn reload_runtime(&self) -> RuntimeReloadReport {
        self.backends
            .reload(
                self.runtime_path
                    .as_deref()
                    .expect("this proxy does not have a runtime file"),
            )
            .await
            .unwrap()
    }

    pub fn disable_backend(&self, id: &str) {
        self.backends
            .registry()
            .get(&BackendId::from(id))
            .expect("configured backend is registered")
            .disable();
    }

    pub fn activate_backend(&self, id: &str) {
        self.backends
            .registry()
            .get(&BackendId::from(id))
            .expect("configured backend is registered")
            .activate()
            .unwrap();
        // The production readiness worker must qualify a replacement topology
        // afresh. This in-process harness has no worker, so emulate its two
        // configured successes after the endpoint generation changes.
        self.routing.record_readiness_success(id);
        self.routing.record_readiness_success(id);
    }

    pub fn registration_config(&self) -> RegistrationConfig {
        self.backends.registration()
    }

    pub fn keys_path(&self) -> &Path {
        self.keys_path
            .as_deref()
            .expect("this proxy does not have a file-backed key store")
    }

    /// Shut the proxy down and return the audit records it wrote.
    pub async fn stop(self) -> Vec<Value> {
        stop(self.shutdown, self.task).await;
        self.worker.join().unwrap();

        let log = std::fs::read_to_string(&self.log_path).unwrap();
        std::fs::remove_file(&self.log_path).unwrap();
        if let Some(keys_path) = self.keys_path {
            std::fs::remove_file(keys_path).unwrap();
        }
        if let Some(runtime_path) = self.runtime_path {
            std::fs::remove_file(runtime_path).unwrap();
        }

        log.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

async fn stop(shutdown: oneshot::Sender<()>, task: JoinHandle<()>) {
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("server did not shut down")
        .expect("server task panicked");
}

/// The single record for `request_id`, asserting there is exactly one.
pub fn record_for<'a>(records: &'a [Value], request_id: &str) -> &'a Value {
    let matching: Vec<&Value> = records
        .iter()
        .filter(|record| record["request_id"] == request_id)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected one record for {request_id}, got {}",
        matching.len()
    );

    matching[0]
}
