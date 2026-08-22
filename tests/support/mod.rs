#![allow(dead_code)]

//! Shared harness: an in-process upstream, an in-process proxy, and helpers
//! for building key stores and reading back the JSONL audit log.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{Router, body::Body, http::Uri};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use mistralrs_proxy::{
    auth::KeyStore,
    keys::KeyRecord,
    logging::{self, LogWorker},
    proxy,
    runtime::{self, Backend, BackendList, RuntimeConfig},
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

    (KeyStore::from_records(records).unwrap(), issued)
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
    backends: BackendList,
    log_path: PathBuf,
    runtime_path: Option<PathBuf>,
    reload_task: Option<JoinHandle<()>>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
    worker: LogWorker,
}

impl Proxy {
    pub async fn start(upstream: Uri, keys: KeyStore) -> Self {
        Self::start_with_backends(
            BackendList::new(vec![Backend::new("test", upstream, true)]),
            keys,
        )
        .await
    }

    pub async fn start_with_backends(backends: BackendList, keys: KeyStore) -> Self {
        Self::start_inner(backends, keys, None, None).await
    }

    pub async fn start_with_runtime(runtime_path: PathBuf, keys: KeyStore) -> Self {
        let config = RuntimeConfig::load(&runtime_path).await.unwrap();
        let backends = BackendList::from_config(config);
        let reload_task = tokio::spawn(runtime::reload(runtime_path.clone(), backends.clone()));

        Self::start_inner(backends, keys, Some(runtime_path), Some(reload_task)).await
    }

    async fn start_inner(
        backends: BackendList,
        keys: KeyStore,
        runtime_path: Option<PathBuf>,
        reload_task: Option<JoinHandle<()>>,
    ) -> Self {
        let log_path = std::env::temp_dir().join(format!("proxy-test-{}.jsonl", Uuid::new_v4()));
        let (logger, worker) = logging::start(&log_path, false).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = proxy::router(Arc::new(proxy::AppState::new(
            http_client(),
            backends.clone(),
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
            log_path,
            runtime_path,
            reload_task,
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

    /// Shut the proxy down and return the audit records it wrote.
    pub async fn stop(self) -> Vec<Value> {
        stop(self.shutdown, self.task).await;
        if let Some(reload_task) = self.reload_task {
            reload_task.abort();
            let _ = reload_task.await;
        }
        self.worker.join().unwrap();

        let log = std::fs::read_to_string(&self.log_path).unwrap();
        std::fs::remove_file(&self.log_path).unwrap();
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
