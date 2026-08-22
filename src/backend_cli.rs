//! Client-side implementation of `mistralrs_proxy backend ...`.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    config::BackendCommand,
    control::{
        ActionResponse, BackendListResponse, BackendView, DrainPhase, DrainProgress,
        DrainStartedResponse, ErrorResponse, ReloadResponse,
    },
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONTROL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ControlClient {
    socket: PathBuf,
}

impl ControlClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub async fn list(&self) -> Result<BackendListResponse, ClientError> {
        self.request(Method::GET, "/control/backends").await
    }

    pub async fn status(&self, id: &str) -> Result<BackendView, ClientError> {
        self.request(Method::GET, &format!("/control/backends/{id}"))
            .await
    }

    pub async fn drain(&self, id: &str) -> Result<DrainStartedResponse, ClientError> {
        self.request(Method::POST, &format!("/control/backends/{id}/drain"))
            .await
    }

    pub async fn operation(&self, id: uuid::Uuid) -> Result<DrainProgress, ClientError> {
        self.request(Method::GET, &format!("/control/operations/{id}"))
            .await
    }

    pub async fn activate(&self, id: &str) -> Result<ActionResponse, ClientError> {
        self.request(Method::POST, &format!("/control/backends/{id}/activate"))
            .await
    }

    pub async fn reload(&self) -> Result<ReloadResponse, ClientError> {
        self.request(Method::POST, "/control/runtime/reload").await
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
    ) -> Result<T, ClientError> {
        #[cfg(not(unix))]
        {
            let _ = (method, path);
            return Err(ClientError::new(
                "backend control requires a Unix-domain socket",
            ));
        }

        #[cfg(unix)]
        {
            let exchange = async {
                let stream = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio::net::UnixStream::connect(&self.socket),
                )
                .await
                .map_err(|_| {
                    ClientError::new(format!(
                        "timed out connecting to control socket {}",
                        self.socket.display()
                    ))
                })?
                .map_err(|error| {
                    ClientError::new(format!(
                        "could not connect to control socket {}: {error}",
                        self.socket.display()
                    ))
                })?;
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream))
                        .await
                        .map_err(ClientError::source)?;
                let driver = AbortOnDrop(tokio::spawn(connection));
                let request = Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::HOST, "localhost")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::new()))
                    .map_err(ClientError::source)?;
                let response = sender
                    .send_request(request)
                    .await
                    .map_err(ClientError::source)?;
                drop(sender);
                let status = response.status();
                let bytes = Limited::new(response.into_body(), MAX_CONTROL_RESPONSE_BYTES)
                    .collect()
                    .await
                    .map_err(ClientError::source)?
                    .to_bytes();
                drop(driver);

                if !status.is_success() {
                    let message = serde_json::from_slice::<ErrorResponse>(&bytes)
                        .map(|error| error.error)
                        .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned());
                    return Err(ClientError {
                        status: Some(status),
                        message,
                    });
                }
                serde_json::from_slice(&bytes).map_err(ClientError::source)
            };
            tokio::time::timeout(CONTROL_REQUEST_TIMEOUT, exchange)
                .await
                .map_err(|_| {
                    ClientError::new(format!(
                        "control request {path} timed out after {}s",
                        CONTROL_REQUEST_TIMEOUT.as_secs()
                    ))
                })?
        }
    }
}

#[cfg(unix)]
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

#[cfg(unix)]
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug)]
pub struct ClientError {
    status: Option<StatusCode>,
    message: String,
}

impl ClientError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            status: None,
            message: message.into(),
        }
    }

    fn source(error: impl fmt::Display) -> Self {
        Self::new(error.to_string())
    }

    pub fn status(&self) -> Option<StatusCode> {
        self.status
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(status) = self.status {
            write!(
                formatter,
                "control server returned {status}: {}",
                self.message
            )
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl Error for ClientError {}

pub fn run(command: BackendCommand) -> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_async(command))
}

async fn run_async(command: BackendCommand) -> Result<(), Box<dyn Error>> {
    match command {
        BackendCommand::List { json, control } => {
            let response = ControlClient::new(control.control_socket).list().await?;
            if json {
                print_json(&response)?;
            } else {
                print_backend_table(&response.backends);
            }
        }
        BackendCommand::Status {
            backend,
            watch,
            json,
            control,
        } => {
            let client = ControlClient::new(control.control_socket);
            loop {
                if let Some(id) = backend.as_deref() {
                    let status = client.status(id).await?;
                    if json {
                        print_json(&status)?;
                    } else {
                        print_backend_detail(&status);
                    }
                } else {
                    let response = client.list().await?;
                    if json {
                        print_json(&response)?;
                    } else {
                        print_backend_table(&response.backends);
                    }
                }
                if !watch {
                    break;
                }
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
        BackendCommand::Drain {
            backend,
            no_wait,
            timeout_seconds,
            control,
        } => {
            let client = ControlClient::new(control.control_socket);
            let started = client.drain(&backend).await?;
            println!(
                "{}: {}; operation {}",
                started.backend_id, started.mode, started.operation_id
            );
            if started.safe_to_stop {
                println!("{}: safe to stop", started.backend_id);
                return Ok(());
            }
            if no_wait {
                return Ok(());
            }
            wait_for_drain(&client, started, timeout_seconds).await?;
        }
        BackendCommand::Activate { backend, control } => {
            let response = ControlClient::new(control.control_socket)
                .activate(&backend)
                .await?;
            println!("{}: {}", response.backend_id, response.message);
        }
        BackendCommand::Reload { control } => {
            let response = ControlClient::new(control.control_socket).reload().await?;
            println!("runtime revision {} applied", response.revision);
            print_changes("added", &response.added);
            print_changes("revived", &response.revived);
            print_changes("updated", &response.updated);
            print_changes("retired", &response.retired);
        }
        BackendCommand::Manage { control } => {
            crate::backend_manage::manage(ControlClient::new(control.control_socket)).await?;
        }
    }
    Ok(())
}

async fn wait_for_drain(
    client: &ControlClient,
    started: DrainStartedResponse,
    timeout_seconds: Option<u64>,
) -> Result<(), Box<dyn Error>> {
    let deadline =
        timeout_seconds.map(|seconds| tokio::time::Instant::now() + Duration::from_secs(seconds));
    let mut previous = None;
    loop {
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return Err(format!(
                "timed out waiting for {}; it remains draining (operation {})",
                started.backend_id, started.operation_id
            )
            .into());
        }
        let progress = if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, client.operation(started.operation_id))
                .await
                .map_err(|_| {
                    format!(
                        "timed out waiting for {}; it remains draining (operation {})",
                        started.backend_id, started.operation_id
                    )
                })??
        } else {
            client.operation(started.operation_id).await?
        };
        let current = (
            progress.phase,
            progress.proxy_active,
            progress.engine_running,
            progress.engine_waiting,
            progress.telemetry,
        );
        if previous != Some(current) {
            println!(
                "{:>8}  proxy={}  running={}  waiting={}  telemetry={}",
                format_elapsed(progress.elapsed_ms),
                progress.proxy_active,
                optional_count(progress.engine_running),
                optional_count(progress.engine_waiting),
                progress.telemetry,
            );
            previous = Some(current);
        }
        match progress.phase {
            DrainPhase::Complete if progress.safe_to_stop => {
                println!("{}: disabled — safe to stop", progress.backend_id);
                return Ok(());
            }
            DrainPhase::Failed | DrainPhase::Cancelled => {
                return Err(progress
                    .message
                    .unwrap_or_else(|| "drain did not complete".to_owned())
                    .into());
            }
            DrainPhase::Draining | DrainPhase::Complete => {}
        }
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                println!("detached; {} remains draining (operation {})", started.backend_id, started.operation_id);
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

fn print_backend_table(backends: &[BackendView]) {
    println!(
        "{:<18} {:<10} {:<13} {:>5} {:>9} {:>5} {:>6} {:>9} {:>7} {:>7}",
        "BACKEND", "MODE", "STATE", "PROXY", "RUN/CAP", "WAIT", "KV%", "TOK/S", "PRESS", "AGE"
    );
    for backend in backends {
        let run_capacity = match (backend.running, backend.effective_capacity) {
            (Some(running), Some(capacity)) => format!("{running}/{capacity}"),
            _ => "-".to_owned(),
        };
        println!(
            "{:<18} {:<10} {:<13} {:>5} {:>9} {:>5} {:>6} {:>9} {:>7} {:>7}",
            truncate(&backend.id, 17),
            backend.mode,
            backend.state,
            backend.proxy_active,
            run_capacity,
            optional_count(backend.waiting),
            backend
                .kv_ratio
                .map_or_else(|| "-".to_owned(), |ratio| format!("{:.0}", ratio * 100.0)),
            backend
                .token_rate
                .map_or_else(|| "-".to_owned(), |rate| format!("{rate:.1}")),
            backend
                .pressure
                .map_or_else(|| "-".to_owned(), |pressure| format!("{pressure:.2}")),
            backend
                .metrics_age_ms
                .map_or_else(|| "-".to_owned(), format_age),
        );
    }
}

fn print_backend_detail(backend: &BackendView) {
    println!("{}", backend.id);
    println!("  state       {}", backend.state);
    println!("  mode        {}", backend.mode);
    println!("  URL         {}", backend.url);
    println!("  readiness   {}", backend.readiness);
    println!("  telemetry   {}", backend.telemetry);
    println!("  circuit     {}", backend.circuit);
    println!("  eligible    {}", backend.eligible);
    println!("  proxy       {} active", backend.proxy_active);
    println!(
        "  engine      {} running, {} waiting / {} capacity",
        optional_count(backend.running),
        optional_count(backend.waiting),
        optional_count(backend.effective_capacity),
    );
    println!(
        "  KV cache    {}",
        backend.kv_ratio.map_or_else(
            || "unavailable".to_owned(),
            |ratio| format!("{:.1}%", ratio * 100.0)
        )
    );
    println!(
        "  pressure    {}",
        backend
            .pressure
            .map_or_else(|| "-".to_owned(), |pressure| format!("{pressure:.3}"))
    );
    if let Some(error) = &backend.readiness_error {
        println!("  ready error {error}");
    }
    if let Some(error) = &backend.metrics_error {
        println!("  metric error {error}");
    }
}

fn print_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_changes(label: &str, values: &[String]) {
    println!(
        "  {label:<8} {}",
        if values.is_empty() {
            "none".to_owned()
        } else {
            values.join(", ")
        }
    );
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn format_elapsed(ms: u64) -> String {
    format!("{:02}:{:02}", ms / 60_000, (ms % 60_000) / 1_000)
}

fn format_age(ms: u64) -> String {
    if ms < 1_000 {
        format!("{:.1}s", ms as f64 / 1_000.0)
    } else {
        format!("{:.0}s", ms as f64 / 1_000.0)
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    value
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>()
        + "…"
}
