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

    pub async fn disable(&self, id: &str, force: bool) -> Result<ActionResponse, ClientError> {
        let path = if force {
            format!("/control/backends/{id}/disable?force=true")
        } else {
            format!("/control/backends/{id}/disable")
        };
        self.request(Method::POST, &path).await
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
        BackendCommand::Disable {
            backend,
            force,
            control,
        } => {
            let response = ControlClient::new(control.control_socket)
                .disable(&backend, force)
                .await?;
            println!("{}: {}", response.backend_id, response.message);
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
    for line in render_backend_table(backends).lines() {
        println!("{line}");
    }
}

/// Column widths grow with the data instead of being fixed, so no value
/// (a long age, a large `running/capacity`, ...) can ever push a row out of
/// alignment. The backend id column stays capped so one odd name cannot
/// stretch the table.
fn render_backend_table(backends: &[BackendView]) -> String {
    const LEFT_ALIGNED_COLUMNS: usize = 3;
    let headers = [
        "BACKEND", "MODE", "STATE", "PROXY", "RUN/CAP", "WAIT", "KV%", "TOK/S", "PREF T/S",
        "DECODE T/S", "PRESS", "AGE",
    ];
    let rows: Vec<Vec<String>> = backends
        .iter()
        .map(|backend| {
            vec![
                truncate(&backend.id, 24),
                backend.mode.to_string(),
                backend.state.to_string(),
                backend.proxy_active.to_string(),
                match (backend.running, backend.effective_capacity) {
                    (Some(running), Some(capacity)) => format!("{running}/{capacity}"),
                    _ => "-".to_owned(),
                },
                optional_count(backend.waiting),
                backend
                    .kv_ratio
                    .map_or_else(|| "-".to_owned(), |ratio| format!("{:.0}", ratio * 100.0)),
                backend
                    .token_rate
                    .map_or_else(|| "-".to_owned(), |rate| format!("{rate:.1}")),
                backend
                    .prefill_token_rate
                    .map_or_else(|| "-".to_owned(), |rate| format!("{rate:.1}")),
                backend
                    .decode_token_rate
                    .map_or_else(|| "-".to_owned(), |rate| format!("{rate:.1}")),
                backend
                    .pressure
                    .map_or_else(|| "-".to_owned(), |pressure| format!("{pressure:.2}")),
                backend
                    .metrics_age_ms
                    .map_or_else(|| "-".to_owned(), format_age),
            ]
        })
        .collect();

    let widths = headers
        .iter()
        .enumerate()
        .map(|(column, header)| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
                .max(header.chars().count())
        })
        .collect::<Vec<_>>();

    let mut out = String::new();
    out.push_str(
        &headers
            .iter()
            .enumerate()
            .map(|(column, header)| {
                format_cell(header, widths[column], column < LEFT_ALIGNED_COLUMNS)
            })
            .collect::<Vec<_>>()
            .join(" "),
    );
    out.push('\n');
    for row in &rows {
        out.push_str(
            &row.iter()
                .enumerate()
                .map(|(column, cell)| {
                    format_cell(cell, widths[column], column < LEFT_ALIGNED_COLUMNS)
                })
                .collect::<Vec<_>>()
                .join(" "),
        );
        out.push('\n');
    }
    out
}

fn format_cell(cell: &str, width: usize, left_aligned: bool) -> String {
    if left_aligned {
        format!("{cell:<width$}")
    } else {
        format!("{cell:>width$}")
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

/// Ages stay in a bounded width so the table's AGE column never grows:
/// `12.3s`, `123s`, `614m`, `25h`, then `12d 4h`. A permanently dead
/// backend's metrics age keeps growing forever, so the last tier must not
/// fall back to raw seconds.
fn format_age(ms: u64) -> String {
    if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1_000.0)
    } else if ms < 3_600_000 {
        format!("{:.0}s", ms / 1_000)
    } else if ms < 86_400_000 {
        format!("{:.0}m", ms / 60_000)
    } else if ms < 604_800_000 {
        format!("{:.0}h", ms / 3_600_000)
    } else {
        let days = ms / 86_400_000;
        let hours = (ms % 86_400_000) / 3_600_000;
        format!("{days}d {hours}h")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::BackendMode,
        routing::{BackendDisplayState, CircuitState, ReadinessState, TelemetryState},
    };

    fn view(id: &str) -> BackendView {
        BackendView {
            id: id.to_owned(),
            url: "http://127.0.0.1:1".to_owned(),
            mode: BackendMode::Active,
            state: BackendDisplayState::Ready,
            readiness: ReadinessState::Ready,
            telemetry: TelemetryState::Fresh,
            circuit: CircuitState::Closed,
            eligible: true,
            proxy_active: 0,
            oldest_proxy_request_ms: None,
            running: None,
            waiting: None,
            reported_capacity: None,
            configured_capacity: None,
            effective_capacity: None,
            capacity_mismatch: false,
            kv_ratio: None,
            token_rate: None,
            prefill_token_rate: None,
            decode_token_rate: None,
            pressure: None,
            metrics_age_ms: None,
            readiness_age_ms: None,
            metrics_error: None,
            readiness_error: None,
        }
    }

    #[test]
    fn format_age_stays_bounded_no_matter_how_old() {
        assert_eq!(format_age(400), "0.4s");
        assert_eq!(format_age(12_300), "12.3s");
        assert_eq!(format_age(123_000), "123s");
        assert_eq!(format_age(36_843_000), "614m");
        assert_eq!(format_age(90_000_000), "25h");
        assert_eq!(format_age(12 * 86_400_000u64 + 4 * 3_600_000u64), "12d 4h");

        // A permanently dead backend ages forever; the string must not.
        for days in [8u64, 365, 3650] {
            let rendered = format_age(days * 86_400_000u64);
            assert!(rendered.chars().count() <= 8, "{rendered} is too wide");
        }
    }

    #[test]
    fn table_rows_stay_aligned_when_values_outgrow_typical_widths() {
        let mut busy = view("gh200-prod-1");
        busy.mode = BackendMode::Draining;
        busy.state = BackendDisplayState::Draining;
        busy.proxy_active = 12_345;
        busy.running = Some(10_000u64);
        busy.effective_capacity = Some(10_000u64);
        busy.waiting = Some(999u64);
        busy.kv_ratio = Some(1.0);
        busy.token_rate = Some(1_234_567.8);
        busy.prefill_token_rate = Some(432_100.5);
        busy.decode_token_rate = Some(802_467.3);
        busy.pressure = Some(12_345.67);
        busy.metrics_age_ms = Some(12 * 86_400_000u64 + 4 * 3_600_000u64);

        let table = render_backend_table(&[busy, view("dev-gh200")]);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3);

        let width = lines[0].chars().count();
        for line in &lines {
            assert_eq!(line.chars().count(), width, "misaligned row:\n{table}");
        }
        assert!(table.contains("10000/10000"), "{table}");
        assert!(table.contains("12d 4h"), "{table}");
        assert!(table.contains("1234567.8"), "{table}");
        assert!(table.contains("432100.5"), "{table}");
        assert!(table.contains("802467.3"), "{table}");
    }

    #[test]
    fn long_backend_ids_are_capped() {
        let long = view(&"x".repeat(60));
        let table = render_backend_table(std::slice::from_ref(&long));
        let mut lines = table.lines();
        let header = lines.next().unwrap();
        let row = lines.next().unwrap();

        assert_eq!(row.chars().count(), header.chars().count(), "{table}");
        let id_cell = row.split(' ').next().unwrap();
        assert_eq!(id_cell.chars().count(), 24, "{id_cell}");
        assert!(id_cell.ends_with('…'), "{id_cell}");
    }
}
