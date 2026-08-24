//! Private backend control plane mounted at `/control` on a Unix socket.

use std::{
    collections::HashMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path as AxumPath, Query, State, connect_info::Connected},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::IncomingStream,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, watch};
use uuid::Uuid;

use crate::{
    backend::{BackendId, BackendMode},
    backend_state::BackendStateStore,
    routing::{
        BackendDisplayState, BackendStatusSnapshot, CircuitState, ReadinessState, RoutingState,
        TelemetryState,
    },
    runtime::{RuntimeReloadReport, RuntimeState},
};

#[derive(Clone, Debug)]
pub struct ControlState {
    runtime: RuntimeState,
    routing: RoutingState,
    state_store: BackendStateStore,
    runtime_file: Arc<PathBuf>,
    operations: Arc<Mutex<HashMap<Uuid, Arc<DrainOperation>>>>,
    lifecycle: Arc<AsyncMutex<()>>,
    quiet: bool,
}

#[derive(Debug)]
struct DrainOperation {
    id: Uuid,
    backend_id: String,
    started_at: Instant,
    metrics_scrapes_started_at_start: u64,
    progress: watch::Sender<DrainProgress>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainPhase {
    Draining,
    Complete,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DrainProgress {
    pub operation_id: Uuid,
    pub backend_id: String,
    pub phase: DrainPhase,
    pub safe_to_stop: bool,
    pub elapsed_ms: u64,
    pub proxy_active: usize,
    pub engine_running: Option<u64>,
    pub engine_waiting: Option<u64>,
    pub telemetry: TelemetryState,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackendView {
    pub id: String,
    pub url: String,
    pub mode: BackendMode,
    pub state: BackendDisplayState,
    pub readiness: ReadinessState,
    pub telemetry: TelemetryState,
    pub circuit: CircuitState,
    pub eligible: bool,
    pub proxy_active: usize,
    pub oldest_proxy_request_ms: Option<u64>,
    pub running: Option<u64>,
    pub waiting: Option<u64>,
    pub reported_capacity: Option<u64>,
    pub configured_capacity: Option<u64>,
    pub effective_capacity: Option<u64>,
    pub capacity_mismatch: bool,
    pub kv_ratio: Option<f64>,
    pub token_rate: Option<f64>,
    pub prefill_token_rate: Option<f64>,
    pub decode_token_rate: Option<f64>,
    pub pressure: Option<f64>,
    pub metrics_age_ms: Option<u64>,
    pub readiness_age_ms: Option<u64>,
    pub metrics_error: Option<String>,
    pub readiness_error: Option<String>,
}

impl From<BackendStatusSnapshot> for BackendView {
    fn from(status: BackendStatusSnapshot) -> Self {
        Self {
            id: status.id,
            url: status.url,
            mode: status.mode,
            state: status.state,
            readiness: status.readiness,
            telemetry: status.telemetry,
            circuit: status.circuit,
            eligible: status.eligible,
            proxy_active: status.proxy_active,
            oldest_proxy_request_ms: status.oldest_proxy_request_ms,
            running: status.running,
            waiting: status.waiting,
            reported_capacity: status.reported_capacity,
            configured_capacity: status.configured_capacity,
            effective_capacity: status.effective_capacity,
            capacity_mismatch: status.capacity_mismatch,
            kv_ratio: status.kv_ratio,
            token_rate: status.token_rate,
            prefill_token_rate: status.prefill_token_rate,
            decode_token_rate: status.decode_token_rate,
            pressure: status.pressure,
            metrics_age_ms: status.metrics_age_ms,
            readiness_age_ms: status.readiness_age_ms,
            metrics_error: status.metrics_error,
            readiness_error: status.readiness_error,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackendListResponse {
    pub runtime_revision: u64,
    pub routing_policy: String,
    pub backends: Vec<BackendView>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DrainStartedResponse {
    pub operation_id: Uuid,
    pub backend_id: String,
    pub mode: BackendMode,
    pub safe_to_stop: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActionResponse {
    pub backend_id: String,
    pub mode: BackendMode,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReloadResponse {
    pub revision: u64,
    pub added: Vec<String>,
    pub revived: Vec<String>,
    pub updated: Vec<String>,
    pub retired: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct UdsPeer {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub pid: Option<u32>,
}

#[cfg(unix)]
impl UdsPeer {
    pub fn from_stream(stream: &tokio::net::UnixStream) -> Self {
        match stream.peer_cred() {
            Ok(credentials) => Self {
                uid: Some(credentials.uid()),
                gid: Some(credentials.gid()),
                pid: credentials.pid().and_then(|pid| pid.try_into().ok()),
            },
            Err(_) => Self {
                uid: None,
                gid: None,
                pid: None,
            },
        }
    }
}

#[cfg(unix)]
impl Connected<IncomingStream<'_, tokio::net::UnixListener>> for UdsPeer {
    fn connect_info(stream: IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        Self::from_stream(stream.io())
    }
}

impl ControlState {
    pub fn new(
        runtime: RuntimeState,
        routing: RoutingState,
        state_store: BackendStateStore,
        runtime_file: PathBuf,
        quiet: bool,
    ) -> Self {
        Self {
            runtime,
            routing,
            state_store,
            runtime_file: Arc::new(runtime_file),
            operations: Arc::new(Mutex::new(HashMap::new())),
            lifecycle: Arc::new(AsyncMutex::new(())),
            quiet,
        }
    }

    pub fn router(self: Arc<Self>) -> Router {
        let routes = Router::new()
            .route("/backends", get(list_backends))
            .route("/backends/{id}", get(get_backend))
            .route("/backends/{id}/drain", post(start_drain))
            .route("/backends/{id}/activate", post(activate_backend))
            .route("/backends/{id}/disable", post(disable_backend))
            .route("/operations/{id}", get(get_operation))
            .route("/runtime/reload", post(reload_runtime));
        Router::new().nest("/control", routes).with_state(self)
    }

    pub fn resume_persisted_drains(&self) {
        for snapshot in self.runtime.registry().snapshots() {
            if snapshot.mode == BackendMode::Draining {
                let _ = self.ensure_drain_operation(snapshot.id().as_str());
            }
        }
    }

    async fn begin_drain(&self, id: &str) -> Result<Arc<DrainOperation>, ControlError> {
        let _lifecycle = self.lifecycle.lock().await;
        let backend_id = BackendId::from(id);
        let slot = self
            .runtime
            .registry()
            .get(&backend_id)
            .ok_or_else(|| ControlError::not_found(format!("unknown backend {id:?}")))?;
        let before = slot.snapshot().mode;
        slot.begin_drain();
        if before != BackendMode::Draining
            && let Err(error) = self.state_store.set_mode(id, BackendMode::Draining)
        {
            match before {
                BackendMode::Active => {
                    let _ = slot.activate();
                }
                BackendMode::Disabled => {
                    slot.disable();
                }
                BackendMode::Draining => unreachable!(),
            }
            return Err(ControlError::internal(format!(
                "could not persist drain fence: {error}"
            )));
        }
        let operation = self.ensure_drain_operation(id);
        if !self.quiet && before != BackendMode::Draining {
            println!(
                "INFO backend {id} entered draining (operation {})",
                operation.id
            );
        }
        Ok(operation)
    }

    fn ensure_drain_operation(&self, backend_id: &str) -> Arc<DrainOperation> {
        if let Some(existing) = self
            .lock_operations()
            .values()
            .find(|operation| {
                operation.backend_id == backend_id
                    && operation.progress.borrow().phase == DrainPhase::Draining
            })
            .cloned()
        {
            return existing;
        }

        let id = Uuid::new_v4();
        let status = self.routing.status(backend_id);
        let initial = DrainProgress {
            operation_id: id,
            backend_id: backend_id.to_owned(),
            phase: DrainPhase::Draining,
            safe_to_stop: false,
            elapsed_ms: 0,
            proxy_active: status.as_ref().map_or(0, |status| status.proxy_active),
            engine_running: status.as_ref().and_then(|status| status.running),
            engine_waiting: status.as_ref().and_then(|status| status.waiting),
            telemetry: status
                .as_ref()
                .map_or(TelemetryState::Unavailable, |status| status.telemetry),
            message: None,
        };
        let (progress, _) = watch::channel(initial);
        let operation = Arc::new(DrainOperation {
            id,
            backend_id: backend_id.to_owned(),
            started_at: Instant::now(),
            metrics_scrapes_started_at_start: status
                .as_ref()
                .map_or(0, |status| status.metrics_scrapes_started),
            progress,
        });
        self.lock_operations().insert(id, Arc::clone(&operation));
        let state = self.clone();
        let task_operation = Arc::clone(&operation);
        tokio::spawn(async move { state.drive_drain(task_operation).await });
        operation
    }

    async fn drive_drain(&self, operation: Arc<DrainOperation>) {
        loop {
            let Some(status) = self.routing.status(&operation.backend_id) else {
                operation.progress.send_replace(DrainProgress {
                    operation_id: operation.id,
                    backend_id: operation.backend_id.clone(),
                    phase: DrainPhase::Failed,
                    safe_to_stop: false,
                    elapsed_ms: elapsed_ms(operation.started_at),
                    proxy_active: 0,
                    engine_running: None,
                    engine_waiting: None,
                    telemetry: TelemetryState::Unavailable,
                    message: Some("backend disappeared while draining".to_owned()),
                });
                return;
            };
            if status.mode != BackendMode::Draining {
                let complete = status.mode == BackendMode::Disabled;
                operation.progress.send_replace(progress_from_status(
                    &operation,
                    &status,
                    if complete {
                        DrainPhase::Complete
                    } else {
                        DrainPhase::Cancelled
                    },
                    complete,
                    Some(if complete {
                        "backend is disabled".to_owned()
                    } else {
                        "drain was superseded".to_owned()
                    }),
                ));
                return;
            }

            let post_drain_samples = status
                .metrics_observation_serial
                .saturating_sub(operation.metrics_scrapes_started_at_start);
            let idle_samples = status.engine_idle_streak.min(post_drain_samples);
            let engine_idle = status.telemetry == TelemetryState::Fresh
                && status.running == Some(0)
                && status.waiting == Some(0)
                && idle_samples >= 2;

            if status.proxy_active == 0 && engine_idle {
                let _lifecycle = self.lifecycle.lock().await;
                let Some(confirmed) = self.routing.status(&operation.backend_id) else {
                    continue;
                };
                let confirmed_post_drain = confirmed
                    .metrics_observation_serial
                    .saturating_sub(operation.metrics_scrapes_started_at_start);
                if confirmed.mode != BackendMode::Draining
                    || confirmed.proxy_active != 0
                    || confirmed.telemetry != TelemetryState::Fresh
                    || confirmed.running != Some(0)
                    || confirmed.waiting != Some(0)
                    || confirmed.engine_idle_streak.min(confirmed_post_drain) < 2
                {
                    continue;
                }
                if let Err(error) = self
                    .state_store
                    .set_mode(&operation.backend_id, BackendMode::Disabled)
                {
                    operation.progress.send_replace(progress_from_status(
                        &operation,
                        &status,
                        DrainPhase::Failed,
                        false,
                        Some(format!("could not persist disabled state: {error}")),
                    ));
                    return;
                }
                let id = BackendId::from(operation.backend_id.as_str());
                if let Some(slot) = self.runtime.registry().get(&id) {
                    slot.disable();
                }
                let final_status = self
                    .routing
                    .status(&operation.backend_id)
                    .unwrap_or(confirmed);
                operation.progress.send_replace(progress_from_status(
                    &operation,
                    &final_status,
                    DrainPhase::Complete,
                    true,
                    Some("proxy and engine are idle".to_owned()),
                ));
                if !self.quiet {
                    println!(
                        "INFO backend {} drained and disabled in {}ms",
                        operation.backend_id,
                        elapsed_ms(operation.started_at)
                    );
                }
                return;
            }

            operation.progress.send_replace(progress_from_status(
                &operation,
                &status,
                DrainPhase::Draining,
                false,
                None,
            ));
            let interval = self.runtime.telemetry().scrape_interval_ms.min(1_000);
            tokio::time::sleep(Duration::from_millis(interval.max(100))).await;
        }
    }

    async fn activate(&self, id: &str) -> Result<ActionResponse, ControlError> {
        let _lifecycle = self.lifecycle.lock().await;
        let status = self
            .routing
            .status(id)
            .ok_or_else(|| ControlError::not_found(format!("unknown backend {id:?}")))?;
        match status.mode {
            BackendMode::Active => {
                return Ok(ActionResponse {
                    backend_id: id.to_owned(),
                    mode: BackendMode::Active,
                    message: "backend is already active".to_owned(),
                });
            }
            BackendMode::Draining => {
                return Err(ControlError::conflict(
                    "backend is draining; wait for it to become disabled before activating",
                ));
            }
            BackendMode::Disabled => {}
        }
        if status.readiness != ReadinessState::Ready {
            return Err(ControlError::conflict(format!(
                "backend is not ready ({})",
                status.readiness
            )));
        }
        if status.telemetry != TelemetryState::Fresh {
            return Err(ControlError::conflict(format!(
                "backend telemetry is {}",
                status.telemetry
            )));
        }

        // Remove the durable fence before opening the in-memory gate. A crash
        // can delay activation but cannot produce an acknowledged unsafe drain.
        let backend_id = BackendId::from(id);
        let slot = self
            .runtime
            .registry()
            .get(&backend_id)
            .ok_or_else(|| ControlError::not_found(format!("unknown backend {id:?}")))?;
        self.state_store
            .set_mode(id, BackendMode::Active)
            .map_err(|error| {
                ControlError::internal(format!("could not remove drain fence: {error}"))
            })?;
        if let Err(error) = slot.activate() {
            let rollback = self.state_store.set_mode(id, BackendMode::Disabled);
            let rollback_note = rollback.err().map_or(String::new(), |rollback| {
                format!("; rollback failed: {rollback}")
            });
            return Err(ControlError::conflict(format!(
                "could not activate backend: {error}{rollback_note}"
            )));
        }
        if !self.quiet {
            println!("INFO backend {id} activated");
        }
        Ok(ActionResponse {
            backend_id: id.to_owned(),
            mode: BackendMode::Active,
            message: "backend activated".to_owned(),
        })
    }

    /// Close the gate and persist the disabled fence without waiting for
    /// in-flight work.
    ///
    /// This is the escape hatch for a backend whose engine is dead: a normal
    /// drain can never observe the fresh idle telemetry samples it needs to
    /// complete. An in-progress drain notices the mode change on its next tick
    /// and completes itself, so a waiting `backend drain` client reports
    /// `safe to stop`.
    async fn disable(&self, id: &str, force: bool) -> Result<ActionResponse, ControlError> {
        let _lifecycle = self.lifecycle.lock().await;
        let status = self
            .routing
            .status(id)
            .ok_or_else(|| ControlError::not_found(format!("unknown backend {id:?}")))?;
        if status.mode == BackendMode::Disabled {
            return Ok(ActionResponse {
                backend_id: id.to_owned(),
                mode: BackendMode::Disabled,
                message: "backend is already disabled".to_owned(),
            });
        }
        if !force && status.proxy_active > 0 {
            return Err(ControlError::conflict(format!(
                "backend has {} in-flight proxy request{}; rerun with --force to disable anyway",
                status.proxy_active,
                if status.proxy_active == 1 { "" } else { "s" }
            )));
        }
        let backend_id = BackendId::from(id);
        let slot = self
            .runtime
            .registry()
            .get(&backend_id)
            .ok_or_else(|| ControlError::not_found(format!("unknown backend {id:?}")))?;
        // Persist the fence before closing the in-memory gate. A crash can
        // delay reactivation but cannot resurrect a removed backend.
        self.state_store
            .set_mode(id, BackendMode::Disabled)
            .map_err(|error| {
                ControlError::internal(format!("could not persist disabled state: {error}"))
            })?;
        let in_flight = status.proxy_active;
        slot.disable();
        if !self.quiet {
            println!("INFO backend {id} disabled (was {})", status.mode);
        }
        let message = if force && in_flight > 0 {
            format!(
                "backend disabled with {in_flight} in-flight request{} still running",
                if in_flight == 1 { "" } else { "s" }
            )
        } else {
            "backend disabled".to_owned()
        };
        Ok(ActionResponse {
            backend_id: id.to_owned(),
            mode: BackendMode::Disabled,
            message,
        })
    }

    async fn reload(&self) -> Result<ReloadResponse, ControlError> {
        let _lifecycle = self.lifecycle.lock().await;
        let modes = self.state_store.modes();
        let report = self
            .runtime
            .reload_with_modes(&self.runtime_file, &modes)
            .await
            .map_err(|error| ControlError::bad_request(error.to_string()))?;
        self.resume_persisted_drains();
        if !self.quiet {
            println!(
                "INFO runtime revision {} loaded from {}",
                report.revision,
                self.runtime_file.display()
            );
        }
        Ok(reload_response(report))
    }

    fn lock_operations(&self) -> MutexGuard<'_, HashMap<Uuid, Arc<DrainOperation>>> {
        self.operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn progress_from_status(
    operation: &DrainOperation,
    status: &BackendStatusSnapshot,
    phase: DrainPhase,
    safe_to_stop: bool,
    message: Option<String>,
) -> DrainProgress {
    DrainProgress {
        operation_id: operation.id,
        backend_id: operation.backend_id.clone(),
        phase,
        safe_to_stop,
        elapsed_ms: elapsed_ms(operation.started_at),
        proxy_active: status.proxy_active,
        engine_running: status.running,
        engine_waiting: status.waiting,
        telemetry: status.telemetry,
        message,
    }
}

fn elapsed_ms(started_at: Instant) -> u64 {
    started_at
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn reload_response(report: RuntimeReloadReport) -> ReloadResponse {
    ReloadResponse {
        revision: report.revision,
        added: report
            .reconciled
            .added
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
        revived: report
            .reconciled
            .revived
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
        updated: report
            .reconciled
            .updated
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
        retired: report
            .reconciled
            .retired
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
    }
}

async fn list_backends(
    State(state): State<Arc<ControlState>>,
    ConnectInfo(_peer): ConnectInfo<UdsPeer>,
) -> Json<BackendListResponse> {
    Json(BackendListResponse {
        runtime_revision: state.runtime.revision(),
        routing_policy: state.runtime.routing().policy.to_string(),
        backends: state
            .routing
            .statuses()
            .into_iter()
            .map(BackendView::from)
            .collect(),
    })
}

async fn get_backend(
    State(state): State<Arc<ControlState>>,
    ConnectInfo(_peer): ConnectInfo<UdsPeer>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<BackendView>, ControlError> {
    state
        .routing
        .status(&id)
        .map(BackendView::from)
        .map(Json)
        .ok_or_else(|| ControlError::not_found(format!("unknown backend {id:?}")))
}

async fn start_drain(
    State(state): State<Arc<ControlState>>,
    ConnectInfo(_peer): ConnectInfo<UdsPeer>,
    AxumPath(id): AxumPath<String>,
) -> Result<(StatusCode, Json<DrainStartedResponse>), ControlError> {
    let operation = state.begin_drain(&id).await?;
    let progress = operation.progress.borrow().clone();
    Ok((
        if progress.safe_to_stop {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        },
        Json(DrainStartedResponse {
            operation_id: operation.id,
            backend_id: id,
            mode: if progress.safe_to_stop {
                BackendMode::Disabled
            } else {
                BackendMode::Draining
            },
            safe_to_stop: progress.safe_to_stop,
        }),
    ))
}

async fn get_operation(
    State(state): State<Arc<ControlState>>,
    ConnectInfo(_peer): ConnectInfo<UdsPeer>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<DrainProgress>, ControlError> {
    let operation = state
        .lock_operations()
        .get(&id)
        .cloned()
        .ok_or_else(|| ControlError::not_found(format!("unknown operation {id}")))?;
    let progress = operation.progress.borrow().clone();
    Ok(Json(progress))
}

async fn activate_backend(
    State(state): State<Arc<ControlState>>,
    ConnectInfo(_peer): ConnectInfo<UdsPeer>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ActionResponse>, ControlError> {
    state.activate(&id).await.map(Json)
}

#[derive(Debug, Deserialize)]
struct DisableQuery {
    force: Option<bool>,
}

async fn disable_backend(
    State(state): State<Arc<ControlState>>,
    ConnectInfo(_peer): ConnectInfo<UdsPeer>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<DisableQuery>,
) -> Result<Json<ActionResponse>, ControlError> {
    state
        .disable(&id, query.force.unwrap_or(false))
        .await
        .map(Json)
}

async fn reload_runtime(
    State(state): State<Arc<ControlState>>,
    ConnectInfo(_peer): ConnectInfo<UdsPeer>,
) -> Result<Json<ReloadResponse>, ControlError> {
    state.reload().await.map(Json)
}

#[derive(Debug)]
pub struct ControlError {
    status: StatusCode,
    message: String,
}

impl ControlError {
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ControlError {}

impl IntoResponse for ControlError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

/// Bind a control socket without ever deleting a non-socket path. A socket
/// that still accepts connections is treated as another live proxy instance.
#[cfg(unix)]
pub async fn bind_control_socket(path: &Path) -> io::Result<tokio::net::UnixListener> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_socket() => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "control socket path {} exists and is not a socket",
                    path.display()
                ),
            ));
        }
        Ok(_) => match tokio::net::UnixStream::connect(path).await {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "a control server is already listening at {}",
                        path.display()
                    ),
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                fs::remove_file(path)?;
            }
            Err(error) => return Err(error),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o660);
    fs::set_permissions(path, permissions)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        routing::RoutingState,
        runtime::{Backend, RuntimeConfig},
    };

    fn idle_metrics() -> crate::telemetry::MistralRsMetrics {
        crate::telemetry::MistralRsMetrics {
            sequences_running: 0,
            sequences_waiting: 0,
            sequences_capacity: Some(32),
            kv_cache: None,
            tokens_processed_total: None,
            prefill_tokens_processed_total: None,
            decode_tokens_processed_total: None,
            sequences_completed_total: None,
        }
    }

    fn state() -> (ControlState, PathBuf, PathBuf) {
        let mut config = RuntimeConfig::new(vec![Backend::new(
            "a",
            "http://127.0.0.1:1".parse().unwrap(),
        )]);
        config.telemetry.scrape_interval_ms = 100;
        let runtime = RuntimeState::from_config(config);
        let routing = RoutingState::new_assume_ready(runtime.clone());
        routing.record_metrics_success("a", idle_metrics());
        let state_path = std::env::temp_dir().join(format!("state-{}.json", Uuid::new_v4()));
        let runtime_path = std::env::temp_dir().join(format!("runtime-{}.toml", Uuid::new_v4()));
        let store = BackendStateStore::load(&state_path).unwrap();
        (
            ControlState::new(runtime, routing, store, runtime_path.clone(), true),
            state_path,
            runtime_path,
        )
    }

    #[tokio::test]
    async fn drain_installs_a_durable_fence_and_completes_after_two_samples() {
        let (state, state_path, runtime_path) = state();
        let operation = state.begin_drain("a").await.unwrap();
        assert_eq!(
            state.runtime.registry().snapshots()[0].mode,
            BackendMode::Draining
        );
        assert_eq!(
            BackendStateStore::load(&state_path).unwrap().modes()["a"],
            BackendMode::Draining
        );

        // Both confirmations must be distinct idle observations made after
        // the acquisition gate closed.
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            state.routing.record_metrics_success("a", idle_metrics());
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if operation.progress.borrow().safe_to_stop {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            state.runtime.registry().snapshots()[0].mode,
            BackendMode::Disabled
        );
        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(runtime_path);
    }

    #[tokio::test]
    async fn a_scrape_started_before_drain_does_not_count_as_a_confirmation() {
        let (state, state_path, runtime_path) = state();
        let generation = state.runtime.backend_generation("a").unwrap();
        let in_flight = state.routing.begin_metrics_scrape("a", generation).unwrap();
        let operation = state.begin_drain("a").await.unwrap();

        state
            .routing
            .record_metrics_success_for("a", generation, idle_metrics(), in_flight);
        state.routing.record_metrics_success("a", idle_metrics());
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!operation.progress.borrow().safe_to_stop);

        state.routing.record_metrics_success("a", idle_metrics());
        tokio::time::timeout(Duration::from_secs(2), async {
            while !operation.progress.borrow().safe_to_stop {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(runtime_path);
    }

    #[tokio::test]
    async fn draining_an_already_disabled_backend_recertifies_it() {
        let (state, state_path, runtime_path) = state();
        let id = BackendId::from("a");
        state.runtime.registry().get(&id).unwrap().disable();
        state
            .state_store
            .set_mode("a", BackendMode::Disabled)
            .unwrap();

        let operation = state.begin_drain("a").await.unwrap();
        assert!(!operation.progress.borrow().safe_to_stop);
        assert_eq!(
            state.runtime.registry().get(&id).unwrap().snapshot().mode,
            BackendMode::Draining
        );
        for _ in 0..2 {
            state.routing.record_metrics_success("a", idle_metrics());
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while !operation.progress.borrow().safe_to_stop {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            state.runtime.registry().get(&id).unwrap().snapshot().mode,
            BackendMode::Disabled
        );
        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(runtime_path);
    }

    #[tokio::test]
    async fn activation_requires_fresh_ready_telemetry() {
        let (state, state_path, runtime_path) = state();
        let slot = state.runtime.registry().snapshots()[0].id().clone();
        state.runtime.registry().get(&slot).unwrap().disable();
        state
            .state_store
            .set_mode("a", BackendMode::Disabled)
            .unwrap();
        assert!(state.activate("a").await.is_ok());
        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(runtime_path);
    }

    #[tokio::test]
    async fn disable_closes_the_gate_and_persists_the_fence_immediately() {
        let (state, state_path, runtime_path) = state();
        let response = state.disable("a", false).await.unwrap();
        assert_eq!(response.mode, BackendMode::Disabled);
        assert_eq!(response.message, "backend disabled");
        assert_eq!(
            state.runtime.registry().snapshots()[0].mode,
            BackendMode::Disabled
        );
        assert_eq!(
            BackendStateStore::load(&state_path).unwrap().modes()["a"],
            BackendMode::Disabled
        );
        // Repeating the command is an idempotent no-op.
        let again = state.disable("a", false).await.unwrap();
        assert_eq!(again.message, "backend is already disabled");
        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(runtime_path);
    }

    #[tokio::test]
    async fn disable_refuses_in_flight_requests_without_force() {
        let (state, state_path, runtime_path) = state();
        let id = BackendId::from("a");
        let lease = state.runtime.registry().try_acquire(&id).unwrap();

        let conflict = state.disable("a", false).await.unwrap_err();
        assert!(conflict.to_string().contains("in-flight"), "{conflict}");
        assert_eq!(
            state.runtime.registry().snapshots()[0].mode,
            BackendMode::Active
        );

        let response = state.disable("a", true).await.unwrap();
        assert_eq!(
            state.runtime.registry().snapshots()[0].mode,
            BackendMode::Disabled
        );
        assert_eq!(
            response.message,
            "backend disabled with 1 in-flight request still running"
        );
        // The in-flight request keeps its lease; the gate only blocks new work.
        assert_eq!(state.runtime.registry().snapshots()[0].local_active, 1);
        drop(lease);
        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(runtime_path);
    }

    #[tokio::test]
    async fn disabling_a_draining_backend_completes_its_operation() {
        let (state, state_path, runtime_path) = state();
        let operation = state.begin_drain("a").await.unwrap();
        assert!(!operation.progress.borrow().safe_to_stop);

        state.disable("a", true).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while operation.progress.borrow().phase != DrainPhase::Complete {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let progress = operation.progress.borrow().clone();
        assert!(progress.safe_to_stop);
        assert_eq!(progress.phase, DrainPhase::Complete);
        assert_eq!(progress.message.as_deref(), Some("backend is disabled"));
        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(runtime_path);
    }

    #[tokio::test]
    async fn disabling_an_unknown_backend_is_a_not_found() {
        let (state, state_path, runtime_path) = state();
        let error = state.disable("ghost", true).await.unwrap_err();
        assert!(error.to_string().contains("unknown backend"), "{error}");
        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(runtime_path);
    }
}
