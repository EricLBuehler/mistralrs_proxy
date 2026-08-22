//! Declarative runtime configuration and its atomically published live view.
//!
//! `runtime.toml` describes backend topology and policy. Operator state such as
//! drains is deliberately not part of this file; it is owned by the control
//! plane and persisted separately. Configuration changes are applied only by
//! an explicit control-plane reload, never by a polling loop.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, RwLock},
};

use axum::http::Uri;
use serde::Deserialize;

use crate::backend::{
    BackendId, BackendMode, BackendRegistry, BackendSpec, ReconcileError, ReconcileReport,
};

pub const RUNTIME_SCHEMA_VERSION: u32 = 1;

const DEFAULT_METRICS_PATH: &str = "/metrics";
const DEFAULT_READINESS_PATH: &str = "/v1/models";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingPolicy {
    LeastPressureV1,
}

impl fmt::Display for RoutingPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeastPressureV1 => formatter.write_str("least-pressure-v1"),
        }
    }
}

fn default_policy() -> RoutingPolicy {
    RoutingPolicy::LeastPressureV1
}

fn default_kv_soft_limit() -> f64 {
    0.85
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default = "default_policy")]
    pub policy: RoutingPolicy,
    #[serde(default = "default_kv_soft_limit")]
    pub kv_soft_limit: f64,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            policy: default_policy(),
            kv_soft_limit: default_kv_soft_limit(),
        }
    }
}

fn default_scrape_interval_ms() -> u64 {
    1_000
}

fn default_scrape_timeout_ms() -> u64 {
    750
}

fn default_stale_after_ms() -> u64 {
    5_000
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default = "default_scrape_interval_ms")]
    pub scrape_interval_ms: u64,
    #[serde(default = "default_scrape_timeout_ms")]
    pub scrape_timeout_ms: u64,
    #[serde(default = "default_stale_after_ms")]
    pub stale_after_ms: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            scrape_interval_ms: default_scrape_interval_ms(),
            scrape_timeout_ms: default_scrape_timeout_ms(),
            stale_after_ms: default_stale_after_ms(),
        }
    }
}

fn default_probe_interval_ms() -> u64 {
    2_000
}

fn default_probe_timeout_ms() -> u64 {
    1_000
}

fn default_success_threshold() -> u32 {
    2
}

fn default_failure_threshold() -> u32 {
    3
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ReadinessConfig {
    #[serde(default = "default_probe_interval_ms")]
    pub probe_interval_ms: u64,
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
}

impl Default for ReadinessConfig {
    fn default() -> Self {
        Self {
            probe_interval_ms: default_probe_interval_ms(),
            probe_timeout_ms: default_probe_timeout_ms(),
            success_threshold: default_success_threshold(),
            failure_threshold: default_failure_threshold(),
        }
    }
}

/// One validated backend definition. Membership means the backend belongs to
/// the routing pool; its operator mode is stored elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub id: String,
    pub url: Uri,
    pub metrics_url: Uri,
    pub readiness_url: Uri,
    /// Optional proxy-side safety ceiling and compatibility fallback.
    pub capacity: Option<u64>,
}

impl Backend {
    pub fn new(id: impl Into<String>, url: Uri) -> Self {
        let metrics_url = append_path(&url, DEFAULT_METRICS_PATH)
            .expect("a validated backend URL accepts a metrics path");
        let readiness_url = append_path(&url, DEFAULT_READINESS_PATH)
            .expect("a validated backend URL accepts a readiness path");
        Self {
            id: id.into(),
            url,
            metrics_url,
            readiness_url,
            capacity: None,
        }
    }

    pub fn registry_spec(&self) -> BackendSpec {
        BackendSpec::new(self.id.clone(), self.url.to_string())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeConfig {
    pub backends: Vec<Backend>,
    pub routing: RoutingConfig,
    pub telemetry: TelemetryConfig,
    pub readiness: ReadinessConfig,
    pub registration: RegistrationConfig,
}

impl RuntimeConfig {
    pub fn new(backends: Vec<Backend>) -> Self {
        Self {
            backends,
            routing: RoutingConfig::default(),
            telemetry: TelemetryConfig::default(),
            readiness: ReadinessConfig::default(),
            registration: RegistrationConfig::default(),
        }
    }
}

/// Runtime controls for the public API-key registration page.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RegistrationConfig {
    pub enabled: bool,
    pub max_keys: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeFile {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    backends: Vec<BackendFile>,
    #[serde(default)]
    routing: RoutingConfig,
    #[serde(default)]
    telemetry: TelemetryConfig,
    #[serde(default)]
    readiness: ReadinessConfig,
    #[serde(default)]
    registration: RegistrationConfig,
}

fn default_schema_version() -> u32 {
    RUNTIME_SCHEMA_VERSION
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendFile {
    id: String,
    url: String,
    metrics_url: Option<String>,
    readiness_url: Option<String>,
    capacity: Option<u64>,
}

impl RuntimeConfig {
    pub async fn load(path: &Path) -> Result<Self, RuntimeConfigError> {
        let contents =
            tokio::fs::read_to_string(path)
                .await
                .map_err(|source| RuntimeConfigError::Read {
                    path: path.to_owned(),
                    source,
                })?;
        Self::parse(&contents)
    }

    pub fn parse(contents: &str) -> Result<Self, RuntimeConfigError> {
        let file: RuntimeFile = toml::from_str(contents).map_err(RuntimeConfigError::Parse)?;
        if file.schema_version != RUNTIME_SCHEMA_VERSION {
            return Err(RuntimeConfigError::Validation(format!(
                "unsupported runtime schema version {} (this build understands {RUNTIME_SCHEMA_VERSION})",
                file.schema_version
            )));
        }
        if file.backends.is_empty() {
            return Err(RuntimeConfigError::Validation(
                "runtime config must contain at least one backend".to_owned(),
            ));
        }
        validate_controls(&file)?;

        let mut ids = HashSet::new();
        let mut backends = Vec::with_capacity(file.backends.len());
        for raw in file.backends {
            validate_backend_id(&raw.id)?;
            if !ids.insert(raw.id.clone()) {
                return Err(RuntimeConfigError::Validation(format!(
                    "backend id {:?} appears more than once",
                    raw.id
                )));
            }

            let url = parse_backend_url(&raw.id, "url", &raw.url)?;
            let metrics_url = match raw.metrics_url {
                Some(value) => parse_backend_url(&raw.id, "metrics_url", &value)?,
                None => append_path(&url, DEFAULT_METRICS_PATH).map_err(|reason| {
                    RuntimeConfigError::InvalidBackendUrl {
                        id: raw.id.clone(),
                        field: "metrics_url",
                        url: url.to_string(),
                        reason,
                    }
                })?,
            };
            let readiness_url = match raw.readiness_url {
                Some(value) => parse_backend_url(&raw.id, "readiness_url", &value)?,
                None => append_path(&url, DEFAULT_READINESS_PATH).map_err(|reason| {
                    RuntimeConfigError::InvalidBackendUrl {
                        id: raw.id.clone(),
                        field: "readiness_url",
                        url: url.to_string(),
                        reason,
                    }
                })?,
            };
            if raw.capacity == Some(0) {
                return Err(RuntimeConfigError::Validation(format!(
                    "backend {:?} capacity must be positive",
                    raw.id
                )));
            }
            backends.push(Backend {
                id: raw.id,
                url,
                metrics_url,
                readiness_url,
                capacity: raw.capacity,
            });
        }

        Ok(Self {
            backends,
            routing: file.routing,
            telemetry: file.telemetry,
            readiness: file.readiness,
            registration: file.registration,
        })
    }
}

fn validate_controls(file: &RuntimeFile) -> Result<(), RuntimeConfigError> {
    if !(0.0..1.0).contains(&file.routing.kv_soft_limit) {
        return Err(RuntimeConfigError::Validation(
            "routing.kv_soft_limit must be greater than or equal to 0 and less than 1".to_owned(),
        ));
    }
    for (name, value) in [
        (
            "telemetry.scrape_interval_ms",
            file.telemetry.scrape_interval_ms,
        ),
        (
            "telemetry.scrape_timeout_ms",
            file.telemetry.scrape_timeout_ms,
        ),
        ("telemetry.stale_after_ms", file.telemetry.stale_after_ms),
        (
            "readiness.probe_interval_ms",
            file.readiness.probe_interval_ms,
        ),
        (
            "readiness.probe_timeout_ms",
            file.readiness.probe_timeout_ms,
        ),
    ] {
        if value == 0 {
            return Err(RuntimeConfigError::Validation(format!(
                "{name} must be positive"
            )));
        }
    }
    if file.telemetry.stale_after_ms < file.telemetry.scrape_interval_ms {
        return Err(RuntimeConfigError::Validation(
            "telemetry.stale_after_ms must be at least telemetry.scrape_interval_ms".to_owned(),
        ));
    }
    if file.readiness.success_threshold == 0 || file.readiness.failure_threshold == 0 {
        return Err(RuntimeConfigError::Validation(
            "readiness thresholds must be positive".to_owned(),
        ));
    }
    Ok(())
}

fn validate_backend_id(id: &str) -> Result<(), RuntimeConfigError> {
    if id.is_empty() || id.len() > 64 {
        return Err(RuntimeConfigError::Validation(
            "backend ids must contain between 1 and 64 characters".to_owned(),
        ));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RuntimeConfigError::Validation(format!(
            "backend id {id:?} may contain only ASCII letters, digits, '-', '_' and '.'"
        )));
    }
    Ok(())
}

fn parse_backend_url(
    id: &str,
    field: &'static str,
    value: &str,
) -> Result<Uri, RuntimeConfigError> {
    let uri = value
        .parse::<Uri>()
        .map_err(|error| RuntimeConfigError::InvalidBackendUrl {
            id: id.to_owned(),
            field,
            url: value.to_owned(),
            reason: format!("invalid URI: {error}"),
        })?;
    validate_uri(&uri).map_err(|reason| RuntimeConfigError::InvalidBackendUrl {
        id: id.to_owned(),
        field,
        url: value.to_owned(),
        reason,
    })?;
    Ok(uri)
}

fn validate_uri(uri: &Uri) -> Result<(), String> {
    if uri.scheme_str() != Some("http") {
        return Err("URL must use http:// (this build has no TLS connector)".to_owned());
    }
    let Some(authority) = uri.authority() else {
        return Err("URL must include a host".to_owned());
    };
    if authority.as_str().contains('@') {
        return Err("URL cannot include user information".to_owned());
    }
    if uri.query().is_some() {
        return Err("URL cannot include a query string".to_owned());
    }
    Ok(())
}

fn append_path(base: &Uri, suffix: &str) -> Result<Uri, String> {
    let base_path = base.path().trim_end_matches('/');
    let suffix = suffix.trim_start_matches('/');
    let path = if base_path.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base_path}/{suffix}")
    };
    Uri::builder()
        .scheme(base.scheme().cloned().ok_or("URL has no scheme")?)
        .authority(base.authority().cloned().ok_or("URL has no authority")?)
        .path_and_query(path)
        .build()
        .map_err(|error| error.to_string())
}

#[derive(Debug)]
pub enum RuntimeConfigError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse(toml::de::Error),
    Validation(String),
    InvalidBackendUrl {
        id: String,
        field: &'static str,
        url: String,
        reason: String,
    },
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "could not read {}: {source}", path.display())
            }
            Self::Parse(source) => write!(formatter, "invalid runtime TOML: {source}"),
            Self::Validation(message) => formatter.write_str(message),
            Self::InvalidBackendUrl {
                id,
                field,
                url,
                reason,
            } => write!(
                formatter,
                "backend {id:?} has invalid {field} {url:?}: {reason}"
            ),
        }
    }
}

impl Error for RuntimeConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::Validation(_) | Self::InvalidBackendUrl { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
struct PublishedRuntime {
    config: RuntimeConfig,
    revision: u64,
    backend_generations: HashMap<String, u64>,
    next_backend_generation: u64,
}

/// Atomically published declarative configuration plus the stable backend
/// registry. Registry slots outlive configuration generations so leases and
/// drains cannot be lost during reload.
#[derive(Clone, Debug)]
pub struct RuntimeState {
    inner: Arc<RwLock<PublishedRuntime>>,
    registry: Arc<BackendRegistry>,
    apply_lock: Arc<Mutex<()>>,
}

impl RuntimeState {
    pub fn new(backends: Vec<Backend>) -> Self {
        Self::from_config(RuntimeConfig::new(backends))
    }

    pub fn from_config(config: RuntimeConfig) -> Self {
        let registry = Arc::new(BackendRegistry::new());
        let report = registry
            .reconcile(config.backends.iter().map(Backend::registry_spec))
            .expect("RuntimeConfig already rejected duplicate backend ids");
        for id in report.added {
            registry
                .get(&id)
                .expect("the backend was just added")
                .activate()
                .expect("a registered backend can be activated");
        }
        let mut backend_generations = HashMap::new();
        let mut next_backend_generation = 1_u64;
        for backend in &config.backends {
            backend_generations.insert(backend.id.clone(), next_backend_generation);
            next_backend_generation = next_backend_generation
                .checked_add(1)
                .expect("backend generation exhausted");
        }
        Self {
            inner: Arc::new(RwLock::new(PublishedRuntime {
                config,
                revision: 1,
                backend_generations,
                next_backend_generation,
            })),
            registry,
            apply_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn registry(&self) -> Arc<BackendRegistry> {
        Arc::clone(&self.registry)
    }

    pub fn revision(&self) -> u64 {
        self.read().revision
    }

    pub fn backends(&self) -> Vec<Backend> {
        self.read().config.backends.clone()
    }

    /// Return one coherent topology snapshot for a probe cycle. The
    /// generation changes whenever a backend is added, revived, or any of its
    /// request/metrics/readiness endpoints changes, allowing late results from
    /// an older endpoint to be discarded.
    pub fn backend_instances(&self) -> Vec<(Backend, u64)> {
        let published = self.read();
        published
            .config
            .backends
            .iter()
            .map(|backend| {
                let generation = published.backend_generations[&backend.id];
                (backend.clone(), generation)
            })
            .collect()
    }

    pub fn backend_generation(&self, id: &str) -> Option<u64> {
        self.read().backend_generations.get(id).copied()
    }

    /// Transitional lookup used until the forwarding layer is wired to
    /// lease-returning routing. It deliberately checks the operator gate.
    pub fn available(&self) -> Option<Backend> {
        self.registry
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.mode == BackendMode::Active)
            .and_then(|snapshot| self.backend(snapshot.id().as_str()))
    }

    pub fn configured(&self) -> Backend {
        self.backends()
            .into_iter()
            .next()
            .expect("runtime config always has at least one backend")
    }

    pub fn backend(&self, id: &str) -> Option<Backend> {
        self.read()
            .config
            .backends
            .iter()
            .find(|backend| backend.id == id)
            .cloned()
    }

    pub fn registration(&self) -> RegistrationConfig {
        self.read().config.registration
    }

    pub fn routing(&self) -> RoutingConfig {
        self.read().config.routing.clone()
    }

    pub fn telemetry(&self) -> TelemetryConfig {
        self.read().config.telemetry.clone()
    }

    pub fn readiness(&self) -> ReadinessConfig {
        self.read().config.readiness.clone()
    }

    /// Apply an already validated candidate. Endpoint changes and removals are
    /// permitted only after a backend is disabled and locally idle.
    pub fn apply(&self, config: RuntimeConfig) -> Result<RuntimeReloadReport, RuntimeApplyError> {
        self.apply_with_modes(config, &HashMap::new())
    }

    /// Apply configuration and a durable operator overlay as one publication.
    /// New/revived slots never become routable before their persisted mode has
    /// been restored.
    pub fn apply_with_modes(
        &self,
        config: RuntimeConfig,
        modes: &HashMap<String, BackendMode>,
    ) -> Result<RuntimeReloadReport, RuntimeApplyError> {
        let _apply = self.lock_apply();
        let (current, current_generations, mut next_backend_generation) = {
            let published = self.read();
            (
                published.config.backends.clone(),
                published.backend_generations.clone(),
                published.next_backend_generation,
            )
        };
        let desired: HashMap<&str, &Backend> = config
            .backends
            .iter()
            .map(|backend| (backend.id.as_str(), backend))
            .collect();
        for old in &current {
            let changes_endpoint = desired.get(old.id.as_str()).is_some_and(|new| {
                new.url != old.url
                    || new.metrics_url != old.metrics_url
                    || new.readiness_url != old.readiness_url
            });
            let removed = !desired.contains_key(old.id.as_str());
            if changes_endpoint || removed {
                let id = BackendId::from(old.id.as_str());
                if let Some(snapshot) = self.registry.get_retained(&id).map(|slot| slot.snapshot())
                    && (snapshot.mode != BackendMode::Disabled || snapshot.local_active != 0)
                {
                    return Err(RuntimeApplyError::BackendMustBeDisabled {
                        backend_id: old.id.clone(),
                        change: if removed {
                            "removed"
                        } else {
                            "changed endpoints"
                        },
                    });
                }
            }
        }

        let current_by_id: HashMap<&str, &Backend> = current
            .iter()
            .map(|backend| (backend.id.as_str(), backend))
            .collect();
        let mut backend_generations = HashMap::with_capacity(config.backends.len());
        for backend in &config.backends {
            let generation = match current_by_id.get(backend.id.as_str()) {
                Some(old)
                    if old.url == backend.url
                        && old.metrics_url == backend.metrics_url
                        && old.readiness_url == backend.readiness_url =>
                {
                    current_generations[&backend.id]
                }
                _ => {
                    let generation = next_backend_generation;
                    next_backend_generation = next_backend_generation
                        .checked_add(1)
                        .expect("backend generation exhausted");
                    generation
                }
            };
            backend_generations.insert(backend.id.clone(), generation);
        }

        let reconciled = self
            .registry
            .reconcile(config.backends.iter().map(Backend::registry_spec))?;
        for id in reconciled.added.iter().chain(&reconciled.revived) {
            let slot = self.registry.get(id).expect("the backend is registered");
            match modes
                .get(id.as_str())
                .copied()
                .unwrap_or(BackendMode::Active)
            {
                BackendMode::Active => {
                    slot.activate()
                        .expect("a registered backend can be activated");
                }
                BackendMode::Draining => {
                    slot.begin_drain();
                }
                BackendMode::Disabled => {
                    slot.disable();
                }
            }
        }
        // Reassert stored fences for existing members too. Missing entries do
        // not override their current in-memory mode.
        for snapshot in self.registry.snapshots() {
            let Some(mode) = modes.get(snapshot.id().as_str()).copied() else {
                continue;
            };
            let slot = self
                .registry
                .get(snapshot.id())
                .expect("snapshot came from the registry");
            match mode {
                BackendMode::Active => {
                    slot.activate()
                        .expect("a registered backend can be activated");
                }
                BackendMode::Draining => {
                    slot.begin_drain();
                }
                BackendMode::Disabled => {
                    slot.disable();
                }
            }
        }

        let mut published = self.write();
        published.config = config;
        published.backend_generations = backend_generations;
        published.next_backend_generation = next_backend_generation;
        published.revision = published
            .revision
            .checked_add(1)
            .expect("runtime revision exhausted");
        Ok(RuntimeReloadReport {
            revision: published.revision,
            reconciled,
        })
    }

    pub async fn reload(&self, path: &Path) -> Result<RuntimeReloadReport, RuntimeReloadError> {
        let config = RuntimeConfig::load(path).await?;
        Ok(self.apply(config)?)
    }

    pub async fn reload_with_modes(
        &self,
        path: &Path,
        modes: &HashMap<String, BackendMode>,
    ) -> Result<RuntimeReloadReport, RuntimeReloadError> {
        let config = RuntimeConfig::load(path).await?;
        Ok(self.apply_with_modes(config, modes)?)
    }

    /// Restore durable non-active modes before the public listener accepts
    /// traffic. Missing entries intentionally mean active.
    pub fn restore_modes(&self, modes: &HashMap<String, BackendMode>) {
        for snapshot in self.registry.snapshots() {
            let Some(mode) = modes.get(snapshot.id().as_str()) else {
                continue;
            };
            let slot = self
                .registry
                .get(snapshot.id())
                .expect("snapshot came from the registry");
            match mode {
                BackendMode::Active => {
                    let _ = slot.activate();
                }
                BackendMode::Draining => {
                    slot.begin_drain();
                }
                BackendMode::Disabled => {
                    slot.disable();
                }
            }
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, PublishedRuntime> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, PublishedRuntime> {
        self.inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_apply(&self) -> MutexGuard<'_, ()> {
        self.apply_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeReloadReport {
    pub revision: u64,
    pub reconciled: ReconcileReport,
}

#[derive(Debug)]
pub enum RuntimeApplyError {
    Reconcile(ReconcileError),
    BackendMustBeDisabled {
        backend_id: String,
        change: &'static str,
    },
}

impl fmt::Display for RuntimeApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reconcile(error) => error.fmt(formatter),
            Self::BackendMustBeDisabled { backend_id, change } => write!(
                formatter,
                "backend {backend_id:?} must be disabled and idle before it can be {change}"
            ),
        }
    }
}

impl Error for RuntimeApplyError {}

impl From<ReconcileError> for RuntimeApplyError {
    fn from(error: ReconcileError) -> Self {
        Self::Reconcile(error)
    }
}

#[derive(Debug)]
pub enum RuntimeReloadError {
    Config(RuntimeConfigError),
    Apply(RuntimeApplyError),
}

impl fmt::Display for RuntimeReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => error.fmt(formatter),
            Self::Apply(error) => error.fmt(formatter),
        }
    }
}

impl Error for RuntimeReloadError {}

impl From<RuntimeConfigError> for RuntimeReloadError {
    fn from(error: RuntimeConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<RuntimeApplyError> for RuntimeReloadError {
    fn from(error: RuntimeApplyError) -> Self {
        Self::Apply(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
schema_version = 1

[routing]
policy = "least-pressure-v1"
kv_soft_limit = 0.85

[telemetry]
scrape_interval_ms = 1000
scrape_timeout_ms = 750
stale_after_ms = 5000

[readiness]
probe_interval_ms = 2000
probe_timeout_ms = 1000
success_threshold = 2
failure_threshold = 3

[[backends]]
id = "gh200-a"
url = "http://127.0.0.1:1234"
capacity = 32
"#;

    #[test]
    fn parses_the_complete_runtime_schema_and_derives_probe_urls() {
        let config = RuntimeConfig::parse(CONFIG).unwrap();
        assert_eq!(config.backends.len(), 1);
        let backend = &config.backends[0];
        assert_eq!(backend.id, "gh200-a");
        assert_eq!(backend.metrics_url, "http://127.0.0.1:1234/metrics");
        assert_eq!(backend.readiness_url, "http://127.0.0.1:1234/v1/models");
        assert_eq!(backend.capacity, Some(32));
        assert_eq!(config.routing.policy, RoutingPolicy::LeastPressureV1);
    }

    #[test]
    fn supports_multiple_backends_with_explicit_probe_urls() {
        let config = RuntimeConfig::parse(&format!(
            "{CONFIG}\n[[backends]]\nid = \"gpu-b\"\nurl = \"http://127.0.0.1:2/base\"\nmetrics_url = \"http://127.0.0.1:3/custom-metrics\"\nreadiness_url = \"http://127.0.0.1:3/ready\"\n"
        ))
        .unwrap();
        assert_eq!(config.backends.len(), 2);
        assert_eq!(
            config.backends[1].metrics_url,
            "http://127.0.0.1:3/custom-metrics"
        );
    }

    #[test]
    fn enabled_and_initial_mode_are_not_configuration_fields() {
        for obsolete in ["enabled = true", "initial_mode = \"active\""] {
            let contents = CONFIG.replace("capacity = 32", obsolete);
            assert!(
                RuntimeConfig::parse(&contents).is_err(),
                "accepted {obsolete}"
            );
        }
    }

    #[test]
    fn rejects_empty_duplicate_or_invalid_backend_ids() {
        assert!(RuntimeConfig::parse("schema_version = 1\nbackends = []").is_err());
        assert!(RuntimeConfig::parse(&format!("{CONFIG}{CONFIG}")).is_err());
        assert!(RuntimeConfig::parse(&CONFIG.replace("gh200-a", "bad id")).is_err());
    }

    #[test]
    fn validates_urls_and_control_ranges() {
        assert!(
            RuntimeConfig::parse(&CONFIG.replace("http://127.0.0.1:1234", "https://x")).is_err()
        );
        assert!(
            RuntimeConfig::parse(&CONFIG.replace("kv_soft_limit = 0.85", "kv_soft_limit = 1.0"))
                .is_err()
        );
        assert!(
            RuntimeConfig::parse(&CONFIG.replace("stale_after_ms = 5000", "stale_after_ms = 1"))
                .is_err()
        );
    }

    #[test]
    fn reload_preserves_modes_and_requires_a_safe_endpoint_change() {
        let initial = RuntimeConfig::parse(CONFIG).unwrap();
        let runtime = RuntimeState::from_config(initial.clone());
        let id = BackendId::from("gh200-a");
        let slot = runtime.registry().get(&id).unwrap();
        let lease = slot.try_acquire().unwrap();
        slot.begin_drain();

        let mut changed = initial;
        changed.backends[0].url = "http://127.0.0.1:9999".parse().unwrap();
        assert!(matches!(
            runtime.apply(changed.clone()),
            Err(RuntimeApplyError::BackendMustBeDisabled { .. })
        ));

        drop(lease);
        slot.disable();
        runtime.apply(changed).unwrap();
        assert_eq!(slot.snapshot().mode, BackendMode::Disabled);
    }
}
