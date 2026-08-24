//! Live readiness, telemetry, circuit breaking, and `least-pressure-v1` routing.

use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::{BodyExt, Limited};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::{
    backend::{BackendId, BackendLease, BackendMode, BackendSnapshot},
    runtime::{Backend, RuntimeState},
    telemetry::{
        LeastPressureV1Score, MistralRsMetrics, least_pressure_v1_with_soft_limit,
        parse_mistralrs_metrics,
    },
};

const CIRCUIT_FAILURE_THRESHOLD: u32 = 3;
const CIRCUIT_OPEN_FOR: Duration = Duration::from_secs(10);
const MAX_PROBE_BODY_BYTES: usize = 2 * 1024 * 1024;

pub type HttpClient = Client<HttpConnector, Body>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Checking,
    Ready,
    Unready,
    Unreachable,
}

impl fmt::Display for ReadinessState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Checking => "checking",
            Self::Ready => "ready",
            Self::Unready => "unready",
            Self::Unreachable => "unreachable",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryState {
    Fresh,
    Stale,
    Unavailable,
}

impl fmt::Display for TelemetryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Unavailable => "unavailable",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl fmt::Display for CircuitState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendDisplayState {
    Disabled,
    Draining,
    Checking,
    Unreachable,
    Unready,
    CircuitOpen,
    Probing,
    Degraded,
    Ready,
}

impl fmt::Display for BackendDisplayState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Disabled => "disabled",
            Self::Draining => "draining",
            Self::Checking => "checking",
            Self::Unreachable => "unreachable",
            Self::Unready => "unready",
            Self::CircuitOpen => "circuit-open",
            Self::Probing => "probing",
            Self::Degraded => "degraded",
            Self::Ready => "ready",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessFailureKind {
    Unready,
    Unreachable,
}

#[derive(Clone, Debug)]
struct MetricsObservation {
    metrics: MistralRsMetrics,
    observed_at: Instant,
    dispatches_at_observation: u64,
    scrape_serial: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MetricsScrapeContext {
    serial: u64,
    dispatches_at_observation: u64,
    observed_at: Instant,
}

#[derive(Clone, Debug)]
enum Circuit {
    Closed,
    Open { until: Instant },
    HalfOpen { trial_in_flight: bool },
}

impl Circuit {
    fn state(&self, now: Instant) -> CircuitState {
        match self {
            Self::Closed => CircuitState::Closed,
            Self::Open { until } if now >= *until => CircuitState::HalfOpen,
            Self::Open { .. } => CircuitState::Open,
            Self::HalfOpen { .. } => CircuitState::HalfOpen,
        }
    }
}

#[derive(Clone, Debug)]
struct LiveBackend {
    topology_generation: u64,
    readiness: ReadinessState,
    readiness_successes: u32,
    readiness_failures: u32,
    readiness_error: Option<String>,
    readiness_checked_at: Option<Instant>,
    metrics: Option<MetricsObservation>,
    metrics_error: Option<String>,
    metrics_attempted_at: Option<Instant>,
    metrics_generation: u64,
    metrics_scrapes_started: u64,
    metrics_last_completed_scrape: u64,
    engine_idle_streak: u64,
    token_rate: Option<f64>,
    previous_token_counter: Option<(f64, Instant)>,
    prefill_token_rate: Option<f64>,
    previous_prefill_counter: Option<(f64, Instant)>,
    decode_token_rate: Option<f64>,
    previous_decode_counter: Option<(f64, Instant)>,
    circuit: Circuit,
    circuit_epoch: u64,
    consecutive_request_failures: u32,
}

impl LiveBackend {
    fn new(topology_generation: u64) -> Self {
        Self {
            topology_generation,
            readiness: ReadinessState::Checking,
            readiness_successes: 0,
            readiness_failures: 0,
            readiness_error: None,
            readiness_checked_at: None,
            metrics: None,
            metrics_error: None,
            metrics_attempted_at: None,
            metrics_generation: 0,
            metrics_scrapes_started: 0,
            metrics_last_completed_scrape: 0,
            engine_idle_streak: 0,
            token_rate: None,
            previous_token_counter: None,
            prefill_token_rate: None,
            previous_prefill_counter: None,
            decode_token_rate: None,
            previous_decode_counter: None,
            circuit: Circuit::Closed,
            circuit_epoch: 0,
            consecutive_request_failures: 0,
        }
    }
}

#[derive(Debug, Default)]
struct RoutingInner {
    backends: HashMap<String, LiveBackend>,
    rotating_cursor: u64,
}

#[derive(Clone, Debug)]
pub struct RoutingState {
    runtime: RuntimeState,
    inner: Arc<Mutex<RoutingInner>>,
    /// Serializes snapshot -> score -> circuit permit -> lease reservation.
    ///
    /// Backend slots provide the authoritative acquire-versus-drain gate, but
    /// selection also needs one linearization point of its own. Without it,
    /// simultaneous selectors can all score the same pre-reservation snapshot
    /// and stampede the backend that was marginally least loaded.
    selection: Arc<Mutex<()>>,
}

#[derive(Clone, Debug)]
pub struct RoutingDecision {
    pub backend_id: String,
    pub routing_policy: &'static str,
    pub routing_reason: &'static str,
    pub eligible_backend_count: usize,
    pub backend_pressure_at_dispatch: Option<f64>,
    pub backend_running_at_dispatch: Option<u64>,
    pub backend_waiting_at_dispatch: Option<u64>,
    pub backend_capacity_at_dispatch: Option<u64>,
    pub backend_kv_pressure_at_dispatch: Option<f64>,
    pub backend_metrics_age_ms: Option<u64>,
    pub backend_proxy_active_at_dispatch: usize,
}

pub struct RouteSelection {
    pub lease: BackendLease,
    pub decision: RoutingDecision,
    circuit_permit: CircuitPermit,
}

impl RouteSelection {
    pub(crate) fn into_response_guard(mut self, status: StatusCode) -> BackendResponseGuard {
        let body_failure = if matches!(status.as_u16(), 500 | 502 | 503 | 504) {
            self.circuit_permit.failure();
            None
        } else if status != StatusCode::TOO_MANY_REQUESTS {
            self.circuit_permit.success_with_body_observer()
        } else {
            self.circuit_permit.neutral();
            None
        };
        BackendResponseGuard {
            _lease: self.lease,
            body_failure,
        }
    }

    pub fn record_transport_failure(mut self) {
        self.circuit_permit.failure();
        // `lease` drops after the circuit outcome is recorded.
    }

    pub fn backend_url(&self) -> &str {
        self.lease.spec().endpoint()
    }
}

/// Holds both the local backend lease and an unresolved successful circuit
/// outcome until the response body reaches EOF. A downstream cancellation is
/// neutral; an upstream body error counts as a transport failure.
pub(crate) struct BackendResponseGuard {
    _lease: BackendLease,
    body_failure: Option<BodyFailureObserver>,
}

impl BackendResponseGuard {
    pub(crate) fn complete(&mut self) {}

    pub(crate) fn body_error(&mut self) {
        if let Some(observer) = self.body_failure.take() {
            observer.failure();
        }
    }
}

struct BodyFailureObserver {
    routing: RoutingState,
    backend_id: String,
    circuit_epoch: u64,
    open_immediately: bool,
}

impl BodyFailureObserver {
    fn failure(self) {
        self.routing.record_body_failure(
            &self.backend_id,
            self.circuit_epoch,
            self.open_immediately,
        );
    }
}

#[derive(Clone, Debug)]
pub struct BackendStatusSnapshot {
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
    pub metrics_generation: u64,
    pub metrics_scrapes_started: u64,
    pub metrics_observation_serial: u64,
    pub engine_idle_streak: u64,
    pub readiness_age_ms: Option<u64>,
    pub metrics_error: Option<String>,
    pub readiness_error: Option<String>,
}

#[derive(Clone, Debug)]
struct Candidate {
    id: BackendId,
    local_active: usize,
    score: Option<LeastPressureV1Score>,
    metrics: Option<CandidateMetrics>,
}

#[derive(Clone, Debug)]
struct CandidateMetrics {
    running: u64,
    waiting: u64,
    capacity: Option<u64>,
    kv_ratio: Option<f64>,
    age: Duration,
}

impl RoutingState {
    pub fn new(runtime: RuntimeState) -> Self {
        let mut inner = RoutingInner::default();
        for (backend, generation) in runtime.backend_instances() {
            inner
                .backends
                .insert(backend.id, LiveBackend::new(generation));
        }
        Self {
            runtime,
            inner: Arc::new(Mutex::new(inner)),
            selection: Arc::new(Mutex::new(())),
        }
    }

    /// Test/embedding helper for callers that intentionally do not run health
    /// workers. Production uses [`Self::new`] and begins in `Checking`.
    pub fn new_assume_ready(runtime: RuntimeState) -> Self {
        let state = Self::new(runtime);
        let mut inner = state.lock();
        for live in inner.backends.values_mut() {
            live.readiness = ReadinessState::Ready;
        }
        drop(inner);
        state
    }

    pub fn runtime(&self) -> &RuntimeState {
        &self.runtime
    }

    fn ensure_backends(&self, inner: &mut RoutingInner) {
        let configured: HashMap<String, u64> = self
            .runtime
            .backend_instances()
            .into_iter()
            .map(|(backend, generation)| (backend.id, generation))
            .collect();
        inner.backends.retain(|id, _| configured.contains_key(id));
        for (id, generation) in configured {
            match inner.backends.entry(id) {
                std::collections::hash_map::Entry::Occupied(mut entry)
                    if entry.get().topology_generation != generation =>
                {
                    entry.insert(LiveBackend::new(generation));
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(LiveBackend::new(generation));
                }
            }
        }
    }

    pub fn record_readiness_success(&self, id: &str) -> Option<(ReadinessState, ReadinessState)> {
        let generation = self.runtime.backend_generation(id)?;
        self.record_readiness_success_for(id, generation)
    }

    fn record_readiness_success_for(
        &self,
        id: &str,
        generation: u64,
    ) -> Option<(ReadinessState, ReadinessState)> {
        let config = self.runtime.readiness();
        let mut inner = self.lock();
        self.ensure_backends(&mut inner);
        let live = inner.backends.get_mut(id)?;
        if live.topology_generation != generation {
            return None;
        }
        let previous = live.readiness;
        live.readiness_checked_at = Some(Instant::now());
        live.readiness_error = None;
        live.readiness_failures = 0;
        live.readiness_successes = live.readiness_successes.saturating_add(1);
        if live.readiness_successes >= config.success_threshold {
            live.readiness = ReadinessState::Ready;
        }
        (previous != live.readiness).then_some((previous, live.readiness))
    }

    pub fn record_readiness_failure(
        &self,
        id: &str,
        kind: ReadinessFailureKind,
        error: String,
    ) -> Option<(ReadinessState, ReadinessState)> {
        let generation = self.runtime.backend_generation(id)?;
        self.record_readiness_failure_for(id, generation, kind, error)
    }

    fn record_readiness_failure_for(
        &self,
        id: &str,
        generation: u64,
        kind: ReadinessFailureKind,
        error: String,
    ) -> Option<(ReadinessState, ReadinessState)> {
        let config = self.runtime.readiness();
        let mut inner = self.lock();
        self.ensure_backends(&mut inner);
        let live = inner.backends.get_mut(id)?;
        if live.topology_generation != generation {
            return None;
        }
        let previous = live.readiness;
        live.readiness_checked_at = Some(Instant::now());
        live.readiness_error = Some(error);
        live.readiness_successes = 0;
        live.readiness_failures = live.readiness_failures.saturating_add(1);
        if live.readiness_failures >= config.failure_threshold {
            live.readiness = match kind {
                ReadinessFailureKind::Unready => ReadinessState::Unready,
                ReadinessFailureKind::Unreachable => ReadinessState::Unreachable,
            };
        }
        (previous != live.readiness).then_some((previous, live.readiness))
    }

    pub fn record_metrics_success(&self, id: &str, metrics: MistralRsMetrics) {
        let Some(generation) = self.runtime.backend_generation(id) else {
            return;
        };
        let Some(scrape) = self.begin_metrics_scrape(id, generation) else {
            return;
        };
        self.record_metrics_success_for(id, generation, metrics, scrape);
    }

    pub(crate) fn begin_metrics_scrape(
        &self,
        id: &str,
        generation: u64,
    ) -> Option<MetricsScrapeContext> {
        // Capture assignments before the HTTP scrape begins. Everything
        // routed after this snapshot is conservatively treated as not yet
        // reflected by the returned engine gauges.
        let dispatches_at_observation = self
            .runtime
            .registry()
            .get(&BackendId::from(id))
            .map(|slot| slot.snapshot().total_acquired)
            .unwrap_or(0);
        let observed_at = Instant::now();
        let mut inner = self.lock();
        self.ensure_backends(&mut inner);
        let live = inner.backends.get_mut(id)?;
        if live.topology_generation != generation {
            return None;
        }
        live.metrics_scrapes_started = live
            .metrics_scrapes_started
            .checked_add(1)
            .expect("backend metrics scrape serial exhausted");
        Some(MetricsScrapeContext {
            serial: live.metrics_scrapes_started,
            dispatches_at_observation,
            observed_at,
        })
    }

    pub(crate) fn record_metrics_success_for(
        &self,
        id: &str,
        generation: u64,
        metrics: MistralRsMetrics,
        scrape: MetricsScrapeContext,
    ) {
        let now = Instant::now();
        let mut inner = self.lock();
        self.ensure_backends(&mut inner);
        let Some(live) = inner.backends.get_mut(id) else {
            return;
        };
        if live.topology_generation != generation {
            return;
        }
        if scrape.serial <= live.metrics_last_completed_scrape {
            return;
        }
        if let Some(tokens) = metrics.tokens_processed_total {
            live.token_rate =
                counter_rate(tokens, live.previous_token_counter, now, live.token_rate);
            live.previous_token_counter = Some((tokens, now));
        }
        if let Some(tokens) = metrics.prefill_tokens_processed_total {
            live.prefill_token_rate = counter_rate(
                tokens,
                live.previous_prefill_counter,
                now,
                live.prefill_token_rate,
            );
            live.previous_prefill_counter = Some((tokens, now));
        }
        if let Some(tokens) = metrics.decode_tokens_processed_total {
            live.decode_token_rate = counter_rate(
                tokens,
                live.previous_decode_counter,
                now,
                live.decode_token_rate,
            );
            live.previous_decode_counter = Some((tokens, now));
        }
        let engine_idle = metrics.sequences_running == 0 && metrics.sequences_waiting == 0;
        live.metrics = Some(MetricsObservation {
            metrics,
            observed_at: scrape.observed_at,
            dispatches_at_observation: scrape.dispatches_at_observation,
            scrape_serial: scrape.serial,
        });
        live.metrics_attempted_at = Some(now);
        live.metrics_generation = live.metrics_generation.wrapping_add(1);
        live.metrics_last_completed_scrape = scrape.serial;
        live.engine_idle_streak = if engine_idle {
            live.engine_idle_streak.saturating_add(1)
        } else {
            0
        };
        live.metrics_error = None;
    }

    pub fn record_metrics_failure(&self, id: &str, error: String) {
        let Some(generation) = self.runtime.backend_generation(id) else {
            return;
        };
        let Some(scrape) = self.begin_metrics_scrape(id, generation) else {
            return;
        };
        self.record_metrics_failure_for(id, generation, scrape.serial, error);
    }

    fn record_metrics_failure_for(
        &self,
        id: &str,
        generation: u64,
        scrape_serial: u64,
        error: String,
    ) {
        let mut inner = self.lock();
        self.ensure_backends(&mut inner);
        if let Some(live) = inner
            .backends
            .get_mut(id)
            .filter(|live| live.topology_generation == generation)
        {
            if scrape_serial <= live.metrics_last_completed_scrape {
                return;
            }
            live.metrics_last_completed_scrape = scrape_serial;
            live.engine_idle_streak = 0;
            live.metrics_attempted_at = Some(Instant::now());
            live.metrics_error = Some(error);
        }
    }

    pub fn select(&self) -> Option<RouteSelection> {
        // Hold this until the chosen backend lease has incremented local
        // accounting. The next selector therefore observes our reservation.
        let _selection = self
            .selection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let registry_snapshots = self.runtime.registry().snapshots();
        let configs: HashMap<String, (Backend, u64)> = self
            .runtime
            .backend_instances()
            .into_iter()
            .map(|(backend, generation)| (backend.id.clone(), (backend, generation)))
            .collect();
        let stale_after = Duration::from_millis(self.runtime.telemetry().stale_after_ms);
        let kv_soft_limit = self.runtime.routing().kv_soft_limit;

        let (mut candidates, cursor) = {
            let mut inner = self.lock();
            self.ensure_backends(&mut inner);
            let mut candidates = Vec::new();
            for snapshot in &registry_snapshots {
                if snapshot.mode != BackendMode::Active {
                    continue;
                }
                let Some(live) = inner.backends.get(snapshot.id().as_str()) else {
                    continue;
                };
                if live.readiness != ReadinessState::Ready
                    || live.circuit.state(now) == CircuitState::Open
                {
                    continue;
                }
                let Some((config, generation)) = configs.get(snapshot.id().as_str()) else {
                    continue;
                };
                if live.topology_generation != *generation {
                    continue;
                }
                let (score, metrics) =
                    score_candidate(snapshot, live, config, now, stale_after, kv_soft_limit);
                candidates.push(Candidate {
                    id: snapshot.id().clone(),
                    local_active: snapshot.local_active,
                    score,
                    metrics,
                });
            }
            let cursor = inner.rotating_cursor;
            inner.rotating_cursor = inner.rotating_cursor.wrapping_add(1);
            (candidates, cursor)
        };

        if candidates.is_empty() {
            return None;
        }
        let eligible_backend_count = candidates.len();
        let has_scored = candidates.iter().any(|candidate| candidate.score.is_some());
        if has_scored {
            candidates.retain(|candidate| candidate.score.is_some());
            candidates.sort_by(|left, right| {
                left.score
                    .expect("retained")
                    .pressure
                    .total_cmp(&right.score.expect("retained").pressure)
                    .then_with(|| left.local_active.cmp(&right.local_active))
                    .then_with(|| rotated_cmp(&left.id, &right.id, cursor))
            });
        } else {
            candidates.sort_by(|left, right| {
                left.local_active
                    .cmp(&right.local_active)
                    .then_with(|| rotated_cmp(&left.id, &right.id, cursor))
            });
        }

        for candidate in candidates {
            let Some(circuit_permit) = self.try_circuit_permit(candidate.id.as_str()) else {
                continue;
            };
            let lease = match self.runtime.registry().try_acquire(&candidate.id) {
                Ok(lease) => lease,
                Err(_) => {
                    drop(circuit_permit);
                    continue;
                }
            };
            let metrics = candidate.metrics.as_ref();
            return Some(RouteSelection {
                decision: RoutingDecision {
                    backend_id: candidate.id.to_string(),
                    routing_policy: "least-pressure-v1",
                    routing_reason: if candidate.score.is_some() {
                        "fresh_metrics_lowest_pressure"
                    } else {
                        "least_inflight_fallback"
                    },
                    eligible_backend_count,
                    backend_pressure_at_dispatch: candidate.score.map(|score| score.pressure),
                    backend_running_at_dispatch: metrics.map(|metrics| metrics.running),
                    backend_waiting_at_dispatch: metrics.map(|metrics| metrics.waiting),
                    backend_capacity_at_dispatch: metrics.and_then(|metrics| metrics.capacity),
                    backend_kv_pressure_at_dispatch: metrics.and_then(|metrics| metrics.kv_ratio),
                    backend_metrics_age_ms: metrics.map(|metrics| duration_ms(metrics.age)),
                    backend_proxy_active_at_dispatch: candidate.local_active + 1,
                },
                lease,
                circuit_permit,
            });
        }
        None
    }

    pub fn statuses(&self) -> Vec<BackendStatusSnapshot> {
        let now = Instant::now();
        let stale_after = Duration::from_millis(self.runtime.telemetry().stale_after_ms);
        let configs: HashMap<String, (Backend, u64)> = self
            .runtime
            .backend_instances()
            .into_iter()
            .map(|(backend, generation)| (backend.id.clone(), (backend, generation)))
            .collect();
        let kv_soft_limit = self.runtime.routing().kv_soft_limit;
        let snapshots = self.runtime.registry().snapshots();
        let mut inner = self.lock();
        self.ensure_backends(&mut inner);
        snapshots
            .iter()
            .filter_map(|snapshot| {
                let (config, generation) = configs.get(snapshot.id().as_str())?;
                let live = inner.backends.get(snapshot.id().as_str())?;
                if live.topology_generation != *generation {
                    return None;
                }
                Some(status_snapshot(
                    snapshot,
                    live,
                    config,
                    now,
                    stale_after,
                    kv_soft_limit,
                ))
            })
            .collect()
    }

    pub fn status(&self, id: &str) -> Option<BackendStatusSnapshot> {
        self.statuses().into_iter().find(|status| status.id == id)
    }

    fn try_circuit_permit(&self, id: &str) -> Option<CircuitPermit> {
        let mut inner = self.lock();
        let live = inner.backends.get_mut(id)?;
        let now = Instant::now();
        let trial = match &mut live.circuit {
            Circuit::Closed => false,
            Circuit::Open { until } if now >= *until => {
                live.circuit = Circuit::HalfOpen {
                    trial_in_flight: true,
                };
                true
            }
            Circuit::Open { .. } => return None,
            Circuit::HalfOpen { trial_in_flight } if !*trial_in_flight => {
                *trial_in_flight = true;
                true
            }
            Circuit::HalfOpen { .. } => return None,
        };
        Some(CircuitPermit {
            routing: self.clone(),
            backend_id: id.to_owned(),
            circuit_epoch: live.circuit_epoch,
            trial,
            resolved: false,
        })
    }

    fn record_circuit_outcome(
        &self,
        id: &str,
        circuit_epoch: u64,
        trial: bool,
        outcome: CircuitOutcome,
    ) {
        let mut inner = self.lock();
        let Some(live) = inner.backends.get_mut(id) else {
            return;
        };
        if live.circuit_epoch != circuit_epoch {
            return;
        }
        match outcome {
            CircuitOutcome::Failure if trial => {
                live.consecutive_request_failures = CIRCUIT_FAILURE_THRESHOLD;
                bump_circuit_epoch(live);
                live.circuit = Circuit::Open {
                    until: Instant::now() + CIRCUIT_OPEN_FOR,
                };
            }
            CircuitOutcome::Failure => {
                live.consecutive_request_failures =
                    live.consecutive_request_failures.saturating_add(1);
                if live.consecutive_request_failures >= CIRCUIT_FAILURE_THRESHOLD {
                    bump_circuit_epoch(live);
                    live.circuit = Circuit::Open {
                        until: Instant::now() + CIRCUIT_OPEN_FOR,
                    };
                }
            }
            CircuitOutcome::Neutral if trial => {
                live.circuit = Circuit::HalfOpen {
                    trial_in_flight: false,
                };
            }
            CircuitOutcome::Neutral => {}
        }
    }

    fn record_success_and_observer(
        &self,
        id: &str,
        circuit_epoch: u64,
        trial: bool,
    ) -> Option<BodyFailureObserver> {
        let mut inner = self.lock();
        let live = inner.backends.get_mut(id)?;
        if live.circuit_epoch != circuit_epoch {
            return None;
        }
        live.consecutive_request_failures = 0;
        if trial {
            bump_circuit_epoch(live);
        }
        live.circuit = Circuit::Closed;
        Some(BodyFailureObserver {
            routing: self.clone(),
            backend_id: id.to_owned(),
            circuit_epoch: live.circuit_epoch,
            open_immediately: trial,
        })
    }

    fn record_body_failure(&self, id: &str, circuit_epoch: u64, open_immediately: bool) {
        let mut inner = self.lock();
        let Some(live) = inner.backends.get_mut(id) else {
            return;
        };
        if live.circuit_epoch != circuit_epoch {
            return;
        }
        live.consecutive_request_failures = if open_immediately {
            CIRCUIT_FAILURE_THRESHOLD
        } else {
            live.consecutive_request_failures.saturating_add(1)
        };
        if live.consecutive_request_failures >= CIRCUIT_FAILURE_THRESHOLD {
            bump_circuit_epoch(live);
            live.circuit = Circuit::Open {
                until: Instant::now() + CIRCUIT_OPEN_FOR,
            };
        }
    }

    fn lock(&self) -> MutexGuard<'_, RoutingInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn score_candidate(
    snapshot: &BackendSnapshot,
    live: &LiveBackend,
    config: &Backend,
    now: Instant,
    stale_after: Duration,
    kv_soft_limit: f64,
) -> (Option<LeastPressureV1Score>, Option<CandidateMetrics>) {
    let Some(observation) = &live.metrics else {
        return (None, None);
    };
    let age = now.saturating_duration_since(observation.observed_at);
    if age > stale_after {
        return (None, None);
    }
    let reported = observation.metrics.sequences_capacity;
    let effective = match (reported, config.capacity) {
        (Some(reported), Some(configured)) => Some(reported.min(configured)),
        (Some(reported), None) => Some(reported),
        (None, configured) => configured,
    };
    let new_sequences = snapshot
        .total_acquired
        .saturating_sub(observation.dispatches_at_observation);
    let score = effective.and_then(|capacity| {
        let inputs = observation
            .metrics
            .pressure_inputs(new_sequences.saturating_add(1), capacity);
        least_pressure_v1_with_soft_limit(inputs, kv_soft_limit).ok()
    });
    let metrics = CandidateMetrics {
        running: observation.metrics.sequences_running,
        waiting: observation.metrics.sequences_waiting,
        capacity: effective,
        kv_ratio: observation.metrics.kv_cache_ratio(),
        age,
    };
    (score, Some(metrics))
}

fn status_snapshot(
    snapshot: &BackendSnapshot,
    live: &LiveBackend,
    config: &Backend,
    now: Instant,
    stale_after: Duration,
    kv_soft_limit: f64,
) -> BackendStatusSnapshot {
    let telemetry = match &live.metrics {
        Some(observation)
            if now.saturating_duration_since(observation.observed_at) <= stale_after =>
        {
            TelemetryState::Fresh
        }
        Some(_) => TelemetryState::Stale,
        None => TelemetryState::Unavailable,
    };
    let circuit = live.circuit.state(now);
    let eligible = snapshot.mode == BackendMode::Active
        && live.readiness == ReadinessState::Ready
        && circuit != CircuitState::Open;
    let state = display_state(snapshot.mode, live.readiness, telemetry, circuit);
    let observation = live.metrics.as_ref();
    let reported_capacity = observation.and_then(|sample| sample.metrics.sequences_capacity);
    let effective_capacity = match (reported_capacity, config.capacity) {
        (Some(reported), Some(configured)) => Some(reported.min(configured)),
        (Some(reported), None) => Some(reported),
        (None, configured) => configured,
    };
    let pressure = if eligible && telemetry == TelemetryState::Fresh {
        observation.and_then(|sample| {
            let capacity = effective_capacity?;
            let new = snapshot
                .total_acquired
                .saturating_sub(sample.dispatches_at_observation);
            least_pressure_v1_with_soft_limit(
                sample.metrics.pressure_inputs(new, capacity),
                kv_soft_limit,
            )
            .ok()
            .map(|score| score.pressure)
        })
    } else {
        None
    };

    BackendStatusSnapshot {
        id: snapshot.id().to_string(),
        url: config.url.to_string(),
        mode: snapshot.mode,
        state,
        readiness: live.readiness,
        telemetry,
        circuit,
        eligible,
        proxy_active: snapshot.local_active,
        oldest_proxy_request_ms: snapshot.oldest_active_age.map(duration_ms),
        running: observation.map(|sample| sample.metrics.sequences_running),
        waiting: observation.map(|sample| sample.metrics.sequences_waiting),
        reported_capacity,
        configured_capacity: config.capacity,
        effective_capacity,
        capacity_mismatch: reported_capacity
            .zip(config.capacity)
            .is_some_and(|(reported, configured)| reported != configured),
        kv_ratio: observation.and_then(|sample| sample.metrics.kv_cache_ratio()),
        token_rate: live.token_rate,
        prefill_token_rate: live.prefill_token_rate,
        decode_token_rate: live.decode_token_rate,
        pressure,
        metrics_age_ms: observation
            .map(|sample| duration_ms(now.saturating_duration_since(sample.observed_at))),
        metrics_generation: live.metrics_generation,
        metrics_scrapes_started: live.metrics_scrapes_started,
        metrics_observation_serial: observation.map_or(0, |sample| sample.scrape_serial),
        engine_idle_streak: live.engine_idle_streak,
        readiness_age_ms: live
            .readiness_checked_at
            .map(|at| duration_ms(now.saturating_duration_since(at))),
        metrics_error: live.metrics_error.clone(),
        readiness_error: live.readiness_error.clone(),
    }
}

/// Exponential moving average of a cumulative counter observed across
/// scrapes. The first observation after startup has no baseline and yields
/// `None`. A backwards jump means the backend restarted and the delta is
/// re-anchored at the counter's new value.
fn counter_rate(
    current: f64,
    previous: Option<(f64, Instant)>,
    now: Instant,
    old_rate: Option<f64>,
) -> Option<f64> {
    let (previous_value, at) = previous?;
    let elapsed = now.saturating_duration_since(at).as_secs_f64();
    if elapsed <= 0.0 {
        return old_rate;
    }
    let delta = if current >= previous_value {
        current - previous_value
    } else {
        // Counter reset after a backend restart.
        current
    };
    let instant_rate = delta / elapsed;
    Some(match old_rate {
        Some(old) => old * 0.8 + instant_rate * 0.2,
        None => instant_rate,
    })
}

fn display_state(
    mode: BackendMode,
    readiness: ReadinessState,
    telemetry: TelemetryState,
    circuit: CircuitState,
) -> BackendDisplayState {
    match mode {
        BackendMode::Disabled => BackendDisplayState::Disabled,
        BackendMode::Draining => BackendDisplayState::Draining,
        BackendMode::Active => match readiness {
            ReadinessState::Checking => BackendDisplayState::Checking,
            ReadinessState::Unreachable => BackendDisplayState::Unreachable,
            ReadinessState::Unready => BackendDisplayState::Unready,
            ReadinessState::Ready => match circuit {
                CircuitState::Open => BackendDisplayState::CircuitOpen,
                CircuitState::HalfOpen => BackendDisplayState::Probing,
                CircuitState::Closed if telemetry != TelemetryState::Fresh => {
                    BackendDisplayState::Degraded
                }
                CircuitState::Closed => BackendDisplayState::Ready,
            },
        },
    }
}

fn rotated_cmp(left: &BackendId, right: &BackendId, cursor: u64) -> Ordering {
    // Stable IDs establish an order, then cursor parity flips it. This is a
    // small deterministic rotating tie-breaker without a random dependency.
    if cursor.is_multiple_of(2) {
        left.cmp(right)
    } else {
        right.cmp(left)
    }
}

fn bump_circuit_epoch(live: &mut LiveBackend) {
    live.circuit_epoch = live
        .circuit_epoch
        .checked_add(1)
        .expect("backend circuit epoch exhausted");
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

enum CircuitOutcome {
    Failure,
    Neutral,
}

struct CircuitPermit {
    routing: RoutingState,
    backend_id: String,
    circuit_epoch: u64,
    trial: bool,
    resolved: bool,
}

impl CircuitPermit {
    fn success_with_body_observer(&mut self) -> Option<BodyFailureObserver> {
        if self.resolved {
            return None;
        }
        self.resolved = true;
        self.routing
            .record_success_and_observer(&self.backend_id, self.circuit_epoch, self.trial)
    }

    fn failure(&mut self) {
        self.resolve(CircuitOutcome::Failure);
    }

    fn neutral(&mut self) {
        self.resolve(CircuitOutcome::Neutral);
    }

    fn resolve(&mut self, outcome: CircuitOutcome) {
        if self.resolved {
            return;
        }
        self.resolved = true;
        self.routing.record_circuit_outcome(
            &self.backend_id,
            self.circuit_epoch,
            self.trial,
            outcome,
        );
    }
}

impl Drop for CircuitPermit {
    fn drop(&mut self) {
        if !self.resolved {
            self.neutral();
        }
    }
}

/// Continuously scrape all configured backends. The first cycle runs
/// immediately; subsequent cycles use the latest explicitly reloaded timing.
pub async fn run_telemetry_worker(
    client: HttpClient,
    runtime: RuntimeState,
    routing: RoutingState,
    quiet: bool,
) -> Result<(), String> {
    loop {
        let config = runtime.telemetry();
        let timeout = Duration::from_millis(config.scrape_timeout_ms);
        let mut jobs = JoinSet::new();
        for (backend, generation) in runtime.backend_instances() {
            let client = client.clone();
            let Some(scrape) = routing.begin_metrics_scrape(&backend.id, generation) else {
                continue;
            };
            jobs.spawn(async move {
                let result = scrape_metrics(&client, &backend, timeout).await;
                (backend.id, generation, scrape, result)
            });
        }
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok((id, generation, scrape, Ok(metrics))) => {
                    routing.record_metrics_success_for(&id, generation, metrics, scrape);
                }
                Ok((id, generation, scrape, Err(error))) => {
                    let previous = routing.status(&id).map(|status| status.telemetry);
                    routing.record_metrics_failure_for(
                        &id,
                        generation,
                        scrape.serial,
                        error.clone(),
                    );
                    if !quiet && previous == Some(TelemetryState::Fresh) {
                        eprintln!("WARN backend {id} telemetry became unavailable: {error}");
                    }
                }
                Err(error) => {
                    return Err(format!("backend telemetry scrape task failed: {error}"));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(config.scrape_interval_ms)).await;
    }
}

pub async fn run_readiness_worker(
    client: HttpClient,
    runtime: RuntimeState,
    routing: RoutingState,
    quiet: bool,
) -> Result<(), String> {
    loop {
        let config = runtime.readiness();
        let timeout = Duration::from_millis(config.probe_timeout_ms);
        let mut jobs = JoinSet::new();
        for (backend, generation) in runtime.backend_instances() {
            let client = client.clone();
            jobs.spawn(async move {
                let result = probe_readiness(&client, &backend, timeout).await;
                (backend.id, generation, result)
            });
        }
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok((id, generation, Ok(()))) => {
                    if let Some((old, new)) = routing.record_readiness_success_for(&id, generation)
                        && !quiet
                    {
                        println!("INFO backend {id} readiness changed from {old} to {new}");
                    }
                }
                Ok((id, generation, Err((kind, error)))) => {
                    if let Some((old, new)) =
                        routing.record_readiness_failure_for(&id, generation, kind, error)
                        && !quiet
                    {
                        eprintln!("WARN backend {id} readiness changed from {old} to {new}");
                    }
                }
                Err(error) => {
                    return Err(format!("backend readiness probe task failed: {error}"));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(config.probe_interval_ms)).await;
    }
}

async fn scrape_metrics(
    client: &HttpClient,
    backend: &Backend,
    timeout: Duration,
) -> Result<MistralRsMetrics, String> {
    let text = fetch_text(client, backend.metrics_url.clone(), timeout).await?;
    parse_mistralrs_metrics(&text).map_err(|error| error.to_string())
}

async fn probe_readiness(
    client: &HttpClient,
    backend: &Backend,
    timeout: Duration,
) -> Result<(), (ReadinessFailureKind, String)> {
    match fetch_text(client, backend.readiness_url.clone(), timeout).await {
        Ok(_) => Ok(()),
        Err(error) if error.starts_with("HTTP ") => Err((ReadinessFailureKind::Unready, error)),
        Err(error) => Err((ReadinessFailureKind::Unreachable, error)),
    }
}

async fn fetch_text(
    client: &HttpClient,
    uri: axum::http::Uri,
    timeout: Duration,
) -> Result<String, String> {
    let request = Request::get(uri)
        .body(Body::empty())
        .map_err(|error| error.to_string())?;
    let response = tokio::time::timeout(timeout, client.request(request))
        .await
        .map_err(|_| format!("request timed out after {}ms", timeout.as_millis()))?
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let bytes = tokio::time::timeout(
        timeout,
        Limited::new(response.into_body(), MAX_PROBE_BODY_BYTES).collect(),
    )
    .await
    .map_err(|_| format!("response body timed out after {}ms", timeout.as_millis()))?
    .map_err(|error| error.to_string())?
    .to_bytes();
    String::from_utf8(bytes.to_vec()).map_err(|_| "response body is not UTF-8".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Backend;

    fn runtime() -> RuntimeState {
        RuntimeState::new(vec![
            Backend::new("a", "http://127.0.0.1:1".parse().unwrap()),
            Backend::new("b", "http://127.0.0.1:2".parse().unwrap()),
        ])
    }

    fn metrics(
        running: u64,
        waiting: u64,
        capacity: u64,
        kv: Option<(u64, u64)>,
    ) -> MistralRsMetrics {
        MistralRsMetrics {
            sequences_running: running,
            sequences_waiting: waiting,
            sequences_capacity: Some(capacity),
            kv_cache: kv.map(|(used, total)| crate::telemetry::KvCacheMetrics { used, total }),
            tokens_processed_total: None,
            prefill_tokens_processed_total: None,
            decode_tokens_processed_total: None,
            sequences_completed_total: None,
        }
    }

    fn ready(state: &RoutingState, id: &str) {
        state.record_readiness_success(id);
        state.record_readiness_success(id);
    }

    #[test]
    fn counter_rate_smooths_and_reanchors_after_reset() {
        let at = Instant::now();
        // First observation has no baseline yet.
        assert_eq!(counter_rate(100.0, None, at, None), None);

        let after = at + Duration::from_secs(10);
        // 100 tokens over 10s = 10 t/s.
        assert_eq!(
            counter_rate(100.0, Some((0.0, at)), after, None),
            Some(10.0)
        );

        // 100 more over 10s keeps the smoothed rate at 10 t/s.
        let later = after + Duration::from_secs(10);
        assert_eq!(
            counter_rate(200.0, Some((100.0, after)), later, Some(10.0)),
            Some(10.0)
        );

        // A backwards jump is a restart: 5 tokens over 10s = 0.5 t/s,
        // blended 0.8 * 10 + 0.2 * 0.5.
        assert_eq!(
            counter_rate(5.0, Some((200.0, after)), later, Some(10.0)),
            Some(10.0 * 0.8 + 0.5 * 0.2)
        );
    }

    #[test]
    fn phase_counters_yield_separate_prefill_and_decode_rates() {
        let runtime = runtime();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        ready(&routing, "a");

        let phase = |total: f64, prefill: f64, decode: f64| {
            let mut m = metrics(1, 0, 32, None);
            m.tokens_processed_total = Some(total);
            m.prefill_tokens_processed_total = Some(prefill);
            m.decode_tokens_processed_total = Some(decode);
            m
        };

        // First observation anchors the counters; the second yields rates.
        routing.record_metrics_success("a", phase(0.0, 0.0, 0.0));
        std::thread::sleep(Duration::from_millis(50));
        routing.record_metrics_success("a", phase(100.0, 60.0, 40.0));

        let status = routing.status("a").unwrap();
        let total = status.token_rate.expect("combined rate should exist");
        let prefill = status.prefill_token_rate.expect("prefill rate should exist");
        let decode = status.decode_token_rate.expect("decode rate should exist");

        // The phase split must reconcile with the combined counter.
        assert!((total - (prefill + decode)).abs() < 1e-9);
        // 60 of the 100 tokens were prefill.
        assert!((prefill / total - 0.6).abs() < 1e-9);
        assert!((decode / total - 0.4).abs() < 1e-9);
    }

    #[test]
    fn lower_pressure_backend_is_selected_and_logged() {
        let runtime = runtime();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        ready(&routing, "b");
        routing.record_metrics_success("a", metrics(20, 2, 32, Some((90, 100))));
        routing.record_metrics_success("b", metrics(3, 0, 32, Some((20, 100))));

        let selection = routing.select().unwrap();
        assert_eq!(selection.decision.backend_id, "b");
        assert_eq!(
            selection.decision.routing_reason,
            "fresh_metrics_lowest_pressure"
        );
    }

    #[test]
    fn stale_or_missing_metrics_fall_back_to_least_inflight() {
        let runtime = runtime();
        let registry = runtime.registry();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        ready(&routing, "b");
        let held = registry
            .try_acquire(&BackendId::from("a"))
            .expect("active backend");

        let selection = routing.select().unwrap();
        assert_eq!(selection.decision.backend_id, "b");
        assert_eq!(selection.decision.routing_reason, "least_inflight_fallback");
        drop(held);
    }

    #[test]
    fn draining_backend_is_never_selected_even_from_an_old_candidate_view() {
        let runtime = runtime();
        let registry = runtime.registry();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        ready(&routing, "b");
        registry.get(&BackendId::from("a")).unwrap().begin_drain();

        for _ in 0..4 {
            assert_eq!(routing.select().unwrap().decision.backend_id, "b");
        }
    }

    #[test]
    fn three_backend_failures_open_the_circuit() {
        let runtime = runtime();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        // Keep b unready so a is deterministic.
        for _ in 0..CIRCUIT_FAILURE_THRESHOLD {
            routing.select().unwrap().record_transport_failure();
        }
        assert_eq!(routing.status("a").unwrap().circuit, CircuitState::Open);
        assert!(routing.select().is_none());
    }

    #[test]
    fn status_dimensions_remain_separate() {
        let runtime = runtime();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        let status = routing.status("a").unwrap();
        assert_eq!(status.mode, BackendMode::Active);
        assert_eq!(status.readiness, ReadinessState::Ready);
        assert_eq!(status.telemetry, TelemetryState::Unavailable);
        assert_eq!(status.state, BackendDisplayState::Degraded);
        assert!(status.eligible);
    }

    #[test]
    fn configured_capacity_is_used_when_metrics_omit_capacity() {
        let mut backend = Backend::new("a", "http://127.0.0.1:1".parse().unwrap());
        backend.capacity = Some(12);
        let runtime = RuntimeState::new(vec![backend]);
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");

        let mut sample = metrics(4, 1, 12, Some((20, 100)));
        sample.sequences_capacity = None;
        routing.record_metrics_success("a", sample);

        let status = routing.status("a").unwrap();
        assert_eq!(status.reported_capacity, None);
        assert_eq!(status.configured_capacity, Some(12));
        assert_eq!(status.effective_capacity, Some(12));
        assert!(status.pressure.is_some());

        let selection = routing.select().unwrap();
        assert_eq!(
            selection.decision.routing_reason,
            "fresh_metrics_lowest_pressure"
        );
        assert_eq!(selection.decision.backend_capacity_at_dispatch, Some(12));
    }

    #[test]
    fn stale_response_outcomes_cannot_close_or_mutate_a_newer_open_circuit() {
        let runtime = runtime();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");

        // One old request has not received headers yet. Another has received
        // acceptable headers but still owns a body observer from epoch zero.
        let stale_headers = routing.select().unwrap();
        let mut stale_body = routing
            .select()
            .unwrap()
            .into_response_guard(StatusCode::OK);

        for _ in 0..CIRCUIT_FAILURE_THRESHOLD {
            routing.select().unwrap().record_transport_failure();
        }
        assert_eq!(routing.status("a").unwrap().circuit, CircuitState::Open);

        // Neither late acceptable headers nor a late body outcome from the
        // old epoch may overwrite the newer open state.
        let _stale_headers_guard = stale_headers.into_response_guard(StatusCode::OK);
        assert_eq!(routing.status("a").unwrap().circuit, CircuitState::Open);
        stale_body.body_error();
        assert_eq!(routing.status("a").unwrap().circuit, CircuitState::Open);
    }

    #[test]
    fn half_open_acceptable_headers_close_before_the_body_lease_is_released() {
        let runtime = runtime();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        for _ in 0..CIRCUIT_FAILURE_THRESHOLD {
            routing.select().unwrap().record_transport_failure();
        }
        {
            let mut inner = routing.lock();
            inner.backends.get_mut("a").unwrap().circuit = Circuit::Open {
                until: Instant::now() - Duration::from_millis(1),
            };
        }

        let selection = routing.select().unwrap();
        assert_eq!(routing.status("a").unwrap().circuit, CircuitState::HalfOpen);
        let mut guard = selection.into_response_guard(StatusCode::OK);

        let status = routing.status("a").unwrap();
        assert_eq!(status.circuit, CircuitState::Closed);
        assert_eq!(
            status.proxy_active, 1,
            "the response body still owns its lease"
        );

        guard.complete();
        drop(guard);
        assert_eq!(routing.status("a").unwrap().proxy_active, 0);
    }

    #[test]
    fn a_half_open_response_body_transport_failure_reopens_the_circuit() {
        let runtime = runtime();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        for _ in 0..CIRCUIT_FAILURE_THRESHOLD {
            routing.select().unwrap().record_transport_failure();
        }
        {
            let mut inner = routing.lock();
            inner.backends.get_mut("a").unwrap().circuit = Circuit::Open {
                until: Instant::now() - Duration::from_millis(1),
            };
        }

        let mut guard = routing
            .select()
            .unwrap()
            .into_response_guard(StatusCode::OK);
        assert_eq!(routing.status("a").unwrap().circuit, CircuitState::Closed);

        guard.body_error();
        assert_eq!(routing.status("a").unwrap().circuit, CircuitState::Open);
    }

    #[test]
    fn topology_generation_resets_live_state_and_rejects_late_probe_results() {
        let original = Backend::new("a", "http://127.0.0.1:1".parse().unwrap());
        let runtime = RuntimeState::new(vec![original]);
        let routing = RoutingState::new(runtime.clone());
        ready(&routing, "a");
        routing.record_metrics_success("a", metrics(2, 1, 8, None));
        let old_generation = runtime.backend_generation("a").unwrap();
        let late_old_scrape = routing.begin_metrics_scrape("a", old_generation).unwrap();
        assert_eq!(
            routing.status("a").unwrap().telemetry,
            TelemetryState::Fresh
        );

        runtime
            .registry()
            .get(&BackendId::from("a"))
            .unwrap()
            .disable();
        let replacement = Backend::new("a", "http://127.0.0.1:9".parse().unwrap());
        runtime
            .apply(crate::runtime::RuntimeConfig::new(vec![replacement]))
            .unwrap();
        let new_generation = runtime.backend_generation("a").unwrap();
        assert_ne!(old_generation, new_generation);

        let reset = routing.status("a").unwrap();
        assert_eq!(reset.readiness, ReadinessState::Checking);
        assert_eq!(reset.telemetry, TelemetryState::Unavailable);
        assert_eq!(reset.metrics_generation, 0);

        assert_eq!(
            routing.record_readiness_success_for("a", old_generation),
            None
        );
        routing.record_metrics_success_for(
            "a",
            old_generation,
            metrics(7, 6, 8, None),
            late_old_scrape,
        );
        let after_late_results = routing.status("a").unwrap();
        assert_eq!(after_late_results.readiness, ReadinessState::Checking);
        assert_eq!(after_late_results.telemetry, TelemetryState::Unavailable);
        assert_eq!(after_late_results.metrics_generation, 0);

        assert_eq!(
            routing.record_readiness_success_for("a", new_generation),
            None
        );
        let current_scrape = routing.begin_metrics_scrape("a", new_generation).unwrap();
        routing.record_metrics_success_for(
            "a",
            new_generation,
            metrics(1, 0, 8, None),
            current_scrape,
        );
        let current = routing.status("a").unwrap();
        assert_eq!(current.telemetry, TelemetryState::Fresh);
        assert_eq!(current.metrics_generation, 1);
    }

    #[test]
    fn scrape_start_dispatch_baseline_accounts_for_in_flight_scrape_arrivals() {
        let runtime = runtime();
        let routing = RoutingState::new(runtime.clone());
        ready(&routing, "a");
        ready(&routing, "b");
        let a_generation = runtime.backend_generation("a").unwrap();
        let b_generation = runtime.backend_generation("b").unwrap();
        let a_scrape = routing.begin_metrics_scrape("a", a_generation).unwrap();
        let b_scrape = routing.begin_metrics_scrape("b", b_generation).unwrap();

        // These requests arrived after the scrape began but before its result
        // was recorded. Dropping the leases isolates the dispatch baseline
        // from the local-inflight tie-breaker.
        for _ in 0..4 {
            drop(
                runtime
                    .registry()
                    .try_acquire(&BackendId::from("a"))
                    .unwrap(),
            );
        }
        routing.record_metrics_success_for("a", a_generation, metrics(0, 0, 10, None), a_scrape);
        routing.record_metrics_success_for("b", b_generation, metrics(0, 0, 10, None), b_scrape);

        let a_pressure = routing.status("a").unwrap().pressure.unwrap();
        let b_pressure = routing.status("b").unwrap().pressure.unwrap();
        assert!(a_pressure > b_pressure);
        assert_eq!(routing.select().unwrap().decision.backend_id, "b");
    }

    #[test]
    fn concurrent_selection_burst_observes_and_distributes_prior_reservations() {
        const BURST: usize = 12;

        let runtime = runtime();
        let routing = RoutingState::new(runtime);
        ready(&routing, "a");
        ready(&routing, "b");

        // Queue the whole burst behind the selection linearization point, then
        // release it at once. Each worker returns its selection so every lease
        // remains held until the complete burst has reserved a backend.
        let selection_gate = routing
            .selection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let selections = std::thread::scope(|scope| {
            let start = Arc::new(std::sync::Barrier::new(BURST + 1));
            let handles = (0..BURST)
                .map(|_| {
                    let routing = routing.clone();
                    let start = Arc::clone(&start);
                    scope.spawn(move || {
                        start.wait();
                        routing.select().unwrap()
                    })
                })
                .collect::<Vec<_>>();

            start.wait();
            drop(selection_gate);
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        let mut reservations: HashMap<String, Vec<usize>> = HashMap::new();
        for selection in &selections {
            reservations
                .entry(selection.decision.backend_id.clone())
                .or_default()
                .push(selection.decision.backend_proxy_active_at_dispatch);
        }

        assert_eq!(reservations.len(), 2);
        for backend in ["a", "b"] {
            let observed = reservations.get_mut(backend).unwrap();
            observed.sort_unstable();
            assert_eq!(observed, &[1, 2, 3, 4, 5, 6]);
        }
    }
}
