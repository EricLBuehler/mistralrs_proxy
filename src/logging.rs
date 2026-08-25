//! Per-request audit logging.
//!
//! Exactly one JSON Lines record is written per proxied request, when its
//! response finishes. Records carry request metadata, the caller's key name,
//! identifier, and digest, and the token counts sniffed out of the response —
//! never a key, a prompt, or a completion.
//!
//! Serialization and file I/O happen on a dedicated OS thread so Tokio's
//! request workers never touch the disk. The same thread prints the
//! optional human-readable arrival and completion lines to stderr.

use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use axum::{
    body::Body,
    http::{
        Method, StatusCode, Uri, Version,
        header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT},
        request, response,
    },
};
use bytes::Bytes;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use pin_project_lite::pin_project;
use serde::Serialize;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::{
    auth::{Authentication, KeyIdentity},
    routing::RoutingDecision,
    usage::{Usage, UsageSniffer},
};

const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
const AUDIT_REQUEST_SLOTS: usize = 4_096;
// One admitted request emits start, route, optional error, response-start, and
// finish events. Reserving this many queue positions per request guarantees
// that terminal events for admitted requests never need to block a Tokio
// worker, even while the log sink is stalled.
const MAX_EVENTS_PER_REQUEST: usize = 5;

/// Handle used by the request path to report events. Cloning is cheap.
#[derive(Clone)]
pub struct LogSender {
    tx: SyncSender<LogEvent>,
    health: Arc<LogHealthState>,
    admitted: Arc<AtomicUsize>,
    request_slots: usize,
}

/// A channel-free handle the serve loop can use to supervise the writer.
#[derive(Clone)]
pub struct LogHealth {
    state: Arc<LogHealthState>,
}

struct LogHealthState {
    healthy: AtomicBool,
    failed: Notify,
}

struct WriterHealthGuard(Arc<LogHealthState>);

impl Drop for WriterHealthGuard {
    fn drop(&mut self) {
        // Also runs if the writer panics, so the async serve supervisor never
        // continues indefinitely after an unexpected thread exit.
        self.0.mark_failed();
    }
}

/// Join handle for the writer thread.
pub struct LogWorker {
    thread: JoinHandle<io::Result<()>>,
    finished: Receiver<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAdmissionError {
    Unavailable,
    Saturated,
}

impl std::fmt::Display for AuditAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "the audit writer is unavailable",
            Self::Saturated => "the audit writer has reached its admitted-request limit",
        })
    }
}

impl std::error::Error for AuditAdmissionError {}

/// How a request ended.
#[derive(Debug)]
pub enum BodyOutcome {
    Complete,
    /// The response body was dropped before it finished.
    Aborted,
    /// The handler was dropped before any response existed, which is what
    /// happens when a client disconnects mid-request.
    Abandoned,
    Error(String),
}

impl BodyOutcome {
    fn describe(&self) -> (bool, &'static str, Option<&str>) {
        match self {
            Self::Complete => (true, "complete", None),
            Self::Aborted => (false, "body_dropped", None),
            Self::Abandoned => (false, "client_disconnected", None),
            Self::Error(error) => (false, "body_error", Some(error.as_str())),
        }
    }
}

/// Everything worth recording about an inbound request. No body, no key.
#[derive(Debug)]
pub struct RequestInfo {
    pub peer: SocketAddr,
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_length: Option<u64>,
    pub key_sha256: Option<String>,
    pub identity: Option<Arc<KeyIdentity>>,
    pub authorized: bool,
    pub auth_error: Option<&'static str>,
}

impl RequestInfo {
    /// Collect the loggable fields of a request and its authentication result.
    pub fn new(peer: SocketAddr, parts: &request::Parts, auth: &Authentication) -> Self {
        Self {
            peer,
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            version: parts.version,
            host: header_string(parts.headers.get(HOST))
                .or_else(|| parts.uri.authority().map(ToString::to_string)),
            user_agent: header_string(parts.headers.get(USER_AGENT)),
            content_length: header_string(parts.headers.get(CONTENT_LENGTH))
                .and_then(|value| value.parse().ok()),
            key_sha256: auth.key_sha256.clone(),
            identity: auth.identity.clone(),
            authorized: auth.result.is_ok(),
            auth_error: auth.result.err().map(|error| error.code()),
        }
    }

    /// `name[identifier]` for a known key, or a stable stand-in when the key is
    /// unknown or absent.
    fn principal(&self) -> String {
        match (&self.identity, &self.key_sha256) {
            (Some(identity), _) => format!("{}[{}]", identity.name, identity.identifier),
            (None, Some(digest)) => format!("unknown[{}]", &digest[..8.min(digest.len())]),
            (None, None) => "anonymous".to_owned(),
        }
    }
}

fn header_string(value: Option<&axum::http::HeaderValue>) -> Option<String> {
    value.map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

enum LogEvent {
    RequestStarted {
        id: Uuid,
        at_unix_ms: u64,
        info: Box<RequestInfo>,
        permit: AuditPermit,
    },
    ResponseStarted {
        id: Uuid,
        status: StatusCode,
        streaming: bool,
    },
    RequestError {
        id: Uuid,
        error: String,
    },
    RequestRouted {
        id: Uuid,
        at_unix_ms: u64,
        routing: Box<RoutingInfo>,
    },
    ResponseFinished {
        id: Uuid,
        at_unix_ms: u64,
        outcome: BodyOutcome,
        observation: BodyObservation,
    },
}

#[derive(Clone, Copy, Debug, Default)]
struct BodyObservation {
    first_byte_at_unix_ms: Option<u64>,
    response_bytes: u64,
    usage: Usage,
}

struct Pending {
    _permit: AuditPermit,
    started_at_unix_ms: u64,
    info: Box<RequestInfo>,
    status: Option<StatusCode>,
    streaming: bool,
    first_byte_at_unix_ms: Option<u64>,
    response_bytes: u64,
    usage: Usage,
    error: Option<String>,
    routing: Option<Box<RoutingInfo>>,
    routed_at_unix_ms: Option<u64>,
}

struct AuditPermit {
    admitted: Arc<AtomicUsize>,
}

impl Drop for AuditPermit {
    fn drop(&mut self) {
        let previous = self.admitted.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "audit admission permit released twice");
    }
}

/// Routing context copied into the final request audit record. A request that
/// was rejected before routing leaves these fields absent; an authorized
/// request with no eligible backend records a reason but no backend id.
#[derive(Clone, Debug, Default)]
pub struct RoutingInfo {
    pub backend_id: Option<String>,
    pub routing_policy: Option<&'static str>,
    pub routing_reason: Option<&'static str>,
    pub eligible_backend_count: Option<usize>,
    pub backend_pressure_at_dispatch: Option<f64>,
    pub backend_running_at_dispatch: Option<u64>,
    pub backend_waiting_at_dispatch: Option<u64>,
    pub backend_capacity_at_dispatch: Option<u64>,
    pub backend_kv_pressure_at_dispatch: Option<f64>,
    pub backend_metrics_age_ms: Option<u64>,
    pub backend_proxy_active_at_dispatch: Option<usize>,
}

impl From<&RoutingDecision> for RoutingInfo {
    fn from(decision: &RoutingDecision) -> Self {
        Self {
            backend_id: Some(decision.backend_id.clone()),
            routing_policy: Some(decision.routing_policy),
            routing_reason: Some(decision.routing_reason),
            eligible_backend_count: Some(decision.eligible_backend_count),
            backend_pressure_at_dispatch: decision.backend_pressure_at_dispatch,
            backend_running_at_dispatch: decision.backend_running_at_dispatch,
            backend_waiting_at_dispatch: decision.backend_waiting_at_dispatch,
            backend_capacity_at_dispatch: decision.backend_capacity_at_dispatch,
            backend_kv_pressure_at_dispatch: decision.backend_kv_pressure_at_dispatch,
            backend_metrics_age_ms: decision.backend_metrics_age_ms,
            backend_proxy_active_at_dispatch: Some(decision.backend_proxy_active_at_dispatch),
        }
    }
}

impl RoutingInfo {
    pub fn unavailable(reason: &'static str) -> Self {
        Self {
            routing_policy: Some("least-pressure-v1"),
            routing_reason: Some(reason),
            eligible_backend_count: Some(0),
            ..Self::default()
        }
    }
}

/// Open the JSONL sink and spawn the writer thread.
///
/// `path` may be `-` for stdout. When `terminal_log` is set, arrival and
/// completion lines are also printed to stderr.
pub fn start(path: &Path, terminal_log: bool) -> io::Result<(LogSender, LogWorker)> {
    let writer: Box<dyn Write + Send> = if path == Path::new("-") {
        Box::new(io::stdout())
    } else {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            let mut permissions = file.metadata()?.permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }
        Box::new(file)
    };

    start_with_writer(writer, terminal_log)
}

fn start_with_writer(
    writer: Box<dyn Write + Send>,
    terminal_log: bool,
) -> io::Result<(LogSender, LogWorker)> {
    start_with_writer_and_slots(writer, terminal_log, AUDIT_REQUEST_SLOTS)
}

fn start_with_writer_and_slots(
    writer: Box<dyn Write + Send>,
    terminal_log: bool,
    request_slots: usize,
) -> io::Result<(LogSender, LogWorker)> {
    assert!(
        request_slots > 0,
        "the audit admission limit must be positive"
    );
    let event_slots = request_slots
        .checked_mul(MAX_EVENTS_PER_REQUEST)
        .expect("audit event capacity exhausted usize");
    let (tx, rx) = mpsc::sync_channel(event_slots);
    let (finished_tx, finished) = mpsc::sync_channel(1);
    let health = Arc::new(LogHealthState {
        healthy: AtomicBool::new(true),
        failed: Notify::new(),
    });
    let worker_health = Arc::clone(&health);
    let thread = thread::Builder::new()
        .name("json-log-writer".to_owned())
        .spawn(move || {
            let _health_guard = WriterHealthGuard(worker_health);
            let result = run_worker(rx, writer, terminal_log);
            if let Err(error) = &result {
                eprintln!("JSON log worker stopped: {error}");
            }
            let _ = finished_tx.send(());
            result
        })?;

    Ok((
        LogSender {
            tx,
            health,
            admitted: Arc::new(AtomicUsize::new(0)),
            request_slots,
        },
        LogWorker { thread, finished },
    ))
}

impl LogHealthState {
    fn mark_failed(&self) {
        if self.healthy.swap(false, Ordering::AcqRel) {
            // There is one serve supervisor. `notify_one` retains a permit if
            // failure happens between its atomic check and the first poll.
            self.failed.notify_one();
        }
    }
}

impl LogHealth {
    pub fn is_healthy(&self) -> bool {
        self.state.healthy.load(Ordering::Acquire)
    }

    pub async fn wait_until_unhealthy(&self) {
        loop {
            let failed = self.state.failed.notified();
            if !self.is_healthy() {
                return;
            }
            failed.await;
        }
    }
}

impl LogWorker {
    pub fn join(self) -> io::Result<()> {
        self.thread
            .join()
            .map_err(|_| io::Error::other("JSON log worker panicked"))?
    }

    /// Wait at most `timeout` for the writer to finish, then detach it so a
    /// wedged filesystem cannot prevent process shutdown indefinitely.
    pub fn join_timeout(self, timeout: Duration) -> io::Result<()> {
        match self.finished.recv_timeout(timeout) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => self.join(),
            Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "audit writer exceeded the {}s shutdown grace and was detached",
                    timeout.as_secs_f64()
                ),
            )),
        }
    }
}

impl LogSender {
    /// False once the writer has failed. The proxy then fails closed rather
    /// than serving traffic with no audit trail.
    pub fn is_healthy(&self) -> bool {
        self.health.healthy.load(Ordering::Acquire)
    }

    pub fn health(&self) -> LogHealth {
        LogHealth {
            state: Arc::clone(&self.health),
        }
    }

    /// Record an arriving request.
    ///
    /// The returned guard closes the record out if the handler is dropped
    /// before it produces a response, so an abandoned request cannot sit in the
    /// worker's pending map forever. Call [`RequestGuard::disarm`] once a
    /// response body has been handed to [`Self::response_body`].
    #[must_use = "the guard closes out abandoned requests"]
    pub fn request_started(
        &self,
        id: Uuid,
        info: RequestInfo,
    ) -> Result<RequestGuard, AuditAdmissionError> {
        if !self.is_healthy() {
            return Err(AuditAdmissionError::Unavailable);
        }
        self.admitted
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.request_slots).then_some(current + 1)
            })
            .map_err(|_| AuditAdmissionError::Saturated)?;
        let permit = AuditPermit {
            admitted: Arc::clone(&self.admitted),
        };

        // Close the small race in which the writer failed while this request
        // was reserving its slot. No backend work is allowed until this method
        // has successfully admitted and enqueued the start event.
        if !self.is_healthy() {
            drop(permit);
            return Err(AuditAdmissionError::Unavailable);
        }
        match self.tx.try_send(LogEvent::RequestStarted {
            id,
            at_unix_ms: now_unix_ms(),
            info: Box::new(info),
            permit,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // The channel is provisioned for every possible event from
                // each admitted request, so fullness indicates an invariant
                // violation. Fail closed instead of losing the start record.
                self.health.mark_failed();
                return Err(AuditAdmissionError::Unavailable);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.health.mark_failed();
                return Err(AuditAdmissionError::Unavailable);
            }
        }

        Ok(RequestGuard {
            logger: self.clone(),
            id,
            armed: true,
        })
    }

    pub fn response_started(&self, id: Uuid, parts: &response::Parts) {
        self.send(LogEvent::ResponseStarted {
            id,
            status: parts.status,
            streaming: is_event_stream(&parts.headers),
        });
    }

    /// Attach an internal failure detail to the server-side audit record.
    pub fn request_error(&self, id: Uuid, error: impl Into<String>) {
        self.send(LogEvent::RequestError {
            id,
            error: error.into(),
        });
    }

    /// Record the backend decision while the request is still pending.
    pub fn request_routed(&self, id: Uuid, routing: RoutingInfo) {
        self.send(LogEvent::RequestRouted {
            id,
            at_unix_ms: now_unix_ms(),
            routing: Box::new(routing),
        });
    }

    /// Wrap a response body so its bytes are counted and scanned for token
    /// usage on the way to the client. The bytes themselves are never stored.
    pub fn response_body(&self, id: Uuid, body: Body) -> Body {
        Body::new(ObservedBody::new(body, self.clone(), id))
    }

    pub(crate) fn response_finished(&self, id: Uuid, outcome: BodyOutcome) {
        self.response_finished_with_observation(id, outcome, BodyObservation::default());
    }

    fn response_finished_with_observation(
        &self,
        id: Uuid,
        outcome: BodyOutcome,
        observation: BodyObservation,
    ) {
        self.send(LogEvent::ResponseFinished {
            id,
            at_unix_ms: now_unix_ms(),
            outcome,
            observation,
        });
    }

    fn send(&self, event: LogEvent) {
        // Events are compact and bounded per request: response bytes are
        // counted and scanned on the body path, then only the final counters
        // cross this channel. Disk I/O can therefore never retain body frames.
        if self.tx.try_send(event).is_err() {
            self.health.mark_failed();
        }
    }
}

/// Closes out a request whose handler was dropped before responding.
pub struct RequestGuard {
    logger: LogSender,
    id: Uuid,
    armed: bool,
}

impl RequestGuard {
    /// Hand responsibility for the record over to the response body.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.armed {
            self.logger
                .response_finished(self.id, BodyOutcome::Abandoned);
        }
    }
}

pin_project! {
    struct ObservedBody {
        #[pin]
        inner: Body,
        completion: CompletionGuard,
    }
}

struct CompletionGuard {
    logger: LogSender,
    id: Uuid,
    finished: bool,
    first_byte_at_unix_ms: Option<u64>,
    response_bytes: u64,
    sniffer: UsageSniffer,
}

impl ObservedBody {
    fn new(inner: Body, logger: LogSender, id: Uuid) -> Self {
        let already_finished = inner.is_end_stream();
        let mut body = Self {
            inner,
            completion: CompletionGuard {
                logger,
                id,
                finished: false,
                first_byte_at_unix_ms: None,
                response_bytes: 0,
                sniffer: UsageSniffer::new(),
            },
        };

        // Hyper never polls some zero-length bodies. Emit the end event at
        // construction so the pending-request entry cannot leak.
        if already_finished {
            body.completion.finish(BodyOutcome::Complete);
        }
        body
    }
}

impl HttpBody for ObservedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    if this.completion.first_byte_at_unix_ms.is_none() {
                        this.completion.first_byte_at_unix_ms = Some(now_unix_ms());
                    }
                    this.completion.response_bytes = this
                        .completion
                        .response_bytes
                        .saturating_add(bytes.len() as u64);
                    this.completion.sniffer.feed(bytes);
                }
                // Consumers commonly stop polling after a frame for which the
                // inner body reports end-of-stream, so observe that transition
                // here rather than waiting for a later `None`.
                if this.inner.is_end_stream() {
                    this.completion.finish(BodyOutcome::Complete);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.completion
                    .finish(BodyOutcome::Error(error.to_string()));
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.completion.finish(BodyOutcome::Complete);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl CompletionGuard {
    fn finish(&mut self, outcome: BodyOutcome) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.logger.response_finished_with_observation(
            self.id,
            outcome,
            BodyObservation {
                first_byte_at_unix_ms: self.first_byte_at_unix_ms,
                response_bytes: self.response_bytes,
                usage: self.sniffer.usage().unwrap_or_default(),
            },
        );
    }
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        self.finish(BodyOutcome::Aborted);
    }
}

fn run_worker(
    rx: Receiver<LogEvent>,
    writer: Box<dyn Write + Send>,
    terminal_log: bool,
) -> io::Result<()> {
    let mut writer = BufWriter::new(writer);
    let mut pending = HashMap::<Uuid, Pending>::new();
    let mut dirty = false;
    let mut last_flush = Instant::now();

    loop {
        let wait = if dirty {
            FLUSH_INTERVAL.saturating_sub(last_flush.elapsed())
        } else {
            FLUSH_INTERVAL
        };
        match rx.recv_timeout(wait) {
            Ok(event) => {
                dirty |= handle_event(&mut writer, &mut pending, event, terminal_log)?;
                if dirty && last_flush.elapsed() >= FLUSH_INTERVAL {
                    writer.flush()?;
                    dirty = false;
                    last_flush = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if dirty {
                    writer.flush()?;
                    dirty = false;
                }
                last_flush = Instant::now();
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    // A response body always reports an outcome from Drop, so this only runs if
    // a producer itself panicked. Emit what we have rather than losing it.
    let ids: Vec<Uuid> = pending.keys().copied().collect();
    for id in ids {
        let record = pending.remove(&id).expect("id came from the same map");
        write_record(
            &mut writer,
            id,
            record,
            now_unix_ms(),
            BodyOutcome::Error("the logger shut down before the response finished".to_owned()),
            terminal_log,
        )?;
    }
    writer.flush()
}

fn handle_event(
    writer: &mut dyn Write,
    pending: &mut HashMap<Uuid, Pending>,
    event: LogEvent,
    terminal_log: bool,
) -> io::Result<bool> {
    match event {
        LogEvent::RequestStarted {
            id,
            at_unix_ms,
            info,
            permit,
        } => {
            if terminal_log {
                eprintln!(
                    "{}  >  {id}  {} {}  {}  from {}",
                    format_timestamp(at_unix_ms),
                    info.method,
                    info.uri,
                    info.principal(),
                    info.peer.ip(),
                );
            }
            pending.insert(
                id,
                Pending {
                    _permit: permit,
                    started_at_unix_ms: at_unix_ms,
                    info,
                    status: None,
                    streaming: false,
                    first_byte_at_unix_ms: None,
                    response_bytes: 0,
                    usage: Usage::default(),
                    error: None,
                    routing: None,
                    routed_at_unix_ms: None,
                },
            );
            Ok(false)
        }
        LogEvent::ResponseStarted {
            id,
            status,
            streaming,
        } => {
            if let Some(entry) = pending.get_mut(&id) {
                entry.status = Some(status);
                entry.streaming = streaming;
            }
            Ok(false)
        }
        LogEvent::RequestError { id, error } => {
            if let Some(entry) = pending.get_mut(&id) {
                entry.error = Some(error);
            }
            Ok(false)
        }
        LogEvent::RequestRouted {
            id,
            at_unix_ms,
            routing,
        } => {
            if let Some(entry) = pending.get_mut(&id) {
                entry.routing = Some(routing);
                entry.routed_at_unix_ms = Some(at_unix_ms);
            }
            Ok(false)
        }
        LogEvent::ResponseFinished {
            id,
            at_unix_ms,
            outcome,
            observation,
        } => match pending.remove(&id) {
            Some(mut entry) => {
                entry.first_byte_at_unix_ms = observation.first_byte_at_unix_ms;
                entry.response_bytes = observation.response_bytes;
                entry.usage = observation.usage;
                write_record(writer, id, entry, at_unix_ms, outcome, terminal_log)?;
                Ok(true)
            }
            None => Ok(false),
        },
    }
}

#[derive(Serialize)]
struct RequestRecord<'a> {
    event: &'static str,
    request_id: String,
    started_at: String,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    duration_ms: u64,
    time_to_first_byte_ms: Option<u64>,
    client_ip: String,
    client_port: u16,
    host: Option<&'a str>,
    user_agent: Option<&'a str>,
    method: &'a str,
    uri: String,
    http_version: &'static str,
    request_content_length: Option<u64>,
    authorized: bool,
    auth_error: Option<&'static str>,
    key_name: Option<&'a str>,
    key_identifier: Option<&'a str>,
    key_sha256: Option<&'a str>,
    key_admin: Option<bool>,
    backend_id: Option<&'a str>,
    routing_policy: Option<&'static str>,
    routing_reason: Option<&'static str>,
    eligible_backend_count: Option<usize>,
    backend_pressure_at_dispatch: Option<f64>,
    backend_running_at_dispatch: Option<u64>,
    backend_waiting_at_dispatch: Option<u64>,
    backend_capacity_at_dispatch: Option<u64>,
    backend_kv_pressure_at_dispatch: Option<f64>,
    backend_metrics_age_ms: Option<u64>,
    backend_proxy_active_at_dispatch: Option<usize>,
    proxy_queue_ms: Option<u64>,
    status: Option<u16>,
    streaming: bool,
    response_bytes: u64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    cached_tokens: Option<u64>,
    complete: bool,
    termination: &'static str,
    error: Option<&'a str>,
}

fn write_record(
    writer: &mut dyn Write,
    id: Uuid,
    entry: Pending,
    finished_at_unix_ms: u64,
    outcome: BodyOutcome,
    terminal_log: bool,
) -> io::Result<()> {
    let (complete, termination, outcome_error) = outcome.describe();
    let error = entry.error.as_deref().or(outcome_error);
    let usage = entry.usage;
    let duration_ms = finished_at_unix_ms.saturating_sub(entry.started_at_unix_ms);
    let info = &entry.info;
    let routing = entry.routing.as_deref();

    if terminal_log {
        eprintln!(
            "{}  <  {id}  {}  {}ms  in={} out={}{}  {}{}",
            format_timestamp(finished_at_unix_ms),
            entry
                .status
                .map_or_else(|| "---".to_owned(), |status| status.as_u16().to_string()),
            duration_ms,
            usage
                .input_tokens
                .map_or_else(|| "-".to_owned(), |tokens| tokens.to_string()),
            usage
                .output_tokens
                .map_or_else(|| "-".to_owned(), |tokens| tokens.to_string()),
            usage
                .cached_tokens
                .map_or_else(String::new, |tokens| format!(" cached={tokens}")),
            info.principal(),
            if complete { "" } else { "  (incomplete)" },
        );
    }

    let record = RequestRecord {
        event: "request",
        request_id: id.to_string(),
        started_at: format_timestamp(entry.started_at_unix_ms),
        started_at_unix_ms: entry.started_at_unix_ms,
        finished_at_unix_ms,
        duration_ms,
        time_to_first_byte_ms: entry
            .first_byte_at_unix_ms
            .map(|at| at.saturating_sub(entry.started_at_unix_ms)),
        client_ip: info.peer.ip().to_string(),
        client_port: info.peer.port(),
        host: info.host.as_deref(),
        user_agent: info.user_agent.as_deref(),
        method: info.method.as_str(),
        uri: info.uri.to_string(),
        http_version: version_string(info.version),
        request_content_length: info.content_length,
        authorized: info.authorized,
        auth_error: info.auth_error,
        key_name: info
            .identity
            .as_ref()
            .map(|identity| identity.name.as_str()),
        key_identifier: info
            .identity
            .as_ref()
            .map(|identity| identity.identifier.as_str()),
        key_sha256: info.key_sha256.as_deref(),
        key_admin: info.identity.as_ref().map(|identity| identity.admin),
        backend_id: routing.and_then(|routing| routing.backend_id.as_deref()),
        routing_policy: routing.and_then(|routing| routing.routing_policy),
        routing_reason: routing.and_then(|routing| routing.routing_reason),
        eligible_backend_count: routing.and_then(|routing| routing.eligible_backend_count),
        backend_pressure_at_dispatch: routing
            .and_then(|routing| routing.backend_pressure_at_dispatch),
        backend_running_at_dispatch: routing
            .and_then(|routing| routing.backend_running_at_dispatch),
        backend_waiting_at_dispatch: routing
            .and_then(|routing| routing.backend_waiting_at_dispatch),
        backend_capacity_at_dispatch: routing
            .and_then(|routing| routing.backend_capacity_at_dispatch),
        backend_kv_pressure_at_dispatch: routing
            .and_then(|routing| routing.backend_kv_pressure_at_dispatch),
        backend_metrics_age_ms: routing.and_then(|routing| routing.backend_metrics_age_ms),
        backend_proxy_active_at_dispatch: routing
            .and_then(|routing| routing.backend_proxy_active_at_dispatch),
        proxy_queue_ms: entry
            .routed_at_unix_ms
            .map(|at| at.saturating_sub(entry.started_at_unix_ms)),
        status: entry.status.map(|status| status.as_u16()),
        streaming: entry.streaming,
        response_bytes: entry.response_bytes,
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        total_tokens: usage.total_tokens,
        cached_tokens: usage.cached_tokens,
        complete,
        termination,
        error,
    };

    serde_json::to_writer(&mut *writer, &record).map_err(io::Error::other)?;
    writer.write_all(b"\n")
}

const fn version_string(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "unknown",
    }
}

/// True when the response is a Server-Sent Events stream, which is how both
/// the Chat Completions and Responses APIs stream.
fn is_event_stream(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` from Unix milliseconds.
pub fn format_timestamp(unix_ms: u64) -> String {
    let seconds = unix_ms / 1_000;
    let millis = unix_ms % 1_000;
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let time = seconds % 86_400;

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        time / 3_600,
        (time % 3_600) / 60,
        time % 60,
    )
}

/// Howard Hinnant's days-from-Unix-epoch to proleptic Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;

    (year + i64::from(month <= 2), month, day)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{fs, net::Ipv4Addr};

    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::Value;

    use super::*;
    use crate::{
        auth::{KeyStore, authenticate},
        keys::KeyRecord,
    };

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("test writer failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("test writer failure"))
        }
    }

    fn store_and_key() -> (KeyStore, String) {
        let (record, key) = KeyRecord::generate("alice", true).unwrap();
        (KeyStore::from_records(vec![record]).unwrap(), key)
    }

    async fn record_for(response_body: &'static str) -> Value {
        let path = std::env::temp_dir().join(format!("proxy-log-{}.jsonl", Uuid::new_v4()));
        let (logger, worker) = start(&path, false).unwrap();
        let (store, key) = store_and_key();
        let id = Uuid::new_v4();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(HOST, "localhost:3000")
            .header(USER_AGENT, "openai-python/1.0")
            .header("authorization", format!("Bearer {key}"))
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let auth = authenticate(&parts.headers, &store);
        logger
            .request_started(
                id,
                RequestInfo::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 4242)), &parts, &auth),
            )
            .unwrap()
            .disarm();

        let response = axum::response::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        let (response_parts, ()) = response.into_parts();
        logger.response_started(id, &response_parts);
        let body = logger.response_body(id, Body::from(response_body));
        assert_eq!(body.collect().await.unwrap().to_bytes(), response_body);

        drop(logger);
        worker.join().unwrap();
        let lines = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();

        let records: Vec<Value> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 1, "expected exactly one record per request");

        records.into_iter().next().unwrap()
    }

    #[test]
    fn writer_failure_marks_the_logger_unhealthy() {
        let (logger, worker) = start_with_writer(Box::new(FailingWriter), false).unwrap();
        let (store, key) = store_and_key();
        let id = Uuid::new_v4();

        let request = Request::builder()
            .uri("/v1/models")
            .header("authorization", format!("Bearer {key}"))
            .body(())
            .unwrap();
        let (request_parts, ()) = request.into_parts();
        let auth = authenticate(&request_parts.headers, &store);
        logger
            .request_started(
                id,
                RequestInfo::new(
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 4242)),
                    &request_parts,
                    &auth,
                ),
            )
            .unwrap()
            .disarm();

        let response = axum::response::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        let (parts, ()) = response.into_parts();
        logger.response_started(id, &parts);
        logger.response_finished(id, BodyOutcome::Complete);

        let deadline = Instant::now() + Duration::from_secs(2);
        while logger.is_healthy() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(!logger.is_healthy());
        assert!(worker.join().is_err());
    }

    #[test]
    fn audit_admission_is_bounded_before_a_request_can_route() {
        let (logger, worker) =
            start_with_writer_and_slots(Box::new(Vec::<u8>::new()), false, 1).unwrap();
        let (store, key) = store_and_key();
        let request = Request::builder()
            .uri("/v1/models")
            .header("authorization", format!("Bearer {key}"))
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let auth = authenticate(&parts.headers, &store);
        let info =
            || RequestInfo::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 4242)), &parts, &auth);

        let first = logger.request_started(Uuid::new_v4(), info()).unwrap();
        assert!(matches!(
            logger.request_started(Uuid::new_v4(), info()),
            Err(AuditAdmissionError::Saturated)
        ));
        assert!(logger.is_healthy(), "backpressure is not writer failure");

        drop(first);
        drop(logger);
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn one_record_carries_metadata_and_token_counts() {
        let record = record_for(
            r#"{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17,"prompt_tokens_details":{"cached_tokens":9}}}"#,
        )
        .await;

        assert_eq!(record["event"], "request");
        assert_eq!(record["client_ip"], "127.0.0.1");
        assert_eq!(record["client_port"], 4242);
        assert_eq!(record["host"], "localhost:3000");
        assert_eq!(record["user_agent"], "openai-python/1.0");
        assert_eq!(record["method"], "POST");
        assert_eq!(record["uri"], "/v1/chat/completions");
        assert_eq!(record["authorized"], true);
        assert_eq!(record["key_name"], "alice");
        assert_eq!(record["key_admin"], true);
        assert_eq!(record["status"], 200);
        assert_eq!(record["input_tokens"], 12);
        assert_eq!(record["output_tokens"], 5);
        assert_eq!(record["total_tokens"], 17);
        assert_eq!(record["cached_tokens"], 9);
        assert_eq!(record["complete"], true);
        assert!(record["started_at"].as_str().unwrap().ends_with('Z'));
        assert!(record["key_sha256"].as_str().unwrap().len() == 64);
    }

    #[tokio::test]
    async fn no_body_content_reaches_the_log() {
        let record = record_for(r#"{"choices":[{"message":{"content":"a secret answer"}}]}"#).await;
        let line = serde_json::to_string(&record).unwrap();

        assert!(!line.contains("secret answer"));
        assert!(!line.contains("choices"));
        assert_eq!(record["input_tokens"], Value::Null);
        assert_eq!(record["output_tokens"], Value::Null);
        assert_eq!(record["cached_tokens"], Value::Null);
        assert!(record["response_bytes"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn streaming_usage_is_recovered_from_the_final_chunk() {
        let record = record_for(
            "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}],\"usage\":null}\n\n\
             data: {\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":8,\"total_tokens\":12,\"prompt_tokens_details\":{\"cached_tokens\":2}}}\n\n\
             data: [DONE]\n\n",
        )
        .await;

        assert_eq!(record["input_tokens"], 4);
        assert_eq!(record["output_tokens"], 8);
        assert_eq!(record["cached_tokens"], 2);
    }

    #[test]
    fn timestamps_format_as_utc_iso8601() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_timestamp(1_755_000_000_123),
            "2025-08-12T12:00:00.123Z"
        );
        assert_eq!(
            format_timestamp(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
    }
}
