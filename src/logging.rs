//! Per-request audit logging.
//!
//! Exactly one JSON Lines record is written per proxied request, when its
//! response finishes. Records carry request metadata, the caller's key name,
//! identifier, and digest, and the token counts sniffed out of the response —
//! never a key, a prompt, or a completion.
//!
//! Serialization and file I/O happen on a dedicated OS thread so Tokio's
//! request workers never touch the disk. The same thread prints the
//! human-readable arrival and completion lines to stderr.

use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
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
use uuid::Uuid;

use crate::{
    auth::{Authentication, KeyIdentity},
    usage::UsageSniffer,
};

const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Handle used by the request path to report events. Cloning is cheap.
#[derive(Clone)]
pub struct LogSender {
    tx: Sender<LogEvent>,
    healthy: Arc<AtomicBool>,
}

/// Join handle for the writer thread.
pub struct LogWorker {
    thread: JoinHandle<io::Result<()>>,
}

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
    },
    ResponseStarted {
        id: Uuid,
        status: StatusCode,
        streaming: bool,
    },
    /// Sent once, when the first body byte reaches the client. Separate from
    /// `ResponseChunk` so the clock is read once per request, not per frame.
    FirstResponseChunk {
        id: Uuid,
        at_unix_ms: u64,
    },
    ResponseChunk {
        id: Uuid,
        bytes: Bytes,
    },
    ResponseFinished {
        id: Uuid,
        at_unix_ms: u64,
        outcome: BodyOutcome,
    },
}

struct Pending {
    started_at_unix_ms: u64,
    info: Box<RequestInfo>,
    status: Option<StatusCode>,
    streaming: bool,
    first_byte_at_unix_ms: Option<u64>,
    response_bytes: u64,
    sniffer: UsageSniffer,
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
    let (tx, rx) = mpsc::channel();
    let healthy = Arc::new(AtomicBool::new(true));
    let worker_health = Arc::clone(&healthy);
    let thread = thread::Builder::new()
        .name("json-log-writer".to_owned())
        .spawn(move || {
            let result = run_worker(rx, writer, terminal_log);
            if let Err(error) = &result {
                worker_health.store(false, Ordering::Release);
                eprintln!("JSON log worker stopped: {error}");
            }
            result
        })?;

    Ok((LogSender { tx, healthy }, LogWorker { thread }))
}

impl LogWorker {
    pub fn join(self) -> io::Result<()> {
        self.thread
            .join()
            .map_err(|_| io::Error::other("JSON log worker panicked"))?
    }
}

impl LogSender {
    /// False once the writer has failed. The proxy then fails closed rather
    /// than serving traffic with no audit trail.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Record an arriving request.
    ///
    /// The returned guard closes the record out if the handler is dropped
    /// before it produces a response, so an abandoned request cannot sit in the
    /// worker's pending map forever. Call [`RequestGuard::disarm`] once a
    /// response body has been handed to [`Self::response_body`].
    #[must_use = "the guard closes out abandoned requests"]
    pub fn request_started(&self, id: Uuid, info: RequestInfo) -> RequestGuard {
        self.send(LogEvent::RequestStarted {
            id,
            at_unix_ms: now_unix_ms(),
            info: Box::new(info),
        });

        RequestGuard {
            logger: self.clone(),
            id,
            armed: true,
        }
    }

    pub fn response_started(&self, id: Uuid, parts: &response::Parts) {
        self.send(LogEvent::ResponseStarted {
            id,
            status: parts.status,
            streaming: is_event_stream(&parts.headers),
        });
    }

    /// Wrap a response body so its bytes are counted and scanned for token
    /// usage on the way to the client. The bytes themselves are never stored.
    pub fn response_body(&self, id: Uuid, body: Body) -> Body {
        Body::new(ObservedBody::new(body, self.clone(), id))
    }

    pub(crate) fn response_finished(&self, id: Uuid, outcome: BodyOutcome) {
        self.send(LogEvent::ResponseFinished {
            id,
            at_unix_ms: now_unix_ms(),
            outcome,
        });
    }

    fn send(&self, event: LogEvent) {
        // std's MPSC channel is unbounded, so this never waits for disk I/O and
        // never intentionally drops an audit event.
        if self.tx.send(event).is_err() {
            self.healthy.store(false, Ordering::Release);
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
    saw_data: bool,
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
                saw_data: false,
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
                    if !this.completion.saw_data {
                        this.completion.saw_data = true;
                        this.completion.logger.send(LogEvent::FirstResponseChunk {
                            id: this.completion.id,
                            at_unix_ms: now_unix_ms(),
                        });
                    }
                    this.completion.logger.send(LogEvent::ResponseChunk {
                        id: this.completion.id,
                        bytes: bytes.clone(),
                    });
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
        self.logger.response_finished(self.id, outcome);
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
                    started_at_unix_ms: at_unix_ms,
                    info,
                    status: None,
                    streaming: false,
                    first_byte_at_unix_ms: None,
                    response_bytes: 0,
                    sniffer: UsageSniffer::new(),
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
        LogEvent::FirstResponseChunk { id, at_unix_ms } => {
            if let Some(entry) = pending.get_mut(&id) {
                entry.first_byte_at_unix_ms.get_or_insert(at_unix_ms);
            }
            Ok(false)
        }
        LogEvent::ResponseChunk { id, bytes } => {
            if let Some(entry) = pending.get_mut(&id) {
                entry.response_bytes = entry.response_bytes.saturating_add(bytes.len() as u64);
                entry.sniffer.feed(&bytes);
            }
            Ok(false)
        }
        LogEvent::ResponseFinished {
            id,
            at_unix_ms,
            outcome,
        } => match pending.remove(&id) {
            Some(entry) => {
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
    status: Option<u16>,
    streaming: bool,
    response_bytes: u64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
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
    let (complete, termination, error) = outcome.describe();
    let usage = entry.sniffer.usage().unwrap_or_default();
    let duration_ms = finished_at_unix_ms.saturating_sub(entry.started_at_unix_ms);
    let info = &entry.info;

    if terminal_log {
        eprintln!(
            "{}  <  {id}  {}  {}ms  in={} out={}  {}{}",
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
        status: entry.status.map(|status| status.as_u16()),
        streaming: entry.streaming,
        response_bytes: entry.response_bytes,
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        total_tokens: usage.total_tokens,
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

    #[tokio::test]
    async fn one_record_carries_metadata_and_token_counts() {
        let record = record_for(
            r#"{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}"#,
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
        assert!(record["response_bytes"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn streaming_usage_is_recovered_from_the_final_chunk() {
        let record = record_for(
            "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}],\"usage\":null}\n\n\
             data: {\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":8,\"total_tokens\":12}}\n\n\
             data: [DONE]\n\n",
        )
        .await;

        assert_eq!(record["input_tokens"], 4);
        assert_eq!(record["output_tokens"], 8);
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
