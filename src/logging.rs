use std::{
    borrow::Cow,
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
    http::{HeaderMap, Method, StatusCode, Uri, Version, header::HOST, request, response},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use pin_project_lite::pin_project;
use serde::Serialize;
use tokio::sync::mpsc as tokio_mpsc;
use uuid::Uuid;

const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct LogSender {
    tx: Sender<LogEvent>,
    healthy: Arc<AtomicBool>,
}

pub struct LogWorker {
    thread: JoinHandle<io::Result<()>>,
}

#[derive(Debug)]
pub enum BodyOutcome {
    Complete,
    Aborted,
    Error(String),
}

enum LogEvent {
    RequestStarted {
        id: Uuid,
        timestamp_unix_ms: u64,
        metadata: RequestMetadata,
    },
    RequestChunk {
        id: Uuid,
        bytes: Bytes,
    },
    RequestTrailers {
        id: Uuid,
        trailers: HeaderMap,
    },
    RequestFinished {
        id: Uuid,
        completed_at_unix_ms: u64,
        outcome: BodyOutcome,
    },
    ResponseStarted {
        id: Uuid,
        timestamp_unix_ms: u64,
        metadata: ResponseMetadata,
    },
    ResponseChunk {
        id: Uuid,
        timestamp_unix_ms: u64,
        sequence: u64,
        offset: u64,
        bytes: Bytes,
    },
    ResponseTrailers {
        id: Uuid,
        timestamp_unix_ms: u64,
        sequence: u64,
        trailers: HeaderMap,
    },
    ResponseFinished {
        id: Uuid,
        timestamp_unix_ms: u64,
        total_body_bytes: u64,
        outcome: BodyOutcome,
    },
}

struct RequestMetadata {
    peer: SocketAddr,
    api_key: Option<String>,
    authorized: bool,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
}

struct ResponseMetadata {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
}

struct PendingRequest {
    timestamp_unix_ms: u64,
    metadata: RequestMetadata,
    body: Vec<u8>,
    trailers: Vec<HeaderMap>,
}

#[derive(Default)]
struct PendingResponse {
    utf8_carry: Vec<u8>,
    carry_offset: u64,
    carry_sequence: u64,
    total_body_bytes: u64,
}

pub fn start(path: &Path) -> io::Result<(LogSender, LogWorker)> {
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

    start_with_writer(writer)
}

fn start_with_writer(writer: Box<dyn Write + Send>) -> io::Result<(LogSender, LogWorker)> {
    let (tx, rx) = mpsc::channel();
    let healthy = Arc::new(AtomicBool::new(true));
    let worker_health = Arc::clone(&healthy);
    let thread = thread::Builder::new()
        .name("json-log-writer".to_owned())
        .spawn(move || {
            let result = run_worker(rx, writer);
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
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    pub fn request_started(
        &self,
        id: Uuid,
        peer: SocketAddr,
        api_key: Option<String>,
        authorized: bool,
        parts: &request::Parts,
    ) {
        self.send(LogEvent::RequestStarted {
            id,
            timestamp_unix_ms: now_unix_ms(),
            metadata: RequestMetadata {
                peer,
                api_key,
                authorized,
                method: parts.method.clone(),
                uri: parts.uri.clone(),
                version: parts.version,
                headers: parts.headers.clone(),
            },
        });
    }

    pub fn request_finished(&self, id: Uuid, outcome: BodyOutcome) {
        self.send(LogEvent::RequestFinished {
            id,
            completed_at_unix_ms: now_unix_ms(),
            outcome,
        });
    }

    pub fn response_started(&self, id: Uuid, parts: &response::Parts) {
        self.send(LogEvent::ResponseStarted {
            id,
            timestamp_unix_ms: now_unix_ms(),
            metadata: ResponseMetadata {
                status: parts.status,
                version: parts.version,
                headers: parts.headers.clone(),
            },
        });
    }

    pub fn request_body(&self, id: Uuid, body: Body) -> Body {
        let size_hint = body.size_hint();
        if body.is_end_stream() {
            self.request_finished(id, BodyOutcome::Complete);
            return body;
        }

        // This bounded pipe preserves normal streaming backpressure. Because
        // the pump owns the inbound body, it keeps draining for the audit log
        // if the upstream stops consuming its side of the pipe.
        let (tx, rx) = tokio_mpsc::channel(8);
        spawn_request_pump(self.clone(), id, body, Some(tx));
        Body::new(ForwardBody { rx, size_hint })
    }

    pub fn drain_request(&self, id: Uuid, body: Body) {
        if body.is_end_stream() {
            self.request_finished(id, BodyOutcome::Complete);
        } else {
            spawn_request_pump(self.clone(), id, body, None);
        }
    }

    pub fn response_body(&self, id: Uuid, body: Body) -> Body {
        Body::new(LoggedBody::new(body, self.clone(), id))
    }

    fn send(&self, event: LogEvent) {
        // std's MPSC channel is unbounded: this call never waits for disk I/O,
        // and it does not intentionally drop audit events. See README.md for
        // the memory/backpressure tradeoff this implies.
        if self.tx.send(event).is_err() {
            self.healthy.store(false, Ordering::Release);
        }
    }
}

struct ForwardBody {
    rx: tokio_mpsc::Receiver<Result<Frame<Bytes>, axum::Error>>,
    size_hint: SizeHint,
}

impl HttpBody for ForwardBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    let length = bytes.len() as u64;
                    let lower = self.size_hint.lower().saturating_sub(length);
                    self.size_hint.set_lower(lower);
                    if let Some(upper) = self.size_hint.upper() {
                        self.size_hint.set_upper(upper.saturating_sub(length));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.rx.is_closed() && self.rx.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        self.size_hint
    }
}

struct RequestPumpGuard {
    logger: LogSender,
    id: Uuid,
    finished: bool,
}

impl RequestPumpGuard {
    fn finish(&mut self, outcome: BodyOutcome) {
        if !self.finished {
            self.finished = true;
            self.logger.request_finished(self.id, outcome);
        }
    }
}

impl Drop for RequestPumpGuard {
    fn drop(&mut self) {
        self.finish(BodyOutcome::Aborted);
    }
}

fn spawn_request_pump(
    logger: LogSender,
    id: Uuid,
    mut body: Body,
    mut forward: Option<tokio_mpsc::Sender<Result<Frame<Bytes>, axum::Error>>>,
) {
    tokio::spawn(async move {
        let mut completion = RequestPumpGuard {
            logger: logger.clone(),
            id,
            finished: false,
        };

        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    let is_trailers = frame.trailers_ref().is_some();
                    if let Some(bytes) = frame.data_ref() {
                        logger.send(LogEvent::RequestChunk {
                            id,
                            bytes: bytes.clone(),
                        });
                    } else if let Some(trailers) = frame.trailers_ref() {
                        logger.send(LogEvent::RequestTrailers {
                            id,
                            trailers: trailers.clone(),
                        });
                    }

                    if let Some(tx) = &forward
                        && tx.send(Ok(frame)).await.is_err()
                    {
                        forward = None;
                    }

                    if is_trailers || body.is_end_stream() {
                        completion.finish(BodyOutcome::Complete);
                        return;
                    }
                }
                Some(Err(error)) => {
                    let message = error.to_string();
                    if let Some(tx) = forward {
                        let _ = tx.send(Err(error)).await;
                    }
                    completion.finish(BodyOutcome::Error(message));
                    return;
                }
                None => {
                    completion.finish(BodyOutcome::Complete);
                    return;
                }
            }
        }
    });
}

pin_project! {
    struct LoggedBody {
        #[pin]
        inner: Body,
        completion: CompletionGuard,
    }
}

struct CompletionGuard {
    logger: LogSender,
    id: Uuid,
    finished: bool,
    sequence: u64,
    body_bytes: u64,
}

impl LoggedBody {
    fn new(inner: Body, logger: LogSender, id: Uuid) -> Self {
        let already_finished = inner.is_end_stream();
        let mut body = Self {
            inner,
            completion: CompletionGuard {
                logger,
                id,
                finished: false,
                sequence: 0,
                body_bytes: 0,
            },
        };

        // Some zero-length bodies are never polled by Hyper. Emit their end
        // event at construction so the request accumulator cannot leak.
        if already_finished {
            body.completion.finish(BodyOutcome::Complete);
        }
        body
    }
}

impl HttpBody for LoggedBody {
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
                    this.completion.observe_data(bytes);
                } else if let Some(trailers) = frame.trailers_ref() {
                    this.completion.observe_trailers(trailers);
                }
                // Consumers commonly stop polling after a frame for which the
                // inner body reports end-of-stream. Observe that transition so
                // completion doesn't depend on a later poll returning None.
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
    fn observe_data(&mut self, bytes: &Bytes) {
        self.logger.send(LogEvent::ResponseChunk {
            id: self.id,
            timestamp_unix_ms: now_unix_ms(),
            sequence: self.sequence,
            offset: self.body_bytes,
            bytes: bytes.clone(),
        });
        self.sequence = self.sequence.saturating_add(1);
        self.body_bytes = self.body_bytes.saturating_add(bytes.len() as u64);
    }

    fn observe_trailers(&mut self, trailers: &HeaderMap) {
        self.logger.send(LogEvent::ResponseTrailers {
            id: self.id,
            timestamp_unix_ms: now_unix_ms(),
            sequence: self.sequence,
            trailers: trailers.clone(),
        });
        self.sequence = self.sequence.saturating_add(1);
        self.finish(BodyOutcome::Complete);
    }

    fn finish(&mut self, outcome: BodyOutcome) {
        if self.finished {
            return;
        }
        self.finished = true;

        self.logger.send(LogEvent::ResponseFinished {
            id: self.id,
            timestamp_unix_ms: now_unix_ms(),
            total_body_bytes: self.body_bytes,
            outcome,
        });
    }
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        self.finish(BodyOutcome::Aborted);
    }
}

fn run_worker(rx: Receiver<LogEvent>, writer: Box<dyn Write + Send>) -> io::Result<()> {
    let mut writer = BufWriter::new(writer);
    let mut pending_requests = HashMap::<Uuid, PendingRequest>::new();
    let mut pending_responses = HashMap::<Uuid, PendingResponse>::new();
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
                dirty |= handle_event(
                    &mut writer,
                    &mut pending_requests,
                    &mut pending_responses,
                    event,
                )?;
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

    // A body should always send an aborted event from Drop. This fallback also
    // makes shutdown output useful if a producer itself panicked.
    for (id, pending) in pending_requests {
        write_request(
            &mut writer,
            id,
            pending,
            now_unix_ms(),
            BodyOutcome::Error("logger channel closed before request body finished".to_owned()),
        )?;
    }
    for (id, mut pending) in pending_responses {
        let timestamp = now_unix_ms();
        flush_response_utf8_tail(&mut writer, id, timestamp, &mut pending)?;
        write_response_end(
            &mut writer,
            id,
            timestamp,
            pending.total_body_bytes,
            BodyOutcome::Error("logger channel closed before response body finished".to_owned()),
        )?;
    }
    writer.flush()
}

fn handle_event(
    writer: &mut dyn Write,
    pending_requests: &mut HashMap<Uuid, PendingRequest>,
    pending_responses: &mut HashMap<Uuid, PendingResponse>,
    event: LogEvent,
) -> io::Result<bool> {
    match event {
        LogEvent::RequestStarted {
            id,
            timestamp_unix_ms,
            metadata,
        } => {
            pending_requests.insert(
                id,
                PendingRequest {
                    timestamp_unix_ms,
                    metadata,
                    body: Vec::new(),
                    trailers: Vec::new(),
                },
            );
            Ok(false)
        }
        LogEvent::RequestChunk { id, bytes } => {
            if let Some(request) = pending_requests.get_mut(&id) {
                request.body.extend_from_slice(&bytes);
            }
            Ok(false)
        }
        LogEvent::RequestTrailers { id, trailers } => {
            if let Some(request) = pending_requests.get_mut(&id) {
                request.trailers.push(trailers);
            }
            Ok(false)
        }
        LogEvent::RequestFinished {
            id,
            completed_at_unix_ms,
            outcome,
        } => {
            if let Some(request) = pending_requests.remove(&id) {
                write_request(writer, id, request, completed_at_unix_ms, outcome)?;
                return Ok(true);
            }
            Ok(false)
        }
        LogEvent::ResponseStarted {
            id,
            timestamp_unix_ms,
            metadata,
        } => {
            pending_responses.insert(id, PendingResponse::default());
            write_response_start(writer, id, timestamp_unix_ms, metadata).map(|()| true)
        }
        LogEvent::ResponseChunk {
            id,
            timestamp_unix_ms,
            sequence,
            offset,
            bytes,
        } => write_response_chunk(
            writer,
            id,
            timestamp_unix_ms,
            sequence,
            offset,
            &bytes,
            pending_responses.entry(id).or_default(),
        )
        .map(|()| true),
        LogEvent::ResponseTrailers {
            id,
            timestamp_unix_ms,
            sequence,
            trailers,
        } => {
            let pending = pending_responses.entry(id).or_default();
            flush_response_utf8_tail(writer, id, timestamp_unix_ms, pending)?;
            write_response_trailers(writer, id, timestamp_unix_ms, sequence, &trailers)
                .map(|()| true)
        }
        LogEvent::ResponseFinished {
            id,
            timestamp_unix_ms,
            total_body_bytes,
            outcome,
        } => {
            if let Some(mut pending) = pending_responses.remove(&id) {
                flush_response_utf8_tail(writer, id, timestamp_unix_ms, &mut pending)?;
            }
            write_response_end(writer, id, timestamp_unix_ms, total_body_bytes, outcome)
                .map(|()| true)
        }
    }
}

#[derive(Serialize)]
struct HeaderRecord {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct RequestRecord<'a> {
    event: &'static str,
    request_id: String,
    timestamp_unix_ms: u64,
    completed_at_unix_ms: u64,
    client_ip: String,
    client_port: u16,
    host: Option<String>,
    api_key: Option<&'a str>,
    authorized: bool,
    method: &'a str,
    uri: String,
    http_version: String,
    headers: Vec<HeaderRecord>,
    body: Option<&'a str>,
    body_utf8_valid: Option<bool>,
    body_bytes_hex: Option<String>,
    trailers: Vec<Vec<HeaderRecord>>,
    complete: bool,
    termination: &'a str,
    error: Option<&'a str>,
}

fn write_request(
    writer: &mut dyn Write,
    id: Uuid,
    pending: PendingRequest,
    completed_at_unix_ms: u64,
    outcome: BodyOutcome,
) -> io::Result<()> {
    let body_text = String::from_utf8_lossy(&pending.body);
    let body_utf8_valid = matches!(body_text, Cow::Borrowed(_));
    let (complete, termination, error) = match &outcome {
        BodyOutcome::Complete => (true, "complete", None),
        BodyOutcome::Aborted => (false, "body_dropped", None),
        BodyOutcome::Error(error) => (false, "body_error", Some(error.as_str())),
    };
    let host = pending
        .metadata
        .headers
        .get(HOST)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .or_else(|| pending.metadata.uri.authority().map(ToString::to_string));
    let trailers = pending.trailers.iter().map(headers_to_records).collect();
    let record = RequestRecord {
        event: "request",
        request_id: id.to_string(),
        timestamp_unix_ms: pending.timestamp_unix_ms,
        completed_at_unix_ms,
        client_ip: pending.metadata.peer.ip().to_string(),
        client_port: pending.metadata.peer.port(),
        host,
        api_key: pending.metadata.api_key.as_deref(),
        authorized: pending.metadata.authorized,
        method: pending.metadata.method.as_str(),
        uri: pending.metadata.uri.to_string(),
        http_version: version_string(pending.metadata.version),
        headers: headers_to_records(&pending.metadata.headers),
        body: Some(body_text.as_ref()),
        body_utf8_valid: Some(body_utf8_valid),
        body_bytes_hex: (!body_utf8_valid).then(|| encode_hex(&pending.body)),
        trailers,
        complete,
        termination,
        error,
    };

    write_json_line(writer, &record)
}

#[derive(Serialize)]
struct ResponseStartRecord {
    event: &'static str,
    request_id: String,
    timestamp_unix_ms: u64,
    status: u16,
    http_version: String,
    headers: Vec<HeaderRecord>,
}

fn write_response_start(
    writer: &mut dyn Write,
    id: Uuid,
    timestamp_unix_ms: u64,
    metadata: ResponseMetadata,
) -> io::Result<()> {
    write_json_line(
        writer,
        &ResponseStartRecord {
            event: "response_start",
            request_id: id.to_string(),
            timestamp_unix_ms,
            status: metadata.status.as_u16(),
            http_version: version_string(metadata.version),
            headers: headers_to_records(&metadata.headers),
        },
    )
}

#[derive(Serialize)]
struct ResponseBodyRecord<'a> {
    event: &'static str,
    request_id: String,
    timestamp_unix_ms: u64,
    sequence: u64,
    offset: u64,
    source_offset: u64,
    source_body_bytes: usize,
    decoded_body_bytes: usize,
    utf8_pending_bytes: usize,
    utf8_tail: bool,
    body: &'a str,
    body_utf8_valid: bool,
    body_bytes_hex: Option<String>,
}

fn write_response_chunk(
    writer: &mut dyn Write,
    id: Uuid,
    timestamp_unix_ms: u64,
    sequence: u64,
    offset: u64,
    bytes: &[u8],
    pending: &mut PendingResponse,
) -> io::Result<()> {
    pending.total_body_bytes = pending
        .total_body_bytes
        .max(offset.saturating_add(bytes.len() as u64));
    let had_carry = !pending.utf8_carry.is_empty();
    let previous_carry_sequence = pending.carry_sequence;
    let decoded_offset = if !had_carry {
        offset
    } else {
        pending.carry_offset
    };
    let mut combined = std::mem::take(&mut pending.utf8_carry);
    let previous_carry_len = combined.len();
    combined.extend_from_slice(bytes);
    let decoded = decode_utf8(&combined, false);
    pending.utf8_carry = combined[decoded.consumed..].to_vec();
    pending.carry_offset = decoded_offset.saturating_add(decoded.consumed as u64);
    if !pending.utf8_carry.is_empty() {
        pending.carry_sequence = if had_carry && decoded.consumed < previous_carry_len {
            previous_carry_sequence
        } else {
            sequence
        };
    }

    write_json_line(
        writer,
        &ResponseBodyRecord {
            event: "response_body",
            request_id: id.to_string(),
            timestamp_unix_ms,
            sequence,
            offset: decoded_offset,
            source_offset: offset,
            source_body_bytes: bytes.len(),
            decoded_body_bytes: decoded.consumed,
            utf8_pending_bytes: pending.utf8_carry.len(),
            utf8_tail: false,
            body: &decoded.text,
            body_utf8_valid: decoded.valid,
            body_bytes_hex: (!decoded.valid).then(|| encode_hex(&combined[..decoded.consumed])),
        },
    )
}

fn flush_response_utf8_tail(
    writer: &mut dyn Write,
    id: Uuid,
    timestamp_unix_ms: u64,
    pending: &mut PendingResponse,
) -> io::Result<()> {
    if pending.utf8_carry.is_empty() {
        return Ok(());
    }

    let bytes = std::mem::take(&mut pending.utf8_carry);
    let decoded = decode_utf8(&bytes, true);
    write_json_line(
        writer,
        &ResponseBodyRecord {
            event: "response_body",
            request_id: id.to_string(),
            timestamp_unix_ms,
            sequence: pending.carry_sequence,
            offset: pending.carry_offset,
            source_offset: pending.carry_offset,
            source_body_bytes: 0,
            decoded_body_bytes: decoded.consumed,
            utf8_pending_bytes: 0,
            utf8_tail: true,
            body: &decoded.text,
            body_utf8_valid: decoded.valid,
            body_bytes_hex: (!decoded.valid).then(|| encode_hex(&bytes)),
        },
    )
}

struct DecodedUtf8 {
    text: String,
    consumed: usize,
    valid: bool,
}

fn decode_utf8(bytes: &[u8], final_chunk: bool) -> DecodedUtf8 {
    let mut text = String::with_capacity(bytes.len());
    let mut consumed = 0;
    let mut valid = true;

    while consumed < bytes.len() {
        match std::str::from_utf8(&bytes[consumed..]) {
            Ok(remainder) => {
                text.push_str(remainder);
                consumed = bytes.len();
            }
            Err(error) => {
                let valid_end = consumed + error.valid_up_to();
                // from_utf8 reported this prefix as valid.
                text.push_str(
                    std::str::from_utf8(&bytes[consumed..valid_end])
                        .expect("validated UTF-8 prefix"),
                );
                consumed = valid_end;

                match error.error_len() {
                    Some(length) => {
                        text.push('\u{fffd}');
                        consumed += length;
                        valid = false;
                    }
                    None if final_chunk => {
                        text.push('\u{fffd}');
                        consumed = bytes.len();
                        valid = false;
                    }
                    None => break,
                }
            }
        }
    }

    DecodedUtf8 {
        text,
        consumed,
        valid,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[derive(Serialize)]
struct ResponseTrailersRecord {
    event: &'static str,
    request_id: String,
    timestamp_unix_ms: u64,
    sequence: u64,
    trailers: Vec<HeaderRecord>,
}

fn write_response_trailers(
    writer: &mut dyn Write,
    id: Uuid,
    timestamp_unix_ms: u64,
    sequence: u64,
    trailers: &HeaderMap,
) -> io::Result<()> {
    write_json_line(
        writer,
        &ResponseTrailersRecord {
            event: "response_trailers",
            request_id: id.to_string(),
            timestamp_unix_ms,
            sequence,
            trailers: headers_to_records(trailers),
        },
    )
}

#[derive(Serialize)]
struct ResponseEndRecord<'a> {
    event: &'static str,
    request_id: String,
    timestamp_unix_ms: u64,
    total_body_bytes: u64,
    complete: bool,
    termination: &'a str,
    error: Option<&'a str>,
}

fn write_response_end(
    writer: &mut dyn Write,
    id: Uuid,
    timestamp_unix_ms: u64,
    total_body_bytes: u64,
    outcome: BodyOutcome,
) -> io::Result<()> {
    let (complete, termination, error) = match &outcome {
        BodyOutcome::Complete => (true, "complete", None),
        BodyOutcome::Aborted => (false, "body_dropped", None),
        BodyOutcome::Error(error) => (false, "body_error", Some(error.as_str())),
    };
    write_json_line(
        writer,
        &ResponseEndRecord {
            event: "response_end",
            request_id: id.to_string(),
            timestamp_unix_ms,
            total_body_bytes,
            complete,
            termination,
            error,
        },
    )
}

fn headers_to_records(headers: &HeaderMap) -> Vec<HeaderRecord> {
    headers
        .iter()
        .map(|(name, value)| HeaderRecord {
            name: name.as_str().to_owned(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

fn version_string(version: Version) -> String {
    format!("{version:?}")
}

fn write_json_line(writer: &mut dyn Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")
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
    use std::{fs, net::Ipv4Addr, time::Instant};

    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::Value;

    use super::*;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("test writer failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("test writer failure"))
        }
    }

    #[test]
    fn writer_failure_marks_the_logger_unhealthy() {
        let (logger, worker) = start_with_writer(Box::new(FailingWriter)).unwrap();
        let id = Uuid::new_v4();
        let response = axum::response::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        let (parts, ()) = response.into_parts();
        logger.response_started(id, &parts);

        let deadline = Instant::now() + Duration::from_secs(2);
        while logger.is_healthy() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(!logger.is_healthy());
        assert!(worker.join().is_err());
    }

    #[tokio::test]
    async fn request_is_one_json_record_after_the_entire_body() {
        let path = std::env::temp_dir().join(format!("proxy-log-{}.jsonl", Uuid::new_v4()));
        let (logger, worker) = start(&path).unwrap();
        let id = Uuid::new_v4();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header(HOST, "localhost:3000")
            .header("authorization", "Bearer foobar")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        logger.request_started(
            id,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 4242)),
            Some("foobar".to_owned()),
            true,
            &parts,
        );
        let body = logger.request_body(id, Body::from("hello\nworld"));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "hello\nworld");

        drop(logger);
        worker.join().unwrap();
        let lines = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let records: Vec<Value> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["event"], "request");
        assert_eq!(records[0]["request_id"], id.to_string());
        assert_eq!(records[0]["client_ip"], "127.0.0.1");
        assert_eq!(records[0]["host"], "localhost:3000");
        assert_eq!(records[0]["api_key"], "foobar");
        assert_eq!(records[0]["body"], "hello\nworld");
        assert_eq!(records[0]["complete"], true);
    }

    #[tokio::test]
    async fn response_is_logged_as_stream_events() {
        let path = std::env::temp_dir().join(format!("proxy-log-{}.jsonl", Uuid::new_v4()));
        let (logger, worker) = start(&path).unwrap();
        let id = Uuid::new_v4();
        let response = axum::response::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        let (parts, ()) = response.into_parts();
        logger.response_started(id, &parts);
        let body = logger.response_body(id, Body::from("data: hello\n\n"));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "data: hello\n\n");

        drop(logger);
        worker.join().unwrap();
        let lines = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let records: Vec<Value> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["event"], "response_start");
        assert_eq!(records[1]["event"], "response_body");
        assert_eq!(records[1]["body"], "data: hello\n\n");
        assert_eq!(records[2]["event"], "response_end");
        assert!(
            records
                .iter()
                .all(|record| record["request_id"] == id.to_string())
        );
    }
}
