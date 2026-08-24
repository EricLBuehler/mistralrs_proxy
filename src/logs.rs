//! Reading and summarising the audit log.
//!
//! The log is append-only JSON Lines, so a second process can follow it while
//! `serve` is running without coordinating with it. [`Tail`] reads only what
//! has been appended since the last poll and holds back a trailing partial
//! line, so a record that is half-written when we look is picked up whole on
//! the next poll.

pub mod tui;

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use serde::Deserialize;

/// One request record, as written by [`crate::logging`].
///
/// Every field is optional so that a log written by a different version still
/// loads; missing fields simply read as their default.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct LogRecord {
    pub request_id: String,
    pub started_at: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub duration_ms: u64,
    pub time_to_first_byte_ms: Option<u64>,
    pub client_ip: String,
    pub client_port: u16,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub method: String,
    pub uri: String,
    pub http_version: String,
    pub request_content_length: Option<u64>,
    pub authorized: bool,
    pub auth_error: Option<String>,
    pub key_name: Option<String>,
    pub key_identifier: Option<String>,
    pub key_sha256: Option<String>,
    pub key_admin: Option<bool>,
    pub backend_id: Option<String>,
    pub routing_policy: Option<String>,
    pub routing_reason: Option<String>,
    pub eligible_backend_count: Option<usize>,
    pub backend_pressure_at_dispatch: Option<f64>,
    pub backend_running_at_dispatch: Option<u64>,
    pub backend_waiting_at_dispatch: Option<u64>,
    pub backend_capacity_at_dispatch: Option<u64>,
    pub backend_kv_pressure_at_dispatch: Option<f64>,
    pub backend_metrics_age_ms: Option<u64>,
    pub backend_proxy_active_at_dispatch: Option<usize>,
    pub proxy_queue_ms: Option<u64>,
    pub status: Option<u16>,
    pub streaming: bool,
    pub response_bytes: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cached_tokens: Option<u64>,
    pub complete: bool,
    pub termination: String,
    pub error: Option<String>,
}

impl LogRecord {
    /// `name[identifier]` for a known key, or a stand-in matching what the
    /// terminal log prints.
    pub fn principal(&self) -> String {
        match (&self.key_name, &self.key_identifier, &self.key_sha256) {
            (Some(name), Some(identifier), _) => format!("{name}[{identifier}]"),
            (Some(name), None, _) => name.clone(),
            (None, _, Some(digest)) => format!("unknown[{}]", &digest[..8.min(digest.len())]),
            (None, _, None) => "anonymous".to_owned(),
        }
    }

    /// The key name for grouping, with a bucket for unauthenticated traffic.
    pub fn key_bucket(&self) -> &str {
        self.key_name.as_deref().unwrap_or("(unauthenticated)")
    }

    /// The URI with any query string removed, so endpoints group together.
    pub fn path(&self) -> &str {
        match self.uri.split_once('?') {
            Some((path, _)) => path,
            None => &self.uri,
        }
    }

    pub fn is_error(&self) -> bool {
        !self.complete || self.status.is_none_or(|status| status >= 400)
    }

    /// Everything a text filter should search.
    fn matches(&self, needle: &str) -> bool {
        let fields = [
            self.request_id.as_str(),
            self.method.as_str(),
            self.uri.as_str(),
            self.client_ip.as_str(),
            self.termination.as_str(),
            self.key_name.as_deref().unwrap_or(""),
            self.key_identifier.as_deref().unwrap_or(""),
            self.auth_error.as_deref().unwrap_or(""),
            self.backend_id.as_deref().unwrap_or(""),
            self.routing_reason.as_deref().unwrap_or(""),
            self.started_at.as_str(),
        ];
        if fields
            .iter()
            .any(|field| field.to_ascii_lowercase().contains(needle))
        {
            return true;
        }

        self.status
            .is_some_and(|status| status.to_string().contains(needle))
    }
}

/// Follows an append-only JSONL file.
pub struct Tail {
    path: PathBuf,
    file: Option<File>,
    offset: u64,
    partial: Vec<u8>,
    /// Lines that were not valid JSON. Surfaced so a corrupt log is visible
    /// rather than silently short.
    pub malformed: u64,
}

/// The result of one [`Tail::poll`].
pub struct Appended {
    pub records: Vec<LogRecord>,
    /// The file shrank, so it was reopened and everything must be re-read.
    /// Callers should discard the records they already hold.
    pub restarted: bool,
}

impl Tail {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            file: None,
            offset: 0,
            partial: Vec::new(),
            malformed: 0,
        }
    }

    /// Parse whatever has been appended since the last call.
    ///
    /// A missing file is not an error: it reads as "nothing new yet", so the
    /// explorer can be opened before the proxy has served its first request.
    pub fn poll(&mut self) -> io::Result<Appended> {
        let mut restarted = false;
        #[cfg(unix)]
        if let Some(open) = self.file.as_ref() {
            match fs::metadata(&self.path) {
                Ok(path_metadata) => {
                    let open_metadata = open.metadata()?;
                    if path_metadata.dev() != open_metadata.dev()
                        || path_metadata.ino() != open_metadata.ino()
                    {
                        self.file = Some(File::open(&self.path)?);
                        self.offset = 0;
                        self.partial.clear();
                        restarted = true;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if self.file.is_none() {
            match File::open(&self.path) {
                Ok(file) => {
                    self.file = Some(file);
                    self.offset = 0;
                    self.partial.clear();
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(Appended {
                        records: Vec::new(),
                        restarted: false,
                    });
                }
                Err(error) => return Err(error),
            }
        }

        let file = self.file.as_mut().expect("just opened");
        // Truncation (or a rotation that reuses the path) means our offset is
        // meaningless; start the file over.
        if file.metadata()?.len() < self.offset {
            file.seek(SeekFrom::Start(0))?;
            self.offset = 0;
            self.partial.clear();
            restarted = true;
        }

        let mut appended = Vec::new();
        file.read_to_end(&mut appended)?;
        self.offset = self.offset.saturating_add(appended.len() as u64);
        self.partial.extend_from_slice(&appended);

        let mut records = Vec::new();
        let mut consumed = 0;
        while let Some(index) = self.partial[consumed..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let line = &self.partial[consumed..consumed + index];
            consumed += index + 1;
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice::<LogRecord>(line) {
                Ok(record) => records.push(record),
                Err(_) => self.malformed = self.malformed.saturating_add(1),
            }
        }
        self.partial.drain(..consumed);

        Ok(Appended { records, restarted })
    }
}

/// Per-key totals.
#[derive(Clone, Debug, Default)]
pub struct KeyTotals {
    pub requests: usize,
    pub errors: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
    pub prefilled_tokens: u64,
}

/// Per-endpoint totals.
#[derive(Clone, Debug, Default)]
pub struct PathTotals {
    pub requests: usize,
    pub errors: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
    pub prefilled_tokens: u64,
}

/// Historical totals and latency distributions for one selected backend.
#[derive(Clone, Debug, Default)]
pub struct BackendTotals {
    pub requests: usize,
    pub errors: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
    pub prefilled_tokens: u64,
    pub queue_ms: Distribution,
    pub first_byte_ms: Distribution,
    pub latency_ms: Distribution,
}

#[derive(Default)]
struct BackendAccumulator {
    requests: usize,
    errors: usize,
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
    prefilled_tokens: u64,
    queues: Vec<u64>,
    first_bytes: Vec<u64>,
    latencies: Vec<u64>,
}

impl BackendAccumulator {
    fn finish(self) -> BackendTotals {
        BackendTotals {
            requests: self.requests,
            errors: self.errors,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cached_tokens: self.cached_tokens,
            prefilled_tokens: self.prefilled_tokens,
            queue_ms: Distribution::from_values(self.queues),
            first_byte_ms: Distribution::from_values(self.first_bytes),
            latency_ms: Distribution::from_values(self.latencies),
        }
    }
}

/// Nearest-rank p50/p95/max over one sample set.
#[derive(Clone, Copy, Debug, Default)]
pub struct Distribution {
    /// How many records contributed. Rows are built only from records that
    /// carry the value, so this is not always the total request count.
    pub samples: usize,
    pub p50: u64,
    pub p95: u64,
    pub max: u64,
}

impl Distribution {
    fn from_values(mut values: Vec<u64>) -> Self {
        values.sort_unstable();

        Self {
            samples: values.len(),
            p50: percentile(&values, 50),
            p95: percentile(&values, 95),
            max: values.last().copied().unwrap_or(0),
        }
    }
}

/// Aggregate view of a set of records.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub requests: usize,
    pub authorized: usize,
    pub rejected: usize,
    pub incomplete: usize,
    pub streaming: usize,
    pub non_streaming: usize,
    pub informational: usize,
    pub successful: usize,
    pub redirected: usize,
    pub client_errors: usize,
    pub server_errors: usize,
    pub no_status: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Prompt tokens served from the prefix cache instead of recomputed.
    pub cached_tokens: u64,
    /// Input tokens that were recomputed: input − cached per request, over the
    /// requests that reported input tokens.
    pub prefilled_tokens: u64,
    pub response_bytes: u64,
    pub first_at: Option<String>,
    pub last_at: Option<String>,
    /// Prompt sizes, over the requests that reported usage.
    pub input_tokens_seen: Distribution,
    /// Completion sizes, over the requests that reported usage.
    pub output_tokens_seen: Distribution,
    /// Per-request share of the prompt served from the prefix cache, 0–100,
    /// over the requests that reported input tokens.
    pub cache_hit_pct_seen: Distribution,
    /// Time to the first response byte over streaming responses only, which is
    /// the time to the first generated token. A non-streaming response does not
    /// send its head until generation has finished, so including those would
    /// just restate total latency.
    pub first_token_ms: Distribution,
    /// Whole-request latency divided by output tokens, in microseconds. This
    /// is the number that is not confounded by how much the model wrote.
    pub per_output_token_us: Distribution,
    /// End-to-end request latency, in milliseconds.
    pub latency_ms: Distribution,
    /// Sorted by request count, descending.
    pub by_key: Vec<(String, KeyTotals)>,
    /// Sorted by request count, descending.
    pub by_path: Vec<(String, PathTotals)>,
    /// Routed requests sorted by backend request count, descending.
    pub by_backend: Vec<(String, BackendTotals)>,
}

impl Summary {
    /// Aggregate cache hit rate over the input tokens of the requests that
    /// reported usage. `None` when no request reported cached tokens, which
    /// is every log written before engines started reporting the field.
    pub fn cache_hit_pct(&self) -> Option<f64> {
        (self.cached_tokens > 0 && self.input_tokens > 0)
            .then(|| 100.0 * self.cached_tokens as f64 / self.input_tokens as f64)
    }
}

pub fn summarize(records: &[LogRecord]) -> Summary {
    let mut summary = Summary {
        requests: records.len(),
        ..Summary::default()
    };
    let mut keys: HashMap<&str, KeyTotals> = HashMap::new();
    let mut paths: HashMap<&str, PathTotals> = HashMap::new();
    let mut backends: HashMap<&str, BackendAccumulator> = HashMap::new();
    let mut latencies = Vec::with_capacity(records.len());
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut first_tokens = Vec::new();
    let mut per_token = Vec::new();
    let mut cache_hit_pct = Vec::new();

    for record in records {
        if record.authorized {
            summary.authorized += 1;
        } else {
            summary.rejected += 1;
        }
        if !record.complete {
            summary.incomplete += 1;
        }
        if record.streaming {
            summary.streaming += 1;
        } else if record.status.is_some_and(|status| status < 400) {
            // Only count served responses; a rejected request never had a shape.
            summary.non_streaming += 1;
        }
        match record.status {
            None => summary.no_status += 1,
            Some(status) => match status / 100 {
                1 => summary.informational += 1,
                2 => summary.successful += 1,
                3 => summary.redirected += 1,
                4 => summary.client_errors += 1,
                _ => summary.server_errors += 1,
            },
        }

        let input = record.input_tokens.unwrap_or(0);
        let output = record.output_tokens.unwrap_or(0);
        let cached = record.cached_tokens.unwrap_or(0);
        summary.input_tokens = summary.input_tokens.saturating_add(input);
        summary.output_tokens = summary.output_tokens.saturating_add(output);
        summary.cached_tokens = summary.cached_tokens.saturating_add(cached);
        // Prefill is the recompute actually performed: the input minus what
        // the prefix cache already held.
        let prefilled = input.saturating_sub(cached);
        if record.input_tokens.is_some() {
            summary.prefilled_tokens = summary.prefilled_tokens.saturating_add(prefilled);
        }
        if let Some(input) = record.input_tokens.filter(|input| *input > 0) {
            cache_hit_pct.push(100 * cached / input);
        }
        summary.response_bytes = summary.response_bytes.saturating_add(record.response_bytes);
        latencies.push(record.duration_ms);
        if let Some(tokens) = record.input_tokens {
            inputs.push(tokens);
        }
        if let Some(tokens) = record.output_tokens {
            outputs.push(tokens);
        }
        if let Some(ms) = record.time_to_first_byte_ms.filter(|_| record.streaming) {
            first_tokens.push(ms);
        }
        // Only requests that actually generated something can have a rate.
        if let Some(tokens) = record.output_tokens.filter(|tokens| *tokens > 0) {
            per_token.push(record.duration_ms.saturating_mul(1_000) / tokens);
        }

        let key = keys.entry(record.key_bucket()).or_default();
        key.requests += 1;
        key.errors += usize::from(record.is_error());
        key.input_tokens = key.input_tokens.saturating_add(input);
        key.output_tokens = key.output_tokens.saturating_add(output);
        key.cached_tokens = key.cached_tokens.saturating_add(cached);
        if record.input_tokens.is_some() {
            key.prefilled_tokens = key.prefilled_tokens.saturating_add(prefilled);
        }

        let path = paths.entry(record.path()).or_default();
        path.requests += 1;
        path.errors += usize::from(record.is_error());
        path.input_tokens = path.input_tokens.saturating_add(input);
        path.output_tokens = path.output_tokens.saturating_add(output);
        path.cached_tokens = path.cached_tokens.saturating_add(cached);
        if record.input_tokens.is_some() {
            path.prefilled_tokens = path.prefilled_tokens.saturating_add(prefilled);
        }

        if let Some(backend_id) = record.backend_id.as_deref() {
            let backend = backends.entry(backend_id).or_default();
            backend.requests += 1;
            backend.errors += usize::from(record.is_error());
            backend.input_tokens = backend.input_tokens.saturating_add(input);
            backend.output_tokens = backend.output_tokens.saturating_add(output);
            backend.cached_tokens = backend.cached_tokens.saturating_add(cached);
            if record.input_tokens.is_some() {
                backend.prefilled_tokens = backend.prefilled_tokens.saturating_add(prefilled);
            }
            backend.latencies.push(record.duration_ms);
            if let Some(ms) = record.proxy_queue_ms {
                backend.queues.push(ms);
            }
            if let Some(ms) = record.time_to_first_byte_ms {
                backend.first_bytes.push(ms);
            }
        }
    }

    // Records are appended in completion order, which is close enough to
    // chronological that the ends of the file bound the window.
    summary.first_at = records
        .iter()
        .min_by_key(|record| record.started_at_unix_ms)
        .map(|record| record.started_at.clone());
    summary.last_at = records
        .iter()
        .max_by_key(|record| record.started_at_unix_ms)
        .map(|record| record.started_at.clone());

    summary.latency_ms = Distribution::from_values(latencies);
    summary.input_tokens_seen = Distribution::from_values(inputs);
    summary.output_tokens_seen = Distribution::from_values(outputs);
    summary.cache_hit_pct_seen = Distribution::from_values(cache_hit_pct);
    summary.first_token_ms = Distribution::from_values(first_tokens);
    summary.per_output_token_us = Distribution::from_values(per_token);

    summary.by_key = sorted_by_requests(keys, |totals| totals.requests);
    summary.by_path = sorted_by_requests(paths, |totals| totals.requests);
    summary.by_backend = backends
        .into_iter()
        .map(|(id, totals)| (id.to_owned(), totals.finish()))
        .collect();
    summary.by_backend.sort_by(|left, right| {
        right
            .1
            .requests
            .cmp(&left.1.requests)
            .then_with(|| left.0.cmp(&right.0))
    });

    summary
}

fn sorted_by_requests<T: Clone>(
    map: HashMap<&str, T>,
    requests: impl Fn(&T) -> usize,
) -> Vec<(String, T)> {
    let mut rows: Vec<(String, T)> = map
        .into_iter()
        .map(|(name, totals)| (name.to_owned(), totals))
        .collect();
    rows.sort_by(|left, right| {
        requests(&right.1)
            .cmp(&requests(&left.1))
            .then_with(|| left.0.cmp(&right.0))
    });

    rows
}

/// Nearest-rank percentile over an ascending slice.
fn percentile(sorted: &[u64], percent: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (sorted.len() as u64 * percent).div_ceil(100).max(1) as usize;

    sorted[rank.min(sorted.len()) - 1]
}

/// Keep only the records matching a text needle and, optionally, only errors.
pub fn filter<'a>(records: &'a [LogRecord], needle: &str, errors_only: bool) -> Vec<&'a LogRecord> {
    let needle = needle.trim().to_ascii_lowercase();

    records
        .iter()
        .filter(|record| !errors_only || record.is_error())
        .filter(|record| needle.is_empty() || record.matches(&needle))
        .collect()
}

/// `1234567` as `1,234,567`.
pub fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }

    grouped
}

/// A sub-millisecond-capable duration, for per-token rates.
pub fn rate(micros: u64) -> String {
    match micros {
        micros if micros < 1_000 => format!("{micros}\u{b5}s"),
        micros if micros < 1_000_000 => format!("{:.1}ms", micros as f64 / 1_000.0),
        micros => format!("{:.1}s", micros as f64 / 1_000_000.0),
    }
}

/// A duration in the largest unit that keeps it readable.
pub fn duration(ms: u64) -> String {
    match ms {
        ms if ms < 1_000 => format!("{ms}ms"),
        ms if ms < 60_000 => format!("{:.1}s", ms as f64 / 1_000.0),
        ms => format!("{}m{:02}s", ms / 60_000, (ms % 60_000) / 1_000),
    }
}

/// Entry point for `mistralrs_proxy logs`.
pub fn run(path: &Path, summary_only: bool) -> Result<(), Box<dyn std::error::Error>> {
    if path == Path::new("-") {
        return Err("cannot read the audit log from stdout; pass --log-file <PATH>".into());
    }
    if !path.exists() {
        return Err(format!(
            "no audit log at {}. Start the proxy, or pass --log-file <PATH>.",
            path.display()
        )
        .into());
    }

    let mut tail = Tail::new(path);
    let records = tail.poll()?.records;

    if summary_only {
        print_summary(path, &summarize(&records), tail.malformed)?;
        return Ok(());
    }

    tui::explore(path, tail, records)
}

/// The non-interactive summary, for `--summary` and for scripting.
pub fn print_summary(path: &Path, summary: &Summary, malformed: u64) -> io::Result<()> {
    write_lines(&summary_lines(path, summary, malformed))
}

/// The summary as text, one line per row.
pub fn summary_lines(path: &Path, summary: &Summary, malformed: u64) -> Vec<String> {
    let mut lines = vec![path.display().to_string()];
    match (&summary.first_at, &summary.last_at) {
        (Some(first), Some(last)) => lines.push(format!(
            "{} requests from {first} to {last}",
            thousands(summary.requests as u64)
        )),
        _ => lines.push("no requests recorded".to_owned()),
    }
    if malformed > 0 {
        lines.push(format!("{malformed} unreadable line(s) skipped"));
    }
    if summary.requests == 0 {
        return lines;
    }

    lines.push(String::new());
    lines.push(format!(
        "  requests   {:>10}   authorized {}   rejected {}   incomplete {}",
        thousands(summary.requests as u64),
        summary.authorized,
        summary.rejected,
        summary.incomplete,
    ));
    lines.push(format!(
        "  statuses   2xx {}   3xx {}   4xx {}   5xx {}   none {}",
        summary.successful,
        summary.redirected,
        summary.client_errors,
        summary.server_errors,
        summary.no_status,
    ));
    lines.push(format!(
        "  tokens     {:>10} in   {} out   {} total",
        thousands(summary.input_tokens),
        thousands(summary.output_tokens),
        thousands(summary.input_tokens + summary.output_tokens),
    ));
    lines.push(format!(
        "  cache      {:>10} cached   {} of input   {} prefilled",
        thousands(summary.cached_tokens),
        summary
            .cache_hit_pct()
            .map_or_else(|| "-".to_owned(), |pct| format!("{pct:.1}%")),
        thousands(summary.prefilled_tokens),
    ));
    lines.push(format!(
        "  shape      {:>10} streaming   {} non-streaming",
        thousands(summary.streaming as u64),
        thousands(summary.non_streaming as u64),
    ));

    lines.push(String::new());
    lines.push(format!(
        "  {:<20}{:>12}{:>12}{:>12}{:>10}",
        "", "P50", "P95", "MAX", "SAMPLES"
    ));
    for (name, row) in percentile_rows(summary) {
        lines.push(format!(
            "  {:<20}{:>12}{:>12}{:>12}{:>10}",
            name, row.p50, row.p95, row.max, row.samples
        ));
    }

    lines.push(String::new());
    lines.push(format!(
        "  {:<24}{:>10}{:>12}{:>12}{:>12}{:>12}{:>7}",
        "KEY", "REQUESTS", "IN", "CACHED", "PREFILLED", "OUT", "ERRORS"
    ));
    for (name, totals) in &summary.by_key {
        lines.push(format!(
            "  {:<24}{:>10}{:>12}{:>12}{:>12}{:>12}{:>7}",
            truncate(name, 23),
            thousands(totals.requests as u64),
            thousands(totals.input_tokens),
            thousands(totals.cached_tokens),
            thousands(totals.prefilled_tokens),
            thousands(totals.output_tokens),
            totals.errors,
        ));
    }

    lines.push(String::new());
    lines.push(format!(
        "  {:<34}{:>10}{:>12}{:>12}{:>12}{:>12}",
        "ENDPOINT", "REQUESTS", "IN", "CACHED", "PREFILLED", "OUT"
    ));
    for (path, totals) in &summary.by_path {
        lines.push(format!(
            "  {:<34}{:>10}{:>12}{:>12}{:>12}{:>12}",
            truncate(path, 33),
            thousands(totals.requests as u64),
            thousands(totals.input_tokens),
            thousands(totals.cached_tokens),
            thousands(totals.prefilled_tokens),
            thousands(totals.output_tokens),
        ));
    }

    if !summary.by_backend.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "  {:<18}{:>10}{:>8}{:>12}{:>12}{:>12}{:>12}{:>9}",
            "BACKEND", "REQUESTS", "SHARE", "IN", "CACHED", "PREFILLED", "OUT", "ERRORS"
        ));
        let routed: usize = summary
            .by_backend
            .iter()
            .map(|(_, totals)| totals.requests)
            .sum();
        for (backend, totals) in &summary.by_backend {
            let share = if routed == 0 {
                0.0
            } else {
                totals.requests as f64 * 100.0 / routed as f64
            };
            lines.push(format!(
                "  {:<18}{:>10}{:>7.1}%{:>12}{:>12}{:>12}{:>12}{:>9}",
                truncate(backend, 17),
                thousands(totals.requests as u64),
                share,
                thousands(totals.input_tokens),
                thousands(totals.cached_tokens),
                thousands(totals.prefilled_tokens),
                thousands(totals.output_tokens),
                totals.errors,
            ));
        }
    }

    lines
}

fn distribution_p95(distribution: Distribution) -> String {
    if distribution.samples == 0 {
        "-".to_owned()
    } else {
        duration(distribution.p95)
    }
}

/// Write lines to stdout, treating a closed pipe as a normal end.
///
/// Rust ignores SIGPIPE, so without this `... | head` would panic.
pub(crate) fn write_lines(lines: &[String]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    for line in lines {
        if let Err(error) = writeln!(out, "{line}") {
            return pipe_ok(error);
        }
    }
    if let Err(error) = out.flush() {
        return pipe_ok(error);
    }

    Ok(())
}

fn pipe_ok(error: io::Error) -> io::Result<()> {
    if error.kind() == io::ErrorKind::BrokenPipe {
        Ok(())
    } else {
        Err(error)
    }
}

/// One formatted percentile row.
pub struct PercentileRow {
    pub p50: String,
    pub p95: String,
    pub max: String,
    pub samples: String,
}

fn formatted(distribution: Distribution, render: impl Fn(u64) -> String) -> PercentileRow {
    if distribution.samples == 0 {
        return PercentileRow {
            p50: "-".to_owned(),
            p95: "-".to_owned(),
            max: "-".to_owned(),
            samples: "0".to_owned(),
        };
    }

    PercentileRow {
        p50: render(distribution.p50),
        p95: render(distribution.p95),
        max: render(distribution.max),
        samples: thousands(distribution.samples as u64),
    }
}

/// The percentile table, in the order both views present it.
///
/// Token sizes come first because they describe the workload; the per-token
/// rate is the latency number that does not move with completion length.
pub fn percentile_rows(summary: &Summary) -> Vec<(&'static str, PercentileRow)> {
    let mut rows = vec![
        (
            "input tokens",
            formatted(summary.input_tokens_seen, thousands),
        ),
        (
            "output tokens",
            formatted(summary.output_tokens_seen, thousands),
        ),
        ("first token", formatted(summary.first_token_ms, duration)),
        (
            "per output token",
            formatted(summary.per_output_token_us, rate),
        ),
        ("total latency", formatted(summary.latency_ms, duration)),
    ];
    // Only shown once some request actually reported cached tokens, so logs
    // written by older proxies do not grow a row of misleading zeros.
    if summary.cached_tokens > 0 {
        rows.push((
            "cache hit %",
            formatted(summary.cache_hit_pct_seen, |pct| format!("{pct}%")),
        ));
    }
    rows
}

pub(crate) fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }

    text.chars()
        .take(width.saturating_sub(1))
        .chain(['…'])
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn record(json: &str) -> LogRecord {
        serde_json::from_str(json).unwrap()
    }

    fn sample() -> Vec<LogRecord> {
        vec![
            record(
                r#"{"request_id":"a","started_at":"2026-08-20T10:00:00.000Z","started_at_unix_ms":100,
                    "duration_ms":100,"method":"POST","uri":"/v1/chat/completions?stream=true",
                    "key_name":"alice","key_identifier":"AAAAAAAA","status":200,"authorized":true,
                    "input_tokens":100,"output_tokens":10,"response_bytes":50,"complete":true,
                    "cached_tokens":75,"streaming":true,"time_to_first_byte_ms":40,"termination":"complete"}"#,
            ),
            record(
                r#"{"request_id":"b","started_at":"2026-08-20T10:00:01.000Z","started_at_unix_ms":200,
                    "duration_ms":300,"method":"POST","uri":"/v1/chat/completions",
                    "key_name":"bot","key_identifier":"BBBBBBBB","status":200,"authorized":true,
                    "input_tokens":20,"output_tokens":5,"response_bytes":30,"complete":true,
                    "termination":"complete"}"#,
            ),
            record(
                r#"{"request_id":"c","started_at":"2026-08-20T10:00:02.000Z","started_at_unix_ms":300,
                    "duration_ms":2000,"method":"GET","uri":"/v1/models","status":401,
                    "authorized":false,"auth_error":"invalid_api_key","complete":true,
                    "termination":"complete","key_sha256":"deadbeefcafebabe0000000000000000000000000000000000000000000000ff"}"#,
            ),
        ]
    }

    #[test]
    fn a_summary_totals_tokens_statuses_and_latency() {
        let summary = summarize(&sample());

        assert_eq!(summary.requests, 3);
        assert_eq!(summary.authorized, 2);
        assert_eq!(summary.rejected, 1);
        assert_eq!(summary.successful, 2);
        assert_eq!(summary.client_errors, 1);
        assert_eq!(summary.input_tokens, 120);
        assert_eq!(summary.output_tokens, 15);
        assert_eq!(summary.cached_tokens, 75);
        assert_eq!(summary.prefilled_tokens, 45);
        assert_eq!(summary.cache_hit_pct(), Some(62.5));
        assert_eq!(summary.latency_ms.max, 2000);
        assert_eq!(summary.latency_ms.p50, 300);
        assert_eq!(summary.latency_ms.samples, 3);
        assert_eq!(
            summary.first_at.as_deref(),
            Some("2026-08-20T10:00:00.000Z")
        );
        assert_eq!(summary.last_at.as_deref(), Some("2026-08-20T10:00:02.000Z"));
    }

    #[test]
    fn keys_and_endpoints_group_with_unauthenticated_traffic_bucketed() {
        let summary = summarize(&sample());

        let keys: Vec<&str> = summary
            .by_key
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(keys, ["(unauthenticated)", "alice", "bot"]);
        assert_eq!(summary.by_key[1].1.input_tokens, 100);
        assert_eq!(summary.by_key[0].1.errors, 1);

        // The query string does not split the endpoint into two rows.
        assert_eq!(summary.by_path[0].0, "/v1/chat/completions");
        assert_eq!(summary.by_path[0].1.requests, 2);
    }

    #[test]
    fn an_empty_log_summarises_without_panicking() {
        let summary = summarize(&[]);

        assert_eq!(summary.requests, 0);
        assert_eq!(summary.latency_ms.p50, 0);
        assert_eq!(summary.latency_ms.samples, 0);
        assert!(summary.by_key.is_empty());
        assert!(summary.first_at.is_none());
    }

    #[test]
    fn filtering_matches_keys_paths_and_statuses() {
        let records = sample();

        assert_eq!(filter(&records, "alice", false).len(), 1);
        assert_eq!(filter(&records, "ALICE", false).len(), 1);
        assert_eq!(filter(&records, "chat", false).len(), 2);
        assert_eq!(filter(&records, "401", false).len(), 1);
        assert_eq!(filter(&records, "", false).len(), 3);
        assert_eq!(filter(&records, "nothing", false).len(), 0);
        // 401 is the only error.
        assert_eq!(filter(&records, "", true).len(), 1);
        assert_eq!(filter(&records, "alice", true).len(), 0);
    }

    #[test]
    fn an_incomplete_request_counts_as_an_error_even_with_a_200() {
        let streamed = record(
            r#"{"request_id":"d","status":200,"complete":false,"termination":"body_dropped"}"#,
        );

        assert!(streamed.is_error());
        assert_eq!(summarize(&[streamed]).incomplete, 1);
    }

    #[test]
    fn tailing_picks_up_appends_and_holds_back_partial_lines() {
        let path = std::env::temp_dir().join(format!("proxy-tail-{}.jsonl", uuid::Uuid::new_v4()));
        let mut file = File::create(&path).unwrap();
        writeln!(file, r#"{{"request_id":"one","status":200}}"#).unwrap();
        file.flush().unwrap();

        let mut tail = Tail::new(&path);
        let first = tail.poll().unwrap();
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].request_id, "one");

        // Nothing new yet.
        assert!(tail.poll().unwrap().records.is_empty());

        // A half-written record is not yielded until its newline arrives.
        write!(file, r#"{{"request_id":"two","stat"#).unwrap();
        file.flush().unwrap();
        assert!(tail.poll().unwrap().records.is_empty());

        writeln!(file, r#"us":200}}"#).unwrap();
        file.flush().unwrap();
        let third = tail.poll().unwrap();
        assert_eq!(third.records.len(), 1);
        assert_eq!(third.records[0].request_id, "two");
        assert_eq!(third.records[0].status, Some(200));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_malformed_line_is_counted_and_skipped() {
        let path = std::env::temp_dir().join(format!("proxy-tail-{}.jsonl", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            "not json\n{\"request_id\":\"ok\"}\n\n{\"request_id\":\"also-ok\"}\n",
        )
        .unwrap();

        let mut tail = Tail::new(&path);
        let appended = tail.poll().unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(appended.records.len(), 2);
        assert_eq!(tail.malformed, 1);
    }

    #[test]
    fn truncation_restarts_the_read() {
        let path = std::env::temp_dir().join(format!("proxy-tail-{}.jsonl", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            "{\"request_id\":\"old\"}\n{\"request_id\":\"older\"}\n",
        )
        .unwrap();
        let mut tail = Tail::new(&path);
        assert_eq!(tail.poll().unwrap().records.len(), 2);

        std::fs::write(&path, "{\"request_id\":\"fresh\"}\n").unwrap();
        let appended = tail.poll().unwrap();
        std::fs::remove_file(&path).unwrap();

        assert!(appended.restarted);
        assert_eq!(appended.records.len(), 1);
        assert_eq!(appended.records[0].request_id, "fresh");
    }

    #[cfg(unix)]
    #[test]
    fn inode_replacement_reopens_the_live_log() {
        let path = std::env::temp_dir().join(format!("proxy-tail-{}.jsonl", uuid::Uuid::new_v4()));
        let rotated = path.with_extension("jsonl.1");
        std::fs::write(&path, "{\"request_id\":\"old\"}\n").unwrap();
        let mut tail = Tail::new(&path);
        assert_eq!(tail.poll().unwrap().records[0].request_id, "old");

        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, "{\"request_id\":\"new\"}\n").unwrap();
        let appended = tail.poll().unwrap();

        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(rotated).unwrap();
        assert!(appended.restarted);
        assert_eq!(appended.records.len(), 1);
        assert_eq!(appended.records[0].request_id, "new");
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let mut tail = Tail::new(std::env::temp_dir().join("definitely-absent.jsonl"));

        let appended = tail.poll().unwrap();

        assert!(appended.records.is_empty());
        assert!(!appended.restarted);
    }

    #[test]
    fn the_text_summary_reports_totals_and_both_breakdowns() {
        let summary = summarize(&sample());

        let text = summary_lines(Path::new("proxy.jsonl"), &summary, 2).join("\n");

        assert!(text.starts_with("proxy.jsonl\n3 requests from "), "{text}");
        assert!(text.contains("2 unreadable line(s) skipped"), "{text}");
        assert!(text.contains("authorized 2   rejected 1"), "{text}");
        assert!(text.contains("2xx 2   3xx 0   4xx 1"), "{text}");
        assert!(text.contains("120 in   15 out   135 total"), "{text}");
        assert!(text.contains("75 cached"), "{text}");
        assert!(text.contains("62.5% of input"), "{text}");
        assert!(text.contains("45 prefilled"), "{text}");
        assert!(text.contains("P50"), "{text}");
        assert!(text.contains("total latency"), "{text}");
        assert!(text.contains("per output token"), "{text}");
        assert!(text.contains("first token"), "{text}");
        assert!(text.contains("1 streaming   1 non-streaming"), "{text}");
        assert!(text.contains("alice"), "{text}");
        assert!(text.contains("/v1/chat/completions"), "{text}");
    }

    #[test]
    fn an_empty_log_summarises_to_a_single_note() {
        let text = summary_lines(Path::new("proxy.jsonl"), &summarize(&[]), 0).join("\n");

        assert_eq!(text, "proxy.jsonl\nno requests recorded");
    }

    #[test]
    fn numbers_and_durations_format_readably() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");

        assert_eq!(duration(0), "0ms");
        assert_eq!(duration(999), "999ms");
        assert_eq!(duration(3_140), "3.1s");
        assert_eq!(duration(125_000), "2m05s");
    }

    #[test]
    fn token_percentiles_only_count_requests_that_reported_usage() {
        let summary = summarize(&sample());

        // The 401 reported no usage, so it is not a zero-token sample.
        // Prompts were 100 and 20 tokens; nearest rank takes the lower of two.
        assert_eq!(summary.input_tokens_seen.samples, 2);
        assert_eq!(summary.input_tokens_seen.p50, 20);
        assert_eq!(summary.input_tokens_seen.max, 100);
        assert_eq!(summary.output_tokens_seen.samples, 2);
        assert_eq!(summary.output_tokens_seen.p50, 5);
        assert_eq!(summary.output_tokens_seen.max, 10);

        // Latency, by contrast, is known for every request.
        assert_eq!(summary.latency_ms.samples, 3);
    }

    #[test]
    fn cache_stats_are_absent_when_no_request_reports_cached_tokens() {
        // Records without the field are what every pre-existing log contains.
        let summary = summarize(&[record(
            r#"{"request_id":"a","started_at":"2026-08-20T10:00:00.000Z",
                "started_at_unix_ms":100,"duration_ms":100,"method":"POST",
                "uri":"/v1/chat/completions","key_name":"alice",
                "key_identifier":"AAAAAAAA","status":200,"authorized":true,
                "input_tokens":100,"output_tokens":10,"complete":true,
                "termination":"complete"}"#,
        )]);

        assert_eq!(summary.cached_tokens, 0);
        assert_eq!(summary.prefilled_tokens, 100);
        assert_eq!(summary.cache_hit_pct(), None);
        assert!(
            percentile_rows(&summary)
                .iter()
                .all(|(name, _)| *name != "cache hit %"),
            "no cache row for a log without the field"
        );

        // The row appears as soon as any request reports cached tokens.
        let summary = summarize(&[record(
            r#"{"request_id":"a","started_at":"2026-08-20T10:00:00.000Z",
                "started_at_unix_ms":100,"duration_ms":100,"method":"POST",
                "uri":"/v1/chat/completions","key_name":"alice",
                "key_identifier":"AAAAAAAA","status":200,"authorized":true,
                "input_tokens":100,"output_tokens":10,"complete":true,
                "cached_tokens":40,"termination":"complete"}"#,
        )]);
        assert_eq!(summary.cache_hit_pct(), Some(40.0));
        assert!(
            percentile_rows(&summary)
                .iter()
                .any(|(name, _)| *name == "cache hit %"),
            "cache row present once cached tokens are reported"
        );
    }

    #[test]
    fn the_per_token_rate_normalises_latency_by_completion_length() {
        // 100ms for 10 tokens and 300ms for 5 tokens: the second is slower per
        // token even though both are quick overall.
        let summary = summarize(&sample());

        assert_eq!(summary.per_output_token_us.samples, 2);
        assert_eq!(summary.per_output_token_us.p50, 10_000);
        assert_eq!(summary.per_output_token_us.max, 60_000);
    }

    #[test]
    fn a_request_that_generated_nothing_has_no_rate() {
        let refused = record(r#"{"request_id":"x","duration_ms":5,"status":401,"complete":true}"#);
        let empty = record(
            r#"{"request_id":"y","duration_ms":5,"status":200,"complete":true,"output_tokens":0}"#,
        );

        let summary = summarize(&[refused, empty]);

        assert_eq!(summary.per_output_token_us.samples, 0);
        assert_eq!(summary.latency_ms.samples, 2);
    }

    #[test]
    fn a_row_with_no_samples_renders_as_dashes() {
        let rows = percentile_rows(&summarize(&[]));
        let (name, row) = &rows[0];

        assert_eq!(*name, "input tokens");
        assert_eq!(row.p50, "-");
        assert_eq!(row.samples, "0");
    }

    #[test]
    fn rates_format_from_microseconds_up() {
        assert_eq!(rate(0), "0\u{b5}s");
        assert_eq!(rate(940), "940\u{b5}s");
        assert_eq!(rate(1_400), "1.4ms");
        assert_eq!(rate(2_500_000), "2.5s");
    }

    #[test]
    fn the_first_token_row_covers_streaming_responses_only() {
        let summary = summarize(&sample());

        // Only the SSE response has a meaningful time to first token.
        assert_eq!(summary.streaming, 1);
        assert_eq!(summary.non_streaming, 1);
        assert_eq!(summary.first_token_ms.samples, 1);
        assert_eq!(summary.first_token_ms.p50, 40);

        let (name, _) = &percentile_rows(&summary)[2];
        assert_eq!(*name, "first token");
    }

    #[test]
    fn a_non_streaming_first_byte_is_not_sampled() {
        // Its head does not arrive until generation is done, so this value
        // would only restate total latency.
        let buffered = record(
            r#"{"request_id":"z","duration_ms":900,"status":200,"complete":true,
                "streaming":false,"time_to_first_byte_ms":880,"output_tokens":30}"#,
        );

        let summary = summarize(&[buffered]);

        assert_eq!(summary.first_token_ms.samples, 0);
        assert_eq!(summary.non_streaming, 1);
        assert_eq!(summary.latency_ms.samples, 1);
    }

    #[test]
    fn a_rejected_request_has_no_shape() {
        let refused = record(r#"{"request_id":"r","status":401,"complete":true}"#);

        let summary = summarize(&[refused]);

        assert_eq!(summary.streaming, 0);
        assert_eq!(summary.non_streaming, 0);
        assert_eq!(summary.rejected, 1);
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let sorted = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

        assert_eq!(percentile(&sorted, 50), 50);
        assert_eq!(percentile(&sorted, 95), 100);
        assert_eq!(percentile(&[7], 50), 7);
        assert_eq!(percentile(&[], 50), 0);
    }

    #[test]
    fn a_principal_falls_back_to_the_digest_then_to_anonymous() {
        assert_eq!(sample()[0].principal(), "alice[AAAAAAAA]");
        assert_eq!(sample()[2].principal(), "unknown[deadbeef]");
        assert_eq!(LogRecord::default().principal(), "anonymous");
    }
}
