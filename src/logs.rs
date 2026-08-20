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
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

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
    pub status: Option<u16>,
    pub response_bytes: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
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
}

/// Per-endpoint totals.
#[derive(Clone, Debug, Default)]
pub struct PathTotals {
    pub requests: usize,
    pub errors: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Aggregate view of a set of records.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub requests: usize,
    pub authorized: usize,
    pub rejected: usize,
    pub incomplete: usize,
    pub informational: usize,
    pub successful: usize,
    pub redirected: usize,
    pub client_errors: usize,
    pub server_errors: usize,
    pub no_status: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub response_bytes: u64,
    pub first_at: Option<String>,
    pub last_at: Option<String>,
    pub median_ms: u64,
    pub p95_ms: u64,
    pub max_ms: u64,
    /// Sorted by request count, descending.
    pub by_key: Vec<(String, KeyTotals)>,
    /// Sorted by request count, descending.
    pub by_path: Vec<(String, PathTotals)>,
}

pub fn summarize(records: &[LogRecord]) -> Summary {
    let mut summary = Summary {
        requests: records.len(),
        ..Summary::default()
    };
    let mut keys: HashMap<&str, KeyTotals> = HashMap::new();
    let mut paths: HashMap<&str, PathTotals> = HashMap::new();
    let mut durations = Vec::with_capacity(records.len());

    for record in records {
        if record.authorized {
            summary.authorized += 1;
        } else {
            summary.rejected += 1;
        }
        if !record.complete {
            summary.incomplete += 1;
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
        summary.input_tokens = summary.input_tokens.saturating_add(input);
        summary.output_tokens = summary.output_tokens.saturating_add(output);
        summary.response_bytes = summary.response_bytes.saturating_add(record.response_bytes);
        durations.push(record.duration_ms);

        let key = keys.entry(record.key_bucket()).or_default();
        key.requests += 1;
        key.errors += usize::from(record.is_error());
        key.input_tokens = key.input_tokens.saturating_add(input);
        key.output_tokens = key.output_tokens.saturating_add(output);

        let path = paths.entry(record.path()).or_default();
        path.requests += 1;
        path.errors += usize::from(record.is_error());
        path.input_tokens = path.input_tokens.saturating_add(input);
        path.output_tokens = path.output_tokens.saturating_add(output);
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

    durations.sort_unstable();
    summary.median_ms = percentile(&durations, 50);
    summary.p95_ms = percentile(&durations, 95);
    summary.max_ms = durations.last().copied().unwrap_or(0);

    summary.by_key = sorted_by_requests(keys, |totals| totals.requests);
    summary.by_path = sorted_by_requests(paths, |totals| totals.requests);

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
        "  latency    p50 {}   p95 {}   max {}",
        duration(summary.median_ms),
        duration(summary.p95_ms),
        duration(summary.max_ms),
    ));

    lines.push(String::new());
    lines.push(format!(
        "  {:<24}{:>10}{:>14}{:>14}{:>9}",
        "KEY", "REQUESTS", "IN", "OUT", "ERRORS"
    ));
    for (name, totals) in &summary.by_key {
        lines.push(format!(
            "  {:<24}{:>10}{:>14}{:>14}{:>9}",
            truncate(name, 23),
            thousands(totals.requests as u64),
            thousands(totals.input_tokens),
            thousands(totals.output_tokens),
            totals.errors,
        ));
    }

    lines.push(String::new());
    lines.push(format!(
        "  {:<34}{:>10}{:>14}{:>14}",
        "ENDPOINT", "REQUESTS", "IN", "OUT"
    ));
    for (path, totals) in &summary.by_path {
        lines.push(format!(
            "  {:<34}{:>10}{:>14}{:>14}",
            truncate(path, 33),
            thousands(totals.requests as u64),
            thousands(totals.input_tokens),
            thousands(totals.output_tokens),
        ));
    }

    lines
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
                    "termination":"complete"}"#,
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
        assert_eq!(summary.max_ms, 2000);
        assert_eq!(summary.median_ms, 300);
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
        assert_eq!(summary.median_ms, 0);
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
        assert!(text.contains("p50 300ms"), "{text}");
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
