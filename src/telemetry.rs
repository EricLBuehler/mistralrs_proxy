//! Parsing and scoring for mistral.rs backend telemetry.
//!
//! The parser intentionally extracts only the small, stable metric contract the
//! router needs. Unknown Prometheus samples are ignored, while malformed or
//! duplicate routing gauges reject the snapshot so an incomplete scrape cannot
//! accidentally look like an idle backend.

use std::{collections::HashSet, error::Error, fmt};

pub const SEQUENCES_RUNNING_METRIC: &str = "mistralrs_sequences_running";
pub const SEQUENCES_WAITING_METRIC: &str = "mistralrs_sequences_waiting";
pub const SEQUENCES_CAPACITY_METRIC: &str = "mistralrs_sequences_capacity";
pub const KV_CACHE_BLOCKS_USED_METRIC: &str = "mistralrs_kv_cache_blocks_used";
pub const KV_CACHE_BLOCKS_TOTAL_METRIC: &str = "mistralrs_kv_cache_blocks_total";
pub const TOKENS_PROCESSED_TOTAL_METRIC: &str = "mistralrs_tokens_processed_total";
pub const PREFILL_TOKENS_PROCESSED_TOTAL_METRIC: &str = "mistralrs_prefill_tokens_processed_total";
pub const DECODE_TOKENS_PROCESSED_TOTAL_METRIC: &str = "mistralrs_decode_tokens_processed_total";
pub const SEQUENCES_COMPLETED_TOTAL_METRIC: &str = "mistralrs_sequences_completed_total";

pub const KV_PENALTY_START: f64 = 0.85;
pub const KV_PENALTY_RANGE: f64 = 0.15;

// Prometheus stores samples as f64. Reject larger integer-valued gauges rather
// than silently accepting a count that can no longer be represented exactly.
const MAX_EXACT_F64_INTEGER: f64 = 9_007_199_254_740_991.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvCacheMetrics {
    pub used: u64,
    pub total: u64,
}

impl KvCacheMetrics {
    /// A value in `[0, 1]`. Exporter inconsistencies where `used > total` are
    /// conservatively treated as full pressure rather than rejecting the whole
    /// otherwise useful snapshot.
    pub fn ratio(self) -> f64 {
        (self.used as f64 / self.total as f64).clamp(0.0, 1.0)
    }

    pub fn is_overcommitted(self) -> bool {
        self.used > self.total
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MistralRsMetrics {
    pub sequences_running: u64,
    pub sequences_waiting: u64,
    /// Capacity reported by mistral.rs. Older engines may omit it; routing can
    /// then use the explicitly configured backend capacity as a fallback.
    pub sequences_capacity: Option<u64>,
    /// `None` means both paged-attention KV gauges were absent. A partial pair
    /// is rejected by [`parse_mistralrs_metrics`].
    pub kv_cache: Option<KvCacheMetrics>,
    /// Best-effort cumulative counters. Invalid optional samples are omitted
    /// without invalidating the routing gauges.
    pub tokens_processed_total: Option<f64>,
    /// Phase split of the combined counter. Older engines omit both, so they
    /// are absent together; the combined total remains the routing signal.
    pub prefill_tokens_processed_total: Option<f64>,
    pub decode_tokens_processed_total: Option<f64>,
    pub sequences_completed_total: Option<f64>,
}

impl MistralRsMetrics {
    pub fn kv_cache_ratio(&self) -> Option<f64> {
        self.kv_cache.map(KvCacheMetrics::ratio)
    }

    /// Build score inputs with a capacity already resolved by the caller. This
    /// lets the routing layer apply its configured/reported capacity precedence
    /// without coupling runtime configuration to this parser.
    pub fn pressure_inputs(
        &self,
        new_sequences: u64,
        effective_capacity: u64,
    ) -> LeastPressureV1Inputs {
        LeastPressureV1Inputs {
            running: self.sequences_running,
            waiting: self.sequences_waiting,
            capacity: effective_capacity,
            new_sequences,
            kv_ratio: self.kv_cache_ratio(),
        }
    }

    pub fn reported_capacity_inputs(&self, new_sequences: u64) -> Option<LeastPressureV1Inputs> {
        self.sequences_capacity
            .map(|capacity| self.pressure_inputs(new_sequences, capacity))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LeastPressureV1Inputs {
    pub running: u64,
    pub waiting: u64,
    pub capacity: u64,
    /// Candidate sequence fan-out plus any locally reserved assignments not yet
    /// reflected by the backend scrape.
    pub new_sequences: u64,
    /// `None` means paged-attention KV pressure is unavailable and contributes
    /// no penalty.
    pub kv_ratio: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LeastPressureV1Score {
    pub occupancy: f64,
    pub kv_penalty: f64,
    pub pressure: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PressureInputError {
    ZeroCapacity,
    NonFiniteKvRatio,
    KvRatioOutOfRange,
}

impl fmt::Display for PressureInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => formatter.write_str("sequence capacity must be positive"),
            Self::NonFiniteKvRatio => formatter.write_str("KV cache ratio must be finite"),
            Self::KvRatioOutOfRange => {
                formatter.write_str("KV cache ratio must be between zero and one")
            }
        }
    }
}

impl Error for PressureInputError {}

/// Compute the agreed `least-pressure-v1` score:
///
/// `occupancy = (running + waiting + new) / capacity`
///
/// `kv_penalty = max(0, (kv_ratio - 0.85) / 0.15)`
pub fn least_pressure_v1(
    inputs: LeastPressureV1Inputs,
) -> Result<LeastPressureV1Score, PressureInputError> {
    least_pressure_v1_with_soft_limit(inputs, KV_PENALTY_START)
}

/// Compute `least-pressure-v1` with the operator's validated KV soft limit.
/// The remaining fraction up to a full cache is mapped linearly onto a
/// penalty from zero to one.
pub fn least_pressure_v1_with_soft_limit(
    inputs: LeastPressureV1Inputs,
    kv_soft_limit: f64,
) -> Result<LeastPressureV1Score, PressureInputError> {
    if inputs.capacity == 0 {
        return Err(PressureInputError::ZeroCapacity);
    }

    let kv_penalty = match inputs.kv_ratio {
        Some(ratio) if !ratio.is_finite() => {
            return Err(PressureInputError::NonFiniteKvRatio);
        }
        Some(ratio) if !(0.0..=1.0).contains(&ratio) => {
            return Err(PressureInputError::KvRatioOutOfRange);
        }
        Some(ratio) => ((ratio - kv_soft_limit) / (1.0 - kv_soft_limit)).max(0.0),
        None => 0.0,
    };
    let occupancy = (inputs.running as f64 + inputs.waiting as f64 + inputs.new_sequences as f64)
        / inputs.capacity as f64;

    Ok(LeastPressureV1Score {
        occupancy,
        kv_penalty,
        pressure: occupancy + kv_penalty,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricsParseError {
    MissingRequiredMetric {
        metric: &'static str,
    },
    DuplicateRequiredMetric {
        metric: &'static str,
        first_line: usize,
        duplicate_line: usize,
    },
    MalformedRequiredMetric {
        metric: &'static str,
        line: usize,
        reason: String,
    },
    IncompleteKvCacheMetrics {
        missing: &'static str,
    },
}

impl fmt::Display for MetricsParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredMetric { metric } => {
                write!(formatter, "required Prometheus metric {metric} is missing")
            }
            Self::DuplicateRequiredMetric {
                metric,
                first_line,
                duplicate_line,
            } => write!(
                formatter,
                "required Prometheus metric {metric} is duplicated on lines {first_line} and {duplicate_line}"
            ),
            Self::MalformedRequiredMetric {
                metric,
                line,
                reason,
            } => write!(
                formatter,
                "required Prometheus metric {metric} is malformed on line {line}: {reason}"
            ),
            Self::IncompleteKvCacheMetrics { missing } => write!(
                formatter,
                "paged-attention KV metrics are incomplete; {missing} is missing"
            ),
        }
    }
}

impl Error for MetricsParseError {}

#[derive(Clone, Copy)]
struct RequiredGauge {
    metric: &'static str,
    value: Option<u64>,
    line: Option<usize>,
    positive: bool,
}

impl RequiredGauge {
    fn new(metric: &'static str, positive: bool) -> Self {
        Self {
            metric,
            value: None,
            line: None,
            positive,
        }
    }

    fn observe(&mut self, sample: ParsedSample<'_>, line: usize) -> Result<(), MetricsParseError> {
        if let Some(first_line) = self.line {
            return Err(MetricsParseError::DuplicateRequiredMetric {
                metric: self.metric,
                first_line,
                duplicate_line: line,
            });
        }
        if sample.labels.is_some() {
            return Err(self.malformed(line, "labels are not allowed"));
        }
        let value = parse_gauge_count(sample.value, self.positive)
            .map_err(|reason| self.malformed(line, reason))?;
        self.value = Some(value);
        self.line = Some(line);
        Ok(())
    }

    fn malformed(&self, line: usize, reason: impl Into<String>) -> MetricsParseError {
        MetricsParseError::MalformedRequiredMetric {
            metric: self.metric,
            line,
            reason: reason.into(),
        }
    }

    fn required(self) -> Result<u64, MetricsParseError> {
        self.value.ok_or(MetricsParseError::MissingRequiredMetric {
            metric: self.metric,
        })
    }
}

#[derive(Default)]
struct OptionalSingleCounter {
    value: Option<f64>,
    invalid: bool,
}

impl OptionalSingleCounter {
    fn observe(&mut self, sample: ParsedSample<'_>) {
        if self.value.is_some() || sample.labels.is_some() {
            self.invalid = true;
            self.value = None;
            return;
        }
        match parse_counter(sample.value) {
            Some(value) => self.value = Some(value),
            None => self.invalid = true,
        }
    }

    fn invalidate(&mut self) {
        self.invalid = true;
        self.value = None;
    }

    fn finish(self) -> Option<f64> {
        (!self.invalid).then_some(self.value).flatten()
    }
}

#[derive(Default)]
struct OptionalCounterFamily {
    total: f64,
    seen: bool,
    invalid: bool,
    series: HashSet<String>,
}

impl OptionalCounterFamily {
    fn observe(&mut self, sample: ParsedSample<'_>) {
        let series = sample.labels.unwrap_or_default().to_owned();
        let Some(value) = parse_counter(sample.value) else {
            self.invalid = true;
            return;
        };
        if !self.series.insert(series) {
            self.invalid = true;
            return;
        }
        self.total += value;
        self.seen = true;
        if !self.total.is_finite() {
            self.invalid = true;
        }
    }

    fn invalidate(&mut self) {
        self.invalid = true;
    }

    fn finish(self) -> Option<f64> {
        (self.seen && !self.invalid).then_some(self.total)
    }
}

/// Parse the mistral.rs Prometheus text exposition needed for routing.
///
/// Running and waiting must each occur exactly once as unlabeled gauges.
/// Capacity is optional for compatibility with older engines, but when present
/// is validated just as strictly. The KV gauges are an optional pair: both
/// absent means the backend has no paged-attention signal, while only one
/// present rejects the snapshot.
pub fn parse_mistralrs_metrics(input: &str) -> Result<MistralRsMetrics, MetricsParseError> {
    let mut running = RequiredGauge::new(SEQUENCES_RUNNING_METRIC, false);
    let mut waiting = RequiredGauge::new(SEQUENCES_WAITING_METRIC, false);
    let mut capacity = RequiredGauge::new(SEQUENCES_CAPACITY_METRIC, true);
    let mut kv_used = RequiredGauge::new(KV_CACHE_BLOCKS_USED_METRIC, false);
    let mut kv_total = RequiredGauge::new(KV_CACHE_BLOCKS_TOTAL_METRIC, true);
    let mut tokens = OptionalSingleCounter::default();
    let mut prefill_tokens = OptionalSingleCounter::default();
    let mut decode_tokens = OptionalSingleCounter::default();
    let mut completions = OptionalCounterFamily::default();

    for (line_index, raw_line) in input.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let metric = metric_name_prefix(line);
        if !is_recognized_metric(metric) {
            continue;
        }

        let sample = match parse_sample_line(line) {
            Ok(sample) => sample,
            Err(reason) => {
                if metric == TOKENS_PROCESSED_TOTAL_METRIC {
                    tokens.invalidate();
                    continue;
                }
                if metric == PREFILL_TOKENS_PROCESSED_TOTAL_METRIC {
                    prefill_tokens.invalidate();
                    continue;
                }
                if metric == DECODE_TOKENS_PROCESSED_TOTAL_METRIC {
                    decode_tokens.invalidate();
                    continue;
                }
                if metric == SEQUENCES_COMPLETED_TOTAL_METRIC {
                    completions.invalidate();
                    continue;
                }
                return Err(MetricsParseError::MalformedRequiredMetric {
                    metric: static_metric_name(metric),
                    line: line_number,
                    reason: reason.to_owned(),
                });
            }
        };

        match sample.name {
            SEQUENCES_RUNNING_METRIC => running.observe(sample, line_number)?,
            SEQUENCES_WAITING_METRIC => waiting.observe(sample, line_number)?,
            SEQUENCES_CAPACITY_METRIC => capacity.observe(sample, line_number)?,
            KV_CACHE_BLOCKS_USED_METRIC => kv_used.observe(sample, line_number)?,
            KV_CACHE_BLOCKS_TOTAL_METRIC => kv_total.observe(sample, line_number)?,
            TOKENS_PROCESSED_TOTAL_METRIC => tokens.observe(sample),
            PREFILL_TOKENS_PROCESSED_TOTAL_METRIC => prefill_tokens.observe(sample),
            DECODE_TOKENS_PROCESSED_TOTAL_METRIC => decode_tokens.observe(sample),
            SEQUENCES_COMPLETED_TOTAL_METRIC => completions.observe(sample),
            _ => unreachable!("recognized metric changed while parsing"),
        }
    }

    let sequences_running = running.required()?;
    let sequences_waiting = waiting.required()?;
    let sequences_capacity = capacity.value;
    let kv_cache = match (kv_used.value, kv_total.value) {
        (None, None) => None,
        (Some(used), Some(total)) => Some(KvCacheMetrics { used, total }),
        (None, Some(_)) => {
            return Err(MetricsParseError::IncompleteKvCacheMetrics {
                missing: KV_CACHE_BLOCKS_USED_METRIC,
            });
        }
        (Some(_), None) => {
            return Err(MetricsParseError::IncompleteKvCacheMetrics {
                missing: KV_CACHE_BLOCKS_TOTAL_METRIC,
            });
        }
    };

    Ok(MistralRsMetrics {
        sequences_running,
        sequences_waiting,
        sequences_capacity,
        kv_cache,
        tokens_processed_total: tokens.finish(),
        prefill_tokens_processed_total: prefill_tokens.finish(),
        decode_tokens_processed_total: decode_tokens.finish(),
        sequences_completed_total: completions.finish(),
    })
}

fn parse_gauge_count(value: &str, positive: bool) -> Result<u64, &'static str> {
    let value = value.parse::<f64>().map_err(|_| "value is not a number")?;
    if !value.is_finite() {
        return Err("value must be finite");
    }
    if value < 0.0 {
        return Err("value must be non-negative");
    }
    if positive && value == 0.0 {
        return Err("value must be positive");
    }
    if value.fract() != 0.0 {
        return Err("value must be an integer");
    }
    if value > MAX_EXACT_F64_INTEGER {
        return Err("value is too large to represent exactly");
    }
    Ok(value as u64)
}

fn parse_counter(value: &str) -> Option<f64> {
    let value = value.parse::<f64>().ok()?;
    (value.is_finite() && value >= 0.0).then_some(value)
}

#[derive(Clone, Copy)]
struct ParsedSample<'a> {
    name: &'a str,
    labels: Option<&'a str>,
    value: &'a str,
}

fn parse_sample_line(line: &str) -> Result<ParsedSample<'_>, &'static str> {
    let bytes = line.as_bytes();
    let name_end = bytes
        .iter()
        .position(|byte| !is_metric_name_continue(*byte))
        .unwrap_or(bytes.len());
    if name_end == 0 || !is_metric_name_start(bytes[0]) {
        return Err("invalid metric name");
    }

    let name = &line[..name_end];
    let mut cursor = name_end;
    let labels = if bytes.get(cursor) == Some(&b'{') {
        let close = find_label_set_end(bytes, cursor)?;
        let labels = &line[cursor..=close];
        cursor = close + 1;
        Some(labels)
    } else {
        None
    };

    if !bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        return Err("expected whitespace before sample value");
    }
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if cursor == bytes.len() {
        return Err("sample value is missing");
    }

    let value_start = cursor;
    while bytes
        .get(cursor)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    let value = &line[value_start..cursor];

    let remainder = line[cursor..].trim_start();
    if !remainder.is_empty() && !remainder.starts_with('#') {
        let timestamp_end = remainder
            .find(char::is_whitespace)
            .unwrap_or(remainder.len());
        if remainder[..timestamp_end].parse::<i64>().is_err() {
            return Err("unexpected content after sample value");
        }
        let after_timestamp = remainder[timestamp_end..].trim_start();
        if !after_timestamp.is_empty() && !after_timestamp.starts_with('#') {
            return Err("unexpected content after sample timestamp");
        }
    }

    Ok(ParsedSample {
        name,
        labels,
        value,
    })
}

fn find_label_set_end(bytes: &[u8], open: usize) -> Result<usize, &'static str> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate().skip(open + 1) {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b'}' {
            return Ok(index);
        }
    }
    Err("unterminated label set")
}

fn metric_name_prefix(line: &str) -> &str {
    let bytes = line.as_bytes();
    if bytes
        .first()
        .is_none_or(|byte| !is_metric_name_start(*byte))
    {
        return "";
    }
    let end = bytes
        .iter()
        .position(|byte| !is_metric_name_continue(*byte))
        .unwrap_or(bytes.len());
    &line[..end]
}

const fn is_metric_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b':'
}

const fn is_metric_name_continue(byte: u8) -> bool {
    is_metric_name_start(byte) || byte.is_ascii_digit()
}

fn is_recognized_metric(metric: &str) -> bool {
    matches!(
        metric,
        SEQUENCES_RUNNING_METRIC
            | SEQUENCES_WAITING_METRIC
            | SEQUENCES_CAPACITY_METRIC
            | KV_CACHE_BLOCKS_USED_METRIC
            | KV_CACHE_BLOCKS_TOTAL_METRIC
            | TOKENS_PROCESSED_TOTAL_METRIC
            | PREFILL_TOKENS_PROCESSED_TOTAL_METRIC
            | DECODE_TOKENS_PROCESSED_TOTAL_METRIC
            | SEQUENCES_COMPLETED_TOTAL_METRIC
    )
}

fn static_metric_name(metric: &str) -> &'static str {
    match metric {
        SEQUENCES_RUNNING_METRIC => SEQUENCES_RUNNING_METRIC,
        SEQUENCES_WAITING_METRIC => SEQUENCES_WAITING_METRIC,
        SEQUENCES_CAPACITY_METRIC => SEQUENCES_CAPACITY_METRIC,
        KV_CACHE_BLOCKS_USED_METRIC => KV_CACHE_BLOCKS_USED_METRIC,
        KV_CACHE_BLOCKS_TOTAL_METRIC => KV_CACHE_BLOCKS_TOTAL_METRIC,
        TOKENS_PROCESSED_TOTAL_METRIC => TOKENS_PROCESSED_TOTAL_METRIC,
        PREFILL_TOKENS_PROCESSED_TOTAL_METRIC => PREFILL_TOKENS_PROCESSED_TOTAL_METRIC,
        DECODE_TOKENS_PROCESSED_TOTAL_METRIC => DECODE_TOKENS_PROCESSED_TOTAL_METRIC,
        SEQUENCES_COMPLETED_TOTAL_METRIC => SEQUENCES_COMPLETED_TOTAL_METRIC,
        _ => unreachable!("metric was checked before conversion"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
# HELP mistralrs_sequences_running Sequences currently running.
# TYPE mistralrs_sequences_running gauge
mistralrs_sequences_running 4
mistralrs_sequences_waiting 2
mistralrs_sequences_capacity 32
mistralrs_kv_cache_blocks_used 70
mistralrs_kv_cache_blocks_total 100
"#;

    #[test]
    fn parses_routing_gauges_and_optional_counters() {
        let metrics = parse_mistralrs_metrics(&format!(
            "{BASE}\n\
             mistralrs_tokens_processed_total 1234\n\
             mistralrs_prefill_tokens_processed_total 900\n\
             mistralrs_decode_tokens_processed_total 334\n\
             mistralrs_sequences_completed_total{{reason=\"stop\"}} 8\n\
             mistralrs_sequences_completed_total{{reason=\"error\"}} 2\n"
        ))
        .unwrap();

        assert_eq!(metrics.sequences_running, 4);
        assert_eq!(metrics.sequences_waiting, 2);
        assert_eq!(metrics.sequences_capacity, Some(32));
        assert_eq!(
            metrics.kv_cache,
            Some(KvCacheMetrics {
                used: 70,
                total: 100
            })
        );
        assert_eq!(metrics.tokens_processed_total, Some(1234.0));
        assert_eq!(metrics.prefill_tokens_processed_total, Some(900.0));
        assert_eq!(metrics.decode_tokens_processed_total, Some(334.0));
        assert_eq!(metrics.sequences_completed_total, Some(10.0));
    }

    #[test]
    fn older_engines_without_the_phase_split_parse_cleanly() {
        let metrics = parse_mistralrs_metrics(BASE).unwrap();

        assert_eq!(metrics.prefill_tokens_processed_total, None);
        assert_eq!(metrics.decode_tokens_processed_total, None);
    }

    #[test]
    fn accepts_missing_kv_pair_as_unavailable() {
        let metrics = parse_mistralrs_metrics(
            "mistralrs_sequences_running 0\n\
             mistralrs_sequences_waiting 0\n\
             mistralrs_sequences_capacity 32\n",
        )
        .unwrap();

        assert_eq!(metrics.kv_cache, None);
        assert_eq!(metrics.kv_cache_ratio(), None);
    }

    #[test]
    fn rejects_each_missing_core_gauge() {
        for (missing, expected) in [
            (SEQUENCES_RUNNING_METRIC, SEQUENCES_RUNNING_METRIC),
            (SEQUENCES_WAITING_METRIC, SEQUENCES_WAITING_METRIC),
        ] {
            let input = BASE
                .lines()
                .filter(|line| !line.starts_with(missing))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                parse_mistralrs_metrics(&input),
                Err(MetricsParseError::MissingRequiredMetric { metric: expected })
            );
        }
    }

    #[test]
    fn accepts_missing_capacity_for_a_configured_fallback() {
        let input = BASE
            .lines()
            .filter(|line| !line.starts_with(SEQUENCES_CAPACITY_METRIC))
            .collect::<Vec<_>>()
            .join("\n");
        let metrics = parse_mistralrs_metrics(&input).unwrap();

        assert_eq!(metrics.sequences_capacity, None);
        assert_eq!(
            metrics.pressure_inputs(1, 16),
            LeastPressureV1Inputs {
                running: 4,
                waiting: 2,
                capacity: 16,
                new_sequences: 1,
                kv_ratio: Some(0.7),
            }
        );
    }

    #[test]
    fn rejects_a_partial_kv_pair() {
        let input = BASE.replace("mistralrs_kv_cache_blocks_total 100\n", "");
        assert_eq!(
            parse_mistralrs_metrics(&input),
            Err(MetricsParseError::IncompleteKvCacheMetrics {
                missing: KV_CACHE_BLOCKS_TOTAL_METRIC
            })
        );
    }

    #[test]
    fn rejects_duplicate_required_samples() {
        let input = format!("{BASE}\nmistralrs_sequences_running 5\n");
        assert!(matches!(
            parse_mistralrs_metrics(&input),
            Err(MetricsParseError::DuplicateRequiredMetric {
                metric: SEQUENCES_RUNNING_METRIC,
                ..
            })
        ));
    }

    #[test]
    fn rejects_labels_on_process_wide_gauges() {
        let input = BASE.replace(
            "mistralrs_sequences_running 4",
            "mistralrs_sequences_running{model=\"a\"} 4",
        );
        assert!(matches!(
            parse_mistralrs_metrics(&input),
            Err(MetricsParseError::MalformedRequiredMetric {
                metric: SEQUENCES_RUNNING_METRIC,
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_count_gauges() {
        for invalid in ["NaN", "inf", "-1", "1.5", "9007199254740992"] {
            let input = BASE.replace(
                "mistralrs_sequences_waiting 2",
                &format!("mistralrs_sequences_waiting {invalid}"),
            );
            assert!(matches!(
                parse_mistralrs_metrics(&input),
                Err(MetricsParseError::MalformedRequiredMetric {
                    metric: SEQUENCES_WAITING_METRIC,
                    ..
                })
            ));
        }
    }

    #[test]
    fn capacity_must_be_positive_and_integral() {
        for invalid in ["0", "-1", "2.5"] {
            let input = BASE.replace(
                "mistralrs_sequences_capacity 32",
                &format!("mistralrs_sequences_capacity {invalid}"),
            );
            assert!(matches!(
                parse_mistralrs_metrics(&input),
                Err(MetricsParseError::MalformedRequiredMetric {
                    metric: SEQUENCES_CAPACITY_METRIC,
                    ..
                })
            ));
        }
    }

    #[test]
    fn kv_total_must_be_positive() {
        let input = BASE.replace(
            "mistralrs_kv_cache_blocks_total 100",
            "mistralrs_kv_cache_blocks_total 0",
        );
        assert!(matches!(
            parse_mistralrs_metrics(&input),
            Err(MetricsParseError::MalformedRequiredMetric {
                metric: KV_CACHE_BLOCKS_TOTAL_METRIC,
                ..
            })
        ));
    }

    #[test]
    fn overcommitted_kv_is_accepted_and_clamped() {
        let input = BASE.replace(
            "mistralrs_kv_cache_blocks_used 70",
            "mistralrs_kv_cache_blocks_used 120",
        );
        let metrics = parse_mistralrs_metrics(&input).unwrap();
        let kv = metrics.kv_cache.unwrap();

        assert!(kv.is_overcommitted());
        assert_eq!(kv.ratio(), 1.0);
    }

    #[test]
    fn accepts_prometheus_timestamps_exemplars_and_quoted_label_spaces() {
        let input = format!(
            "{BASE}\n\
             mistralrs_tokens_processed_total 10 1712345678\n\
             mistralrs_sequences_completed_total{{reason=\"tool calls\"}} 3 # {{trace_id=\"abc\"}} 1\n"
        );
        let metrics = parse_mistralrs_metrics(&input).unwrap();

        assert_eq!(metrics.tokens_processed_total, Some(10.0));
        assert_eq!(metrics.sequences_completed_total, Some(3.0));
    }

    #[test]
    fn malformed_optional_counters_do_not_discard_routing_data() {
        let input = format!(
            "{BASE}\n\
             mistralrs_tokens_processed_total nope\n\
             mistralrs_prefill_tokens_processed_total -3\n\
             mistralrs_decode_tokens_processed_total inf\n\
             mistralrs_sequences_completed_total{{reason=\"stop\"}} NaN\n"
        );
        let metrics = parse_mistralrs_metrics(&input).unwrap();

        assert_eq!(metrics.tokens_processed_total, None);
        assert_eq!(metrics.prefill_tokens_processed_total, None);
        assert_eq!(metrics.decode_tokens_processed_total, None);
        assert_eq!(metrics.sequences_completed_total, None);
    }

    #[test]
    fn duplicate_optional_series_are_omitted_not_fatal() {
        let input = format!(
            "{BASE}\n\
             mistralrs_tokens_processed_total 10\n\
             mistralrs_tokens_processed_total 11\n\
             mistralrs_prefill_tokens_processed_total 4\n\
             mistralrs_prefill_tokens_processed_total 5\n\
             mistralrs_sequences_completed_total{{reason=\"stop\"}} 2\n\
             mistralrs_sequences_completed_total{{reason=\"stop\"}} 2\n"
        );
        let metrics = parse_mistralrs_metrics(&input).unwrap();

        assert_eq!(metrics.tokens_processed_total, None);
        assert_eq!(metrics.prefill_tokens_processed_total, None);
        assert_eq!(metrics.decode_tokens_processed_total, None);
        assert_eq!(metrics.sequences_completed_total, None);
    }

    #[test]
    fn ignores_unrelated_and_malformed_unknown_samples() {
        let input = format!("not even prometheus\nother_metric{{broken 2\n{BASE}");
        assert!(parse_mistralrs_metrics(&input).is_ok());
    }

    #[test]
    fn rejects_malformed_required_sample_syntax() {
        let input = BASE.replace(
            "mistralrs_sequences_running 4",
            "mistralrs_sequences_running{model=\"a\" 4",
        );
        assert!(matches!(
            parse_mistralrs_metrics(&input),
            Err(MetricsParseError::MalformedRequiredMetric {
                metric: SEQUENCES_RUNNING_METRIC,
                ..
            })
        ));
    }

    #[test]
    fn computes_least_pressure_without_kv_signal() {
        let score = least_pressure_v1(LeastPressureV1Inputs {
            running: 10,
            waiting: 2,
            capacity: 20,
            new_sequences: 1,
            kv_ratio: None,
        })
        .unwrap();

        assert_eq!(score.occupancy, 0.65);
        assert_eq!(score.kv_penalty, 0.0);
        assert_eq!(score.pressure, 0.65);
    }

    #[test]
    fn computes_kv_penalty_above_eighty_five_percent() {
        let score = least_pressure_v1(LeastPressureV1Inputs {
            running: 0,
            waiting: 0,
            capacity: 10,
            new_sequences: 1,
            kv_ratio: Some(0.925),
        })
        .unwrap();

        assert!((score.occupancy - 0.1).abs() < f64::EPSILON);
        assert!((score.kv_penalty - 0.5).abs() < 1e-12);
        assert!((score.pressure - 0.6).abs() < 1e-12);
    }

    #[test]
    fn kv_penalty_is_zero_at_and_below_threshold() {
        for ratio in [0.0, 0.5, KV_PENALTY_START] {
            let score = least_pressure_v1(LeastPressureV1Inputs {
                running: 0,
                waiting: 0,
                capacity: 1,
                new_sequences: 0,
                kv_ratio: Some(ratio),
            })
            .unwrap();
            assert_eq!(score.kv_penalty, 0.0);
        }
    }

    #[test]
    fn validates_direct_pressure_inputs() {
        let base = LeastPressureV1Inputs {
            running: 0,
            waiting: 0,
            capacity: 1,
            new_sequences: 1,
            kv_ratio: None,
        };
        assert_eq!(
            least_pressure_v1(LeastPressureV1Inputs {
                capacity: 0,
                ..base
            }),
            Err(PressureInputError::ZeroCapacity)
        );
        for ratio in [f64::NAN, f64::INFINITY] {
            assert_eq!(
                least_pressure_v1(LeastPressureV1Inputs {
                    kv_ratio: Some(ratio),
                    ..base
                }),
                Err(PressureInputError::NonFiniteKvRatio)
            );
        }
        for ratio in [-0.1, 1.1] {
            assert_eq!(
                least_pressure_v1(LeastPressureV1Inputs {
                    kv_ratio: Some(ratio),
                    ..base
                }),
                Err(PressureInputError::KvRatioOutOfRange)
            );
        }
    }

    #[test]
    fn snapshot_can_use_a_conservative_effective_capacity() {
        let metrics = parse_mistralrs_metrics(BASE).unwrap();
        let inputs = metrics.pressure_inputs(2, 16);

        assert_eq!(inputs.capacity, 16);
        assert_eq!(inputs.new_sequences, 2);
        assert_eq!(inputs.kv_ratio, Some(0.7));
    }
}
