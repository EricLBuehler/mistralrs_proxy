//! Incremental token accounting.
//!
//! The proxy never stores request or response bodies. To still bill and report
//! traffic it scans the response byte stream for the `usage` object that both
//! the Chat Completions and Responses APIs emit, in streaming and
//! non-streaming form alike, and keeps only the token counts.
//!
//! The scanner is a small state machine, so it works across frame boundaries
//! without buffering the body. Only the `usage` object itself is buffered, and
//! that buffer is capped.

use serde::Deserialize;

/// Bytes of a candidate `usage` object we are willing to buffer before giving
/// up on it. Real usage objects are well under a hundred bytes.
const MAX_OBJECT_BYTES: usize = 4096;

const NEEDLE: &[u8] = b"\"usage\"";
const NULL: &[u8] = b"null";

/// Token counts recovered from a response.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    /// Prompt tokens served from the prefix cache instead of recomputed.
    /// Absent on engines that do not report it, or when nothing was cached.
    pub cached_tokens: Option<u64>,
} 

impl Usage {
    fn is_informative(&self) -> bool {
        self.input_tokens.is_some() || self.output_tokens.is_some() || self.total_tokens.is_some()
    }
}

/// The Chat Completions API names these `prompt_tokens`/`completion_tokens`;
/// the Responses API names them `input_tokens`/`output_tokens`. Accept both.
#[derive(Deserialize)]
struct UsageFields {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    /// Chat Completions / Completions API prefix-cache breakdown.
    prompt_tokens_details: Option<TokensDetails>,
    /// Responses API prefix-cache breakdown.
    input_tokens_details: Option<TokensDetails>,
}

#[derive(Deserialize)]
struct TokensDetails {
    cached_tokens: Option<u64>,
}

impl From<UsageFields> for Usage {
    fn from(fields: UsageFields) -> Self {
        Self {
            input_tokens: fields.input_tokens.or(fields.prompt_tokens),
            output_tokens: fields.output_tokens.or(fields.completion_tokens),
            total_tokens: fields.total_tokens,
            cached_tokens: fields
                .prompt_tokens_details
                .or(fields.input_tokens_details)
                .and_then(|details| details.cached_tokens),
        }
    }
}

enum State {
    /// Looking for the `"usage"` field name. `matched` counts needle bytes seen.
    Searching { matched: usize },
    /// Saw the field name; skipping whitespace before `:`.
    AwaitingColon,
    /// Saw `:`; skipping whitespace before the value.
    AwaitingValue,
    /// The value started with `n`; confirming it is `null`.
    SkippingNull { matched: usize },
    /// Buffering a `{...}` value.
    Capturing {
        depth: u32,
        in_string: bool,
        escaped: bool,
    },
}

/// Scans a response body for `usage` objects, keeping the last one seen.
///
/// Streaming responses repeat `"usage": null` on every chunk and carry the real
/// counts in a final chunk, so last-one-wins is the right rule.
pub struct UsageSniffer {
    state: State,
    object: Vec<u8>,
    latest: Option<Usage>,
}

impl Default for UsageSniffer {
    fn default() -> Self {
        Self::new()
    }
}

impl UsageSniffer {
    pub fn new() -> Self {
        Self {
            state: State::Searching { matched: 0 },
            object: Vec::new(),
            latest: None,
        }
    }

    /// Token counts from the most recent `usage` object, if one was found.
    pub fn usage(&self) -> Option<Usage> {
        self.latest
    }

    /// Feed the next slice of response bytes.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.feed_byte(byte);
        }
    }

    fn feed_byte(&mut self, byte: u8) {
        match &mut self.state {
            State::Searching { matched } => {
                if byte == NEEDLE[*matched] {
                    *matched += 1;
                    if *matched == NEEDLE.len() {
                        self.state = State::AwaitingColon;
                    }
                } else {
                    // No byte of the needle after the first is a quote, so the
                    // only possible partial match after a mismatch is a new
                    // opening quote.
                    *matched = usize::from(byte == b'"');
                }
            }
            State::AwaitingColon => {
                if byte == b':' {
                    self.state = State::AwaitingValue;
                } else if !byte.is_ascii_whitespace() {
                    self.restart(byte);
                }
            }
            State::AwaitingValue => {
                if byte == b'{' {
                    self.object.clear();
                    self.object.push(b'{');
                    self.state = State::Capturing {
                        depth: 1,
                        in_string: false,
                        escaped: false,
                    };
                } else if byte == b'n' {
                    self.state = State::SkippingNull { matched: 1 };
                } else if !byte.is_ascii_whitespace() {
                    self.restart(byte);
                }
            }
            State::SkippingNull { matched } => {
                if byte == NULL[*matched] {
                    *matched += 1;
                    if *matched == NULL.len() {
                        self.state = State::Searching { matched: 0 };
                    }
                } else {
                    self.restart(byte);
                }
            }
            State::Capturing {
                depth,
                in_string,
                escaped,
            } => {
                if *in_string {
                    if *escaped {
                        *escaped = false;
                    } else if byte == b'\\' {
                        *escaped = true;
                    } else if byte == b'"' {
                        *in_string = false;
                    }
                } else {
                    match byte {
                        b'"' => *in_string = true,
                        b'{' => *depth += 1,
                        b'}' => *depth -= 1,
                        _ => {}
                    }
                }
                self.object.push(byte);

                if *depth == 0 {
                    self.finish_object();
                } else if self.object.len() >= MAX_OBJECT_BYTES {
                    // Not a usage object we recognise; drop it and keep looking.
                    self.object.clear();
                    self.state = State::Searching { matched: 0 };
                }
            }
        }
    }

    fn finish_object(&mut self) {
        if let Ok(fields) = serde_json::from_slice::<UsageFields>(&self.object) {
            let usage = Usage::from(fields);
            if usage.is_informative() {
                self.latest = Some(usage);
            }
        }
        self.object.clear();
        self.state = State::Searching { matched: 0 };
    }

    fn restart(&mut self, byte: u8) {
        self.object.clear();
        self.state = State::Searching {
            matched: usize::from(byte == b'"'),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sniff(chunks: &[&str]) -> Option<Usage> {
        let mut sniffer = UsageSniffer::new();
        for chunk in chunks {
            sniffer.feed(chunk.as_bytes());
        }
        sniffer.usage()
    }

    #[test]
    fn reads_chat_completion_usage() {
        let body = r#"{"id":"c1","choices":[{"message":{"content":"hi"}}],
            "usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}}"#;

        assert_eq!(
            sniff(&[body]),
            Some(Usage {
                input_tokens: Some(11),
                output_tokens: Some(4),
                total_tokens: Some(15),
                cached_tokens: None,
            })
        );
    }

    #[test]
    fn reads_responses_api_usage() {
        let body = r#"{"id":"resp_1","output":[],"usage":{"input_tokens":7,
            "input_tokens_details":{"cached_tokens":0},"output_tokens":21,
            "output_tokens_details":{"reasoning_tokens":5},"total_tokens":28}}"#;

        assert_eq!(
            sniff(&[body]),
            Some(Usage {
                input_tokens: Some(7),
                output_tokens: Some(21),
                total_tokens: Some(28),
                cached_tokens: Some(0),
            })
        );
    }

    #[test]
    fn skips_null_usage_and_keeps_the_final_streamed_object() {
        let usage = sniff(&[
            "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}],\"usage\":null}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}],\"usage\":null}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":9,\"total_tokens\":12}}\n\n",
            "data: [DONE]\n\n",
        ]);

        assert_eq!(
            usage,
            Some(Usage {
                input_tokens: Some(3),
                output_tokens: Some(9),
                total_tokens: Some(12),
                cached_tokens: None,
            })
        );
    }

    #[test]
    fn finds_usage_split_across_frame_boundaries() {
        let usage = sniff(&[
            "data: {\"choices\":[],\"us",
            "age\"",
            "  :  {\"prompt_to",
            "kens\":2,\"completion_tokens\"",
            ":5,\"total_tokens\":7}}\n\n",
        ]);

        assert_eq!(
            usage,
            Some(Usage {
                input_tokens: Some(2),
                output_tokens: Some(5),
                total_tokens: Some(7),
                cached_tokens: None,
            })
        );
    }

    #[test]
    fn generated_text_mentioning_usage_is_not_mistaken_for_the_field() {
        // The model wrote the literal text: the "usage" field is {"a": 1}.
        let body = r#"{"choices":[{"delta":{"content":"the \"usage\" field is {\"a\": 1}"}}],
            "usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#;

        assert_eq!(
            sniff(&[body]),
            Some(Usage {
                input_tokens: Some(1),
                output_tokens: Some(2),
                total_tokens: Some(3),
                cached_tokens: None,
            })
        );
    }

    #[test]
    fn a_string_valued_usage_field_is_ignored() {
        assert_eq!(sniff(&[r#"{"usage":"high","choices":[]}"#]), None);
    }

    #[test]
    fn reads_chat_completion_cached_tokens() {
        let body = r#"{"usage":{"prompt_tokens":480,"completion_tokens":12,
            "total_tokens":492,"prompt_tokens_details":{"cached_tokens":320}}}"#;

        assert_eq!(
            sniff(&[body]),
            Some(Usage {
                input_tokens: Some(480),
                output_tokens: Some(12),
                total_tokens: Some(492),
                cached_tokens: Some(320),
            })
        );
    }

    #[test]
    fn reads_responses_api_cached_tokens() {
        let body = r#"{"usage":{"input_tokens":500,
            "input_tokens_details":{"cached_tokens":450},"output_tokens":20,
            "total_tokens":520}}"#;

        assert_eq!(
            sniff(&[body]),
            Some(Usage {
                input_tokens: Some(500),
                output_tokens: Some(20),
                total_tokens: Some(520),
                cached_tokens: Some(450),
            })
        );
    }

    #[test]
    fn nested_objects_inside_usage_do_not_end_the_capture_early() {
        let body = r#"{"usage":{"input_tokens_details":{"cached_tokens":0},"input_tokens":4,
            "output_tokens":6}}"#;

        assert_eq!(
            sniff(&[body]),
            Some(Usage {
                input_tokens: Some(4),
                output_tokens: Some(6),
                total_tokens: None,
                cached_tokens: Some(0),
            })
        );
    }

    #[test]
    fn an_oversized_candidate_object_is_abandoned() {
        let filler = "x".repeat(MAX_OBJECT_BYTES);
        let body = format!(
            "{{\"usage\":{{\"note\":\"{filler}\"}},\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}"
        );

        assert_eq!(
            sniff(&[&body]),
            Some(Usage {
                input_tokens: Some(1),
                output_tokens: Some(1),
                total_tokens: Some(2),
                cached_tokens: None,
            })
        );
    }

    #[test]
    fn a_body_without_usage_yields_nothing() {
        assert_eq!(sniff(&[r#"{"error":{"message":"nope"}}"#]), None);
    }

    #[test]
    fn byte_at_a_time_matches_whole_body_feeding() {
        let body = r#"{"usage":{"prompt_tokens":8,"completion_tokens":2,"total_tokens":10}}"#;
        let mut sniffer = UsageSniffer::new();
        for byte in body.as_bytes() {
            sniffer.feed(&[*byte]);
        }

        assert_eq!(sniffer.usage(), sniff(&[body]));
    }
}
