# mistralrs_proxy

A small HTTP/1.1 reverse proxy for an OpenAI-compatible API. It authenticates
clients against an allowlist loaded once at startup and writes correlated
request/response events as JSON Lines without doing serialization or file I/O
on Tokio's request workers.

## Configure and run

Create a UTF-8 key file containing one printable-ASCII API key per line. Empty
lines and lines beginning with `#` are ignored; duplicate keys and whitespace
around a key are rejected. For example:

```text
# Local development
foobar
```

Protect the file with appropriate permissions (for example, `chmod 600
api_keys.txt`). It is read exactly once during startup. Editing, replacing, or
deleting it has no effect on a running process; restart the proxy to load a new
set of keys.

Clients authenticate in the same form used by the OpenAI SDK:

```http
Authorization: Bearer foobar
```

```console
cargo run --release -- --api-keys-file api_keys.txt --listen-addr 0.0.0.0:3000 --upstream-url http://127.0.0.1:1234 --log-file proxy.jsonl
```

`API_KEYS_FILE`, `LISTEN_ADDR`, `UPSTREAM_URL`, `CONNECT_TIMEOUT_MS`, and
`LOG_FILE` are equivalent environment variables. `--log-file -` writes JSONL to
stdout; startup and logger diagnostics go to stderr. Run `cargo run -- --help`
for the complete CLI.

The current Hyper connector intentionally supports plain HTTP upstreams only,
which is appropriate for a local mistral.rs server. The proxy sends the original
`Authorization` header upstream.

## Log records

Every request gets a UUID, also returned in `x-proxy-request-id`. All related
records use that value as `request_id`.

- One `request` record is emitted after the complete request body arrives. It
  includes the direct peer IP/port, original Host, API key, method, URI, version,
  headers, trailers, and plaintext body.
- `response_start` contains status and headers.
- Each streamed response data frame becomes a `response_body` record with a
  sequence number and byte offset. Response trailers and completion become
  `response_trailers` and `response_end` records.
- If a body errors or is dropped early, its final record says `complete: false`
  and records the termination reason. Rejected requests are marked with
  `authorized: false`; their bodies are drained and logged without delaying the
  401 response.

JSON escaping keeps each record on one line. The response decoder carries at
most three bytes between frames, so a UTF-8 character split at a frame boundary
is reconstructed correctly without buffering the response. Truly invalid UTF-8
uses the Unicode replacement character, sets `body_utf8_valid: false`, and adds
`body_bytes_hex` so the original bytes are still recoverable. Requests receive
the same invalid-byte fallback after their complete body is assembled.

## Performance and security notes

Request frames are drained by a small task into a bounded eight-frame pipe to
the upstream. This preserves streaming backpressure while letting the task keep
draining the inbound request for logging if the upstream fails or replies early.
Response frames are forwarded unchanged. Producers enqueue cheap `Bytes` clones
on an unbounded in-memory log channel; a named OS thread assembles request
bodies, incrementally decodes response text, serializes JSON, writes it, and
flushes within 100 ms. This avoids disk backpressure and logging locks in the
async hot path and does not intentionally drop records. It also means a stalled
disk or very large/full-speed bodies can grow memory without a fixed bound.
Guaranteed logging, bounded memory, and zero request backpressure cannot all be
provided simultaneously; this implementation chooses guaranteed enqueueing and
a nonblocking request path. If the writer fails, subsequent requests receive
503 instead of being proxied without an audit trail.

The direct socket peer is logged as the client address. Forwarded-IP headers are
not trusted because the proxy has no trusted-proxy configuration.

Logs intentionally contain plaintext API keys, headers, prompts, and responses.
Log files are restricted to mode `0600` on Unix. Apply suitable access,
retention, and rotation controls. The allowlist file should receive the same
care; the standalone proxy retains only key digests after loading it. The default
local `api_keys.txt` and `proxy.jsonl` paths are ignored by Git.
