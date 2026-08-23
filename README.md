# mistralrs_proxy

An HTTP reverse proxy for OpenAI-compatible inference backends. It authenticates
clients against your own API keys, routes requests across healthy backends, and
records who called what, where the request was sent, and how many tokens it used.

## Install

```console
cargo build --release
```

The binary is `target/release/mistralrs_proxy`.

## Create a key

```console
mistralrs_proxy key create alice
```

The key is printed once and cannot be recovered afterwards; copy it now. Repeat
for each client. The first key created is an admin key; add `--admin` to make
later keys admin too.

Keys are stored in `keys.json` (`--keys-file` or `KEYS_FILE` to change the
path). Keep it private — `chmod 600` is applied for you.

## Run

Configure topology and routing policy in `runtime.toml`:

```toml
schema_version = 1

[routing]
policy = "least-pressure-v1"
kv_soft_limit = 0.85

[telemetry]
scrape_interval_ms = 2000
scrape_timeout_ms = 750
stale_after_ms = 10000

[readiness]
probe_interval_ms = 5000
probe_timeout_ms = 1000
success_threshold = 2
failure_threshold = 3

[[backends]]
id = "gh200-a"
url = "http://127.0.0.1:18001"
capacity = 32

[[backends]]
id = "gh200-b"
url = "http://127.0.0.1:18002"

[registration]
enabled = true
# Omit max_keys for unlimited registrations.
# max_keys = 100
```

```console
mistralrs_proxy serve
```

Options (each also settable by environment variable):

| Flag | Variable | Default |
| --- | --- | --- |
| `--keys-file` | `KEYS_FILE` | `keys.json` |
| `--listen-addr` | `LISTEN_ADDR` | `127.0.0.1:3000` |
| `--runtime-file` | `RUNTIME_FILE` | `runtime.toml` |
| `--control-socket` | `CONTROL_SOCKET` | `control.sock` |
| `--backend-state-file` | `BACKEND_STATE_FILE` | `backend-state.json` |
| `--connect-timeout-ms` | `CONNECT_TIMEOUT_MS` | `5000` |
| `--log-file` | `LOG_FILE` | `proxy.jsonl` |
| `--quiet` | `QUIET` | off |

Backend URLs must use plain `http://`; this build has no upstream TLS connector.
`metrics_url` and `readiness_url` are optional and default to `<url>/metrics`
and `<url>/v1/models`. The checked-in [runtime.toml](runtime.toml) shows every
setting, including explicit probe URLs and an optional capacity ceiling.

`runtime.toml` is declarative: it contains backend membership, endpoints, and
policy, but no `enabled` or `initial_mode` field. Live modes are controlled by
the backend commands and non-active modes are persisted in
`backend-state.json`. This keeps a drain fence in place across proxy restarts.

The server does not poll `runtime.toml`. After editing it, validate and apply it
atomically through the running process:

```console
mistralrs_proxy backend reload
```

An invalid reload leaves the current revision in service. A backend must be
fully disabled and locally idle before its URL can change or it can be removed.
New backends begin active but do not receive traffic until their readiness
threshold is met.

Registration is disabled when `[registration]` is omitted. Set its
`enabled = true` to expose the local key-registration page, and optionally set
`max_keys` to stop issuing keys once the key database reaches that size. Keys
issued by the page are persisted and become usable immediately. Changes made
with the CLI key manager still require a restart; do not run the key manager
while the server is accepting registrations.

If no backend is eligible, clients receive a generic `503 service_unavailable`
response with `Retry-After: 1`; private topology and connection details remain
in the audit log. Run `mistralrs_proxy serve --help` for the full option list.

## Routing and backend telemetry

The proxy probes readiness and Prometheus telemetry in the background; request
handling never waits for a scrape. A valid `/metrics` snapshot contains the
running and waiting gauges exactly once. Capacity is recommended but optional:

```text
mistralrs_sequences_running 4
mistralrs_sequences_waiting 2
mistralrs_sequences_capacity 32
```

Paged-attention backends may also publish both
`mistralrs_kv_cache_blocks_used` and `mistralrs_kv_cache_blocks_total`. The
optional `mistralrs_tokens_processed_total` counter supplies the live token
rate shown by backend status. Unknown Prometheus metrics are ignored.

`least-pressure-v1` scores each active, ready backend with fresh telemetry:

```text
occupancy  = (running + waiting + new assignments) / effective capacity
kv_penalty = max(0, (kv_ratio - kv_soft_limit) / (1 - kv_soft_limit))
pressure   = occupancy + kv_penalty
```

The candidate with the lowest pressure wins. `new assignments` includes the
request being routed and proxy-side reservations made since the last scrape,
which prevents a fast burst from piling onto one backend. If both capacities
exist, effective capacity is the smaller of the configured ceiling and the
backend's reported `mistralrs_sequences_capacity`. If the backend omits the
metric, configured `capacity` is the fallback; if the config omits it, the
reported value is used. With neither capacity, running/waiting remain visible
and drains still work, but the backend is used only in the pool-wide
least-in-flight fallback when no eligible candidate can be pressure-scored.

Readiness uses the configured consecutive-success and consecutive-failure
thresholds. Separately, three consecutive transport failures or upstream
`500`, `502`, `503`, or `504` responses open that backend's circuit for 10 seconds;
afterward a single half-open trial decides whether to close or reopen it.

## Manage backends

All live backend inspection and control is under `mistralrs_proxy backend`:

```console
mistralrs_proxy backend list
mistralrs_proxy backend status [BACKEND]
mistralrs_proxy backend status --watch
mistralrs_proxy backend manage
mistralrs_proxy backend drain gh200-a
mistralrs_proxy backend disable gh200-a
mistralrs_proxy backend activate gh200-a
mistralrs_proxy backend reload
```

`list` shows `BACKEND`, `MODE`, `STATE`, proxy in-flight requests, engine
running/capacity and waiting counts, KV use, token rate, pressure, and metric
age. Use `list --json` or `status --json` for automation. Every backend command
accepts `--control-socket`; it must match the server's socket. In `manage`, use
`↑`/`↓` to select, `d` to drain with confirmation, `a` to activate, `r` to
reload `runtime.toml`, `R` to refresh immediately, and `q` to quit.

There are three operator modes:

- `active`: eligible for new work once readiness and the circuit permit it.
- `draining`: closed to new assignments while existing work finishes.
- `disabled`: closed; either certified safe to stop by a drain, or closed
  immediately with `backend disable --force`.

Mode and observed state are deliberately separate. An active backend can, for
example, have state `checking`, `unready`, `unreachable`, `circuit-open`,
`probing`, `degraded`, or `ready` without an operator changing its mode.

`backend drain` first installs a durable drain fence and atomically closes the
assignment gate. Its lease covers the complete response body, including an SSE
stream, so a request remains active until the stream ends or the client
disconnects. The command returns successfully only after proxy in-flight work
is zero and the engine reports both running and waiting as zero on two distinct,
fresh metrics scrapes. It then persists `disabled` and prints `safe to stop`;
at that point the backend process can be killed.

Use `--no-wait` to start a drain and return immediately, or
`--timeout-seconds N` to bound only how long the CLI waits. A timeout or Ctrl-C
detaches from the operation; it does not cancel the durable drain, and status
remains available from another CLI process. Activation is allowed only after a
backend is disabled, ready, and telemetry-fresh.

`backend disable` closes a backend immediately without waiting for in-flight
work and persists the disabled fence. It is the escape hatch for a dead
backend, whose drain can never observe the fresh idle telemetry samples a
drain needs to complete. If a drain is already in progress, it completes at
once and a running `backend drain` client reports `safe to stop`. While the
proxy still has in-flight requests on the backend, the command refuses unless
you pass `--force`; with `--force` those requests run to completion (or fail
on their own) while no new work is assigned.

The commands speak HTTP under `/control`, but only over the private Unix-domain
socket (created mode `0660`). `/control` is not forwarded or exposed by the
public TCP listener. Give control-socket access only to trusted operators.

## Register a key

Open `http://127.0.0.1:3000/register`, enter your name, and copy the API key
when it appears. The plaintext is shown only once and is never written to the
key database or audit log. Keys created here are active non-admin keys.

Registration is intentionally unauthenticated: anyone who can reach this page
can create a key until `max_keys` is reached. Use a trusted network or put the
proxy behind TLS and appropriate network access controls when exposing it
beyond localhost.

## Call it

Point any OpenAI client at the proxy and use the key as the API key:

```console
curl http://127.0.0.1:3000/v1/chat/completions \
  -H "Authorization: Bearer eb_..." \
  -H 'Content-Type: application/json' \
  -d '{"model":"...","messages":[{"role":"user","content":"hi"}]}'
```

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:3000/v1", api_key="eb_...")
```

Apart from proxy-owned `/register` and the reserved `/control` namespace, paths
are forwarded unchanged, so Chat Completions, Responses, streaming, and other
upstream APIs work as usual. An unknown key gets `401`, a disabled key gets
`403`.

## Manage keys

```console
mistralrs_proxy key manage
```

An interactive view of every key and its flags:

| Key | Action |
| --- | --- |
| `↑` `↓` | Move |
| `a` | Toggle admin |
| `d` | Enable/disable the key |
| `x` | Delete the key |
| `s` | Save |
| `r` | Reload, discarding edits |
| `q` | Quit |

Edits apply when you press `s`, and take effect on the next restart. The last
enabled admin key cannot be disabled or deleted.

## What gets logged

Two places, neither containing API keys, prompts, or responses.

**Standard output** — `serve` emits sparse operational events suitable for
`journalctl`: startup and shutdown, readiness recovery, drains, activations,
and applied runtime revisions. It does not duplicate every request to the
terminal. Warnings and fatal errors go to standard error. Pass `--quiet` to
suppress routine operational lines; choosing `--log-file -` does this
automatically so standard output remains JSONL.

**The audit log** — one JSON object per request in `--log-file` (`proxy.jsonl`
by default; `-` sends it to stdout instead). Alongside identity, request,
status, latency, and token fields, it records the selected backend, routing
reason, eligible-backend count, pressure inputs at dispatch, and time spent in
the proxy before routing:

```json
{"event":"request","request_id":"517e8f4e-...","started_at":"2026-08-20T13:50:24.447Z","duration_ms":652,"time_to_first_byte_ms":256,"client_ip":"127.0.0.1","method":"POST","uri":"/v1/chat/completions","key_name":"alice","key_identifier":"HFTLdymp","backend_id":"gh200-b","routing_policy":"least-pressure-v1","routing_reason":"fresh_metrics_lowest_pressure","eligible_backend_count":2,"backend_pressure_at_dispatch":0.21875,"backend_running_at_dispatch":5,"backend_waiting_at_dispatch":0,"backend_capacity_at_dispatch":32,"backend_kv_pressure_at_dispatch":0.73,"backend_metrics_age_ms":184,"backend_proxy_active_at_dispatch":2,"proxy_queue_ms":1,"status":200,"streaming":true,"input_tokens":480,"output_tokens":12,"total_tokens":492,"complete":true}
```

Streaming requests produce one record too, written when the stream ends. Token
counts come from the API's own `usage` field; they are `null` if the upstream
did not report usage, or if the client hung up before it arrived. For streaming
Chat Completions, ask for usage with `"stream_options": {"include_usage": true}`.

The log file is created `chmod 600`. For rotation, use `copytruncate` or restart
the service after a rename; an already-open writer continues writing its inode.
If the log cannot be written, the proxy stops serving traffic rather than
serving it unrecorded.

## Read the log

```console
mistralrs_proxy logs
```

Opens an explorer over the audit log. Safe to run while the proxy is serving —
it only reads, and picks up new requests as they land.

Three views, `tab` to switch:

- **Summary** — request and status counts, total tokens, the streaming mix,
  p50/p95/max for prompt size, completion size, time to first token, per-token
  latency and total latency, plus totals by key and endpoint.
- **Backends** — historical routed-request share, token totals, errors, proxy
  queue p95, time-to-first-byte p95, and end-to-end latency p95 per backend.
- **Requests** — every request, newest first, with the full record for whichever
  one is selected.

| Key | Action |
| --- | --- |
| `tab` | Switch view |
| `1` / `2` / `3` | Summary / Backends / Requests |
| `↑` `↓` | Move |
| `/` | Filter by key, endpoint, status, id… |
| `e` | Show only errors and incomplete requests |
| `r` | Refresh now |
| `q` | Quit |

For a one-shot summary with no TUI — handy over SSH or in a cron job:

```console
mistralrs_proxy logs --summary
```

```text
proxy.jsonl
10 requests from 2026-08-20T15:26:33.966Z to 2026-08-20T15:26:37.827Z

  requests           10   authorized 9   rejected 1   incomplete 0
  statuses   2xx 9   3xx 0   4xx 1   5xx 0   none 0
  tokens          1,760 in   44 out   1,804 total
  shape               6 streaming   3 non-streaming

                               P50         P95         MAX   SAMPLES
  input tokens                 160         480         480         9
  output tokens                  4          12          12         9
  first token                255ms       256ms       256ms         6
  per output token          95.8ms      98.8ms      98.8ms         9
  total latency              383ms       652ms       652ms        10

  KEY                       REQUESTS            IN           OUT   ERRORS
  alice                            9         1,760            44        0
  (unauthenticated)                1             0             0        1

  ENDPOINT                            REQUESTS            IN           OUT
  /v1/chat/completions                       9         1,760            44
  /v1/models                                 1             0             0

  BACKEND             REQUESTS   SHARE          IN         OUT   ERRORS    QUEUE95     TTFB95  LATENCY95
  gh200-a                    5   55.6%         960          24        0        1ms      255ms      620ms
  gh200-b                    4   44.4%         800          20        0        1ms      256ms      652ms
```

The backend share is calculated over routed requests; pre-routing rejections
are not assigned to a backend. Pass `--log-file` if the log is not at
`proxy.jsonl`.

### Reading the percentile table

`SAMPLES` is not the request count — each row only counts the requests that
could contribute to it. Token rows need the upstream to have reported usage, so
rejected requests are absent rather than entering as zeros.

`first token` covers streaming responses only. A non-streaming response does not
send its head until generation has finished, so its time-to-first-byte is just
its total latency; including those would blur the number rather than inform it.

`per output token` is total latency divided by output tokens. It is the latency
number that does not move with how much the model chose to write, which makes it
the one worth comparing across days. For short completions it is dominated by
prefill.
