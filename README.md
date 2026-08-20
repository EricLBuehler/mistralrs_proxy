# mistralrs_proxy

An HTTP reverse proxy for an OpenAI-compatible API. It authenticates clients
against your own API keys, forwards requests unchanged, and records who called
what and how many tokens they used.

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

```console
mistralrs_proxy serve --upstream-url http://127.0.0.1:1234
```

Options (each also settable by environment variable):

| Flag | Variable | Default |
| --- | --- | --- |
| `--keys-file` | `KEYS_FILE` | `keys.json` |
| `--listen-addr` | `LISTEN_ADDR` | `127.0.0.1:3000` |
| `--upstream-url` | `UPSTREAM_URL` | `http://127.0.0.1:1234` |
| `--connect-timeout-ms` | `CONNECT_TIMEOUT_MS` | `5000` |
| `--log-file` | `LOG_FILE` | `proxy.jsonl` |
| `--quiet` | `QUIET` | off |

The upstream must be plain `http://`. Run `mistralrs_proxy serve --help` for
the full list.

Keys are read once at startup. After creating, changing, or deleting a key,
restart the proxy.

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

Every path is forwarded, so Chat Completions, Responses, streaming, and
everything else your upstream serves work as usual. An unknown key gets `401`,
a disabled key gets `403`.

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

**Your terminal** — one line when a request arrives and one when it finishes:

```text
2026-08-20T13:50:24.447Z  >  517e8f4e-4eed-425b-b0af-52292262577d  POST /v1/chat/completions  alice[HFTLdymp]  from 127.0.0.1
2026-08-20T13:50:24.448Z  <  517e8f4e-4eed-425b-b0af-52292262577d  200  1ms  in=42 out=13  alice[HFTLdymp]
```

Pass `--quiet` to turn these off.

**The audit log** — one JSON object per request in `--log-file` (`proxy.jsonl`
by default; `-` sends it to stdout instead), with the key
name and identifier, client address, method and path, status, duration, and the
input and output token counts:

```json
{"event":"request","request_id":"517e8f4e-...","started_at":"2026-08-20T13:50:24.447Z","duration_ms":652,"time_to_first_byte_ms":256,"client_ip":"127.0.0.1","method":"POST","uri":"/v1/chat/completions","key_name":"alice","key_identifier":"HFTLdymp","status":200,"streaming":true,"input_tokens":480,"output_tokens":12,"total_tokens":492,"complete":true}
```

Streaming requests produce one record too, written when the stream ends. Token
counts come from the API's own `usage` field; they are `null` if the upstream
did not report usage, or if the client hung up before it arrived. For streaming
Chat Completions, ask for usage with `"stream_options": {"include_usage": true}`.

The log file is created `chmod 600`. Apply your own rotation. If the log cannot
be written, the proxy stops serving traffic rather than serving it unrecorded.

## Read the log

```console
mistralrs_proxy logs
```

Opens an explorer over the audit log. Safe to run while the proxy is serving —
it only reads, and picks up new requests as they land.

Two views, `tab` to switch:

- **Summary** — request and status counts, total tokens, the streaming mix,
  p50/p95/max for prompt size, completion size, time to first token, per-token
  latency and total latency, and totals broken down by key and by endpoint.
- **Requests** — every request, newest first, with the full record for whichever
  one is selected.

| Key | Action |
| --- | --- |
| `tab` | Switch view |
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
```

Pass `--log-file` if the log is not at `proxy.jsonl`.

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
