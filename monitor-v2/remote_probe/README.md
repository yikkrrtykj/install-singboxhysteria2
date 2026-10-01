# P6 office remote-probe agent (PR-6A, DARK)

Implements the office/client-side evidence half of the frozen P6 contract
(issue #67). **PR-6A ships this package DARK**: there is no server ingest
route, no server database, no History/classifier/UI/deploy change and no
version bump. The agent produces canonical signed samples, spools them
durably and can drain them against any injected transport; only fixtures and
mock transports are used in this phase.

## What it does

One bounded cycle (deadline <= 20 s, cadence default 60 s / minimum 30 s, no
overlapping cycles) collects:

| evidence | how | honesty boundary |
|---|---|---|
| `mihomo_api` | audited `/version` GET | reachability only |
| `active[reality]`, `active[hy2]` | ONE active delay test per role through the explicitly configured node | "the diagnostic HTTPS request completed through that node to the frozen destination" -- it does NOT prove arbitrary application destinations |
| `dns` | system resolution of one reviewed hostname | bounded by budget |
| `https` | direct HTTPS with normal TLS validation | a certificate failure is a failure |
| `vps_tcp` | TCP connect to the configured listener | **transport reachability only, never a Reality handshake** |
| `egress` | reviewed egress endpoint, validated by the canonical global-IP gate | no ISP inference, ever |

There is deliberately **no** unauthenticated-UDP "HY2 reachability" verdict:
silence is not evidence of HY2 failure.

## Reuse, never fork

`monitor-v2/mihomo/` is imported, not copied, and **not modified**:

* `parse_controller_url` -- loopback-only controller parsing, fail-closed;
* `HttpTransport` -- structurally GET-only (`get(path)` is the whole request
  surface, so no PUT/POST/PATCH/DELETE can be issued even by a bug);
* `check_secret_mode` / `_read_secret_file` -- the 0600 secret-file discipline;
* `parse_proxies` -- the audited `/proxies` payload semantics.

`P6Mihomo` adds only three named operations (`version`, `proxies`, `delay`)
over that transport. There is no generic method/request API, so proxy
selection, connection closing, config writes, restart and upgrade are
unreachable by construction.

The audited transport clamps every request to 1..3 s. The contract permits up
to 5 s per active delay test, so reuse makes P6 **stricter** than the contract
(`TRANSPORT_TIMEOUT_SECONDS <= 5 s`, pinned by the lane).

## Cache-effect truthfulness

P6 active delay requests mutate Mihomo's own node delay cache/history. A later
E4/E4-Diag observation may therefore contain a measurement P6 itself caused.
`evidence.merge_evidence` owns the rule: an entry whose `(role, test_id)`
matches one of our own active tests is kept for the operator but marked
`independent=False` and excluded from the corroboration count. One active test
can never be counted twice, no matter when the cache echo arrives.

## Spool (spool-before-ack)

* dedicated real directory, no symlink component, mode 0700;
* records are regular/no-follow 0600 files, `O_APPEND`;
* the **exact canonical body bytes** are stored (base64 inside the record);
  a parsed object is never spooled for later re-serialization;
* complete write loop, then `fsync` -- durable before the record counts;
* startup repairs AT MOST one incomplete trailing fragment;
* rotation: file fsync, rename, directory fsync;
* bounds: `<= 7 days`, `<= 32 MiB`; every drop is counted and visible in
  `spool.status()` (`expired_total`, `budget_dropped_total`, `corrupt_total`);
* ONE writer per spool directory: the cursor is persisted state, so a second
  instance over the same directory could resurrect records the first one
  already resolved (the same single-writer discipline the audited E4-Diag
  writer enforces with its instance lock);
* a record leaves the queue only in a terminal state (acknowledged or
  quarantined), so a permanently-rejected record can never block later
  samples;
* if the spool cannot accept the sample, the sample is **not uploaded at all**.

Note on the two bounds: `<= 32 MiB` holds far fewer than 7 days of *maximum*
16 KiB bodies, so the effective local horizon is `min(7 days, 32 MiB)`. Real
bodies are ~1 KB, which fits 7 days comfortably; the counters above make any
shortening visible rather than silent.

## Wire contract (frozen here; PR-6B must honor it)

Body: exact canonical compact JSON (`sort_keys`, compact separators, ASCII),
closed schema, unknown fields rejected, `<= 16 KiB` encoded.

```
{"v":1,"probe_id":..,"run":..,"seq":..,"sample_epoch":..,
 "dns":{status,latency_ms,error_code},"https":{...},"vps_tcp":{...},
 "egress":{status,latency_ms,error_code,ip,change},
 "mihomo_api":{"status":ok|unavailable|invalid},
 "active":[{role,source,outcome,delay_ms,test_id,independent}],
 "flags":{"truncated":bool,"source_unavailable":[...]}}
```

Signature input:

```
p6-v1\nPOST\n/api/v1/remote-probes/ingest\n<probe_id>\n<sent_epoch>\n<run>\n<seq>\n<sha256(raw_body_bytes)>
```

`HMAC-SHA256(per_probe_secret, signature_input)`, lowercase hex; verification
is constant-time. Retry keeps the exact body bytes and the tuple
(`probe_id`, `run`, `seq`) and refreshes only `sent_epoch` + signature.

Closed outcome vocabulary for active tests: `ok | timeout | unavailable |
invalid`, with `invalid` reserved for configuration/contract reasons (missing
node, refused credentials, malformed reply) so a configuration mistake can
never be rendered as path failure. `delay == 0` is Mihomo's FAILED-test
encoding: it is recorded as `unavailable` with `delay_ms = null`, never as
0 ms of latency.

Disposition of an upload answer is total: ACK (2xx with the frozen success
schema), PERMANENT (malformed 2xx, every 3xx -- never followed --, 400/401/403/
404/405/409/413, other 4xx except 408/429), RETRY (408, 429, 5xx, network/TLS
failure), and unknown classes retry only a bounded number of times before
sanitized quarantine.

## Not in this phase

No server ingest route, no remote database, no History schema change, no
classifier change, no UI change, no deploy change, no version bump, no
production activation, no automatic failover, no Mihomo config mutation, no
arbitrary user-defined diagnostic URLs.
