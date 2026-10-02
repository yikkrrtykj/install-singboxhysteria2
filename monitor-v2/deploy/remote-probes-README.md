# PR-6B operator notes (Monitor 0.7.0)

Issue [#67](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/67)
is the authoritative contract, re-frozen on 2026-10-02. PR #69 remains a
draft for independent review. Merge and production deployment are not
authorized. These notes do not change that authorization.

## Registry authority

The operator supplies `/etc/singbox-monitor/remote-probes.json` (regular,
root:sboxweb 0640), the real, non-symlink `remote-probes.d` directory
(root:sboxweb 0750), and per-identity keys (regular/no-follow,
root:sboxweb 0640). Keys contain exactly 64 lowercase hex characters,
optionally surrounded by ASCII whitespace. The installer never generates
or overwrites these secrets. Binary, unreadable, oversized or unsafe keys
disable that identity and expose `remote_config_invalid`; other valid
identities remain usable. Malformed metadata disables the remote plane.

## Evidence and continuity storage

The remote store is exclusively
`<state>/remote-probes/remote-probes.sqlite3` (0600 in a real 0700 directory).
It is separate from History v5 and its deploy prestate backup. Schema v1
has exactly `remote_probe_samples`, `remote_probe_runs`, and
`remote_probe_receipts`. Receipt hashes are the original SHA-256 body
digest, stored as 32-byte BLOBs. Only authenticated canonical evidence
bodies enter the sample table; receipts contain no payload or credentials.

A previous, unmerged two-table draft v1 is incompatible. Startup rejects
it without mutation; it never reconstructs receipts from high-water or
silently deletes the DB. Disposable test fixtures may explicitly create
a fresh DB. No production migration or reset endpoint is provided.

Evidence is retained **up to 7 days**. Its separate sample charge is
`length(canonical body) + 256` per row, soft target 16 MiB / hard ceiling
24 MiB. Startup, acceptance and status/read apply retention. Sample pressure
prunes oldest evidence only; run/receipt authority survives. SQLite freelist
pages remain reusable within the independently bounded main DB, rather
than treating total DB pages as sample bytes or vacuuming on every request.

Run authority expires only after **30 days without accepted/valid retry
activity**. All its receipts share that expiry, regardless of their own
age. Duplicate activity refreshes the run; equivocation/invalid traffic
does not. A continuously active run can keep older receipts indefinitely
until it reaches admission capacity. High-water constrains new tuples;
it never proves a missing receipt existed. Receipt comparison precedes
new-sample age/progression checks after HMAC, transport freshness,
authenticated limits and canonical validation.

| Resource | Frozen limit / accounting |
| --- | --- |
| Unexpired runs | 64/probe, 4096 global; 1024 bytes/run, 4 MiB global |
| Unexpired receipts | 131,072/probe, 1,048,576 global; 256 bytes/receipt, 256 MiB global |
| Sample evidence | body bytes + 256/row; soft 16 MiB / hard 24 MiB; age 7 days |
| Main DB live and allocated pages | 320 MiB each, all tables/indexes included |
| Whole working footprint | 1 GiB including main DB, DELETE journal and reclamation scratch |

New admission reserves conservatively for three full 320 MiB DB copies
plus 8 MiB of journal/rounding overhead, with any other remote-directory
files also charged. It requires at least 648 MiB of available scratch
space on the store filesystem. SQLite's page ceiling bounds growth during
the transaction; prospective and post-write checks gate commit. This can
refuse new tuples before the logical receipt count is exhausted when
physical layout or free disk space reaches its independent bound.

Saturation returns retryable HTTP 503 with `remote_run_capacity`,
`remote_receipt_capacity` or `remote_storage_capacity`; I/O/schema failure
returns `remote_store_unavailable`. No live receipt/run is evicted. Known
receipt duplicate/equivocation verdicts remain available at capacity,
subject to actual store availability and the normal auth/rate limits.
Failed admission never advances seq or creates partial accepted state.
Capacity recovers automatically when a prospective admission becomes legal.

The cap is not a promise to accept every 64-probe workload for 30 days:
at the default 60-second cadence, 64 probes generate about 2,764,800 receipts
in 30 days, above the global cap. Long-lived runs can also saturate. Raising
limits requires a separate reviewed contract change.

## Status and internal reads

Remote status includes independent sample/receipt/run counts and byte
charges, live/allocated DB bytes, capacity code, retained_since_epoch and
per-probe status. An enabled probe without a sample in the last 180 seconds
(three default cycles) is `source_unavailable/probe_not_reporting`.
Freshness uses original sample_epoch, never receipt or HTTP arrival time.
Budget-shortened evidence reports `degraded/remote_budget_pruned`.

Internal retained-sample reads allow at most a seven-day window and 256
rows. Labels come only from the current operator mapping; removed/disabled
mappings return retired metadata without invented labels. Receipts are
never presented as retained evidence. No PR-6C incident route, P5 schema
change or classifier/core-health input is added.

## Reverse proxy validation

Include `remote-probes-proxy.conf.example` from nginx's **http context**.
The example supports nginx >= 1.18.0 with TLS support and leaves HTTP/2
optional. The two zone directives belong to http, as required by the
[request-limit](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req_zone)
and [connection-limit](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html#limit_conn_zone)
documentation. It does not use the `http2 on` directive introduced in
[1.25.1](https://nginx.org/en/docs/http/ngx_http_v2_module.html#http2).

Only the exact ingest path is forwarded to loopback, with body/header bytes
preserved and bounded buffering. Supply operator certificates/DNS/port
settings before validating with `nginx -t`. The example is never installed
or activated automatically. CI validates the real template with disposable
certificates on all supported Ubuntu baselines and confirms nginx rejects
the former invalid server-context zone placement. It starts no proxy service
and performs no production deployment.

The exact public ingest location rejects non-HTTP/1.1 client requests,
Transfer-Encoding and missing original Content-Length before nginx request
buffering can normalize framing. Monitor separately checks request_version.
The Linux nginx lane exercises a real temporary TLS proxy and capture upstream:
only HTTP/1.1 with explicit Content-Length reaches upstream, with byte-exact
body and all five signature headers; HTTP/1.0, chunked and missing-CL requests
return 400 without reaching upstream (six parser/runtime checks in total).
