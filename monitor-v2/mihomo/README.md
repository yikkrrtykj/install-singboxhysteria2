# Monitor v2 -- Phase E4 Mihomo client API enrichment (OPTIONAL, read-only)

E4 is **optional client-side enrichment only**. It is NOT an identity data
source and it is NOT a fallback for the server Monitor.

## Identity boundary (immutable, E4 must never cross it)

```text
Server truth (Phase E1 -- sing-box service.api, authoritative):
    Device      = API USER
    Protocol    = API INBOUND TAG
    Lifecycle   = API connection ID
    Source IP   = metadata, display only

Mihomo API (this phase -- client-local external-controller):
    optional enrichment, display only, own freshness domain
```

Consequences, all enforced by construction:

* `sing-box service.api` is NOT replaceable by the Mihomo API, and the Mihomo
  API is NOT usable as device identity -- not even as a hint;
* the enrichment object is sealed through a FIXED key whitelist
  (`model.ENRICHMENT_KEYS`); no field of it can carry a device/USER meaning;
* a Mihomo node display name (`vmix-01-HY2`, `香港-01`, anything else) is
  echoed verbatim as `selected_proxy` for DISPLAY ONLY. It is never parsed,
  never matched, never mapped onto a server-side Device. If the client names
  its node `香港-01`, the device stays `vmix-01` server-side;
* this module does not import anything from the server-side monitor code and
  never touches its state; the E1 regression suite (232/232) must stay green.

UI may therefore show, side by side:

```text
Device:                vmix-01        (server truth, USER)
Server protocol:       HY2            (server truth, INBOUND)
Client selected node:  vmix-01-HY2    (Mihomo display only)
```

## Field contract (verified against the real API source, not guessed)

Verified against MetaCubeX/mihomo source (`hub/route/*.go`,
`tunnel/statistic/*.go`, `adapter/*.go`, `constant/adapters.go`) and the
official web UI (MetaCubeX/metacubexd). Classification per field:

| Field / endpoint | Source | Class | Notes |
|---|---|---|---|
| `version`, `meta` | `GET /version` -> `{"meta": bool, "version": str}` | **stable** | primary reachability probe; `meta` is always true on mihomo |
| hello | `GET /` -> `{"hello": "mihomo"}` | stable | legacy clash answered `"clash"` -- probe only, unused by the adapter |
| `mode` | `GET /configs` -> `{..., "mode": "rule"\|"global"\|"direct"}` | **stable** | displayed verbatim (lower-cased); never a security decision |
| proxy groups + nodes | `GET /proxies` -> `{"proxies": {name: {...}}}` | **stable** | entries carry `type/name/udp/alive/history`; groups additionally `now`/`all` |
| selected node of a group | `now` on group-type entries (Selector/URLTest/Fallback/LoadBalance/Relay) | **stable** | plain outbounds have no `now`; the group must be named EXPLICITLY by the caller (`--group`), the adapter never guesses |
| node delay | selected node's `history[-1].delay` (`{"time", "delay"}`) | **optional** | exists only after some earlier delay test; `delay == 0` means the last probe FAILED (not a latency); the adapter NEVER triggers a test |
| per-test-URL histories | `extra: {testUrl: {alive, history}}` | **version-dependent** | newer builds only; unused in v1 |
| active connections | `GET /connections` -> `{"downloadTotal","uploadTotal","connections": [...] , "memory"}` | **stable** | snapshot form (plain GET); per-connection counters are `upload`/`download` while the totals are `uploadTotal`/`downloadTotal` (mirrored names -- easy to swap) |
| idle / unknown connections | same endpoint: `"connections": null` (official idle shape), `[]`, key absent, or wrong type | **stable quirk** | `null` and `[]` -> `0` (confirmed empty); key MISSING or wrong type -> `null` (schema drift / unknown -- never rendered as idle) |
| core memory | `memory` in the snapshot / `GET /memory` stream | **optional, version-dependent** | mihomo-specific; not needed for enrichment v1 |
| instantaneous traffic rate | `GET /traffic` -> INDEFINITE stream, one flushed `JSON + \n` per second, connection stays OPEN, first sample ~1 s after connect | **optional, streaming** | newline-framed first-sample reader: returns the moment the first complete line arrives (bounded `read1` calls + absolute deadline), never waits for the connection to close or a full read buffer; only the instantaneous `up`/`down` pair is kept |
| local traffic totals | `upTotal`/`downTotal` in the same stream | **unsuitable** | client-local since core start; redundant with (and inferior to) the server's authoritative counters |
| rules | `GET /rules` | **unsuitable for v1** | large payload, no enrichment value yet |
| logs / memory streams / DNS debug | `GET /logs`, `GET /memory`, `GET /dns/query` | **unsuitable for v1** | streams / debug tools |
| proxy providers | `GET /providers/proxies` | **optional, version-dependent** | only present when providers are configured |

FORBIDDEN control-plane operations (read-only mandate -- the transport
exposes `get(path)` ONLY; there is no `method` parameter anywhere, so a
mutation verb cannot even be expressed):

* selecting a proxy (`PUT /proxies/{group}`), closing connections
  (`DELETE /connections[/{id}]`), mode/config change or reload
  (`PATCH`/`PUT /configs`), restart (`POST /restart`), upgrade
  (`POST /upgrade`);
* `GET /proxies/{name}/delay` -- despite looking read-only it performs an
  ACTIVE probe THROUGH the node (traffic + load); only cached history is read;
* the websocket-style `?token=` query fallback for auth (secret must never
  travel in a URL).

Version-dependent transport note: newer builds can also serve the controller
on a Unix socket / Windows named pipe (`external-controller-unix` /
`external-controller-pipe`); E4 v1 targets the TCP loopback listener only.

## Output object (one per collect())

```json
{
  "reachable": true,
  "version": "v1.19.13",
  "mode": "rule",
  "selected_group": "PROXY",
  "selected_proxy": "vmix-01-HY2",
  "delay_ms": 82,
  "active_connections": 11,
  "traffic_up_bps": 1234,
  "traffic_down_bps": 5678,
  "checked_at": "2026-09-12T10:00:00+00:00",
  "updated_at": "2026-09-12T10:00:00+00:00",
  "stale": false,
  "error": null
}
```

* `selected_group` / `selected_proxy` / `delay_ms` are `null` unless the
  caller named a group (`--group`).
* `reachable` is decided by `/version` only. Unreachable, disabled listener,
  wrong secret (401) and client offline are ALL just `reachable: false` plus
  a redacted `error` -- NEVER a device problem and NEVER a server Monitor
  problem.
* Optional endpoints fail in isolation: a broken `/configs` nulls only
  `mode`, and the object stays `reachable: true`.
* `active_connections` is an int ONLY when the snapshot shape was understood;
  schema drift (missing key, wrong type) yields `null` -- "unknown", which
  must never be rendered as 0/idle.

## Freshness / stale / error semantics (independent domains)

Vocabulary (stateless single-poll semantics, v1):

```text
checked_at  = when THIS poll completed (always set, success or failure)
updated_at  = when valid enrichment data was last obtained (null on a
              failed poll -- a failure is never backdated into freshness)
reachable   = whether the LAST /version probe succeeded
stale       = true whenever updated_at is null, or older than max_age
```

* every collect() stamps `checked_at`; a SUCCESSFUL poll also stamps
  `updated_at` (same instant) and seals `stale: false`;
* a FAILED poll (unreachable / 401 / timeout / malformed `/version`) seals
  `updated_at: null`, `stale: true` -- "unreachable but fresh" is impossible,
  and a stateless poll never invents an older success;
* `model.apply_freshness(enrichment, now, max_age)` marks a STORED sample
  stale after `max_age` seconds (default 30); an object without a usable
  `updated_at` is stale by definition. A future stateful wrapper keeps the
  last successful `updated_at` and recomputes `stale` -- it must never
  fabricate `updated_at` for a failed poll;
* client enrichment staleness and server Monitor staleness are completely
  separate: `Mihomo down` while the E1 stream is healthy means
  `enrichment.stale = true` alongside a healthy server snapshot -- and the
  reverse changes nothing server-side. A stale enrichment NEVER flips a
  Device to OFFLINE and never feeds the lifecycle/liveness logic.

## Security model

* **Loopback only, fail-closed**: `parse_controller_url` accepts
  `127.0.0.1` / `localhost` / `::1` (default port 9090) and refuses
  everything else before a single byte is sent -- including embedded
  credentials (`user:pass@`), non-root paths, query strings and fragments.
  Error messages never echo the full URL (a URL can carry credentials);
  only non-secret components (scheme / host / path / port) are named.
  The Mihomo API is a client-local service; `browser -> Internet -> Mihomo
  API` and `external-controller: 0.0.0.0:9090` are explicitly rejected
  designs. If a server ever needs this data, that is an explicit agent /
  outbound connection / secure tunnel design -- not a widened bind address.
* **Read-only transport by construction**: `HttpTransport.get(path)` is the
  only request surface -- no `method` parameter exists, so PUT/POST/PATCH/
  DELETE cannot be issued even by accident (guarded by static and runtime
  regression tests).
* **Secret handling**: resolved from the `MIHOMO_API_SECRET` environment
  variable or `--secret-file`; sent ONLY in the `Authorization: Bearer`
  header; never logged, never serialized into the output object, never
  placed in a URL query string; redacted from every stored error message
  (including secrets that show up inside transport exceptions or HTTP error
  bodies).
* **Secret-file permission contract**: on ALL platforms the file MUST be a
  regular file. On POSIX it must additionally be owner-readable with NO
  group/other permission bits -- `0600` / `0400` pass; `0000`, `0200`,
  `0644` / `0664` / `0666` are rejected BEFORE the content is read (so a
  rejected file's content can never reach an error message); symlinks are
  rejected (`O_NOFOLLOW` + fd/fstat, so the checked object is the read
  object). On Windows the POSIX permission-bit rejection is NOT applied --
  mode bits carry no access semantics on NTFS; E4 v1 relies on filesystem
  ACLs there (documented limitation). Any open/read failure becomes a
  redacted `SecretFileError` -- never a traceback, never secret content.
* **Per-request timeouts**: every INDIVIDUAL API request is bounded to 1-3
  seconds (default 2.0) and `collect()` never raises. A full poll runs
  several requests sequentially and may therefore take multiple request
  budgets -- the whole-poll deadline (and concurrency) is deliberately NOT
  invented here; that is a separate design once E4 is actually integrated
  into an agent. The `/traffic` sample reader is bounded by an absolute
  deadline and returns on the first complete newline-framed JSON line.
* **No public exposure**: nothing in this phase listens on any port.

## Files

```text
monitor-v2/mihomo/
├── client.py      # transport + fail-closed URL parse + read-only poller + CLI
├── diag.py        # E4-Diag: stateful read-only failover-forensics recorder (JSONL)
├── model.py       # whitelist-sealed output object, normalizers, freshness
└── fixtures/      # realistic endpoint payloads for the regression suite
```

## Usage

```bash
# one enrichment object (observation tool; always exits 0 -- even when the
# client API is unreachable -- so the exit code can never gate anything)
python3 monitor-v2/mihomo/client.py --url http://127.0.0.1:9090 \
    --group PROXY --pretty

# secret via env or 0600 file (env wins)
MIHOMO_API_SECRET=... python3 monitor-v2/mihomo/client.py ...
python3 monitor-v2/mihomo/client.py --secret-file /etc/mihomo/monitor.secret ...
```

Tests: `tests/test-monitor-v2-e4.sh` (fixture-driven, plus a real loopback
wire check). E1 regression: `tests/test-monitor-v2-e1.sh` must stay 232/232.

---

# E4-Diag -- failover forensics recorder (issue #41, OBSERVABILITY ONLY)

`diag.py` is a separate stateful CLI, deliberately NOT part of the enrichment
object: `model.ENRICHMENT_KEYS` is an E4 invariant and diagnostics write their
own closed JSONL records instead. It exists because at the last "Reality broke,
no switch happened" incident the client-side `/proxies` evidence needed to
separate the candidate explanations was never captured. It changes NOTHING
about selection or failover -- same read-only mandate as E4 (GET-only
transport by construction, no `PUT /proxies`, no `DELETE /connections`, no
`/delay` active probes; only `/version`, `/proxies` and `/connections` are
read), reusing E4's audited pieces verbatim (`parse_controller_url`,
`HttpTransport`, `clamp_timeout`, `resolve_secret`, the 0600 secret-file
contract).

## Record schema (closed -- EXACTLY FOUR record types, nothing else is ever written)

Schema version `v=1`; every record carries the envelope `{v, t, ts, run, seq}`:
`ts` is UTC Z-form (`YYYY-MM-DDTHH:MM:SSZ`), `run` is a fresh non-secret 32-hex
id per PROCESS (restarts and gaps are explicit evidence, never backfilled),
`seq` is a strictly increasing per-run counter. There is deliberately NO
run/header record type: a restart is visible as the `run` change plus the
always-emitted first `sample`.

| `t` | emitted | keys beyond the envelope | carries |
|---|---|---|---|
| `sample` | EVERY cycle, no matter what failed | `api_reachable, mihomo_version, proxies_status, connections_status, groups, nodes, connection_chains, truncated, invalid_fields` | the per-cycle evidence snapshot below |
| `selection_changed` | only on change | `group, from, to` | selection transitions with timestamps (H3: was it even automatic?) |
| `alive_flipped` | only on flip | `node, from, to` | health-check verdict flips (H1 vs H2) |
| `collector` | once per present failure code per cycle | `code, scope, count` | closed failure vocabulary; the bounded `scope` distinguishes endpoints; `count` = consecutive cycles |

A `sample` is emitted even when `/version` is unreachable -- with
`api_reachable: false`, `mihomo_version: null` and honest endpoint statuses
`"unavailable"` -- so an outage or a restart during an outage is visible
evidence, never a hole.

`collector.code` (closed enum) with its fixed `scope`: `mihomo_unreachable`
(version -- ANY `/version` failure: transport error, non-200 including 401,
malformed body, or a missing/unusable version field); `proxies_invalid`
(proxies); `connections_invalid` (connections); `group_missing` (proxies);
`node_missing` (proxies); `storage_error` (storage). Endpoint statuses on
`sample` are the closed set `ok | unavailable | invalid`.

Accounting (whole-cycle, dedup): the cycle's whole code set is computed FIRST;
each present code produces exactly ONE `collector` record with its count
incremented once -- the same code on several endpoints is never recorded
twice in one cycle. A code resets only after a FULL cycle in which it was
absent; a `/version` failure shortens the cycle (the other reads are skipped),
so it increments and never resets.

## What a `sample` proves

* `groups`: for each caller-named group ONLY -- `name, type, now, members`
  (plus `alive` only when the source value is a real boolean). Group names
  are never guessed or discovered; at least one `--group` is REQUIRED (a
  zero-group collector would record empty evidence forever -- refused).
* `nodes`: every observed member (union of named-group members and current
  selections), each `{name, type, alive, history, extra}`: `alive` is a
  strict bool or `null` ("unknown", never False); `history` entries are
  `{ts, delay_ms}` newest-last, tail of 8. **`delay == 0` is preserved RAW
  as integer 0** (a FAILED probe, the single most important missing datum,
  E4-H1); a delay must be a true bounded integer -- a float (even `1.0`),
  bool or string is dropped and counted, never coerced; a delay whose
  timestamp does not parse keeps the entry with `ts: null` (soft-invalid,
  counted). `extra` holds per-test-URL histories (H4) where the build
  exposes them: the RAW URL is never stored -- each is replaced by
  `test_id = HMAC-SHA256(local 256-bit key, raw_url)[:16 hex]`, stable
  across samples AND restarts while the URL (which may embed private query
  tokens) never crosses the persistence boundary.
* `connection_chains`: from `/connections` ONLY `chains` and `start` are ever
  read, immediately aggregated per observed node to
  `{node, active_chain_count, oldest_start, newest_start, invalid_start_count}`.
  `"connections": null` and `[]` are the official empty shapes -> confirmed
  zero; a missing key or wrong type -> `connections_status: "invalid"`
  (unknown, NEVER zero). Only well-formed connection objects count toward
  `active_chain_count`; a valid connection without a usable `start` raises
  that node's `invalid_start_count`. NO cross-group "stale" verdict is
  derived -- under nested topologies (outer Selector -> inner automatic
  group) it would overclaim; the analyst compares these raw facts against
  same-run `selection_changed` records. Connection ids, IPs, hosts, rules,
  metadata and traffic totals are structurally never written -- asserted by
  a whole-file leak wall in the test suite.
* `truncated` / `invalid_fields`: cardinality caps (8 groups, 32 stored
  members per group, 64 observed nodes, 8 history entries, 8 extra
  test-ids per node, names 1..128 UTF-8 bytes without C0/C1 controls) and
  the hard record ceiling -- one encoded line is at most 64 KiB INCLUDING
  the trailing newline; an oversized record is trimmed STRUCTURALLY (never
  byte-sliced) and flagged. Nothing arbitrary is persisted anywhere: no
  exception text, no HTTP body bytes, no raw URLs, no credentials, no
  paths -- the only error vocabulary is the closed (code, scope, count)
  triple.

## Causal boundary (diff events are run-local)

`selection_changed` / `alive_flipped` are emitted ONLY between two valid
`/proxies` observations inside the SAME process run with no invalid or
unavailable gap between them; the first valid sample seeds silently, and
after a gap the next valid sample re-seeds silently (an edge across a gap
would be a fabricated causal claim -- the change may have happened at any
time in between). A missing group/node, a group whose `now` is present but
unusable, or a node whose `alive` is unknown breaks that subject's chain. A
`/version` failure breaks the chain exactly like an unavailable `/proxies`
cycle. Consequence: one-shot `--once` invocations can never prove
transitions across invocations -- the resident loop is the mode that
produces edges.

## Cadence, persistence, process discipline

* interval clamped to 30-60s (default 30): >=2 samples inside a ~65s
  worst-case health-check detection window separates "never switched" from
  "not yet re-tested" (H5);
* `--out-dir` is REQUIRED and fail-closed: no symlink component anywhere on
  the path, real directory, 0700 (a permission-tightening failure is FATAL
  on POSIX; Windows relies on NTFS ACLs -- documented limitation, same as
  the secret file). One advisory `diag.lock` makes a second collector on
  the same directory refuse to start. `diag.key` (the HMAC key) is created
  once with `O_CREAT|O_EXCL` (a lost race re-reads the existing key through
  the same safe loader, never overwrites it), `O_NOFOLLOW` +
  fstat-verified regular, 0600 enforced fail-closed. `diag.jsonl` is opened
  `O_APPEND|O_NOFOLLOW`, fstat-verified regular, fchmod'ed 0600 (failure
  fatal on POSIX), appended with one write-until-complete loop per cycle
  batch, `fsync` per cycle; a pre-existing torn trailing line is
  frame-protected with a leading newline, never destroyed;
* size-shift rotation (`diag.jsonl` -> `.1` -> ... -> `.N-1`) above
  `--max-mb` (default 4) keeping `--files` (default 4, budget
  `max-mb * files <= 32 MiB`): file fsync before the rename, directory
  fsync after it; `--prune-now` rotates without sampling.

## Exit codes -- failures are visible, but never gate the proxy

`--once` (systemd-timer shape, default): `0` ok, `2` config (non-loopback
URL, missing/invalid `--group`, missing `--out-dir`, bad rotation args, bad
secret file), `3` any endpoint failed, `4` storage failed, `5` both.
`--resident`: API failures are RECORDS not exits (evidence must keep being
collected while the controller misbehaves); a storage failure exits `4`
immediately so the supervisor notices; SIGTERM exits `0`. Nothing here
restarts, gates or mutates Mihomo.

```bash
# example: two caller-named groups, one cycle per systemd timer tick
python3 monitor-v2/mihomo/diag.py --url http://127.0.0.1:9090 \
    --group 节点选择 --group 自动选择 \
    --out-dir /var/lib/mihomo-diag --once
```

Tests: `tests/test-monitor-v2-e4diag.sh` (343 assertions, fail-closed gate:
static mutation-free greps plus residue greps, the strict four-type proof,
delay-0 raw preservation, leak wall, B4 storage primitives via fault
injection, encode bounds, B6 ledger semantics, exit-code matrix). The E4
suite (161) and E1 (232) must stay green -- `diag.py` lives under `mihomo/`
and is covered by the same static greps.
