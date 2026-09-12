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
  never touches its state; the E1 regression suite (188/188) must stay green.

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
wire check). E1 regression: `tests/test-monitor-v2-e1.sh` must stay 188/188.
