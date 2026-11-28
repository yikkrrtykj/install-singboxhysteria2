# UM-LT — Linux read-only traffic data source: architecture and trust boundaries

Status: **CANDIDATE design for the rev-7 contract package — docs/schema/fixtures
only, pending independent review/CI and the Owner's conditional merge
authorization. NOT published/frozen, NOT merged, NOT implemented.** No
production deployment, no `service.api` enablement, no new write-capable
credential holder and no paid/VPS/Cloudflare resource is authorized or used.
Normative protocol text: [`um-a/04-node-protocol-v1.rev7.md`](um-a/04-node-protocol-v1.rev7.md).
Data semantics: [`um-lt-data-semantics.md`](um-lt-data-semantics.md). Source
authorization audit: [`um-lt-source-authorization-audit.md`](um-lt-source-authorization-audit.md).

## 1. Purpose and scope

The frozen UM contract has no honest Linux per-inbound byte series: the only
per-inbound source is the write-capable sing-box `service.api` stream (P1-10
**FAIL**), so `collect.singbox_api` is DISABLED and Linux traffic is
`unavailable`. The existing non-root `monitor-v2` already observes connection
lifecycles through that stream and can emit a probe-observed **lower bound**.

UM-LT adds the smallest read-only path that can carry that lower bound to the
center without enabling `service.api` on the agent, without giving the agent a
write-capable credential, and without widening existing monitor permissions:

1. the already-running non-root monitor writes a restricted **aggregate JSON
   export** from its in-memory observation accumulator;
2. the unprivileged Linux Go agent reads the export locally, applies the
   center-configured inbound allow-list, and reports it as an observed lower
   bound inside a signed rev-7 snapshot;
3. the center validates, stores and queries it with explicit lower-bound,
   freshness and epoch semantics;
4. the browser (later phase) displays "observed at least X", never a total.

This is a Linux-only additive source. Windows, metrics, events, enrollment,
rotation, revocation, RBAC/session/TOTP/CSRF and rev-5/rev-6 behavior are out of
scope and unchanged.

## 2. Data path

```text
sing-box service.api (write-capable secret, loopback only)
        │  official SubscribeConnections stream (existing monitor behaviour)
        ▼
monitor-v2 collector (non-root sboxweb)
  in-memory observation accumulator + observation epoch (source_epoch)
        │  aggregate per inbound: observed lower-bound bytes, rates,
        │  active connections, observed_at, sequence; privacy-filtered
        ▼
atomic restricted file export  /var/lib/um-lt-export/traffic-export.json
  root:um-lt-export 2750 dir; sboxweb:um-lt-export 0640 file; temp+fsync+rename
        │  read-only, O_NOFOLLOW, bounded 64 KiB, fixed compiled path
        ▼
Linux um-agent (unprivileged umagent, no listening socket)
  validate export → tag/kind allow-list vs applied expected_inbound_tags
  → derive age/freshness/availability → rev-7 snapshot
  traffic_observation {source, source_epoch, sequence, observed_at, ...}
        │  unchanged rev-5 signed report transport (Ed25519 headers,
        │  nonce/seq/boot/fingerprint/dedupe/fsync/spool)
        ▼
um-center ingest (rev-7-capable build, source audit recorded)
  dispatch by contract_revision + node class + effective-dated config
  → schema + coherence + allow-list + privacy validation
  → one durable SQLite transaction (transport state + structured observation)
        │
        ▼
center storage: latest observation + bounded bucketed history, epoch identity
        │
        ▼
admin query layer (event-scoped, read-only): lower-bound label + freshness/
  availability/quality + age + source-epoch boundary; never a total
```

The center is still a management plane: it holds no VPS credentials, has no
command channel to nodes and is never in the data path of a competition
connection.

## 3. Components and new/unchanged boundaries

| Component | Change | Boundary |
| --- | --- | --- |
| `monitor-v2` collector/API bridge | **modified by the implementation PR only**: add a bounded aggregate export writer; read-only consumption unchanged | already holds the existing `service.api` secret internally; keeps it; exports no secret and no raw data |
| export directory/file | **new** | one restricted group `um-lt-export`; monitor writes, agent reads; no other principal |
| `um-agent` Linux | **modified by the implementation PR only**: read one fixed read-only path, build rev-7 observation, no new socket/credential | unprivileged `umagent`, no exec, no listener; never writes/deletes the export |
| `um-center` ingest | **modified by the implementation PR only**: rev-7 dispatch/validation/storage/query | existing authenticated report path; unchanged signing/replay/durability |
| Windows agent, rev-5 collectors, `/etc`/`/var/lib` sing-box or `sbox-cm` permissions | **unchanged** | no permission widening, no Windows change |

Trust boundaries added or extended:

| ID | Boundary | What crosses | Controls | Failure mode |
| --- | --- | --- | --- | --- |
| B7a | monitor process ↔ export directory | aggregate counters/timestamps only | monitor writes only there; complete-document atomic replace; no secret/raw fields | missing/stale file; agent reports unavailable/stale |
| B7b | export file ↔ agent process | the same aggregate document, read-only | owner/group/mode + `O_NOFOLLOW` regular-file checks, 64 KiB cap, strict schema/coherence, allow-list | reject document; sentinel unavailable; closed local counter |
| B7c | agent report ↔ center ingest | signed rev-7 body | unchanged rev-5 header/signature/replay/dedupe/durability rules + rev-7 schema/coherence/allow-list/class rules | 400/409/503 per frozen vocabulary; no partial state |
| B7d | center ↔ admin query | lower-bound projections only | existing event scoping/RBAC; explicit lower-bound/freshness labels | UNKNOWN/UNAVAILABLE rendered, never fake zero |

The monitor already sits behind boundary B7 in the rev-5 architecture (event VPS
local services ↔ agent). UM-LT does not move it, does not add a credential to the
agent, and does not change the `sbox-cm` mutation plane, which remains
inaccessible from the monitor/agent/center read path used here.

## 4. Monitor observation model (implementation-facing summary)

- The monitor subscribes to the official `daemon.StartedService/SubscribeConnections`
  stream with its existing loopback client. The first message of a subscription
  is a `reset` batch containing all currently active connections plus recently
  closed ones; later events are `NEW`/`UPDATE`/`CLOSED`.
- The monitor keeps an in-memory accumulator: active lifecycles with
  authoritative per-connection totals, finalized `CLOSED` lifecycles banked
  exactly once, and `ABANDONED` lifecycles (active IDs missing from a later
  reset) banked as a lower bound that is un-banked if the ID reappears. An
  independent LRU replay guard prevents double-banking of replayed IDs.
- For the export writer, per configured/observed inbound tag it aggregates
  across all devices: `banked finalized totals + current active lifecycle
  totals` per direction; active connection count; and rates derived from the
  stream's delta/elapsed updates. No per-device row leaves the monitor.
- The writer also emits monitor-side observability: `generated_at` (write time),
  `monitor_stale` (the monitor's own accumulator/stream-degradation flag) and
  `monitor_last_success_at` (last successful observation time in this epoch,
  nullable). These are export-only: the agent uses them to avoid claiming the
  observation is `ok` while the monitor knows it is degraded, and never forwards
  them in the report.
- The accumulator is created with the process; when it restarts, a new
  `source_epoch` is generated and the counters restart at zero. This is
  fundamentally different from the host-boot `counter_epoch`, and the contract
  keeps them independent.
- The export is not exact: lifecycles that are never observed (opened and closed
  entirely between stream events or outside the replay window), stream gaps and
  accounting limits make the value a **lower bound**. See
  [`um-lt-data-semantics.md`](um-lt-data-semantics.md) for the complete
  definition, including short/abandoned/replayed connections and the
  float→integer conversion rule.

## 5. Export file contract

The normative document shape, field constraints and coherence rules are in
[`um-a/04-node-protocol-v1.rev7.md`](um-a/04-node-protocol-v1.rev7.md) §4; this
section records the file/transport architecture.

The file is a monitor-owned document identified by
`schema: "singbox-monitor-traffic-export"`, `schema_version: 1`,
`source: "monitor-v2"`, `counter_scope: "observation_epoch"` and
`exactness: "lower_bound"`. It is **not** the report body: the agent re-validates
it, derives `age_seconds`/`freshness`/`availability`, maps
`observed_uplink_bytes`/`observed_downlink_bytes` to the report's
`uplink_observed_lower_bound_bytes`/`downlink_observed_lower_bound_bytes`, and
sets the report source token `traffic_observation.source =
"monitor_readonly_export"`. Export-only observability fields (`generated_at`,
`monitor_stale`, `monitor_last_success_at`) are never forwarded into the report.

### 5.1 File, group and ACL model

Reference names (the implementation PR fixes them and the installer asserts
them; they are never center-configurable):

| Path | Owner:group | Mode | Purpose |
| --- | --- | --- | --- |
| `/var/lib/um-lt-export/` | `root:um-lt-export` | `2750` | dedicated export directory (setgid; no world access) |
| `/var/lib/um-lt-export/traffic-export.json` | `sboxweb:um-lt-export` | `0640` | current complete export |
| `/var/lib/um-lt-export/.traffic-export.tmp.*` | `sboxweb:um-lt-export` | `0640` | monitor-owned temporary files only; removed by the monitor |

- System group `um-lt-export` has exactly two members: the monitor service user
  (e.g. `sboxweb`) and the agent service user (e.g. `umagent`). No login shells,
  no interactive users.
- The agent is **not** added to any monitor, sing-box or `sbox-cm` group; the
  monitor gets no new path outside its existing data root except this export
  directory (a `ReadWritePaths=`/equivalent unit addition for that directory
  only). No existing file mode/owner is changed.
- The agent opens with `O_RDONLY|O_NOFOLLOW`, requires a regular file, verifies
  size/owner/group/mode and that the resolved path is the fixed path, and reads
  at most 64 KiB. A symlink, FIFO, device, directory, wrong owner/mode or
  oversized file is rejected as unavailable.
- The agent has no write bit and no directory write permission; it cannot
  create, replace, delete or clean up export files. Stale/old files are the
  monitor's responsibility.

### 5.2 Atomic replacement and startup deletion of stale export

Writer order (required): build the whole document in memory → create-exclusive
temporary file in the same directory → write → `fsync` → set owner/group/mode →
`rename()` over `traffic-export.json` → `fsync` the directory. Readers see the
old complete document or the new complete document, never a partial one.

At monitor startup a new observation epoch begins: the monitor deletes the
previous `traffic-export.json` and any stale temporary files it owns **before**
its first new write. This prevents an agent from treating a previous monitor
lifetime's file as the current epoch after a monitor restart. If the monitor is
stopped, no file is refreshed: the agent ages the observation out to `stale`
and then to the no-observation sentinel — it does not invent zero traffic.

### 5.3 Bounded sizes

| Bound | Value |
| --- | --- |
| decoded export document | ≤64 KiB |
| file format | `schema` const + `schema_version` const 1 + `source` const + `counter_scope`/`exactness` consts |
| inbounds per export / per observation | ≤8 |
| inbound tag | frozen rev-5 grammar, ≤64 chars |
| byte counters | integer `0..9007199254740991` |
| rates / rate window | `0..10^12` bps / `(0, 3600]` s |
| active connections | `0..1000000` |
| sequence | integer `0..9007199254740991` |
| timestamps | `generated_at`/`observed_at` epoch seconds `0..10^12`, `observed_at ≤ generated_at`; observation age ≤86400 s |
| monitor observability | `monitor_stale` boolean; `monitor_last_success_at` integer `0..10^12` or `null` |

No unbounded array, string, nesting or free text exists in the format; unknown
fields are rejected, so the writer cannot grow the schema sideways.

## 6. Agent behavior

- The agent reads the export only when the applied, effective-dated center config
  has `collect.monitor_export = true`; default absent/false means it never opens
  the path and emits only rev-5 bodies (`traffic: []`,
  `availability.traffic: unavailable`).
- On each collection it reads one complete file, validates it against the
  agent-side copy of the export/observation rules, filters entries to the applied
  `expected_inbound_tags` tag+kind pairs, derives `age_seconds`/`freshness`/
  final `availability`, and builds the rev-7 snapshot. It uses no shell, no
  exec, no subprocess and no network access for the source.
- The report is spooled/signed by the unchanged rev-5 runtime; the signature
  covers the decoded body including the observation object. The agent does not
  rewrite or downgrade fsynced records.
- The agent does not persist the export and keeps only an in-memory
  `(source_epoch, sequence, observed_at)` cache. On restart it accepts the
  current file as a current observation (freshness rules still apply); on a
  config downgrade it stops creating rev-7 records and quarantines queued
  rev-7 records per [`um-lt-compatibility.md`](um-lt-compatibility.md).
- Closed local diagnostics counters (e.g. export_missing, export_invalid,
  export_stale, tag_dropped) carry no payload and are never sent as free text.

## 7. Center validate/store/query

### 7.1 Config emission gate

A rev-7-capable center includes `collect.monitor_export` only when: the build
supports rev-7; the node is `linux_vps`; the source authorization audit version
matches the implementation; the operator/rollout gate has enabled the source for
that node; and the node's last authenticated agent version is at least the rev-7
minimum. Otherwise the key is absent (= false). The key is a compatibility/source
switch, not a credential and not an authorization proof.

### 7.2 Ingest validation

The unchanged rev-5 transaction order still applies (headers/encoding/size →
identity/event/class → key state → freshness → signature → nonce → boot →
sequence → report dedupe → schema/platform/privacy → apply → durable commit →
ACK). Rev-7 adds, inside the schema/validation step:

- dispatch to the rev-7 schema only when the body has `contract_revision: 7`,
  the node class is `linux_vps`, and the effective-dated config at
  `collected_at` enabled `monitor_export`; otherwise reject (`invalid_request`,
  `platform_mismatch` for a class violation) before any data apply;
- schema validation plus the §8 implementation-enforced coherence rules
  (duplicate tags, allow-list tag+kind, freshness/availability/quality coupling,
  lexical integers, sentinel, base `traffic=[]`/`availability.traffic≠ok`);
- the accepted snapshot is stored in the same single `synchronous=FULL`
  transaction with transport high-water, report dedupe and the structured
  observation; no ACK before commit.

### 7.3 Storage (additive migration)

The implementation PR adds an append-only migration (current store schema is
version 13; the rev-7 migration must be additive and the old binary fails closed
on a newer database). Planned tables (names may change in the implementation PR;
the invariants are normative):

| Table | Purpose | Retention |
| --- | --- | --- |
| `traffic_observation_latest` | one current observation per node: source_epoch, sequence, observed_at, collected_at, age, freshness, availability, exactness, active_connections, rate window | current only; replaced only by a non-older observation / newer epoch, removed 30 d after last accepted report or node retire |
| `traffic_inbound_latest` | per node/inbound current lower-bound bytes, rates, active count, availability, quality, observed_at (≤8 rows/node) | current only, same removal rule |
| `traffic_observation_bucket` | 5-minute buckets per node/epoch/inbound: last/max observed lower bound in the bucket, max active, last rates, availability/quality flags, observed_at; source epoch identity (`epoch_seq`) | 30 d rolling / policy-B archive tail, same class rules as other telemetry |
| `traffic_epoch` | per node observation-epoch registry (`epoch_seq`, `source_epoch`, first/last observed_at, restart count) diagnostics only, never an authorization source | with node identity, bounded last 8 epochs |

The center MUST NOT retain the full rev-7 `traffic_observation` as a second raw
payload per report for 30 days: at the 150-node / 30 s worst case that alone
would exceed the frozen 5 GiB active planning basis. The received body SHA-256
remains the dedupe/conflict identity and the frozen base rev-5 projection may be
stored as before; the observation is extracted into the bounded structured rows.
Exact row sizes and the measured ratio belong to the implementation PR and UM-E.

### 7.4 Query semantics

- Latest: a node shows per-inbound "observed lower bound at least X bytes
  (quality lower_bound), observed at T, age A, freshness F, availability A";
  never "total traffic", "exact", "used", or a billing-style number.
- History: 5-minute buckets within the 30-day/archive policy; ordered series
  never difference across `source_epoch`/`epoch_seq`; a monitor restart shows an
  epoch boundary/reset marker; a stale or unavailable interval is rendered as
  such, never interpolated into zero.
- An aggregate across nodes/inbounds may be shown only as a lower-bound sum
  (still labelled lower bound); no per-minute sums, no cross-epoch deltas, no
  client/device rows.
- Event scoping/RBAC and the rev-5 two-layer scope rule are unchanged; Windows
  terminal and rev-5 dashboard queries are unchanged.

## 8. Default-disabled and authorization gates

| Gate | Default | Enable condition | Failure mode |
| --- | --- | --- | --- |
| `collect.monitor_export` | absent/false | rev-7 center + recorded source audit version + linux_vps node/rollout gate + rev-7-capable agent | no rev-7 data; rev-5 body with traffic unavailable |
| `collect.singbox_api` | false | **never for rev-7**: P1-10 FAIL stands; a future separate owner decision/audit only | stays disabled/unavailable; no credential path |
| center rev-7 ingest | off until deployed | rev-7-capable build and schema set; old center rejects rev-7 | old center: invalid_request; agent sends rev-5 only |
| export writer | off until monitor release | monitor version with the audited export writer + explicit deployment | no/missing export; agent unavailable |

The source is not enabled by an unauthenticated claim, environment variable,
center URL, local file, or a browser/session action. The switch is delivered
inside the authenticated/signed config pull; the export format is authorized by
a versioned audit and fixed build-time path.

## 9. No new listener, no new write-capable credential holder

- No component gains a listening socket, port, UNIX socket, named pipe or
  network service: the monitor keeps its existing loopback listeners, the agent
  keeps no listener, the center keeps its existing listeners.
- The agent never receives a `service.api` credential, monitor admin
  password/session, monitor state DB access, `sbox-cm` socket or root
  permission. The monitor's existing write-capable secret stays inside the
  monitor.
- The export is data, not a capability: possessing it gives no write path to
  sing-box, Mihomo, HA, `sbox-cm`, the monitor or the center.
- No new root process, setuid binary, sudoers rule, capability or writable path
  outside the dedicated export directory and the agent's own state.

## 10. Why not the rejected alternatives

| Alternative | Why rejected |
| --- | --- |
| Give the agent the `service.api` secret directly | the secret authorizes a write/control RPC surface; P1-10 FAIL; would create a new write-capable credential holder and expand agent permissions |
| Agent reads monitor's loopback snapshot/SSE (admin session) | admin password/session credential; raw source/destination addresses and connection IDs; not a machine contract; new credential holder |
| Reuse `state/snapshot.json` | only written in the compatibility collector-loop mode (would drop the production dashboard); raw per-connection/device data; not versioned/epoch/lower-bound aware |
| Read the monitor diagnostics DB | sboxweb/root-only internal 7-day schema; would require permission expansion; no epoch/lower-bound contract |
| Add a loopback HTTP stats endpoint/token to the monitor | adds a listener/socket and a new token-holding principal; the file path already provides a one-way read channel |
| Use `sbox-cm` | privileged mutation plane with no statistics; out of scope and forbidden |
| Journal reader | carries no byte counters; reuse forbidden by the UM-A review |
| Center polls nodes | no center→node channel exists and none is added; agent-only pull protected by the frozen transport |

## 11. Failure isolation and Windows non-impact

- Monitor stopped/crashed: agents report stale then unavailable; sing-box and all
  business services are unaffected; when the monitor restarts, a new
  `source_epoch` begins and the center shows a reset boundary (no negative
  deltas, no cross-epoch differencing).
- Export missing/invalid/stale/oversized/symlinked: the agent fails closed to the
  no-observation sentinel; no fake zero; the rest of the snapshot (rev-5 base
  data) is still reported honestly.
- Agent stopped/crashed: only its node's observation is stale; spool/replay
  semantics are unchanged.
- Center down/restart/storage failure: agents spool and replay under unchanged
  rev-5 rules; no ACK before durable commit; no partial observation state.
- Config downgrade/rollback: see [`um-lt-compatibility.md`](um-lt-compatibility.md).
- Windows: no Windows code path, schema, config key, permission or behavior
  changes. A `windows_terminal` node never sends a rev-7 body and never receives
  `monitor_export=true`; a violation is `platform_mismatch`. Windows terminal
  telemetry, R1/R2 source rules and HA-UI/P6/#67 behavior are untouched.
- No component makes client failover decisions; the center remains outside the
  competition data path.
