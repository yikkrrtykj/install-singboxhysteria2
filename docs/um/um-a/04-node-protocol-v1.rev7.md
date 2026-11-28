# UM-A 04 — Node protocol v1, revision 7 normative overlay (Linux read-only traffic observation)

Status: **CANDIDATE revision-7 ADDITIVE OVERLAY — docs/schema/fixtures only,
pending independent review, exact-head CI and the Owner's conditional merge
authorization. NOT published, NOT frozen, NOT merged.** This file is the
normative candidate overlay on revisions 5 and 6. It does not rewrite or delete
revision-5/6 history; those documents remain the base contract. Nothing in this
overlay authorizes production deployment, `singbox_api`, `service.api`, monitor
permission widening, or a new write-capable credential holder.

- Base contract: [`04-node-protocol-v1.md`](04-node-protocol-v1.md), revision 5,
  contract commit `048fc170685da5b7140bebd9e3347616cb3ec656`.
- Restart/power-loss overlay: [`04-node-protocol-v1.rev6.md`](04-node-protocol-v1.rev6.md),
  merged by PR #132 (`a5ee4d8b0d11f15595c14db03d1f6df47de34868`).
- Candidate base: `main` `3bf1fadf32f84aead0433b1534619cb9820d2e44` (UM-C
  closure); this branch is `docs/um-127-linux-traffic-rev7`.
- Read-only source investigation: [`../../../um/docs/um-b4-data-source-investigation.md`](../../../um/docs/um-b4-data-source-investigation.md)
  and the failed P1-10 audit [`../../../um/docs/um-b3-singbox-serviceapi-audit.md`](../../../um/docs/um-b3-singbox-serviceapi-audit.md).
- Owner boundaries carried by this revision: the 2026-11-27 limited decisions in
  [`../um-127/10-owner-decisions-rev6.md`](../um-127/10-owner-decisions-rev6.md)
  §3 must be read first. The Linux Reality/Hysteria2 real-traffic capability is
  the pre-production blocker on Issue #127; this overlay adds a **new, separate,
  audited local file source**, it does not unblock or enable `service.api`.
- Machine-readable normative artifacts:
  [`rev7/report-snapshot.rev7.schema.json`](../contracts/v1/rev7/report-snapshot.rev7.schema.json),
  [`rev7/agent-config.rev7.schema.json`](../contracts/v1/rev7/agent-config.rev7.schema.json),
  positive fixtures under [`../contracts/v1/examples/`](../contracts/v1/examples/),
  and [`rev7/negative-vectors.json`](../contracts/v1/rev7/negative-vectors.json).

## 0. Precedence and compatibility

1. For the subjects covered here, **this overlay controls** where revision-5 or
   revision-6 text is ambiguous or contradicted by the rules below.
2. Every revision-5/6 requirement not explicitly extended here remains in force
   unchanged. This overlay is **additive**: revision-5 bodies, headers, signing
   strings, endpoints, numeric bounds, dedupe/sequence/boot/rotation/revocation
   rules and node classes are untouched.
3. Revision-5/6 files, schemas, vectors, fixtures and historical review evidence
   are **not edited or deleted** by this revision. Revision-5 bodies remain valid
   and are the only form a new agent may emit when the center does not advertise
   `collect.monitor_export`.
4. There is no new endpoint, HTTP header, signing string, content-encoding rule,
   error code, retry rule or body `v` change. `v` stays `1`; the rev-7
   discriminator is the required body field `contract_revision: 7`.
5. The rev-7 source object is **required only in rev-7 bodies**; its absence
   means frozen rev-5 semantics (traffic unavailable, no observation).
6. An incompatible future change requires a new explicit design revision and
   independent review before implementation; this overlay only adds the
   read-only observation source.

## 1. Problem resolved

Revision 5 has no honest representation for the Linux traffic that the existing
non-root Monitor can actually observe. The only per-inbound byte source is the
sing-box `1.14 service.api` connection stream, whose single secret authorizes a
write/control RPC surface: P1-10 remains **FAIL**, `collect.singbox_api` remains
**DISABLED**, and the agent reports `traffic: []` /
`availability.traffic: unavailable`. The Monitor's in-memory accumulator can
produce a bounded probe-observed **lower bound**, but the frozen traffic schema
can only express total bytes, so a lower bound cannot be submitted without lying.

Revision-7 resolves this by adding a new source and representation:

- the existing non-root `monitor-v2` process writes a restricted, sanitized,
  atomically replaced local JSON export from its already-running observation
  accumulator (no new process, no new credential, no new listener);
- the Linux agent reads that file locally, applies the center-configured
  expected-tag allow-list, and reports it as an observed **lower bound** with an
  independent **source epoch**, freshness, availability and quality;
- the center validates, stores and queries it with explicit lower-bound
  semantics and never presents it as a total or exact byte count.

`service.api` is not involved, remains disabled, and its P1-10 audit remains FAIL.

## 2. Revision history

| Revision | Subject | State |
| --- | --- | --- |
| 5 | Base v1 contract (recovery, classes, Windows telemetry, numeric/storage rules) | PUBLISHED / FROZEN |
| 6 | Restart/power-loss generation semantics (additive overlay) | PUBLISHED / FROZEN (PR #132) |
| **7 (this file)** | **Linux read-only monitor-export traffic observation (additive overlay)** | **CANDIDATE — pending review/CI/owner merge; not published** |

## 3. Source model and authorization

- Source token in the report: `traffic_observation.source = "monitor_readonly_export"`.
  The token `monitor_export` is the **agent-config switch name**, not the
  observation source; see §5. The export file has its own identity
  (`source = "monitor-v2"`, `schema = "singbox-monitor-traffic-export"`); the
  file token and the report token are different identifiers by design.
- The observation is produced by the existing `monitor-v2` collector from the
  official `SubscribeConnections` stream it already consumes. The monitor's
  observation epoch begins when its in-memory accumulator is (re)created; all
  values are scoped to that epoch (`counter_scope = "observation_epoch"`).
- The export is a **file**, not a network interface: no new listening socket,
  port, loopback HTTP route, UNIX socket or IPC channel is added, on the monitor
  or on the agent.
- The monitor holds no new secret and exports no secret. It continues to hold
  its existing write-capable `service.api` credential internally; that credential
  is neither delivered to the agent nor referenced by the export.
- The agent has **read-only** access to the export path, cannot write, replace,
  rename or delete it, and never receives the path from the center (the path is
  fixed at build/package time).
- The source is authorized by the versioned audit
  [`../um-lt-source-authorization-audit.md`](../um-lt-source-authorization-audit.md).
  The switch is not the authorization: a center that has not recorded a matching
  audit version, or that is not rev-7 capable, must not advertise it.
- `collect.singbox_api` remains `false`/DISABLED in every rev-7 scope. Rev-7 does
  not accept, deliver or use the `service.api` secret, and P1-10 remains FAIL.

## 4. Monitor export transport (normative)

The export is a bounded, versioned JSON document written by the non-root monitor
user (`sboxweb` on the reference deployment) and read by the unprivileged agent
user (`umagent`). Exact names/paths are fixed by the implementation PR and must
match this section; they are never configurable by the center.

### 4.1 File and permissions (reference model, audited)

| Item | Requirement |
| --- | --- |
| Directory | `/var/lib/um-lt-export/`, root-owned, group `um-lt-export`, mode `2750` |
| File | `traffic-export.json`, owner `sboxweb`, group `um-lt-export`, mode `0640` |
| Group members | only the monitor service user (write side) and the agent service user (read side); no login shell, no other member |
| Parent traversal | no monitor data-root permission is widened; the export directory is separate from `/var/lib/singbox-monitor/` |
| Agent access | read-only; agent opens with `O_RDONLY|O_NOFOLLOW`, requires a regular file, checks owner/group/mode and size before parsing |
| Monitor access | create/replace/delete only inside this directory; existing monitor/sing-box/`sbox-cm` permissions unchanged |

The implementation PR must include the exact installer assertions (owner, group,
mode, no world access, no symlink, no extra group member) and negative tests for
symlinked directory/file, wrong owner/mode, FIFO, oversized file and concurrent
replacement.

### 4.2 Atomic replacement and startup cleanup

The monitor MUST, in this order: build the complete document in memory, write it
to a fresh temporary file in the same directory (create-exclusive), `fsync` the
file, set owner/mode, `rename()` over `traffic-export.json`, and `fsync` the
directory. A reader therefore sees either the previous complete document or the
new complete document, never a partial or mixed document. Temporary files that
are not the current export are monitor-owned garbage and are removed by the
monitor at startup and by bounded cleanup; the agent MUST NOT delete them.

At monitor startup (new observation epoch) the monitor removes the previous
`traffic-export.json` before the first new write, so a reader cannot mistake a
previous monitor lifetime's file for the current epoch. The agent must treat a
missing file, an unreadable file, or a file older than `EXPORT_MAX_AGE_SECONDS`
as "no current observation" and emit the no-observation sentinel (§7.6) — never
a zero.

### 4.3 Document shape (file format `singbox-monitor-traffic-export`, version 1)

The export document is closed (no unknown fields) and bounded (≤64 KiB). It
carries only aggregate, per-inbound, privacy-filtered values plus monitor-side
staleness observability:

```json
{
  "schema": "singbox-monitor-traffic-export",
  "schema_version": 1,
  "source": "monitor-v2",
  "source_epoch": "<32 lowercase hex>",
  "sequence": 8421,
  "generated_at": 1795622400,
  "observed_at": 1795622399,
  "monitor_stale": false,
  "monitor_last_success_at": 1795622399,
  "counter_scope": "observation_epoch",
  "exactness": "lower_bound",
  "active_connections": 4,
  "rate_window_seconds": 5,
  "inbounds": [
    {
      "inbound_tag": "vless-in",
      "kind": "reality",
      "observed_uplink_bytes": 1048576,
      "observed_downlink_bytes": 20971520,
      "uplink_observed_rate_bps": 125000.5,
      "downlink_observed_rate_bps": 480000.25,
      "active_connections": 2,
      "observed_at": 1795622399,
      "quality": "lower_bound"
    }
  ]
}
```

Rules:

- Required file fields: `schema`, `schema_version`, `source`, `source_epoch`,
  `sequence`, `generated_at`, `observed_at`, `monitor_stale`,
  `monitor_last_success_at`, `counter_scope`, `exactness`,
  `active_connections`, `rate_window_seconds`, `inbounds`. Unknown fields are
  forbidden; `null` is used for unknown values, never `0`.
- Constants: `schema = "singbox-monitor-traffic-export"`, `schema_version = 1`,
  `source = "monitor-v2"`, `counter_scope = "observation_epoch"`,
  `exactness = "lower_bound"`.
- `source_epoch` is generated by the monitor with a cryptographic or equivalent
  random source when the observation accumulator starts; it identifies one
  monitor observation epoch and does not change while that accumulator lives.
- `sequence` starts at `0` for a new epoch and strictly increases for each
  accepted export written inside that epoch; it is a local freshness/ordering
  token only and is not an authorization token.
- `generated_at` is the monitor write time (epoch seconds); `observed_at` is the
  accumulator sample time; both are integers `0..1000000000000` and
  `observed_at ≤ generated_at`. The agent uses `observed_at` (not `generated_at`)
  to compute the report's `age_seconds`.
- `monitor_stale` is the monitor's own boolean staleness flag (for example its
  connection stream is disconnected or it cannot refresh the accumulator) and
  `monitor_last_success_at` is the last successful observation time in this epoch
  or `null`. These are **export-only observability fields**: they are never
  copied into the report (the report schema is closed and unchanged); the agent
  uses `monitor_stale` to avoid claiming `availability = ok` and may use
  `monitor_last_success_at` for diagnostics only.
- Per-inbound byte fields are `observed_uplink_bytes` / `observed_downlink_bytes`,
  integer lower bounds `0..9007199254740991` or `null`; the agent maps them to
  the report fields `uplink_observed_lower_bound_bytes` /
  `downlink_observed_lower_bound_bytes` without arithmetic, rounding or
  relabelling. Rates/window, `active_connections`, `observed_at` and `quality`
  have the same bounds and closed enums as the report object; the file has no
  per-entry `availability` — the agent derives the report's per-entry
  `availability` from `quality` and `monitor_stale` (§5.4).
- `inbounds` contains at most `8` entries, one per observed inbound tag; duplicate
  tags are forbidden. The monitor MUST NOT write per-device rows, connection
  rows, source/destination addresses, IDs, names, URLs, paths, free text or any
  credential (privacy allow-list, §9).
- The monitor MUST NOT write a document it cannot write completely and validly:
  on any encode/write/fsync failure it leaves the previous complete file in place
  (or removes a stale one), never a partial file.

### 4.4 Bounded sizes and read limits

Decoded export ≤64 KiB; `inbounds` ≤8; tag ≤64 chars; every numeric field is
bounded as in §6. The agent rejects an export larger than 64 KiB, with junk after
the JSON document, with unknown fields, or with any schema/coherence violation,
and produces the no-observation sentinel plus a closed local diagnostic counter.
The agent never logs the raw export.

## 5. Report object semantics

### 5.1 Rev-7 discriminator and platform

- A rev-7 snapshot body is exactly the frozen rev-5 Linux snapshot shape plus
  required top-level `contract_revision: 7` plus required top-level
  `traffic_observation`; see
  [`rev7/report-snapshot.rev7.schema.json`](../contracts/v1/rev7/report-snapshot.rev7.schema.json).
- Only a `linux_vps` node may send a rev-7 body. A `windows_terminal` node
  sending one is `400 platform_mismatch`; Windows stays on revision-5 bodies.
- A rev-7 body is expected only when the applied config contained
  `collect.monitor_export=true`, which the center emits only under the
  agent-version gate in §11.1 (minimum `agent.version` `1.1.0`).
- `terminal` remains forbidden for `linux_vps`; rev-7 does not change platform
  isolation or event isolation.

### 5.2 Base snapshot fields

| Field | Rev-7 rule |
| --- | --- |
| `v`, `type`, `report_id`, `collected_at`, `agent`, `host` | unchanged rev-5 |
| `availability.system/services/protocols/clients` | unchanged rev-5 coherence |
| `counter_epoch` | unchanged host-boot epoch; **never** used to difference monitor counters |
| `traffic` | MUST be `[]` (a lower-bound observation is not a total-byte series) |
| `availability.traffic` | MUST NOT be `ok`; it is `partial` when the observation's availability is `ok`/`partial`, and `unavailable` when the observation's availability is `unavailable`. The implementation relaxes only the rev-5 "partial requires a non-empty traffic array" coherence **for rev-7 Linux bodies**, and this exception is proved by negative vector `NEG7-SNAP-24` |
| `clients` | unchanged rev-5; unavailable/null/empty is honest |

### 5.3 `traffic_observation` fields

| Field | Type / constraint | Semantics |
| --- | --- | --- |
| `source` | const `monitor_readonly_export` | the only rev-7 report source; `monitor_export` is the config switch and the file source is `monitor-v2` |
| `source_epoch` | 32 lowercase hex | independent monitor observation epoch; changes on monitor accumulator restart; never equal to or derived from `counter_epoch` |
| `sequence` | integer `0..9007199254740991` | strictly increasing inside one `source_epoch`; ordering/freshness token only, not authorization |
| `observed_at` | integer `0..1000000000000` | epoch seconds of the monitor observation |
| `age_seconds` | integer `0..86400` | agent-computed `max(0, collected_at - observed_at)`; `observed_at` more than 60 s in the future relative to `collected_at` is rejected as untrusted clock data; see §7.3 |
| `freshness` | `fresh\|stale\|unavailable` | derived, see §7.3 |
| `availability` | `ok\|partial\|unavailable` | final agent view of the whole observation, see §7.4 |
| `counter_scope` | const `observation_epoch` | counters are scoped to the monitor observation epoch, not the daemon lifetime and not host boot |
| `exactness` | const `lower_bound` | the bytes are a lower bound; never an exact total |
| `active_connections` | integer `0..1000000` or `null` | monitor-observed active connection count at `observed_at`; `null` unknown |
| `rate_window_seconds` | number `>0` and `≤3600`, or `null` | window the monitor used for the observed rates; `null` means rates are `null` |
| `inbounds` | array `0..8`, unique tags | per-inbound observations, see §5.4 |

`traffic_observation` and all nested objects are closed; no unknown field, no
free text, no signature field, no additional counter.

### 5.4 Per-inbound entries

Required fields per entry: `inbound_tag`, `kind`, `observed_at`, `availability`,
`quality`, `uplink_observed_lower_bound_bytes`,
`downlink_observed_lower_bound_bytes`, `uplink_observed_rate_bps`,
`downlink_observed_rate_bps`, `active_connections`.

- `inbound_tag` uses the frozen rev-5 grammar (same as `expected_inbound_tags`,
  max 64). `kind` is `reality|hysteria2|other`.
- The agent maps the export's `observed_uplink_bytes` /
  `observed_downlink_bytes` to the report's
  `uplink_observed_lower_bound_bytes`/`downlink_observed_lower_bound_bytes`
  unchanged (integer to integer, no arithmetic). The report's `availability` is
  derived from the export's `quality` and `monitor_stale`:
  `quality=lower_bound` → `availability=ok` unless `monitor_stale=true` (then
  `partial`); `quality=partial` → `partial`; `quality=unavailable` → `unavailable`.
- `availability` is `ok|partial|unavailable`; `quality` is
  `lower_bound|partial|unavailable`.
- Byte fields are integer lower bounds `0..9007199254740991` or `null`; rates are
  numbers `0..10^12` bps or `null`; `active_connections` is an integer
  `0..1000000` or `null`.
- An entry is valid data for the agent only when its tag **and** kind exactly
  match one of the center-configured `expected_inbound_tags` for that node; the
  agent drops non-matching entries and never forwards them. The center
  independently rejects a body containing an unauthorized tag or kind
  (`invalid_request`) as defense in depth.
- Duplicate tags are forbidden even though JSON Schema cannot express
  uniqueness; the agent/center reject them.

## 6. Numeric bounds and encoding

1. Byte counters use the JSON integer form only: a lexical token containing
   `.`, `e` or `E` (for example `1048576.0`) MUST be rejected by the receiving
   implementation even though JSON Schema classifies it as an integer. The
   monitor converts its floating in-memory accumulator to integer bytes by
   **truncation toward zero** (never rounding up), after rejecting negative,
   NaN/Inf or out-of-bound values; a value above the bound is capped at
   `9007199254740991` (still a valid lower bound) or marked unavailable, never
   wrapped.
2. `MAX_SAFE_BYTES = 9007199254740991` (2^53−1) for rev-7 byte counters. This is
   stricter than the rev-5 `MAX_NUMERIC` so every JSON consumer, including the
   dashboard front-end, sees the exact value. Rev-5 fields keep their rev-5
   bounds.
3. `sequence` is an integer `0..9007199254740991`; `observed_at`,
   `collected_at`, per-inbound `observed_at` are integers
   `0..1000000000000`; `age_seconds` is an integer `0..86400`;
   `rate_window_seconds` is a number `(0, 3600]`; rates are numbers
   `0..1000000000000`; connection counts are integers `0..1000000`.
4. A rate value has meaning only with a non-null `rate_window_seconds`; rates
   must be `null` when the window is `null`.
5. No negative, fractional, NaN/Inf, string-encoded, hex-encoded,
   exponent-overflow or wrapped numeric value is accepted for a byte counter; the
   center stores rev-7 counters as SQLite `INTEGER` in the bounded range.

## 7. Epoch, ordering, freshness and availability

### 7.1 Independent source epoch

`source_epoch` is independent of `counter_epoch`, of the agent boot generation,
and of any rev-5 counter. On monitor restart / accumulator reinitialisation the
monitor MUST choose a new random `source_epoch`, restart `sequence` at `0`, and
restart observed bytes at zero for that epoch (bytes before the restart are not
reconstructed). The agent treats any `source_epoch` change as a hard reset: it
MUST NOT subtract counters, treat a decrease as negative traffic, or carry the
previous epoch's values forward. The center stores the epoch identity with the
observation and marks epoch boundaries; historical queries MUST NOT difference
values across different `source_epoch` values.

### 7.2 Agent-side export acceptance

The agent reads the export on its normal collection cadence only when the
applied center config enables `collect.monitor_export` (absent/false = disabled).
For one report it uses exactly one complete export document. It rejects the
document (no-observation sentinel + closed local counter) when: the file is
missing/unreadable/not a regular file/not owned by the expected monitor
user/group/mode; it is larger than 64 KiB or has trailing data; JSON is invalid;
`schema`/`schema_version`/`source` or a required constant is wrong; required
fields are missing or unknown fields are present; `observed_at > generated_at`;
`generated_at`/`observed_at` are more than 60 s in the future relative to
`collected_at`; `monitor_stale` is not a boolean or
`monitor_last_success_at` is neither `null` nor an in-range integer; the
tag/kind allow-list or duplicate-tag rule fails; numeric lexical/range rules
fail; the age relation/coherence rules below fail. The agent never logs the
document contents and never swaps in a
cached document older than `EXPORT_MAX_AGE_SECONDS`.

### 7.3 Freshness and age

- `age_seconds = max(0, collected_at - observed_at)` (integer, `0..86400`).
- An observation with `observed_at > collected_at + 60 s` is rejected as
  untrusted clock data (no-observation sentinel), not clamped into a fresh
  observation. A small non-negative skew (at most 60 s) yields age `0`; the
  agent never fabricates a negative age or a future timestamp.
- `freshness` is derived by the agent from `age_seconds` and the applied
  `cadence_seconds`:
  - `fresh` iff `age_seconds ≤ max(2 × cadence_seconds, 120)` (range
    120..600 s for the frozen 30..300 s cadence);
  - `stale` iff a complete, coherent observation exists but age is above the
    fresh bound and `≤ 86400`;
  - `unavailable` iff there is no usable current observation (missing,
    unreadable, invalid, expired beyond 86400 s, or explicitly unavailable).
- `availability = ok` requires `freshness = fresh` and `monitor_stale = false`;
  a `stale` observation can be at most `partial`. `freshness = unavailable`
  requires `availability = unavailable`.
- `monitor_stale`/`monitor_last_success_at` are monitor-side observability only:
  they are never copied into the report, and `monitor_stale` never changes
  `age_seconds`/`freshness` (those are derived from the clock); it caps
  availability at `partial` so a monitor that knows it is degraded cannot be
  displayed as `ok`.

### 7.4 Availability and quality coherence

- Top-level `availability`:
  - `unavailable` iff the no-observation sentinel applies;
  - `ok` iff a usable, fresh observation exists, `monitor_stale = false`, every
    configured expected tag is present with per-entry `availability = ok`, and
    all coherence rules hold;
  - `partial` otherwise for a usable observation (stale, monitor-stale, a
    missing expected tag, or any per-entry availability not `ok`).
- Per-entry `quality` (copied from the export's `quality`; the report's
  per-entry `availability` is derived from it and `monitor_stale`):
  - `lower_bound`: both integer lower-bound counters present; entry availability
    `ok` unless `monitor_stale = true` (then `partial`);
  - `partial`: some values are `null`; entry availability `partial`;
  - `unavailable`: both byte counters `null`; entry availability `unavailable`.
- When top-level availability is `ok`, `active_connections` equals the sum of the
  per-entry non-null `active_connections` (all entries must be present for
  `ok`); when it is `partial`, values may be `null`/incomplete and no fabricated
  zero is inserted.
- `observed_at` of an entry MUST be within the report window
  `[collected_at − 86400, collected_at + 60]` and within 60 s of the top-level
  `observed_at`.
- Base `traffic` stays `[]` and `availability.traffic` follows §5.2 in every
  case.

### 7.5 No fabricated data

Missing, unreadable, disabled, unauthorized or expired data is never converted
to `0`, `up`, `ok` or a stale-but-plausible number. A numeric zero is legal only
as an observed zero inside a coherent, available observation (for example an
idle inbound with `active_connections = 0` and observed byte counters that are
genuinely zero). The no-observation sentinel below is the only representation
of "nothing observed".

### 7.6 No-observation sentinel (normative)

When a rev-7 body must be emitted and there is no usable observation, the agent
emits exactly:

```json
{
  "source": "monitor_readonly_export",
  "source_epoch": "00000000000000000000000000000000",
  "sequence": 0,
  "observed_at": 0,
  "age_seconds": 86400,
  "freshness": "unavailable",
  "availability": "unavailable",
  "counter_scope": "observation_epoch",
  "exactness": "lower_bound",
  "active_connections": null,
  "rate_window_seconds": null,
  "inbounds": []
}
```

This sentinel is the only legal use of the all-zero `source_epoch`; it is never
stored as measured data and is never rendered as a value. Mixed sentinel/non-
sentinel values (`sequence ≠ 0`, `observed_at ≠ 0`, non-empty `inbounds`, any
non-null counter) are rejected.

## 8. Implementation-enforced rules not expressible in JSON Schema

The following are normative and MUST be executed by the implementation
(agent and center), not merely documented:

1. duplicate `inbound_tag` in `traffic_observation.inbounds` is rejected;
2. tag+kind must belong to the applied `expected_inbound_tags`;
3. `freshness = fresh` iff the age relation holds; `availability = ok` requires
   `freshness = fresh` and a complete expected-tag set; stale/monitor-partial
   observations are at most `partial`;
4. `quality`/byte/rate/active-count coherence as in §7.4;
5. `rate_window_seconds = null` iff rates are `null` in each available entry;
6. base `traffic = []` and `availability.traffic ≠ ok` for rev-7 Linux bodies
   (with the narrow rev-5 coherence exception in §5.2);
7. lexical integer enforcement for byte/sequence/time fields (§6.1);
8. the no-observation sentinel is exact (§7.6);
9. rev-7 bodies are accepted only from `linux_vps` nodes whose effective-dated
   config at `collected_at` enabled `collect.monitor_export`, and only by a
   rev-7-capable center that has seen the §11.1 agent-version gate satisfied;
   otherwise `platform_mismatch`/`invalid_request` with no state change;
10. the center extracts and stores only bounded structured observation fields
    (never a second raw copy of the observation per report) and never presents a
    lower bound as a total;
11. `singbox_api` cannot be enabled, borrowed or inferred by/from this source;
    the `service.api` secret is never read, delivered or accepted by the agent.

## 9. Source authorization and privacy (summary)

The versioned audit [`../um-lt-source-authorization-audit.md`](../um-lt-source-authorization-audit.md)
is part of this overlay. In summary: the monitor already holds the write-capable
`service.api` secret and keeps it; the export carries only the privacy
allow-list below; the agent cannot read the secret or raw monitor data and
cannot write/delete the export; the center cannot send a path, URL or command;
there is no new listener and no new write-credential holder; `singbox_api` stays
DISABLED and P1-10 stays FAIL. The implementation PR must record the audit
version and prove the tests before any environment enables the source.

Privacy allow-list for export and report (normative): per-inbound aggregate
tags from the configured set, kinds, observed lower-bound byte counters,
observed rates and window, active connection counts, observation timestamps,
`source_epoch`/`sequence`, freshness/availability/quality tokens, and the frozen
rev-5 base fields. The export-only observability fields `generated_at`,
`monitor_stale` and `monitor_last_success_at` stay in the monitor file and are
never forwarded into the report. Forbidden everywhere: source/destination IPs or
hostnames,
raw connection IDs, API user/device names, `node_id`/`event_id`/`key_id` or any
UUID, proxy/outbound names, SNI, URLs, YAML, journal/log text, filesystem paths,
commands, free text, error messages, credentials/secrets/tokens/private keys,
passwords and per-client byte rows. The monitor's raw in-memory snapshot already
contains device names and source/destination addresses; the export writer MUST
aggregate per inbound and MUST NOT serialize those fields. All synthetic
fixtures contain synthetic values only.

## 10. Agent behavior and runtime impact

- The agent reads the export only when the applied config has
  `collect.monitor_export = true`; default is disabled. It performs bounded
  regular-file reads of the fixed path, with no shell, no exec, no network
  listener, no subprocess and no center-controlled path.
- The rev-7 body is built from the accepted export plus the frozen base
  snapshot fields; signing, headers, nonce, sequence, boot generation,
  fingerprint and spool behavior are unchanged (the signature still covers the
  decoded body bytes, which now include `traffic_observation`).
- A new agent talking to a rev-5 center (no `monitor_export` in the applied
  config) emits only rev-5 bodies: no `contract_revision`, no
  `traffic_observation`, `traffic: []`, `availability.traffic: unavailable`.
- The agent does not persist the export, does not rewrite fsynced spool records,
  and keeps at most an in-memory `(source_epoch, sequence, observed_at)` cache.
- On a config downgrade that removes `monitor_export`, the agent stops creating
  rev-7 records immediately; queued rev-7 records follow the compatibility and
  rollback-drain rules in [`../um-lt-compatibility.md`](../um-lt-compatibility.md).
- Rev-5 files, permissions and service behavior are unchanged; the agent gains
  exactly one read-only path.

## 11. Center behavior

- Config: a rev-7-capable center MAY include `collect.monitor_export` (boolean)
  only for a `linux_vps` node that is enabled under the center rollout gate, has
  the matching source-authorization audit version recorded, and has a latest
  signed snapshot reporting `agent.version >= MIN_REV7_AGENT_VERSION` (§11.1).
  It MUST NOT include it for `windows_terminal`, for an unknown/older agent, or
  while the source audit version does not match. While the version gate is not
  satisfied the key MUST be **absent entirely** (not emitted as `false`). Absent
  means false. The stored source-enable flag becomes effective at the next config
  pull after the gate is satisfied; no manual re-enable or extra handshake is
  required, and no path/URL/token field is added.
- Ingest: the center dispatches by `contract_revision`/node capability. A rev-7
  body from a node without an effective-dated config enabling the source is
  rejected (`invalid_request`); a rev-7 body from a `windows_terminal` node is
  `platform_mismatch`; schema + §8 semantics are enforced before storage; an
  accepted rev-7 snapshot follows the unchanged transaction order, dedupe,
  boot/sequence/nonce/signature/fsync rules.
- Storage/query: extract bounded structured latest and bucketed history rows;
  retain source epoch identity; label values as observed lower bounds with
  freshness/availability/quality and age; never store a second raw copy of the
  observation per report (capacity requirement in
  [`../um-lt-capacity.md`](../um-lt-capacity.md)); never difference across
  `source_epoch`; never present a lower bound as a total. Existing Windows,
  metrics, events and rev-5 snapshot behavior is unchanged.
- Failure: monitor missing/stale/invalid, disabled switch, wrong class,
  audit-version mismatch, or center not rev-7 capable all yield honest
  `unavailable`/`partial` states with no fake zero and no security-gate
  weakening.

### 11.1 Rev-7 agent-version gate (normative, rule `CFG-REV7`)

- `MIN_REV7_AGENT_VERSION = "1.1.0"`: the rev-7 Linux agent build (implementation
  PR) advertises `agent.version >= 1.1.0` in its signed snapshot; the current
  rev-5 agent is `1.0.0`. The frozen `agent.version` grammar and snapshot field
  are unchanged; this is only a new minimum for rev-7 eligibility.
- Comparison: compare the numeric `major.minor.patch` components of the latest
  `agent.version` received in a successfully authenticated snapshot. A node is
  rev-7-eligible iff `major > 1` or (`major == 1` and `minor >= 1`). Suffixes
  (pre-release/build metadata) do not make an otherwise older build eligible.
  The comparator is a testable implementation rule, not a security boundary.
- The center MUST track the latest signed-snapshot `agent.version` per node and
  MUST **omit the `collect.monitor_export` key entirely** (not emit `false`)
  while that version is unknown, missing or `< 1.1.0`, even if the
  operator/stored source-enable flag is set.
- Once a signed snapshot reports `>= 1.1.0`, the stored source-enable flag
  becomes effective at the **next config pull**: the center then includes
  `monitor_export=true` in the node's config. No manual re-enable action and no
  extra capability handshake, URL, token or banner is introduced.
- If a later signed snapshot reports an older version (for example an agent
  binary rollback), the center MUST omit the key again on the next pull.
- A version report grants no privilege: the versioned source audit, the
  operator/rollout gate, the `linux_vps` class and the applied config switch
  still apply. An old agent cannot gain anything by misreporting a version — it
  would receive a config its strict validator rejects fail-closed.
- Testable cases (encoded in [`rev7/negative-vectors.json`](../contracts/v1/rev7/negative-vectors.json)
  `NEG7-CFG-04..07` and required in the implementation PR): `CFG-REV7-01`
  unknown version ⇒ key absent; `CFG-REV7-02` reported `< 1.1.0` ⇒ key absent
  even with the stored flag set; `CFG-REV7-03` reported `>= 1.1.0` ⇒ the next
  config pull includes `monitor_export=true`; `CFG-REV7-04` later reported older
  version ⇒ key absent again on the next pull. `CFG-REV7-05`: the key is never
  emitted for `windows_terminal` or an unknown class (covered by
  `NEG7-CFG-01` and the class rules).

## 12. Compatibility and failure modes

The full matrix is in [`../um-lt-compatibility.md`](../um-lt-compatibility.md).
Key rules: rev-5 centers reject rev-7 bodies, so new agents emit rev-7 only under
a rev-7-capable center config (`collect.monitor_export` present/true); rev-5
agents reject a seventh `collect` key (fail closed, previous config kept), so a
new center must not send the key to a non-rev-7 agent; the center withholds the
key until the `CFG-REV7` agent-version gate is satisfied by the latest signed
snapshot (§11.1), and makes a stored enable flag effective on the next config
pull after that; queued rev-7 reports on
downgrade are quarantined/dropped by the agent without rewriting fsynced
`report_id`/body, and rev-5 spool records are preserved and drained first.

Closed failure → representation mapping (no new wire error codes):

| Condition | Representation |
| --- | --- |
| export missing/unreadable/invalid | sentinel `availability=unavailable`, `freshness=unavailable` |
| export older than fresh bound | `freshness=stale`, `availability=partial` (never `ok`) |
| export older than 86400 s | sentinel unavailable |
| monitor partial/incomplete | `availability=partial` |
| monitor `monitor_stale=true` | `availability=partial` at most (freshness still derived from age) |
| expected tag missing | `availability=partial`, no invented entry |
| tag/kind not configured | agent drops entry; center rejects a body containing it (`invalid_request`) |
| monitor restart/new epoch | new `source_epoch`, series reset, no cross-epoch differencing |
| `monitor_export` disabled | rev-5 body with `traffic: []`, `availability.traffic=unavailable` |
| node class violation | `400 platform_mismatch` |

## 13. Conformance artifacts (candidate)

- [`rev7/report-snapshot.rev7.schema.json`](../contracts/v1/rev7/report-snapshot.rev7.schema.json),
  [`rev7/agent-config.rev7.schema.json`](../contracts/v1/rev7/agent-config.rev7.schema.json):
  closed draft 2020-12 schemas that keep the frozen rev-5 base shape exactly and
  add only the rev-7 fields.
- [`rev7/examples/report-snapshot.json`](../contracts/v1/rev7/examples/report-snapshot.json),
  [`rev7/examples/agent-config.json`](../contracts/v1/rev7/examples/agent-config.json):
  synthetic positive fixtures.
- [`rev7/negative-vectors.json`](../contracts/v1/rev7/negative-vectors.json):
  37 machine-readable negative/gating vectors (schema, implementation-semantic
  and platform/config stages) covering exact/lower-bound ambiguity, float/
  negative/over-bound bytes, bad epoch/sequence, stale-with-ok-availability,
  unknown tag, wrong kind, duplicate tag, rate-without-window, unknown fields,
  Windows class, `contract_revision: 6`, bad freshness/quality tokens, and the
  four `CFG-REV7` agent-version gate cases (unknown/`<1.1.0` ⇒ key absent;
  `>=1.1.0` ⇒ included on the next pull; later older version ⇒ absent again).

This contract PR proves only that the schemas/fixtures/vectors are internally
consistent and JSON-valid; **no runner exists yet and no conformance claim is
made**. The implementation PR must add a real runner (schema + semantic cases)
and UM-E/lab must prove the source, privacy and semantics against a real
monitor/agent/center. JSON parsing alone is not conformance.

## 14. No weakening of the frozen contract

Revision-7 does not change or weaken: Ed25519 transport-header signing and the
15-line signing string; boot generation/boot id and `MAX_BOOT_GAP`; sequence
rules/high-water/ACK `next_seq`; nonce uniqueness and request fingerprint;
`report_id` dedupe/report-conflict; rotation state machine and proof; revocation;
`fsync`/durability/transaction ordering; spool bounds and replay; node
classes/platform isolation; event isolation/RBAC; Windows terminal telemetry and
its R1/R2 source rules; privacy/allow-list enforcement; TOTP/session/CSRF/Access
web security; `singbox_api` DISABLED / P1-10 FAIL; no new write-capable
credential holder; no public listener; no center→agent command channel. The only
new capability is reading an authorized local aggregate file to report an
observed lower bound.

## 15. Approval and provenance (candidate)

- This file is a **candidate**; it is not normative until independently
  reviewed, exact-head CI is green, the Owner's conditional merge authorization
  is used, and the normal Merge Commit lands on `main`. Being PR-mergeable is not
  publication; only merged `main` makes it **REV-7 PUBLISHED / FROZEN**.
- Owner boundaries: contract PR only; no merge by the contract author; no
  production resources; no Cloudflare/DNS/certificates/VPS/SSH/paid resources;
  `PRODUCTION HOLD`, R1 production HOLD, `singbox_api` DISABLED, UM-F DEFERRED
  all remain in force.
- Decision requests and assumptions are recorded in
  [`../um-lt-owner-decisions.md`](../um-lt-owner-decisions.md).
