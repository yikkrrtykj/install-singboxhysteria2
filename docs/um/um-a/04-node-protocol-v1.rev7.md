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
  [`rev7/traffic-export.schema.json`](../contracts/v1/rev7/traffic-export.schema.json),
  positive fixtures under
  [`rev7/examples/`](../contracts/v1/rev7/examples/) and
  [`rev7/negative-vectors.json`](../contracts/v1/rev7/negative-vectors.json).
- Contract-side conformance tests (test-only, not implementation):
  [`um/internal/schema/rev7_schema_test.go`](../../../um/internal/schema/rev7_schema_test.go)
  compiles the overlay and validates the positive fixtures;
  [`um/internal/schema/rev7_negative_vectors_test.go`](../../../um/internal/schema/rev7_negative_vectors_test.go)
  executes the `json_schema` stage vectors (including raw-body lexical vectors).
  Reviewed HEAD `1aa71abe` Unified Monitor Go CI run `46156909313` completed with
  all five jobs success; this contract-PR revision is a subsequent review-fix
  commit whose exact-head CI is recorded in the PR after the commit (the
  contract does not claim a green run for an uncommitted tree).

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

The export is written by the non-root monitor service user (packaged:
`sboxweb`, referenced as `<monitor-user>`) and read by the unprivileged agent
service user (`<agent-user>`; reference `umagent`). The operator creates the
directory and the reader group; the installer and the monitor never create or
own the directory (an absent directory simply means no export path). There is
**no ACL** beyond POSIX owner/group/other bits.

| Item | Requirement |
| --- | --- |
| Directory | `/run/singbox-monitor-export/`, owner `<monitor-user>`, group `sboxmon-export`, mode `2750` (setgid; group r-x, no world access) |
| File | `traffic.json`, owner `<monitor-user>`, group `sboxmon-export`, mode `0640` |
| Group members | only the non-root agent service user (`<agent-user>`); never root, never interactive/login users, no other member |
| Parent | `/run` is root-controlled tmpfs, so an unrelated local user cannot create entries before the operator; after a host reboot the operator recreates the directory (systemd-tmpfiles/install script) and `/run` being empty is an unavailable source, never a stale trusted file |
| Agent access | read-only; opens with `O_RDONLY|O_NOFOLLOW`, requires a regular file, checks owner/group/mode and size before parsing; cannot create/write/replace/delete anything |
| Monitor access | writes as the directory owner; its systemd unit adds exactly `ReadWritePaths=-/run/singbox-monitor-export` (optional path, so a default install without the directory is untouched); no other writable path changes |
| Existing permissions | no sing-box/Monitor/`sbox-cm`/data-root permission is widened or changed, and no root process is added |

Monitors run under `ProtectSystem=strict`; the optional `/run` write path is
the only new exception. The implementation PR must include the exact installer/
operator assertions (owner, group, mode, no world access, no symlink, no extra
group member, no ACL) and negative tests for symlinked directory/file, wrong
owner/mode, FIFO, oversized file and concurrent replacement.

### 4.2 Atomic replacement and startup cleanup

`EXPORT_MAX_AGE_SECONDS = 86400`: the agent treats an export whose
`observed_at` is older than this bound (measured consistently from
`observed_at`, with `generated_at` required to be `>= observed_at`) as unusable
rather than merely stale.

The monitor MUST, in this order: build the complete document in memory, write it
to a fresh temporary file in the same directory (create-exclusive), `fsync` the
file, set owner/mode, `rename()` over `traffic.json`, and `fsync` the directory.
A reader therefore sees either the previous complete document or the new
complete document, never a partial or mixed document. Temporary files that are
not the current export are monitor-owned garbage and are removed by the monitor
at startup and by bounded cleanup; the agent MUST NOT delete them.

At monitor startup (new observation epoch) the monitor removes the previous
`traffic.json` before the first new write, so a reader cannot mistake a previous
monitor lifetime's file for the current epoch. The agent must treat a missing
file, an unreadable file, or a file older than `EXPORT_MAX_AGE_SECONDS` as "no
current observation" and emit the no-observation/unavailable representation
(§7.6) — never a zero.

### 4.3 Document shape (file format `singbox-monitor-traffic-export`, version 1)

The export document is schema-pinned in
[`rev7/traffic-export.schema.json`](../contracts/v1/rev7/traffic-export.schema.json);
a positive fixture is
[`rev7/examples/traffic-export.json`](../contracts/v1/rev7/examples/traffic-export.json).
It is closed (no unknown fields), has exactly 14 top-level and 9 per-entry
members, and is bounded (≤64 KiB). It carries only aggregate, per-inbound,
privacy-filtered values plus monitor-side staleness observability:

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

Per-entry required members (exactly these 9, all required, closed):

| Member | Meaning |
| --- | --- |
| `inbound_tag` | frozen rev-5 tag grammar; MUST be one of the operator-configured allow-list tags |
| `kind` | `reality\|hysteria2\|other`, taken **only** from the operator allow-list pair `TAG:KIND`; never inferred from sing-box `inbound_type`, protocol names or any other heuristic |
| `observed_uplink_bytes` / `observed_downlink_bytes` | exact safe-integer lower-bound bytes `0..9007199254740991` or `null` (null means unavailable, never zero) |
| `uplink_observed_rate_bps` / `downlink_observed_rate_bps` | observed rate estimate `0..10^12` bps or `null` |
| `active_connections` | non-negative integer `0..1000000` for that configured tag |
| `observed_at` | integer epoch seconds, `<= generated_at` |
| `quality` | `lower_bound\|partial\|unavailable`, coherent with the counters/rates as below |

Rules:

- Required file fields: `schema`, `schema_version`, `source`, `source_epoch`,
  `sequence`, `generated_at`, `observed_at`, `monitor_stale`,
  `monitor_last_success_at`, `counter_scope`, `exactness`,
  `active_connections`, `rate_window_seconds`, `inbounds`. Unknown fields are
  forbidden; `null` is used for unknown values, never `0`.
- Constants: `schema = "singbox-monitor-traffic-export"`, `schema_version = 1`,
  `source = "monitor-v2"`, `counter_scope = "observation_epoch"`,
  `exactness = "lower_bound"`.
- The only inbounds that may appear in the file are the operator-configured
  `TAG:KIND` pairs (the monitor's `--traffic-export-inbound` allow-list); the
  writer never derives a tag or kind from the daemon's raw `inbound_type`, and
  an inbound not in the allow-list is never serialized. This is why the file's
  `kind` is an operator attestation, not an observed classification.
- `source_epoch` is generated by the monitor with a cryptographic or equivalent
  random source when the observation accumulator starts; it identifies one
  monitor observation epoch and does not change while that accumulator lives.
- `sequence` starts at `0` for a new epoch and strictly increases for each
  accepted export written inside that epoch; it is a local freshness/ordering
  token only and is not an authorization token.
- `generated_at` is the monitor write time (epoch seconds); `observed_at` is the
  accumulator sample time; both are integers `0..1000000000000` and
  `observed_at <= generated_at`. The agent uses `observed_at` — consistently,
  not `generated_at` — to compute the report's `age_seconds`.
- `monitor_stale` is the monitor's own boolean staleness flag (for example its
  connection stream is disconnected or it cannot refresh the accumulator). When
  true, every published row must be `quality=partial` with null rates, and
  configured tags with no observation are omitted. `monitor_last_success_at`
  is the last successful observation time in this epoch (required non-null
  whenever `monitor_stale=false`). These are **export-only observability
  fields**: they are never copied into the report (the report schema is closed
  and unchanged); the agent uses them to derive freshness/availability and may
  use `monitor_last_success_at` for diagnostics only.
- Counter/rate/quality coherence that is expressible in JSON Schema is enforced
  by the export schema (`lower_bound` requires both integer byte counters;
  `unavailable` requires null counters and rates; `partial` requires at least
  one observed counter or rate; stale rows may only be `partial`; a non-null
  rate requires a positive window; a non-stale document requires a non-null
  last-success timestamp). The remaining relations (`observed_at <=
  generated_at` value comparison, unique tags, total active count covering the
  per-row sum, ≤64 KiB, no trailing bytes, lexical integers) are
  implementation-enforced and covered by vectors.
- `inbounds` contains at most `8` entries, one per observed inbound tag; duplicate
  tags are forbidden. The monitor MUST NOT write per-device rows, connection
  rows, source/destination addresses, IDs, names, URLs, paths, free text or any
  credential (privacy allow-list, §9).
- The monitor MUST NOT write a document it cannot write completely and validly:
  on any encode/write/fsync failure it leaves the previous complete file in place
  (or removes a stale one), never a partial file.

### 4.4 Bounded sizes and read limits

Decoded export ≤64 KiB; `inbounds` ≤8; tag ≤64 chars; every numeric field is
bounded as in §6. The export schema
([`rev7/traffic-export.schema.json`](../contracts/v1/rev7/traffic-export.schema.json))
enforces the closed shape and the schema-expressible coherence; the agent rejects
an export larger than 64 KiB, with junk after the JSON document, with unknown
fields, or with any schema/coherence violation, and produces the
no-observation/unavailable representation plus a closed local diagnostic counter.
The agent never logs the raw export. The contract-side schema-stage tests live in
`um/internal/schema/rev7_schema_test.go` and
`um/internal/schema/rev7_negative_vectors_test.go`; the implementation parser
tests remain the implementation PR's evidence.

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
| `availability.traffic` | MUST NOT be `ok`; it is `partial` when the observation's availability is `ok`/`partial`, and `unavailable` when the observation's availability is `unavailable`. The implementation relaxes only the rev-5 "partial requires a non-empty traffic array" coherence **for rev-7 Linux bodies**; this exception is recorded as OD-LT-09 and its forbidden direction is proved by negative vector `NEG7-SNAP-24` |
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
| `rate_window_seconds` | number `>0` and `≤3600`, or `null` | window behind the observed rates; a non-null rate requires a non-null window, but a non-null window may have null rates when a row is partial/unavailable |
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
  unchanged (integer to integer, no arithmetic). The report's per-entry
  `availability` is coherent with the export's `quality`:
  `lower_bound` → `ok`, `partial` → `partial`, `unavailable` → `unavailable`.
  The producer already restricts stale rows to `partial`, so the agent does not
  invent a status: a `monitor_stale=true` document with a `lower_bound` row is
  rejected as invalid rather than relabelled (export schema rule).
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

1. Integer counters use the JSON integer lexical form only: a token containing
   `.`, `e` or `E` (for example `1048576.0`) MUST be rejected by the receiving
   implementation even though JSON Schema classifies such a number as an
   integer. The monitor keeps counters as exact integers internally (never as
   floats); a counter outside `0..9007199254740991` is published as `null` with
   `quality=partial`, never rounded, clamped or wrapped. The agent copies the
   integer unchanged into the report; the legacy float-formatted dashboard
   snapshot stays an independent presentation path.
   The lexical-integer fields are exactly: report `traffic_observation.sequence`,
   `observed_at`, `age_seconds`, each entry `observed_at`, each entry's two byte
   counters and `active_connections`, plus top-level `active_connections`; and
   export `sequence`, `generated_at`, `observed_at`, `monitor_last_success_at`,
   each entry `observed_at`, each entry's two byte counters and
   `active_connections`, plus top-level `active_connections`. Rates and
   `rate_window_seconds` are numbers (fractional allowed); all other timestamps
   are integers.
2. `MAX_SAFE_BYTES = 9007199254740991` (2^53−1) for rev-7 byte counters. This is
   stricter than the rev-5 `MAX_NUMERIC` so every JSON consumer, including the
   dashboard front-end, sees the exact value. Rev-5 fields keep their rev-5
   bounds.
3. `sequence` is an integer `0..9007199254740991`; `observed_at`,
   `collected_at`, `generated_at`, per-inbound `observed_at` are integers
   `0..1000000000000`; `age_seconds` is an integer `0..86400`;
   `rate_window_seconds` is a number `(0, 3600]`; rates are numbers
   `0..1000000000000`; connection counts are integers `0..1000000`.
4. A rate value has meaning only with a non-null `rate_window_seconds`: a
   non-null observed rate requires a positive window. The converse is not true —
   a present window may still have null rates when the row is
   partial/unavailable — so "window null ⇔ rates null" is deliberately **not**
   the rule.
5. No negative, fractional, NaN/Inf, string-encoded, hex-encoded,
   exponent-overflow or wrapped numeric value is accepted for a byte counter; the
   center stores rev-7 counters as SQLite `INTEGER` in the bounded range.

## 7. Epoch, ordering, freshness and availability

### 7.1 Independent source epoch

`source_epoch` is independent of `counter_epoch`, of the agent boot generation,
and of any rev-5 counter. On monitor restart / accumulator reinitialisation the
monitor MUST choose a new random `source_epoch`, restart `sequence` at `0`, and
restart its in-memory counters at zero for that epoch. The agent treats any
`source_epoch` change as a hard reset: it MUST NOT subtract counters, treat a
decrease as negative traffic, or carry the previous epoch's values forward. The
center stores the epoch identity with the observation and marks epoch
boundaries; historical queries MUST NOT difference values across different
`source_epoch` values.

**Epoch-boundary caveat (normative).** "Counters restart at zero" describes the
monitor accumulator, not the meaning of the first published value. The first
subscription `reset` batch can contain currently active lifecycles (and recently
closed lifecycles replayed by the server) whose **authoritative lifecycle totals
include bytes transferred before the observation epoch began**. Those totals are
legitimately counted from the epoch's first publication onward. Therefore the
number is an observed lower bound on the totals of the lifecycles the monitor has
observed — it is **never a pure epoch delta** ("bytes during this epoch only")
and **never a daemon-lifetime exact total**. Consumers must not label it as
either; a monitor restart is an epoch reset (new `source_epoch`), not a claim
that the old bytes were lost from the daemon.

### 7.2 Agent-side export acceptance

The agent reads the export on its normal collection cadence only when the
applied center config enables `collect.monitor_export` (absent/false = disabled).
For one report it uses exactly one complete export document. It rejects the
document (no-observation/unavailable representation + closed local counter) when:
the file is missing/unreadable/not a regular file/not owned by the expected
monitor user/group/mode; it is larger than 64 KiB or has trailing data; JSON is
invalid; `schema`/`schema_version`/`source` or a required constant is wrong;
required fields are missing or unknown fields are present; `observed_at >
generated_at`; `generated_at`/`observed_at` are more than 60 s in the future
relative to `collected_at`; `monitor_stale` is not a boolean;
`monitor_last_success_at` violates the non-null-when-not-stale rule or is not an
in-range integer; the tag/kind allow-list or duplicate-tag rule fails; numeric
lexical/range rules fail; the age relation/coherence rules below fail. The agent
never logs the document contents and never swaps in a cached document older than
`EXPORT_MAX_AGE_SECONDS = 86400`.

### 7.3 Freshness and age

- `age_seconds = clamp(collected_at - observed_at, 0, 86400)` (integer). Age is
  measured **from `observed_at`** consistently; `generated_at` is only used for
  the document's internal `observed_at <= generated_at` coherence and the
  60-second future bound, never as the age origin.
- An observation with `observed_at > collected_at + 60 s` is rejected as
  untrusted clock data (no-observation/unavailable), not clamped into a fresh
  observation; implementations MAY use a tighter future tolerance. A small
  non-negative skew (at most 60 s) yields age `0`; the agent never fabricates a
  negative age or a future timestamp.
- `freshness` is derived by the agent from `age_seconds`, the monitor's
  `monitor_stale` flag, and the **effective-dated `cadence_seconds` of the node
  config effective at `collected_at`** (not the current/mutable config row):
  - `fresh` iff `monitor_stale = false` and
    `age_seconds ≤ max(2 × cadence_seconds, 120)` (range 120..600 s for the
    frozen 30..300 s cadence);
  - `stale` iff a usable observation exists but either `monitor_stale = true`
    or the age is above the fresh bound, and the age is `≤ 86400`
    (`EXPORT_MAX_AGE_SECONDS`);
  - `unavailable` iff there is no usable current observation (missing,
    unreadable, invalid, expired beyond `EXPORT_MAX_AGE_SECONDS`, or a
    structurally valid export with no observed values — see §7.4).
- `availability = ok` requires `freshness = fresh` and `monitor_stale = false`;
  a `stale` observation can be at most `partial`. `freshness = unavailable`
  requires `availability = unavailable`.
- `monitor_stale`/`monitor_last_success_at` are monitor-side observability only:
  they are never copied into the report. `monitor_stale=true` means the monitor
  itself refuses to vouch for freshness, so it can never produce `fresh` and caps
  availability at `partial`; the agent still derives `age_seconds` from its own
  clock rather than trusting the flag as a timestamp.

### 7.4 Availability and quality coherence

- Top-level `availability`:
  - `unavailable` iff the no-observation sentinel applies, **or** a structurally
    valid export contains no observed values (empty `inbounds`, or every row
    `quality=unavailable`). The latter is the **status-only real-epoch form**:
    it keeps the real `source_epoch`, `sequence`, `observed_at` and derived
    `freshness`, carries no byte/rate/active values, and is never a zero claim;
  - `ok` iff a usable, fresh observation exists, `monitor_stale = false`, every
    configured expected tag is present with per-entry `availability = ok`, and
    all coherence rules hold;
  - `partial` otherwise for a usable observation with at least one observed row
    (stale, monitor-stale, a missing expected tag, or any per-entry availability
    not `ok`).
- Per-entry `availability` is coherent with the export's `quality`:
  `lower_bound → ok`, `partial → partial`, `unavailable → unavailable`. The agent
  does not relabel a producer status; a `monitor_stale=true` document with a
  `lower_bound` row is rejected as invalid by the export schema/parser.
- Per-entry byte/rate/quality coherence:
  - `lower_bound`: both integer lower-bound counters present;
  - `partial`: every field may be null, but at least one counter or rate is
    observed;
  - `unavailable`: both byte counters and both rates are `null`.
- The total `active_connections`, when present, MUST NOT be less than the sum of
  the reported per-entry non-null counts; when top-level availability is
  `unavailable` it MUST be `null`. It is `null` when unknown.
- `observed_at` of an entry MUST be within the report window
  `[collected_at − 86400, collected_at + 60]` and within 60 s of the top-level
  `observed_at`.
- Base `traffic` stays `[]` and `availability.traffic` follows §5.2 in every
  case; for the status-only real-epoch form, `availability.traffic` is
  `unavailable`.

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

**Status-only real-epoch form (normative).** A structurally valid, readable
export that contains no observed values (empty `inbounds`, or every row
`quality=unavailable`) is reported as `availability=unavailable` /
`freshness=unavailable` but keeps its **real** `source_epoch`, `sequence`,
`observed_at` and clamped `age_seconds`; `active_connections`,
`rate_window_seconds` and all counters/rates are null, and `inbounds` is empty or
contains only `unavailable` rows with null values. This form is not the zero-epoch
sentinel: it tells the center the source is reachable and current but has nothing
observed, and it MUST supersede a previous latest status as unavailable (see
§11). Neither form may be stored as measured bytes or keyed into observation
epoch/bucket series.

## 8. Implementation-enforced rules not expressible in JSON Schema

The following are normative and MUST be executed by the implementation
(agent and center), not merely documented:

1. duplicate `inbound_tag` in `traffic_observation.inbounds` is rejected;
2. tag+kind must belong to the applied `expected_inbound_tags`;
3. `freshness = fresh` iff the age relation holds; `availability = ok` requires
   `freshness = fresh` and a complete expected-tag set; stale/monitor-partial
   observations are at most `partial`;
4. `quality`/byte/rate/active-count coherence as in §7.4;
5. a non-null observed rate requires a non-null positive `rate_window_seconds`
   (the converse is not required; a null window MUST NOT be paired with a
   non-null rate);
6. base `traffic = []` and `availability.traffic ≠ ok` for rev-7 Linux bodies
   (with the narrow rev-5 coherence exception in §5.2, OD-LT-09);
7. lexical integer enforcement for byte/sequence/time fields (§6.1);
8. the no-observation sentinel is exact and the status-only real-epoch form is
   distinct from it (§7.6);
9. rev-7 bodies are accepted only from `linux_vps` nodes whose effective-dated
   config at `collected_at` enabled `collect.monitor_export`, and only by a
   rev-7-capable center that has seen the §11.1 agent-version gate satisfied;
   otherwise `platform_mismatch`/`invalid_request` with no state change;
10. the center extracts and stores only bounded structured observation fields
    (never a second raw copy of the observation per report) and never presents a
    lower bound as a total; sentinel/status-only reports are stored as
    status/metadata only and never key epoch or bucket series (§11);
11. `singbox_api` cannot be enabled, borrowed or inferred by/from this source;
    the `service.api` secret is never read, delivered or accepted by the agent;
12. the consumer must require the export's `monitor_last_success_at` non-null
    whenever `monitor_stale=false`, and must treat `monitor_stale=true` as "not
    fresh" at best (§7.3, export schema).

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
- Monitor compatibility: the export writer lives in the production web-mode
  runtime (`webapp.py serve` → collector → broker). The legacy compatibility
  collector-loop mode (which writes `state/snapshot.json`) does not publish the
  UM-LT export; if that mode is active, the agent sees a missing/expired file and
  reports honest unavailable — no fallback to the legacy snapshot, no fabricated
  data, and no change to that mode's behavior. The export is enabled only by the
  monitor's explicit operator flags; flags absent = feature dark (no writer
  thread, no file I/O).
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
- Storage/query (normative for the center): extract bounded structured latest and
  bucketed history rows; retain source epoch identity; label values as observed
  lower bounds with freshness/availability/quality and age; never store a second
  raw copy of the observation per report (capacity requirement in
  [`../um-lt-capacity.md`](../um-lt-capacity.md)); never difference across
  `source_epoch`; never present a lower bound as a total. Existing Windows,
  metrics, events and rev-5 snapshot behavior is unchanged.
- Sentinel / status-only storage and query rules (normative):
  1. an accepted zero-epoch no-observation sentinel stores **report-level header
     and status metadata only**: `report_id`, `event_id`, `node_id`,
     `collected_at`/`received_at`, `freshness=unavailable`,
     `availability=unavailable`, `counter_scope`, `exactness` and the all-zero
     epoch marker as an unavailable status. It MUST NOT store bytes, rates,
     active counts, per-inbound value rows, bucket rows or epoch-series rows, and
     the all-zero epoch MUST NEVER be inserted into the observation-epoch
     registry or any history/bucket key.
  2. an accepted **status-only real-epoch form** (valid export with no observed
     values, §7.6) likewise stores status/header metadata only, including its real
     `source_epoch`/`sequence`/`observed_at` for diagnostics, and creates no
     bytes/rates/active value rows, no bucket rows and no epoch series rows.
  3. both forms MUST supersede the previous latest observation status as
     `unavailable`; a query must never keep rendering the previous lower-bound
     value as current after a newer sentinel/status-only report has been accepted.
  4. bucket/epoch-series rows are created only for observations that contain at
     least one observed inbound value row; the zero epoch is never a row key and
     an epoch change never rewrites earlier buckets.
  5. query surfaces for unavailable/status-only rows render UNKNOWN/UNAVAILABLE
     with the observation timestamp/freshness, never zero and never a synthetic
     series point.
  Expected implementation tests (implementation PR): sentinel status-only storage
  and previous-latest invalidation, zero-epoch-never-keyed, all-unavailable valid
  export becomes status-only, no bucket/epoch row for unavailable status, and
  query renders unknown — for example
  `TestTrafficObservationStateExposesUnavailableSentinel`,
  `TestTrafficQueryLatestUsesObservedAt`,
  `TestTrafficQueryHistoryGapEpochAndTruncation` in the reference implementation,
  plus equivalent new sentinel/status-only storage cases.
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
  version ⇒ key absent again on the next pull. `CFG-REV7-05` is the
  class/unknown-class case (`windows_terminal` or an unknown class never receives
  the key), mapped to vector `NEG7-CFG-01` and the class rules; the vector's
  `expected.rule` field carries `CFG-REV7-05`. The contract-side schema test
  asserts that all five rule ids have exactly one vector mapping.

## 12. Compatibility and failure modes

The full matrix is in [`../um-lt-compatibility.md`](../um-lt-compatibility.md).
Key rules: rev-5 centers reject rev-7 bodies, so new agents emit rev-7 only under
a rev-7-capable center config (`collect.monitor_export` present/true); the center
withholds the key until the `CFG-REV7` agent-version gate is satisfied by the
latest signed snapshot (§11.1), and makes a stored enable flag effective on the
next config pull after that. A rev-5 agent does not tolerate a seventh `collect`
key: its frozen strict config validator rejects the config fail-closed and it
retries the config request immediately without exponential backoff while
continuing its existing (rev-5) collection; it does not queue new snapshots
under a rejected config. The center-side gate is therefore mandatory, not
defensive: a new center MUST NOT emit the key to an agent that has never reported
the rev-7 build. Queued rev-7 reports on downgrade are quarantined/dropped by the
agent without rewriting fsynced `report_id`/body, and rev-5 spool records are
preserved and drained first.

Closed failure → representation mapping (no new wire error codes):

| Condition | Representation |
| --- | --- |
| export missing/unreadable/invalid | zero-epoch sentinel: `availability=unavailable`, `freshness=unavailable` |
| export older than fresh bound but ≤86400 s | `freshness=stale`, `availability=partial` (never `ok`) |
| export older than `EXPORT_MAX_AGE_SECONDS` (86400 s) | zero-epoch sentinel unavailable (not reused as stale) |
| monitor partial/incomplete | `availability=partial` |
| monitor `monitor_stale=true` | `freshness=stale` at best, `availability=partial` at most; rows are `partial`, rates null |
| valid export with no observed values (empty/all-unavailable rows) | status-only real-epoch form: `availability=unavailable`, real epoch/sequence/observed_at kept, no values |
| expected tag missing | `availability=partial`, no invented entry |
| tag/kind not configured | agent drops entry; center rejects a body containing it (`invalid_request`) |
| monitor restart/new epoch | new `source_epoch`, series reset, no cross-epoch differencing |
| `monitor_export` disabled / monitor in legacy collector-loop mode | rev-5 body with `traffic: []`, `availability.traffic=unavailable` |
| node class violation | `400 platform_mismatch` |

## 13. Conformance artifacts (candidate)

- [`rev7/report-snapshot.rev7.schema.json`](../contracts/v1/rev7/report-snapshot.rev7.schema.json),
  [`rev7/agent-config.rev7.schema.json`](../contracts/v1/rev7/agent-config.rev7.schema.json),
  [`rev7/traffic-export.schema.json`](../contracts/v1/rev7/traffic-export.schema.json):
  closed draft 2020-12 schemas; the report/config schemas keep the frozen rev-5
  base shape exactly and add only the rev-7 fields; the export schema pins the
  monitor file's 14 top-level / 9 per-entry closed members and its
  schema-expressible stale/quality/rate coherence.
- [`rev7/examples/report-snapshot.json`](../contracts/v1/rev7/examples/report-snapshot.json),
  [`rev7/examples/agent-config.json`](../contracts/v1/rev7/examples/agent-config.json),
  [`rev7/examples/traffic-export.json`](../contracts/v1/rev7/examples/traffic-export.json):
  synthetic positive fixtures.
- [`rev7/negative-vectors.json`](../contracts/v1/rev7/negative-vectors.json):
  55 machine-readable negative/gating vectors (schema, implementation-semantic,
  platform and config-generation stages), including the report/config vectors,
  the export-file unknown/missing/bounds/float/coherence vectors, the two
  raw-body lexical vectors, duplicate-tag/active-sum/trailing-size semantic
  cases, and the five `CFG-REV7` gate cases (`CFG-REV7-01..05`).
- Contract-side conformance tests (test-only):
  [`um/internal/schema/rev7_schema_test.go`](../../../um/internal/schema/rev7_schema_test.go)
  compiles the overlay and validates all three positive fixtures;
  [`um/internal/schema/rev7_negative_vectors_test.go`](../../../um/internal/schema/rev7_negative_vectors_test.go)
  executes every `json_schema`-stage vector (31 executed), pins the structural
  stage split, unique ids and the `CFG-REV7` rule mapping, and asserts that the
  two committed raw-body lexical vectors are schema-accepted (proving the
  schema/implementation split while the implementation must feed those exact
  committed bytes and reject them even though JSON Schema sees an integral
  number). Exact command: `cd um && go test ./internal/schema -run 'TestRev7' -v`.
  Exact-head Unified Monitor Go CI run `46156909313` (HEAD `1aa71abe`) completed
  all five jobs success; the review-fix commit's exact-head CI is recorded in the
  PR after the commit and is not claimed here. Quality-owned workflows are not
  claimed green by this contract PR.

The contract-side tests prove the overlay schemas compile, the positive fixtures
are valid and the schema-stage negative vectors are rejected by the real schema
engine; they do **not** execute the implementation-semantic/platform/config
cases or any real monitor/agent/center behavior. The implementation PR must run
the full vector set (`schema` + semantic stages) and UM-E/lab must prove the
source, privacy and semantics against a real monitor/agent/center. JSON parsing
alone is not conformance.

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

Documented exception (not a weakening): on downgrade/rollback the agent MAY move
a queued rev-7 spool record into its existing bounded quarantine. That is a
storage-location move only — `report_id`, `collected_at`, type, body bytes and
the persisted attempt/fingerprint are preserved byte-identically, the record is
never rewritten or re-signed, and rev-5 spool records remain unaffected
(OD-LT-14, [`../um-lt-compatibility.md`](../um-lt-compatibility.md) §5).

## 15. Approval and provenance (candidate)

- This file is a **candidate**; it is not normative until independently
  reviewed, exact-head CI is green, the Owner's conditional merge authorization
  is used, and the normal Merge Commit lands on `main`. Being PR-mergeable is not
  publication; only merged `main` makes it **REV-7 PUBLISHED / FROZEN**.
- PR #135 is the contract PR for this candidate. Reviewed HEAD `1aa71abe`
  passed the Unified Monitor Go workflow (run `46156909313`: native
  ubuntu/windows, linux-race, coverage, govulncheck all success) with the
  contract-side schema tests in place; the review-fix commit that carries this
  text gets its own exact-head checks recorded in the PR. No quality-owned
  workflow and no implementation/lab gate is claimed green here.
- Contract-side test-only files added by this package:
  `um/internal/schema/rev7_schema_test.go` (overlay compile + positive fixtures)
  and `um/internal/schema/rev7_negative_vectors_test.go` (schema-stage execution
  + structural/stage assertions + raw-body lexical cases). No Go production code
  is added or changed by the contract PR.
- Owner boundaries: contract PR only; no merge by the contract author; no
  production resources; no Cloudflare/DNS/certificates/VPS/SSH/paid resources;
  `PRODUCTION HOLD`, R1 production HOLD, `singbox_api` DISABLED, UM-F DEFERRED
  all remain in force.
- Decision requests and assumptions are recorded in
  [`../um-lt-owner-decisions.md`](../um-lt-owner-decisions.md).
