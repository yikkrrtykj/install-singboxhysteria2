# UM-LT — Traffic data semantics (observed observation-epoch lower bounds)

Status: **CANDIDATE normative semantics for the rev-7 contract package —
docs-only, pending independent review/CI and the Owner's conditional merge
authorization. NOT published/frozen, NOT merged, NOT implemented.**
Normative protocol text: [`um-a/04-node-protocol-v1.rev7.md`](um-a/04-node-protocol-v1.rev7.md).
Architecture: [`um-lt-architecture.md`](um-lt-architecture.md).

This document defines exactly what the rev-7 numbers mean, what they do not
mean, and the edge cases the implementation must get right. A lower bound that
is presented as a total is a contract violation; an unknown that is presented
as zero is also a contract violation.

## 1. Definitions

| Term | Definition |
| --- | --- |
| **Observation epoch** | The lifetime of the monitor's in-memory traffic accumulator. It begins when the monitor process/collector creates the accumulator and ends when that process stops or the accumulator is reinitialised. Each epoch is identified by a random 32-hex `source_epoch` and starts `sequence` at 0 with byte counters at zero. |
| **Observed lower bound** | For one inbound tag and one direction, the sum of authoritative byte totals of the connection lifecycles the monitor has observed **so far in the current observation epoch**, counting each observed lifecycle at most once: finalized (`CLOSED`) lifecycles banked exactly once, plus currently active lifecycles' latest authoritative totals. It can only understate what sing-box actually transferred for those lifecycles; it never claims exactness. |
| **Daemon-lifetime exact cumulative total** | The exact total bytes a sing-box daemon has transferred for an inbound since the daemon started. **The rev-7 source cannot produce this number.** There is no per-inbound daemon-lifetime counter in the frozen `service.api` surface; only the aggregate daemon counter and per-connection counters exist. |
| **Banked / finalized** | A lifecycle that received its terminal `CLOSED` event (authoritative final totals) or was banked as abandoned during a stream reset and is no longer active; counted exactly once into the epoch accumulator. |
| **Abandoned** | An active lifecycle that disappears from a subscription `reset` batch without a `CLOSED` event. It is never presented as closed; its last known totals are banked as a lower bound and un-banked if the same ID reappears. |
| **Active connections** | Count of connection lifecycles currently known active in the accumulator at the sampling instant, not a cumulative count. |
| **Observed rate** | A monitor-computed bytes-per-second estimate for currently active connections over the monitor's declared `rate_window_seconds`; an observation, not a total, and only meaningful together with that window. |
| **`sequence`** | Monitor-local strictly increasing integer per observation epoch; used to order/identify exports. It is **not** an authorization token and is independent of `X-UM-Seq`. |
| **`observed_at`** | Epoch seconds when the monitor sampled the accumulator for this export. |
| **`age_seconds`** | Agent-computed `collected_at − observed_at` of the report, 0..86400. |
| **`counter_epoch`** (rev-5 base field) | Host-boot-derived epoch for the base snapshot counters. It is **not** the monitor epoch and is never used to difference monitor traffic. |

## 2. What a rev-7 number is and is not

| Claim | Allowed? |
| --- | --- |
| "At least X bytes were observed on inbound T in observation direction D during epoch E" | **Yes** (with freshness/availability/quality and `observed_at`) |
| "At least X bytes were observed across inbound T since the monitor epoch started" | Yes only with the caveat in §3.3 (a lifecycle that began before the epoch may contribute its pre-epoch totals) |
| "The service transferred exactly X bytes" | **No** — never claim or display exactness |
| "The daemon has transferred X bytes since it started" | **No** — no such counter is observable |
| "X bytes were transferred in interval [t1,t2]" as an exact figure | **No**; at most "observed at least the difference of two same-epoch lower bounds" with a lower-bound label — and not across epochs |
| "Traffic in this period was 0" when the source was unavailable/stale/missing | **No**; that is UNKNOWN/UNAVAILABLE, never zero |
| Billing/quota/abuse decision based on the number | **No** — the frozen contract uses this only for honest display/observability |

## 3. Lower-bound model

### 3.1 Per-inbound aggregation

For inbound tag `T` and direction `D` (uplink/downlink), the monitor accumulates
across all devices/connections of that inbound:

```text
LB_D(T) = Σ (authoritative D totals of banked lifecycles for T)
        + Σ (latest authoritative D totals of active lifecycles for T)
```

In the export file these values are `observed_uplink_bytes` /
`observed_downlink_bytes`; the report carries the same integers as
`uplink_observed_lower_bound_bytes` / `downlink_observed_lower_bound_bytes`
(no arithmetic, rounding, relabelling or reordering at that boundary). The
export also carries monitor-side observability (`generated_at`, `monitor_stale`,
`monitor_last_success_at`) that is never forwarded into the report.

with these accounting rules (existing monitor behavior, verified in
`monitor-v2/collector.py`):

- `NEW` carries authoritative lifecycle totals; `UPDATE` adds deltas or replaces
  totals when the connection object is present; `CLOSED` carries the final
  authoritative totals and banks exactly once.
- A finalized ID is not banked twice on replay; an abandoned ID is banked as a
  lower bound and un-banked before being counted again if it reappears.
- Identity drift (a connection ID suddenly belonging to another user/inbound) is
  rejected by the monitor's identity guard; the ID keeps one identity forever.
- The aggregate is per inbound only; per-device, per-connection and address data
  never leaves the monitor.

### 3.2 This is a subset sum

The accumulator counts only lifecycles the monitor actually observed. Anything
it did not observe is missing and keeps the value a lower bound:

- lifecycles that opened and closed entirely while the stream was disconnected or
  between two delivered batches (outside the server's replay window);
- traffic the per-connection accounting itself cannot attribute (e.g. transport
  overhead, connections older than the replay window at first subscription);
- any reset/restart where in-memory state was lost.

The value is therefore always `≤` the true transferred bytes for the observed
lifecycles, and it is never "all sing-box traffic". The source does not read
conntrack, `ss`, packet capture, journal or sing-box aggregate counters.

### 3.3 Pre-epoch and pre-subscription bytes

The first `reset` batch of a subscription contains all currently active
lifecycles with their **authoritative lifecycle totals**, which include bytes
transferred before the monitor first observed that lifecycle (possibly before
the observation epoch or before the subscription started). The same is true for
the ~1000 recently-closed livecycles the server replays in a reset batch: they
are legitimate lifecycle totals that this monitor epoch has not counted before.

Consequences:

- the number is a lower bound on the sum of the observed lifecycles' lifetime
  totals, **not** a pure "bytes during this epoch" counter;
- a fresh monitor can start with a non-zero baseline (pre-subscription/active or
  replayed-closed totals) — this is an observed baseline, not fabricated or
  double-counted data;
- a monitor restart loses the previous epoch's banked totals, so the new epoch's
  value restarts lower. This is an epoch reset, not negative traffic (§6).

### 3.4 Worked example (synthetic)

Epoch `E1`, inbound `vless-in`, uplink:

| Event | Active totals | Banked | `LB_uplink` |
| --- | --- | --- | --- |
| initial reset: one active connection with 100 bytes | 100 | 0 | 100 |
| update +50 bytes | 150 | 0 | 150 |
| closed with final 180 bytes | 0 | 180 | 180 |
| new connection with 20 bytes | 20 | 180 | 200 |
| stream reset, that connection disappears without `CLOSED` (abandoned) | 0 | 200 (180 + abandoned 20) | 200 |
| same ID reappears with total 30 | 30 | 180 (abandoned record un-banked) | 210 |
| monitor restarts → epoch `E2`: 0 bytes observed | 0 | 0 | 0 in `E2` |

The `E1` series is monotone non-decreasing. The `E1` → `E2` transition is an
epoch boundary, not a decrease in traffic to be charted as negative or smoothed
away.

## 4. Active-connection bytes and interval deltas

- **Active-connection bytes** are part of the lower bound: the accumulator adds
  the current authoritative totals of active lifecycles at each sample. On
  `CLOSED`, the final authoritative totals replace (not add to) the last active
  totals, then the lifecycle is banked once. Active connections are also reported
  as a count (`active_connections` per inbound and top-level) so the UI can show
  "lower bound is growing while N connections are active".
- **Interval delta**: within one `source_epoch`, the lower bound is
  monotone non-decreasing by construction. The center MAY derive
  `observed_delta = LB(t2) − LB(t1)` for display and label it "observed at least
  ... in this interval". It MUST NOT:
  - present the delta as exact transferred bytes;
  - difference values across `source_epoch`/monitor restart or across an
    unobserved gap as if continuous;
  - sum deltas of adjacent intervals and call the result an exact total;
  - allow a negative delta to be stored or rendered (a decrease within one epoch
    is a source/implementation fault, reported as unavailable/corrupt, never
    clamped silently).
- **Counter decrease**: a decrease inside the same `source_epoch` must not be
  explained away by the agent/center. The agent detects it (new value lower than
  the last accepted value for the same `(source_epoch, tag, direction)`) and
  reports the observation as unavailable (sentinel), with a closed local
  diagnostic counter; the center must never store a negative interval or a
  decrease as valid data. A new `source_epoch` is the only normal cause of a
  lower value.

## 5. Observed rates and the rate window

- The monitor derives per-connection rates from the delta and elapsed time
  between stream updates (`uplink_delta / max(now − last_seen)`), then aggregates
  the active connections per inbound direction.
- The export declares a single `rate_window_seconds` for the document (the
  monitor's configured/de-facto aggregation window). A non-null rate requires a
  non-null positive window; a null window implies null rates, but a present
  window may still have null rates on partial/unavailable rows. The converse
  "window null iff rates null" is deliberately not the rule.
- Rates are **instantaneous/interval observations of active connections only**.
  They are not averages over the whole epoch, not a total and not billable.
- A rate may be `0` while connections are idle; that is an observed zero, not a
  fabricated one, provided the observation itself is available and coherent.
- Rate values are bounded (`0..10^12` bps) and are the only rev-7 numeric fields
  that may be fractional; byte counters are integers.

## 6. Monitor restart, `source_epoch`, and reset semantics

- When the monitor's accumulator is recreated (process start, crash restart,
  collector reinitialisation), the monitor:
  1. generates a new random 32-hex `source_epoch`;
  2. restarts `sequence` at 0;
  3. restarts its in-memory counters at zero;
  4. deletes/overwrites the previous export before writing the first new one.
  "Restarts at zero" describes the accumulator only: the first subscription
  `reset` batch can immediately reintroduce active/recent lifecycles whose
  authoritative totals include pre-epoch bytes (§3.3), so the first published
  value is not necessarily 0 and is never a pure epoch delta.
- The legacy compatibility collector-loop mode does not publish the UM-LT export;
  a node running only that mode has no export and reports honest unavailable (no
  fallback to `state/snapshot.json` and no behavior change to that mode).
- The agent treats a `source_epoch` change as a hard reset: it never subtracts
  the previous value, never emits a negative or clamped delta, and reports the
  new observation under the new epoch.
- The center stores the epoch identity (`source_epoch`, `epoch_seq`) with the
  observation and history bucket, renders a restart/reset boundary, and MUST NOT
  difference across epochs. Across epochs only "at least X observed in epoch E"
  statements are valid; totals spanning epochs cannot be reconstructed from this
  source.
- `source_epoch` is independent of the rev-5 `counter_epoch` (host boot), the
  agent boot generation and `X-UM-Seq`. A host reboot does not by itself create a
  new monitor epoch unless the monitor restarts; a monitor restart can happen
  without a host reboot.
- Old exports from a previous epoch are not authoritative after the monitor
  starts a new epoch; the monitor removes the stale file at startup, and an agent
  seeing an old file ages it to `stale` and then to the no-observation sentinel
  (never zero).

## 7. Connection lifecycle edge cases

| Case | Monitor/contract treatment |
| --- | --- |
| **Closed lifecycles** | `CLOSED` carries authoritative final totals (including bytes after the last `UPDATE`); banked exactly once; a duplicate/replayed `CLOSED` for a banked ID is not counted again. |
| **Short connections** | May open and close entirely between deliveries or outside the replay window: never observed, so absent from the lower bound. This is a known under-count, not an error to "fix" by estimating. |
| **Abandoned connections** | Active ID missing from a later reset without `CLOSED`: last known totals banked as a lower bound, not presented as closed/recent; un-banked if the ID reappears so nothing is double counted. |
| **Replay / dedupe cap** | The server replays ~1000 recently closed connections in every reset. The monitor keeps an independent bounded LRU replay guard (4096 IDs in the existing monitor) so a replayed lifecycle is not banked twice; the display cache TTL never decides accounting. The guard is bounded, so pathological ID histories beyond it are an implementation risk recorded in the source audit, not a reason to call the number exact. |
| **ID reuse** | A connection ID identifies exactly one lifecycle. An event that tries to move an ID to another user/inbound is rejected by the monitor's identity guard. A reused ID after a very long gap could confuse the bounded guard; the resulting value remains an observation, never an exact total, and the source audit records the residual risk. |
| **Counter decrease within an epoch** | Source fault: agent reports unavailable/status-only, center never stores/renders a negative delta (see §4). |
| **Overflow** | Monitor counters are exact integers internally; a value outside `0..9007199254740991` is published as `null` with `quality=partial` (never rounded/clamped through float64, never wrapped). The agent copies integers unchanged. |
| **Float→integer migration** | The legacy dashboard keeps its historical float formatting independently. The rev-7 writer keeps counters as exact integers (protobuf int64/uint64) and emits JSON integer tokens only; it never derives the exported value from a display-rounded float, never rounds up, and never emits a lexical float token for an integer field. A lexical `1048576.0` is rejected by the consumer even though JSON Schema would call it an integer. |
| **Duplicate export** | The file is read whole; a repeated `sequence` is idempotent at the agent (reuse of the last accepted observation if still fresh) and a lower `sequence` in the same epoch is treated as replay/invalid, not as new data. |

## 8. Missing, partial, stale and unavailable

| State | Meaning | Representation |
| --- | --- | --- |
| no export ever / monitor not deployed / switch disabled | no observation source | rev-5 body or rev-7 no-observation sentinel depending on config; `availability.traffic=unavailable` |
| export missing/unreadable/symlinked/oversized/invalid | can't trust a current observation | sentinel `freshness=unavailable`, `availability=unavailable`, `inbounds=[]` |
| export valid but older than the fresh bound | usable past observation, not current; fresh bound = `max(2 × effective-dated cadence at collected_at, 120)s` | `freshness=stale`, `availability=partial` (never `ok`), values retained with `observed_at`/`age_seconds` |
| export valid but some expected inbounds missing or monitor-partial | partial coverage | `availability=partial`; missing tags absent (no fabricated zero), present tags carry their own availability/quality |
| export valid but `monitor_stale=true` | the monitor itself flags its stream/accumulator as degraded | `freshness=stale` at best (never `fresh`) and `availability=partial` at most; rows are `partial`, rates null; age is still derived from the agent clock |
| `monitor_last_success_at` older than the fresh bound or `null` with `monitor_stale=true` | monitor has no recent successful observation | at most `partial`; if no usable counters remain, the status-only/unavailable form |
| export valid but contains no observed values (empty or all rows unavailable) | source reachable/current but nothing observed | **status-only real-epoch form**: real `source_epoch`/`sequence`/`observed_at` kept, `freshness=availability=unavailable`, no bytes/rates/active, no bucket/epoch rows |
| export older than `EXPORT_MAX_AGE_SECONDS` (86400 s) | beyond the bounded payload age | zero-epoch sentinel unavailable (it is not replayed as a stale measurement) |
| monitor unavailable state in export | monitor itself says it cannot observe | sentinel unavailable |
| node/agent disabled or center not rev-7 capable | source not authorized in effect | rev-5 body / no rev-7 data; `traffic=[]`, `availability.traffic=unavailable` |

No state above may be converted to `0`, `ok`, `up`, a guessed value or a
smooth chart. The UI must render UNKNOWN/UNAVAILABLE/STALE explicitly (UM-D
rule, unchanged).

## 9. When the source is unavailable (normative list)

The rev-7 observation is `unavailable` — either the zero-epoch no-observation
sentinel or the distinct status-only real-epoch form (valid export, no observed
values) — when any of the following is true; the list is closed for v1 and the
implementation must map each to a closed diagnostic counter rather than free
text:

1. the monitor export file does not exist, is not a regular file, is a symlink,
   has the wrong owner/group/mode, or is larger than 64 KiB;
2. the file is not valid closed-schema JSON, has trailing data, unknown fields,
   wrong `schema`/`schema_version`/`source`/constant, or missing required fields,
   or violates the `observed_at ≤ generated_at` or monitor-observability field
   rules;
3. a numeric lexical/range rule fails (float token, negative, NaN/Inf, over
   bound, non-integer active count) or `sequence`/epoch grammar fails;
4. the no-observation sentinel is inconsistent, or any coherence rule in the
   rev-7 overlay §7–§8 fails;
5. `observed_at` is more than 60 s in the future relative to `collected_at`, or
   the observation is older than 86400 s, or the file's `generated_at`/
   `observed_at`/`monitor_stale`/`monitor_last_success_at` observability fields
   are missing, out of range or inconsistent (`observed_at > generated_at`);
6. a `source_epoch` change is observed mid-stream in a way the agent cannot
   safely order (replay/rollback of files), or a same-epoch counter decrease is
   detected;
7. the applied config does not enable `collect.monitor_export`, the node is not
   `linux_vps`, the center is not rev-7 capable, or the source authorization
   audit version does not match the implementation;
8. the monitor itself reports stale/unavailable state, a structurally valid
   export contains no observed values (status-only real-epoch form), or the
   monitor is known stopped (no fresh file);
9. the monitor runs only the legacy compatibility collector-loop mode, which
   never publishes this export.

Availability is never inferred from silence or absence of traffic; a quiet
service with a healthy export is an observed zero/vsmall lower bound, while an
absent export is UNKNOWN.

## 10. Relationship to the frozen rev-5 fields

- `counter_epoch` (rev-5) remains the host-boot epoch of the base snapshot
  counters. It is **not** the monitor epoch and MUST NOT be used to difference
  monitor traffic. A monitor restart changes `source_epoch` but not
  `counter_epoch`; a host reboot changes `counter_epoch` but does not by itself
  change `source_epoch`.
- `traffic` (rev-5 total-byte array) stays `[]` for rev-7 Linux; the lower bounds
  are not total bytes and must not be relabelled into that array.
  `availability.traffic` is `partial`/`unavailable`, never `ok`.
- `availability`, `services`, `protocols`, `system`, `clients` and the Windows
  `terminal` object keep their rev-5 meaning and coherence rules.
- The original rev-5/rev-6 signed semantics (`report_id`, `collected_at`,
  `X-UM-Seq`, `X-UM-Boot-Gen`, nonce, fingerprint, dedupe) are unchanged; the
  observation is payload content, not a transport concept.

## 11. Privacy of the underlying data

The lower-bound semantics do not change the privacy rule. The monitor's raw
in-memory data contains device/API user names, source/destination addresses,
connection IDs and protocol details; none of it may be exported or reported.
Only per-inbound aggregate counters, rates, counts, timestamps and the frozen
allow-list fields cross the boundary. See
[`um-lt-source-authorization-audit.md`](um-lt-source-authorization-audit.md).
