# UM-LT — Capacity planning (parameterized estimates; production acceptance remains UM-E)

Status: **CANDIDATE capacity analysis for the rev-7 contract package — docs-only,
pending independent review/CI and the Owner's conditional merge authorization.
NOT published/frozen, NOT merged, NOT implemented. These are planning estimates,
not measured acceptance results.** Production capacity acceptance remains UM-E;
real row-size/query/retention measurement belongs to the implementation PR and
UM-E, not to this contract PR. Frozen platform rules:
[`um-a/05-retention-capacity-backup.md`](um-a/05-retention-capacity-backup.md);
rev-7 protocol: [`um-a/04-node-protocol-v1.rev7.md`](um-a/04-node-protocol-v1.rev7.md).

## 1. Inputs (from the goal and the frozen capacity contract)

| Parameter | Value used | Source |
| --- | --- | --- |
| Active nodes | 150 | goal brief; ≤100 per event |
| Inbounds per node | ≤8 configured, 8 used for worst-case sizing | `expected_inbound_tags` maxItems 8 |
| History retention | 30 days active (policy A basis; policy B overlap treated separately) | rev-5 doc 05 |
| Agent cadence | 30–300 s (30 s = storage/ingest worst case) | frozen `agent-config` range |
| Active telemetry payload basis | **5 GiB** | rev-5 doc 05 / B2 clarification C3 |
| Active + archived overlap budget | **10 GiB** (2× basis) | rev-5 doc 05 / B2 clarification C3 |
| Existing store schema | version 13, SQLite WAL `synchronous=FULL`, STRICT tables | `um/internal/store/schema.go` |
| Existing per-report snapshot payload retention | 30 d per accepted snapshot (frozen rev-5 behavior) | B2 retention |
| Disk planning envelope | 40 GB budget incl. OS/WAL/backups/VACUUM temp | rev-5 doc 05 §4 |

All estimates below are **payload bytes** (the unit used by the frozen capacity
budget), not SQLite file size. SQLite file size adds page overhead, free-page
fragmentation and WAL; those follow the frozen doc-05 rules and are not double
counted here.

## 2. Design constraint: do not store the observation as a second raw payload

In the existing center, every accepted snapshot body is retained as
`snapshots.payload_json` for the retention window. If a rev-7 body (frozen base
projection plus `traffic_observation` of up to 8 inbounds, roughly 0.7–1.2 KB of
additional JSON) were stored whole in that generic row, the addition would be
unbounded by the 5 GiB basis:

```text
full-body addition = N × (86400 / C) × D × S7
N=150, D=30 d, S7≈1.0 KB per rev-7 observation
C=30 s  → 150 × 2880 × 30 × 1.0 KB ≈ 12.96 GB  (fails the 5 GiB basis)
C=60 s  → 150 × 1440 × 30 × 1.0 KB ≈  6.48 GB  (fails the 5 GiB basis)
C=300 s → 150 ×  288 × 30 × 1.0 KB ≈  1.30 GB  (fits only at slow cadence)
```

**Capacity requirement:** the center MUST extract the observation into the
bounded structured tables below and MUST NOT retain a second raw copy of
`traffic_observation` per report for 30 days. The received-body SHA-256 remains
the dedupe/conflict identity, and the frozen rev-5 base projection may be
retained exactly as today. This keeps the rev-7 addition independent of cadence
in the worst case. Implementation PR must prove the stored projection excludes
the observation (or stores an equivalent bounded encoding) and measure the
actual bytes.

## 3. Per-report ingest rates (validation, not storage)

| Cadence C | Reports/node/day | Fleet reports/day (150) | Fleet reports/s |
| --- | --- | --- | --- |
| 30 s | 2 880 | 432 000 | 5.0 |
| 60 s | 1 440 | 216 000 | 2.5 |
| 300 s | 288 | 43 200 | 0.5 |

Rev-7 adds one bounded structured write per accepted snapshot (latest upsert +
at most 8 bucket upserts, amortised: at most 1 bucket row per 300 s bucket per
inbound) inside the existing single `synchronous=FULL` transaction. This does
not change the SQLite→PostgreSQL gate (doc 05 §5: >50 writes/s sustained etc.);
the dominant cost stays the existing one durable commit per report.

## 4. Structured storage model

### 4.1 Tables and cardinality

| Table | Rows (worst case) | Notes |
| --- | --- | --- |
| `traffic_observation_latest` | 150 (one per node) | current observation metadata only |
| `traffic_inbound_latest` | ≤150 × 8 = 1 200 | one row per node/inbound current value |
| `traffic_observation_bucket` | **N × I × B/day × D** | 5-minute buckets by default; one row per node/epoch/tag/bucket that has an accepted observation |
| `traffic_epoch` | 150 × ≤8 recent epochs | bounded epoch registry, diagnostics only |

Bucket row count is **independent of cadence** for C ∈ [30 s, 300 s], because at
most one row exists per 5-minute bucket and tag:

```text
buckets/day = 86 400 / 300 s = 288
rows = 150 × 8 × 288 × 30 = 10 368 000 rows  (worst case: all 8 tags, 30 days)
```

If the implementation chooses a different bucket B (60 s, 300 s, 900 s), the
formula is `rows = N × I × (86 400 / B) × D`. The contract does not freeze the
bucket size; a bucket ≤300 s preserves observation accuracy, and a larger bucket
must be a documented implementation/capacity decision.

### 4.2 Row-size formula

```text
bucket_row_bytes  = H + node_ref + event_ref + epoch_ref + bucket_ref
                  + tag_bytes + up_lb + down_lb + active
                  + rate_u + rate_d + window + observed_at
                  + flags + sequence
index_bytes       ≈ PK index + event-scope index + node-time index
stored_bytes/row  = 1.15 × bucket_row_bytes + index_bytes   (page/varint overhead)
```

Reference size (existing store style with TEXT UUIDs, conservative):

| Component | Bytes |
| --- | --- |
| SQLite row header/varints | ~10 |
| `node_id` TEXT (UUID) | 36 |
| `event_id` TEXT (UUID) | 36 |
| `epoch_seq` INTEGER | ~3 |
| `bucket_start` INTEGER | ~5 |
| `inbound_tag` TEXT (average 16–24) | 20 |
| `uplink_lb` / `downlink_lb` INTEGER | 7–8 each |
| `active_max` INTEGER | 2–3 |
| `rate_u` / `rate_d` REAL nullable | 8 each |
| `rate_window_seconds` REAL nullable | 8 |
| `observed_at` INTEGER | 5 |
| availability/quality/freshness/state flags | 3 |
| last `sequence` | 5 |
| **payload subtotal** | **~160–170** |
| page overhead (~15%) | ~25 |
| indexes (PK + event/time + node/time) | ~35–60 |
| **stored bytes/row (R)** | **~220–255 B** |

A normalized implementation that stores integer surrogates/tag ids can reach
~110–140 B/row; the sheet keeps the conservative UUID-text variant for the
upper bound.

### 4.3 Estimates

| Scenario | Rows | Payload (R=140 B) | Payload (R=250 B) | Share of 5 GiB basis |
| --- | --- | --- | --- | --- |
| 30 d, 5-min buckets, 8 tags, 150 nodes | 10 368 000 | ≈1.45 GB (1.35 GiB) | ≈2.59 GB (2.41 GiB) | 27–48 % |
| 30 d, 15-min buckets, 8 tags, 150 nodes | 3 456 000 | ≈0.48 GB | ≈0.86 GB | 9–16 % |
| 30 d, 1-min buckets, 8 tags, 150 nodes | 51 840 000 | ≈7.26 GB | ≈12.96 GB | **fails** the basis |
| 30 d, per-observation rows at C=30 s | 103 680 000 | ≈14.5 GB | ≈25.9 GB | **fails** the basis |

Latest tables add ≤~0.4 MB, negligible.

### 4.4 Overlap (policy B)

Policy-B worst case doubles the retained payload for an archived event
(`2×` active basis = 10 GiB). With 5-minute buckets the rev-7 history is
1.4–2.6 GB; doubling it gives 2.7–5.2 GB, i.e. **27–52 % of the 10 GiB overlap
budget**, leaving the rest for the frozen rev-5 telemetry. At 1-minute buckets
the rev-7 share alone would exceed the overlap budget even before rev-5 data, so
1-minute buckets are not permitted without a separate capacity/owner decision.
The exact bucket choice must be recorded with measured numbers in the
implementation PR and re-checked in UM-E.

### 4.5 Cadence and the 5 GiB basis

Lowering the fleet cadence from 300 s to 30 s multiplies report ingest and
snapshot-body traffic by 10× but does **not** multiply rev-7 structured history
(as §4.1 shows). The remaining risk is the frozen rev-5 `snapshots.payload_json`
retention, which grows with cadence and is outside this source's control; the
implementation/UM-E must not use rev-7 as an excuse to relax that frozen rule.
If measured base payload + rev-7 structured rows exceed the 5 GiB basis, the
response is capacity tuning (bucket size, retention class behavior, cadence
policy) or an owner sizing decision, not silent data loss.

## 5. Index plan and query patterns

| Object | Key / index | Query served |
| --- | --- | --- |
| `traffic_observation_latest` | PK `node_id`; index `(event_id, node_id)` | latest observation per node, event-scoped dashboards |
| `traffic_inbound_latest` | PK `(node_id, inbound_tag)`; index `(event_id, node_id)` | per-inbound latest card values |
| `traffic_observation_bucket` | PK `(node_id, epoch_seq, bucket_start, inbound_tag)`; index `(event_id, bucket_start, node_id)`; index `(node_id, bucket_start)` | event-scoped history windows; per-node series |
| `traffic_epoch` | PK `node_id`; unique `(node_id, source_epoch)` | epoch boundary/reset markers, diagnostics |

Rules:

- Every row carries `event_id`; event-scoped queries resolve the allowed event
  set first and filter in SQL (unchanged two-layer rule).
- Deletion: hourly retention job deletes bucket rows older than the class cutoff
  in bounded batches (≤50 000 rows/transaction, oldest-first, resumable) exactly
  as the frozen doc-05 mechanism; latest rows use the frozen 30-d-after-last-
  report/retire rule.
- Query bounds: maximum 30-day window, bounded node list, no unbounded scans; the
  admin query layer never joins across events except content-free counts.
- No index on raw observation values; no full-text/free-text fields exist.
- `STRICT` tables and `CHECK` constraints for numeric bounds/`typeof` rules match
  the frozen storage conventions; observation bytes are INTEGER, rates may be
  REAL with bounds; nullable unknowns are NULL, never sentinel 0.
- No cross-epoch difference query is allowed; the epoch key is part of the
  bucket key so mixed-epoch rows cannot be silently merged.

## 6. Disk / maintenance effects

- WAL: unchanged bounded checkpoint policy; rev-7 writes ride the existing
  per-report transaction.
- VACUUM temp: doc-05 rule (free space ≥ DB size + 10 %, never concurrent with
  backup) is unchanged; the rev-7 addition is included in the DB size input.
- Backups: compressed local backups are sized from the whole DB; an additional
  1.4–2.6 GB payload implies roughly 0.5–1.3 GB compressed (35–45 % ratio), still
  covered by the frozen ≤6 GB local backup envelope for the 150-node ceiling if
  the base stays within budget.
- Disk-pressure degradation order, quota alarms and the PG gate are unchanged
  and NOT overridden by this source.

## 7. What this contract PR proves vs what remains

| Item | Contract PR (this package) | Implementation PR | UM-E |
| --- | --- | --- | --- |
| Formula, bucket design, index plan | **provided as estimates** | must implement and measure | re-check |
| Real rows/byte ratio/query p95 | NOT RUN | required | required |
| 150-node, 30-day accelerated retention load | NOT RUN | partial lab | required for acceptance |
| Disk-pressure/VACUUM/backup overlap | NOT RUN | no | required |
| Production capacity acceptance (150/200/500-node gates) | NOT RUN | no | **UM-E-owned** |

**Production capacity acceptance remains UM-E.** This document is a parameterized
estimate to keep the rev-7 addition inside the frozen 5 GiB active / 10 GiB
overlap planning envelope; no capacity PASS is claimed.
