# UM-A 05 — Retention, capacity, database decision gate and backup/restore

Status: design freeze for UM-A review. Numbers are **planning estimates** with
stated assumptions; UM-B must validate them with real measurements and UM-E
must prove the performance/capacity budget ([06](06-threat-model-security-tests-performance.md)).

## 1. Data classes and retention (frozen)

| Data class | Content | Retention | Notes |
| --- | --- | --- | --- |
| `node_latest` + `node_services` + `node_protocols` + `node_traffic` | last authenticated snapshot projection | current only; row removed 30 d after last accepted report / node retire | upsert idempotent; no history |
| `metric_minute` | per-node minute rollups | **30 days** | 1 row/node/collection minute |
| `protocol_minute` | per-node per-protocol minute state + traffic deltas | **30 days** | ≤4 protocols/node |
| `client_hourly` | top-N pseudonymous client summaries (aggregates only) | **30 days** | per node per hour; old hours may be compacted first under disk pressure |
| `events_history` | fault/incident/agent events timeline | **30 days** | fault timeline source for UM-D |
| `incidents` | derived incident open/close groups | **30 days** | rules owned by UM-D; never delete open incidents |
| `reports_dedupe` | replay/sequence dedupe keys + body hashes | **10 minutes** | bounded; may be memory-backed |
| `enroll_tokens` | token hashes | deleted on use or TTL expiry | single-use |
| `node_keys` | node public keys + revocation/rotation metadata | with node identity; revocation record 30 d after event purge | needed for audit/forensics |
| `audit_log` | administrative/security audit | **180 days** (size-bounded, configurable down, never below 30) | actor/target/action/result only |
| `sessions` | server-side sessions | expire (15 min idle / 8 h absolute) | in DB or memory; deletion on expiry |
| `events` | event catalog | until purge | archived events keep history aging out |
| `retention_runs`, `schema_migrations` | maintenance state | current | — |

Hard rule: **every data row that belongs to an event is deleted by the 30-day
retention boundary except an explicitly archived/preserved event catalog row.**
"Node destroyed"/"event ended" does not shorten history: history remains
queryable until its own 30-day age-out (owner requirement).

## 2. Deletion rules (frozen)

1. **Age-out**: an hourly (configurable to 15 min) retention job deletes rows of
   each class whose timestamp is older than the class cutoff. Deletion is
   per-class and bounded per run (e.g. ≤50 000 rows/transaction) so a large purge
   never blocks ingest for long; the job resumes until caught up. It is
   idempotent and restart-safe.
2. **Open incidents are never age-pruned**; closed incident rows age out by
   `closed_at`.
3. **Event archive**: stops ingestion and admin listing defaults to hidden;
   history remains queryable to the 30-day boundary. Archiving is reversible by
   platform_admin (audited).
4. **Event purge**: only for an archived event; requires platform_admin and an
   explicit type-to-confirm name. One transaction deletes event-scoped data
   (nodes, keys, reports, state, rollups, events, incidents); a bounded purge
   audit record (event id, actor, counts, timestamps — no content) is retained
   for 180 days. Backups already written are not rewritten; they age out under
   backup retention (restore of a purged event must be an explicit owner
   operation, documented).
5. **Node retire**: sets node state `retired`, rejects reports, keeps history
   until its age-out; latest-state rows removed after 30 d.
6. **Key revocation**: key row and audit record retained with the node identity;
   reports rejected immediately.
7. **No "cleanup newest-first"** and no per-table independent cutoff that can
   leave newer rows deleted while older rows survive: within a class, deletion is
   strictly oldest-first; cross-class ordering is irrelevant because classes
   have different cutoffs.
8. **Retention failure is soft and visible**: a failed run records a closed
   error code, increments a failure counter, raises a degraded flag, and retries
   next schedule. It never crashes the center and never silently skips forever.
9. **Disk-pressure override**: if the disk is critically low, the center drops
   *client-summary granularity* first, then *metric granularity* (see §4), and
   alerts; it never deletes data inside the last 24 hours and never deletes
   `events_history` before its 30-day boundary.

## 3. Capacity model (planning, to be measured)

### 3.1 Assumptions

| Input | Assumption | Source/status |
| --- | --- | --- |
| Events | up to 10 | planning ceiling |
| Nodes | up to 200 (planning); 500-node stress in UM-E | planning ceiling |
| Protocols monitored per node | 2 typical (Reality + HY2), max 4 | campaign architecture #48 |
| Agent cadence | 60 s snapshot + 60 s minute metric + events as they happen | doc 04 (agent-controlled, center-configurable 30–300 s) |
| Client summaries | top 50 `device_ref` refs/node/hour + aggregate counts | privacy design (doc 04) |
| Retention | 30 d metric/protocol/client/events | owner requirement |
| Average node DB row | ~120 B including index overhead (to be measured) | estimate |
| Report ingress body | ≤32 KiB snapshot, ~2 KiB typical | doc 04 |
| Per-node network | ≤20 MB/day (assumption, to be measured) | estimate |

### 3.2 Steady-state sizing (200 nodes)

Rows/day/node: metrics 1 440 + protocol 2 880 + client 1 200 + events ~50 ≈
**5 570**. At 200 nodes: ~1.11 M rows/day → **33.4 M rows / 30 d**.
At ~120 B average (incl. indexes): ≈4.0 GB raw + SQLite overhead/WAL ≈
**5.0–6.0 GB DB at 30 days**. At 500 nodes: ≈12.5 GB (still below the
PostgreSQL gate, but the 40 GB disk budget must be re-checked with backups).

Ingest load: 200 nodes × ~2 requests/min ≈ **6.7 req/s** steady, with bursts
≤50 req/s; a single small center handles this comfortably. Ingress bandwidth
≈ 200 × (32 KiB + 2 KiB + events) per minute ≈ **0.3 MB/s** worst case.

### 3.3 40 GB disk budget (200 nodes)

| Item | Budget |
| --- | --- |
| OS + packages + Go binary + logs | ≤8 GB |
| SQLite DB (30-day data) | ≤6 GB |
| WAL + temp | ≤1 GB |
| Backups (2 compressed local) | ≤4 GB |
| Headroom / growth | remaining ≥20 GB |

Alarm thresholds: warn at 70 % used; reduce client granularity at 80 %; reduce
metric granularity at 90 %; emergency write-only-latest at 95 % (see §4); never
reclaim below the last-24 h or the 30-day events contract.

### 3.4 Capacity limits enforced by the center

- Per-node report rate limit (doc 04 §9); global ingest concurrency and body
  caps; per-event node quota (default 100, configurable by platform_admin).
- Client summaries: bounded top-N (50) per node per hour; overflow becomes
  aggregate counts only, never raw identifiers.
- `detail` maps in events bounded (≤8 scalars, ≤64 chars each).
- Purge/retention batch bounds; backup concurrency 1.
- No unbounded JSON blobs, no per-connection raw storage.

## 4. Database decision gate (SQLite → PostgreSQL)

v1 uses SQLite WAL with a single writer process
([ADR-UM-004](02-technology-selection-adr.md)). The storage interface keeps SQL
portable. A PostgreSQL migration (its own reviewed phase) is triggered when any
of the following is measured/decided:

| Trigger | Threshold |
| --- | --- |
| Sustained write rate | >50 writes/s for 1 h at the planning ceiling |
| Database size | >24 GB with the 30-day contract intact and backups on the same disk budget |
| Write latency | p95 write transaction >50 ms for 1 h |
| Concurrency need | separate web/ingest/worker *processes* must write concurrently |
| Availability need | multi-instance / read replica / HA required by owner |
| Operational incident | SQLite corruption/lock incident that cannot be prevented structurally |

Before the gate, the center must remain a single-writer process; if a second
writer is proposed, PostgreSQL (or a redesign) is required first.

## 5. Backup and restore (frozen targets)

| Property | Value |
| --- | --- |
| Method | SQLite online consistent backup (`VACUUM INTO` or backup API) from the live DB; no file copy of a hot WAL DB |
| Schedule | nightly 03:00 center-local time (configurable), plus an immediate backup before every schema migration |
| Verification | `PRAGMA integrity_check` (or `quick_check`) + table/schema shape check + SHA-256 manifest per backup |
| Encryption | backup encrypted **before** leaving the center host; owner-held key (age or equivalent AEAD tooling chosen in UM-E), never plaintext off-host |
| Local retention | 2 most recent verified backups (compressed target ≤4 GB total at 200 nodes) |
| Off-host | owner-initiated pull (no center-held off-host credentials), weekly, retained by owner |
| RPO | ≤24 h |
| RTO | ≤2 h for a single-host restore to the same release |
| Restore drill | at least once per phase UM-E, plus after any schema migration; restore must be proven, not assumed |
| Restore secrets | DB contains encrypted TOTP secrets; the master key lives outside the backup and is required to restore admin TOTP (owner-secured, documented) |
| Rollback | binary rollback within the same DB schema is supported; DB schema downgrade is refused (pre-migration backup is the only downgrade path, mirroring the audited `monitor-v2` discipline) |

Backup content excludes: node private keys (never at center), Cloudflare tunnel
token, master key, session/CSRF tokens. Backups include the full monitoring DB
with audit and (encrypted) TOTP secrets.

## 6. Center self-monitoring and alerts

- Internal health (`/internal/health`, loopback-only): DB open/WAL, retention
  last success, backup last success, disk free, ingest queue depth, auth failures
  rate, clock offset — closed codes only, no secrets.
- Owner-facing alerts (out of band, UM-E decides: email/webhook) for: disk ≥70 %,
  retention failure ≥2 runs, backup failure, node stale >15 min (per node),
  ingest 5xx rate, repeated signature failures, event purge executed.
- UM-E must run a 30-day simulated/accelerated retention cycle and a restore
  drill before production authorization.

## 7. Explicit non-goals

- No indefinite raw telemetry, no connection-level history, no raw packet/log
  storage, no per-client credentials or full YAML in history.
- No switching to PostgreSQL, no HA/clustering, no remote object storage in
  UM-A..UM-E without a separate owner-approved design.
- No backup of VPS root credentials (none exist centrally).
