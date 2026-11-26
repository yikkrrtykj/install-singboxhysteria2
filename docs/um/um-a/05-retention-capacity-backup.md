# UM-A 05 — Retention, capacity, database gate and backup/restore (revision 5)

Status: final targeted amendment for UM-A rev-5; values marked "owner decision"
are **not** approved yet. Revision 5 adds `node_class`/Windows terminal data and
versioned route-mapping retention; numbers remain planning estimates to be
measured by UM-B/UM-E.

## 1. Retention policy: A vs B (owner decision, recommendation B)

| Policy | Definition | Advantages | Costs |
| --- | --- | --- | --- |
| **A** | All telemetry rows are retained 30 days by `collected_at`, independent of event state. | Simple, bounded, predictable. | An archived event gets no extra history beyond its 30-day rolling window; almost half of an archived event's last month may already be expired at archive time. |
| **B (recommended)** | Active event: rolling 30 days by `collected_at`. On archive at T, the remaining history is kept until **T + 30 days** (no new ingest); then it is deleted until the event is purged. | Fulfils "history remains queryable after the event ends / nodes destroyed" without indefinite storage. | Worst case doubles storage when many events archive near each other; needs a clear overlap cap. |

**Recommendation: B with an explicit overlap cap.** A single event can occupy at
most 60 days of its own history (30 rolling + ≤30 archive tail). Total storage in
the worst case is therefore ≤2× the active-only estimate. The owner must confirm
B and the overlap rule (doc 07 Q-RET). Until confirmed, UM-B must not implement
either deletion policy beyond the class table below.

Frozen rules for policy B (if approved):

- Event archive stops ingest and starts the archive tail: no row older than
  `archive_time + 30 d` survives; rows newer than the archive time do not exist.
- A node destroyed while its event is active keeps its history under the active
  event's rolling/archive rules — destroy does not shorten retention.
- Open incidents are never pruned; once closed they age out by `closed_at`
  (active) or by the archive-tail boundary.
- Purge (explicit, type-to-confirm) deletes immediately regardless of age and
  records a purge tombstone (event id, actor, time, counts; no content) retained
  180 days.
- The event catalog row survives its data until purge (so an archived event can
  still be listed).

## 2. Data classes and exceptions (single source of truth)

| Data class | Retention (policy B) | Exceptions / notes |
| --- | --- | --- |
| latest state (`node_latest`, services/protocols/traffic) | current; removed 30 d after last accepted report or node retire | replaced only by newer `collected_at`; stale snapshots are `stale_ignored` |
| Windows terminal latest (`terminal_latest`: six-token selection/connection aggregates) | current; same remove rule as latest state | tokens/counts/timestamps only; no proxy names/targets/credentials |
| `metric_minute`, `protocol_minute`, `client_hourly` | active: 30 d rolling; archived: until T+30 | disk-pressure degradation may reduce granularity, never below the last 24 h |
| `events_history`, `incidents` | same 30 d / T+30 | open incidents never pruned; includes Windows terminal route/source events |
| `report_dedupe` | 8 d | needed to dedupe spool replay (7 d spool + margin) |
| `nonce_dedupe` | 24 h | transport replay window, unique `(node_id, nonce)` |
| `seq_dedupe` | current generation, bounded last 256 per node | exact-retry classification; not an authorization source |
| `boot_registry` | with node identity; bounded last 8 generations | diagnostics only; retired generations are rejected by the persistent generation high-water (`stale_boot_generation`), never by registry presence |
| `node_boot` (authoritative high-water) | current only, persistent | highest generation/boot id/last seq/last fingerprint; survives center restart |
| `route_mapping_versions` | with event history; never rewritten or deleted before event purge | append-only version/effective_from; historical attribution is resolved by effective time; mapping changes audited 180 d |
| `node_keys` | with node identity; revocation record 30 d after purge | audit/forensics |
| `key_rotations` | with node/key identity | rotation state machine recovery (doc 04 §7) |
| `audit_log` | 180 d (owner decision Q-AUD; configurable down, never below 30) | security audit, size-bounded |
| security ledger (`security-ledger.jsonl`) | 180 d, append-only, hash-chained; included in every backup/offsite copy | revocations/purges/restores/account changes; must never be silently truncated |
| `enroll_tokens` | deleted on use/expiry | hash only; scope{event_id,node_class} stored with the token record |
| `sessions`, `recovery_codes` | expire / one-time | not archived |
| backups | see §6 | not a second history store |

No document may define a different retention for these classes; this table is
normative for UM-B..UM-E and is duplicated only by reference.

## 3. Deletion rules (normative)

1. Hourly retention job (configurable to 15 min): per class, delete rows older
   than the class cutoff; bounded batches (≤50 000 rows/transaction) so ingest is
   never blocked; resumable and idempotent; strictly oldest-first within a class.
2. Open incidents and unexpired audit rows are excluded; purge is the only way to
   delete event data earlier.
3. Event archive/purge/retire and key revocation are written to the audit log and
   to a separate **security ledger** (see §6.4) that is included in backups and
   in the owner's off-host copies.
4. Retention failure is soft and visible: closed error code, failure counter,
   degraded flag, retry next schedule; never crash and never silently skip.
5. Disk pressure order: (a) client summaries older than 7 d → daily aggregates;
   (b) metric rollups older than 7 d → 5-minute granularity; (c) stop accepting
   client summaries; (d) write only latest snapshots + events. Never delete data
   <24 h old; never delete `events_history` before its policy boundary; always
   raise an alert.
6. After a large purge, full `VACUUM` is scheduled (SQLite cannot otherwise
   return pages from the middle/oldest end to the OS); `auto_vacuum` incremental
   is enabled but full VACUUM is the guaranteed shrink step.

## 4. Capacity model (planning; measure in UM-B/UM-E)

Assumptions: 10 events, 200 nodes planning ceiling (500-node stress in UM-E),
2 protocols/node typical (max 4), 60 s cadence, client summaries top-50
`device_ref`/node/hour, average DB row ~120 B incl. index (to be measured).

Rows/day/node: metrics 1 440 + protocol 2 880 + client 1 200 + events ~50 ≈
**5 570**. At 200 nodes: 1.11 M/day → **33.4 M rows / 30 d ≈ 5–6 GB**.

Additional mandatory capacity terms (previously omitted, P1-11):

| Term | Estimate at 200 nodes | Notes |
| --- | --- | --- |
| `report_dedupe` | ~2.3 M rows (8 d × 288k reports/day) ≈ 0.5–0.8 GB | one row per report; prune by 8 d |
| `nonce_dedupe` | 288k rows/day × 24 h ≈ 0.1 GB | nonce + fingerprint |
| `seq_dedupe` + `boot_registry` | ≤200 × (256 + 8) rows ≈ 0.05 GB | bounded |
| `audit_log` | ≤0.1 GB | 180 d closed records |
| security ledger | <0.05 GB | append-only JSONL |
| WAL | ≤1 GB | checkpoint bounded |
| VACUUM temp | up to ~1× the DB size transiently | full VACUUM needs free space ≥ DB size |
| backups (2 local, compressed) | ~35–45 % of DB size each | independent copies |

Policy A: DB ~5–6 GB (+dedupe ≈0.8) → total working set ~7–8 GB.
Policy B worst case: ≤2× data ≈ 10–12 GB (+dedupe) → ~12–14 GB DB.
40 GB budget with policy B and *simultaneous* VACUUM + backup: DB 14 + VACUUM
temp 14 + backups 6 + WAL 1 + OS 8 = **43 GB > 40 GB**. Therefore the frozen
consequence is:

- 40 GB with policy B supports a **planning ceiling of ~150 active nodes** when
  full VACUUM and backup can overlap; the center MUST schedule VACUUM only when
  free space ≥ (DB size + 10 %) and no backup is running, and MUST defer it
  otherwise (incremental `auto_vacuum` still runs; fragmentation is reported).
- **200 active nodes with policy B requires either a larger disk (owner Q-SIZE) or
  policy A**; without that, the center refuses new enrollment at the hard quota
  (below) rather than running out of disk.
- A 500-node stress is a PostgreSQL/disk decision gate, not assumed.

### 4.1 Global quotas (frozen defaults; owner-adjustable only upward with capacity evidence)

| Quota | Default | Behavior at limit |
| --- | --- | --- |
| Active nodes (all events) | 200 planning; hard 250 on ≥60 GB, 150 hard on 40 GB policy B | soft alarm at 80 %; at hard limit new enrollment tokens are refused (`quota_exceeded`), existing nodes unaffected |
| Active nodes per event | 100 | token creation refused for that event |
| Archived events with retained data | 10 | archive refused unless older archived data is purged |
| Archived + active retention storage | DB budget in the table above; hard alarm when DB > 80 % of its allocated budget | degraded mode per §3; archive/purge required before further retention growth |
| Events (total catalog) | 50 | create/rename refused until purge |
| Total retention overlap | ≤2× active-only DB estimate (policy B cap) | archive refused when adding the tail would exceed the cap |


Policy A: ~5–6 GB. Policy B worst case: ≤2× ≈ **10–12 GB** plus indexes/overhead
(~12–14 GB). At the 500-node UM-E stress with policy B: ~30 GB — **above the
40 GB budget when backups are included**, so either the stress target is smaller,
the disk is enlarged, or PostgreSQL/retention tuning is decided by the owner. This
is explicitly a design gate, not an assumption that 500 nodes fit on 40 GB.

40 GB disk budget (200 nodes, policy B worst case):

| Item | Budget |
| --- | --- |
| OS + packages + binary + logs | ≤8 GB |
| SQLite DB (policy B worst case) | ≤14 GB |
| WAL + temp (bounded checkpoint) | ≤1 GB |
| Backups (2 local, compressed) | ≤6 GB |
| Headroom / growth | remaining ≈11 GB |

Alarm thresholds: warn at 70 % used; granularity degradation at 80 %; stop
client summaries at 90 %; emergency latest-only at 95 %. No backup may fill the
disk below the emergency floor; a failed backup is reported, not silently
overwritten.

Ingest load: 200 nodes × ~2 requests/min ≈ 6.7 req/s steady; a single small center
is sufficient. `synchronous=FULL` adds one fsync per report; at this rate it is
well within the performance budget (doc 06); UM-B must measure p95 commit latency
and, if needed, use SQLite group commit **only** if every ACK still follows a
durable commit.

## 5. Database gate (SQLite → PostgreSQL)

v1: SQLite WAL, single writer process, `synchronous=FULL`. PostgreSQL migration
(its own reviewed phase) when any is measured/decided:

| Trigger | Threshold |
| --- | --- |
| Sustained write rate | >50 writes/s for 1 h at the planning ceiling |
| DB size | >24 GB with the retention contract intact (policy B on 40 GB disk requires owner sizing first) |
| Write latency | p95 durable commit >50 ms for 1 h |
| Concurrency | separate processes must write concurrently |
| Availability | multi-instance/replica/HA required |
| Operational | SQLite corruption/lock incident not structurally preventable |

## 6. Backup and restore

### 6.1 RPO/RTO (split by failure class; owner decision Q-BACKUP)

| Failure | Data loss target (RPO) | Recovery time (RTO) |
| --- | --- | --- |
| Center process crash / bad deploy | 0 (committed data survives via WAL FULL + pre-migration snapshot) | <30 min |
| Center host disk/host failure (same VPS restorable) | ≤24 h if the latest **verified backup can be restored from the local/off-host copy** | ≤2 h |
| **Whole VPS permanently lost** | **must be agreed by the owner.** If the owner requires ≤24 h, the center must push a daily encrypted backup to owner-controlled storage (or the owner pulls daily); a weekly manual pull implies **RPO = 7 d** for whole-VPS loss and must be stated that way, not as 24 h. | ≤1 business day with owner-provided host |

Frozen minimum without new credentials: local/failure RPO 24 h; whole-VPS RPO =
last owner off-host copy. A daily off-host copy is the recommended owner decision
(push to owner-controlled storage with a restricted write-only credential, or
owner daily pull); it must not store center/VPS credentials.

### 6.2 Backup mechanics

- Nightly (and pre-migration) SQLite consistent backup (`VACUUM INTO`/backup API),
  `integrity_check`/`quick_check` + schema/table-shape check, SHA-256 manifest,
  compressed, then encrypted before leaving the center host (owner-held key; age
  or AEAD tooling chosen in UM-E).
- Local retention: 2 verified compressed backups (≤6 GB total at 200 nodes).
- Off-host: owner-decided (see §6.1); owner verifies and retains. If a daily push
  is selected, the center holds only a write-only/duplicate-preventing
  destination credential — never a VPS/root credential.
- Backups exclude node private keys (never at center), tunnel token, master key
  and session/CSRF tokens. TOTP secrets are inside the DB encrypted with the
  master key; restore therefore requires the separately stored master key.
- Restore drill: at least once per phase UM-E, after every schema migration, and
  before production authorization; measure actual RTO and record it.

### 6.3 Security ledger and restore quarantine (P1-11)

A restore is a point-in-time rollback and can resurrect identities/data revoked
or purged after the backup was taken. The ledger is the authority for
revocation/purge facts across restores.

**A verifiable copy is not the latest copy.** A backup/ledger whose chain and
signature verify only proves internal consistency and a known prefix; it does not
prove that it is the newest security state. After a whole-machine loss, if the
operator cannot prove ledger completeness/latestness (e.g. only an older verifiable
backup exists and the newest off-host copy/checkpoint cannot be authenticated),
the restore MUST stay in quarantine and no node permissions are restored merely
because an old backup is signature-valid. Actual off-host storage selection and
restore drills are scheduled in UM-E.

Ledger properties (frozen):

- Append-only `security-ledger.jsonl`, one canonical JSON record per line with
  fields `{seq (monotonic 1..), at, actor_type, actor_id, action closed enum,
  target closed fields, result, prev_hash, record_hash}`; `prev_hash` chains the
  previous record and `record_hash = SHA-256(canonical record without
  record_hash)`. The file ends with a signed checkpoint (center master key) over
  the last `seq`/`record_hash`; checkpoints are periodic and at every backup.
- **Durability/order**: a security mutation (node/key revoke, event archive/purge,
  admin credential/role change) appends the ledger record and fsyncs the file
  **before** the corresponding DB transaction commits and before the admin
  response is returned. The DB transaction later records the same operation in
  `audit_log`; if the process dies between ledger fsync and DB commit, the
  operation is retried idempotently from the persisted ledger seq (no duplicate
  effect; ledger append is idempotent by `(seq, record_hash)`).
- Every backup and every off-host copy includes the ledger file plus the latest
  signed checkpoint; the backup manifest records ledger last `seq`/`record_hash`.
- **Latest-version determination**: compare `(seq, record_hash)` plus the signed
  checkpoint; a ledger whose chain/checkpoint does not verify is invalid. The
  newest valid ledger (prefer off-host) is authoritative.
- **Offsite restore**: restore starts in **quarantine** (ingest disabled, web
  maintenance, no agent traffic). The restored DB backup's ledger suffix is
  compared with the newest valid ledger; missing/unverifiable ledger ⇒ remain
  quarantined and require owner decision — never auto-enable ingest.
- Replay ledger events newer than the backup (or at minimum re-apply listed
  revocations/purges) before ingest is re-enabled. If the operator cannot prove
  ledger completeness, the restore remains quarantined (fail-closed).
- Restoring a backup that predates a purge requires explicit owner confirmation
  and is audited; purged data may only reappear with that approval.
- Restored identities whose revocation cannot be disproven are treated as revoked
  until proven otherwise; a restored node must re-prove its key (report) and any
  ledger revocation of that key still applies.

### 6.4 Center self-monitoring

Loopback-only health: DB open/WAL, last retention success, last backup success +
integrity, disk free, ingest queue depth, auth failure rate, clock offset —
closed codes only. Owner alerts for disk ≥70 %, 2 consecutive retention failures,
backup failure, node stale >15 min, ingest 5xx rate, repeated signature failures,
purge/restore events. UM-E must run an accelerated 30-day retention cycle and a
restore+ledger drill before production authorization.

## 7. Non-goals

No indefinite raw telemetry, no connection-level history, no raw packet/log
storage, no per-client credentials or YAML; no PostgreSQL/HA/object storage switch
without a new owner-approved design; no backup of VPS root credentials (none
exist centrally).
