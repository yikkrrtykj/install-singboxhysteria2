# UM-B2 conformance and delivery map (Draft)

- Base B1: merged PR #129 / main `ceca20d9260f95badef774466ae15383fe1dd62a`
  (approved B1 HEAD `dcf97a41`, tree `805d30a4`), main CI 6/6 green.
- B2 branch: `codex/um-b2-center`; one independent Draft PR linked to #127.
- Frozen contract: UM-A rev-5 (`docs/um/contracts/v1/**` unchanged).
- This map reports only **actually executed** checks. B3-owned REC-17/18/27 remain
  deferred and are not counted as PASS.

## Delivered B2 modules

| Area | Location |
| --- | --- |
| Center process / flags / graceful shutdown | `cmd/um-center/main.go` |
| Isolated HTTP ingest + admin planes, strict headers/encoding/body caps, rate limiting, closed errors | `internal/center/{api,server,headers,body,ingest,response,ratelimit}.go` |
| Real auth/enrollment/rotation/report service path | `internal/center/service_impl.go` |
| B2 store schema/migrations (enrollment, configs, snapshots/latest, metrics, events, archive, retention runs) | `internal/store/{schema,b2}.go` |
| Real listener + SQLite + synthetic agents tests | `internal/center/integration_test.go` |
| B2 REC 16 tests through HTTP/SQLite | `internal/center/b2_conformance_test.go` |
| Concurrency/load/sustained smoke | `internal/center/load_test.go` |
| Store retention/capacity/enrollment/rotation tests | `internal/store/b2_test.go` |

## B2 REC execution matrix (16/16 executed)

| REC | Scenario | Executed by | Result |
| --- | --- | --- | --- |
| REC-03 | Lost ACK, new seq, same report_id | `TestB2REC03LostACKDuplicate` | duplicate, high-water advanced |
| REC-04 | Restart; first new-generation report is duplicate | `TestB2REC04NewGenerationFirstReportDuplicate` | duplicate; new-gen high-water committed |
| REC-05 | Two offline restarts (gap 2) | `TestB2REC05GenerationGap` | accepted |
| REC-06 | Oldest-first spool replay / no loss | `TestB2REC06SpoolReplayOldestFirst` | accepted + duplicate; latest not overwritten |
| REC-10 | Delayed lower-seq superseded attempt | `TestB2REC10DelayedLowerSequenceConflict` | 409 sequence_conflict |
| REC-13 | Multiple lost ACKs / adopt next_seq | `TestB2REC13ACKNextSeqReconciliation` | accepted, monotonic next_seq |
| REC-15 | 503 first attempt then retry | `TestB2REC15AbortedTransactionThenRetry` (injected 503) | 503 then accepted; no high-water from failure |
| REC-16 | Non-retryable payload error, next record | `TestB2REC16NonRetryablePayloadThenNextRecord` | 400 then accepted first contact |
| REC-19 | Rotate intent across two restarts | `TestB2REC19RotateIntentAcrossRestarts` | identical response; high-water committed |
| REC-20 | Rotate intent expired | `TestB2REC20RotateExpired` | 409 rotation_expired |
| REC-21 | Revocation during backlog | `TestB2REC21RevokedDuringBacklog` | 401 revoked_key |
| REC-22 | First contact is config pull seq>1 | `TestB2REC22FirstContactConfig` | 200 agent-config |
| REC-23 | First contact is rotate | `TestB2REC23FirstContactRotate` | 200 rotate-response |
| REC-24 | Enrollment response lost / token replay | `TestB2REC24EnrollmentResponseLoss` | 401 token_used; orphan revoke path |
| REC-29 | Older snapshot after newer latest | `TestB2REC29StaleSnapshot` | stale_ignored; latest unchanged |
| REC-30 | Interleaved spool across generations | `TestB2REC30InterleavedGenerations` | gen2 accepted; old gen stale_boot_generation |

B1 regression: the existing `internal/conformance` suite (11 executed B1 RECs,
REC-29 deferred in the B1 map, 18 B2/B3 deferred) remains green in the same
`go test ./...` run. B1's negative-vector subset also remains green.

## Applicable rev-5 behavioural negative coverage

- Boundary: `internal/center/http_test.go` (39 test functions) covers duplicate
  and unknown headers, missing headers, header grammar, content type, encoding
  mismatch, gzip/trailing data, compressed/decoded body caps, strict JSON,
  config body shape, request schemas, method/path isolation, rate limiting and
  error vocabulary.
- Service: bad signature, stale timestamp, platform mismatch (Linux terminal /
  Windows metrics), nonce reuse (rotate intent refresh), revoked key, token
  scope/reuse/expiry, oversized/duplicate-header cases are exercised through the
  real HTTP path in `internal/center/*_test.go`.
- Privacy sentinel semantics remain covered by `internal/contract` and are
  applied by the B2 service before storage.

## Real HTTP / SQLite evidence

- `TestCenterCommandProcessStartStop`: builds and runs the real `cmd/um-center`
  binary with real listeners and SQLite, checks admin health, verifies ingest
  plane does not serve admin paths, and stops the process gracefully (or kills
  it on Windows where os.Interrupt is not deliverable).
- `TestServerStartShutdownRealListeners`: real loopback ingest/admin listeners,
  actual `Start`/`Shutdown`, plane isolation.
- `TestB2CenterEnrollmentTelemetryRotation`: enroll → config → Linux
  snapshot/metrics/events → latest/stale ordering → rotate intent/replay/proof →
  old-key revocation → platform isolation, all over HTTP against real SQLite.
- `TestB2CenterWindowsTerminalFlow`: Windows enrollment, config terminal source,
  terminal snapshot storage, Windows metrics rejection.
- `TestB2CenterRestartPersistence`: close/reopen SQLite and center; committed
  report dedupe/high-water/latest survive; duplicate after restart.
- `TestB2ConcurrentDuplicateReport`: concurrent same-report race stores exactly
  one snapshot.
- `TestB2CrossEndpointNonceReuseRejected`: a nonce used on config is rejected as
  nonce_reuse on report.
- `TestB2PrivacySentinelRejectedBeforeStorage`: planted credential sentinel is
  rejected before storage; no snapshot row is written.
- `TestB2EnrollmentTokenConcurrentSingleUse`: concurrent enrollment with one
  token creates exactly one node; the loser gets token_used.
- `TestB2SyntheticLoadSmoke`: 2 synthetic events, 4 Linux VPS + 30 Windows
  terminal identities, real HTTP + SQLite.
- `TestB2SustainedSyntheticAgent`: 10 sequential reports, high-water and
  snapshots advance.
- `internal/store/b2_test.go`: enrollment single-use/scope/expiry/concurrency,
  rotation lifecycle/abort/admin revoke/state integrity, authenticated ingest
  transaction rollback, snapshot latest ordering, policy-B event lifecycle with
  exact T+30d boundaries and multi-event archive times, bounded seq/boot pruning,
  node_boot preservation, fault injection without source-data loss, degraded
  retention state, quotas, event normalization (one report payload + normalized
  event rows with severity), capacity/WAL statistics and security-ledger entries.

## Retention / capacity — policy B (review correction)

`RunRetentionB2` now implements the frozen policy B with an event lifecycle
instead of a per-table archive copy:

- **Active event**: rolling 30 days by `collected_at`; older rows are deleted;
- **Archive at T**: `event_catalog` becomes archived, ingest is closed, and the
  remaining data stays in its own tables until T+30d (no second copy, no
  LIMIT-1 data-loss path);
- **T+30d**: all event telemetry is deleted; the catalog row survives until an
  explicit purge (B4 UI), which writes a content-free 180-day tombstone;
- **node retire** never shortens event history; latest state is removed 30 days
  after its last update or 30 days after node retire;
- seq_dedupe: current generation latest 256 rows, **old-generation rows are
  deleted** (retired generations are rejected by the persistent generation
  high-water, not by registry presence); boot_registry keeps the last 8
  generations; node_boot is never deleted;
- nonce 24h, report_dedupe 8d, report_activity 30d;
- deletion is bounded to **50,000 rows per transaction**, resumable/idempotent;
  `retention_runs` itself is bounded to the latest 100 runs; soft failures set
  `retention_state.degraded`/`failure_count` without deleting unprocessed data;
- latest pointers are removed before their snapshots to preserve FK integrity.

Tests: `TestB2RetentionPhysicalPruning`,
`TestB2PolicyBEventLifecycle`,
`TestB2PolicyBMultipleArchiveTimesAndExactBoundary`,
`TestB2ArchiveMultipleReportsNoLoss`,
`TestB2ArchiveAndRetentionFaultLeavesDataIntact`,
`TestB2RetentionFailureDegradedAndIdempotent`,
`TestB2QuotaRefusesNewEnrollment`, `TestB2QuotaPerEventAndCatalog`,
`TestB2ArchivedEventQuota`, `TestB2EventStorageNormalizationAndCrossTypeConflict`.

Capacity gates (frozen planning defaults): 150 active nodes total, 100 active
nodes per event, 10 archived events with retained data, 50 event-catalog rows.
New token/enrollment/archive operations check these under the SQLite capacity
lock; quota failures are typed and do not write partial state. The DB/WAL/row
growth snapshot is exposed by `CapacityStatsExtended`; this is a bounded smoke,
not a 200-node performance SLA or real-event acceptance (UM-E).

## Deferred / not claimed as PASS

- REC-17/18/27 (UM-B3 agent boot-state/power-loss) remain deferred.
- No real Windows Service, real Mihomo Controller, VPS, Cloudflare, production
  credentials or production deployment.
- UM-B4 mapping management API/audit, full telemetry-to-mapping UI association;
  B2 preserves the immutable mapping basis only.
- UM-C public login and Cloudflare ingress configuration not implemented.
- Signed checkpoints, offsite backup and full-machine restore validation remain
  UM-E; `VerifyChain` is not recovery authorization.
- The B2 smoke load is synthetic; it is not a production performance/security
  acceptance.


## B2 review correction matrix (P0/P1)

| Finding | Fix/evidence |
| --- | --- |
| P0-01 events archive LIMIT-1 data loss | no archive copy; live event rows governed by catalog lifecycle; multi-report/metrics/events + multi-event archive tests; fault injection before writes/scan/delete leaves source intact |
| P1-02 real policy B | `event_catalog`, archive at T, T+30d tail deletion, catalog survives until purge, tombstone; two events with different archive times, exact boundary, restart/idempotent runs, ingest/enrollment rejected after archive, node retire keeps history |
| P1-03 physical capacity | old-generation seq rows deleted; current 256; boot 8; 50k per-transaction batches; degraded/failure counters; retention_runs bounded; 150/100/10/50 quotas under capacity lock; DB/WAL/row growth stats |
| P1-04 key/rotation integrity | ConfirmRotationTx invalid states are typed errors; revoking either side revokes provisional counterpart and aborts intent; node vs key revoke separated; provisional key proof only via in-transaction auth; tests |
| P1-05 ACK/transaction | Report uses the committed transaction's `result.NextSeq` (no post-commit GetBoot); exhaustion only when protocol says null; success/config/rotate response construction validated before commit where applicable; real transaction fault test confirms nonce/report/boot/seq/telemetry rollback |
| P1-06 config/telemetry auth | config class/source/tag/cadence validation before persistence; report reads config inside transaction; current disabled-source data rejected, historical spool accepted; snapshot/metric/event tag bindings; no new report fields |
| P1-07 enrollment freshness | enroll now enforces ±300s; stale/future/boundary/bad-signature tests; token not consumed on pre-commit failures; concurrent token single-use |
| P1-08 rotation/audit | expired awaiting intents aborted before new rotation; same-nonce retry rotation_expired; nonce check before boot/seq conflict; boot_generation_gap ledger; privacy rejection audit; no secret/payload logging |
| P1-11 telemetry/resource | events report payload stored once + normalized event rows with severity; report-id cross-type conflict; capacity/WAL growth stats; global in-flight concurrency bound; machine/admin listener isolation |

## Deferred confirmation

B3 REC-17/18/27; complete management API/UI and type-to-confirm purge (B4);
Cloudflare/UM-C public ingress; signed checkpoints, offsite backup, restore
drills and 200/500-node capacity/performance acceptance (UM-E). UM-F DEFERRED,
production HOLD.


## Round-8 targeted fixes (F1–F7)

| Finding | Implementation | Evidence |
| --- | --- | --- |
| F1 purge lifecycle/immutable mappings | durable `purge_ops` persisted before deletion; triggers allow only mapping/finalizing purge state; purging blocks ingest/enrollment/token/config/rotation/mapping; resumable/idempotent; progress/actor/counts; final tombstone+audit; failure stays fail-closed | `TestB2PurgeWithMappingsAndPermanentGraveyard`, `TestB2PurgeRecoveryAndFaults`, `TestB2PurgeBlocksIngestAndEnrollmentConcurrently` (real SQLite, faults after batch, mapping, tombstone, restart) |
| F2 permanent identity isolation | permanent `event_graveyard` separate from 180-day audit tombstone; event gate checks graveyard/incomplete purge; purge revokes old nodes/keys and keeps old high-water; token issuance cannot recreate | same tests + `EventGraveyardExists`, tombstone-expiry token rejection, old node/key revoked |
| F3 capacity/retention boundaries | active quota joins active event lifecycle; archived events stop consuming active quota; conservative 2x active-only payload overlap gate; deterministic rowid batches; `rows.Err`; retention_runs off-by-one fixed (keeps 100); per-event lifecycle re-read; latest/FK tests; DB/WAL/payload/tx growth log | `TestB2RetentionRunsBoundedAndLatestFK`, `TestB2Quota*`, capacity smoke t.Log |
| F4 config authorization history | append-only `node_config_history`; Report validates against config effective at collected_at; never-enabled source cannot borrow later authorization; tag/source boundaries; synthetic legacy tests explicitly configure effective epoch policy | `TestB2F4NeverEnabledSourceCannotBorrowLaterAuthorization`, `TestB2F4TagChangeBoundaryAndHistoricalSpool`, existing source-switch/Windows tests |
| F5 endpoint permissions/rotate | endpoint-specific auth: Report allows provisional proof; Config/Rotate require active old key; frozen §7 boot/seq before nonce; no post-commit config reread; expiry equality consistent | `TestB2F5ConfigRejectsProvisionalKey`, `TestB2F5RotateBootSequenceBeforeNonce`, `TestB2RotationExpiryEqualityBoundary` |
| F6 report identity/audit | cross-check report id across dedupe + all 30-day telemetry tables; expired dedupe cannot change type/body; rejection audit for nonce_reuse/report_conflict/validation; audit write failure returns retryable storage error | `TestB2F6ReportIdentityAcrossDedupeWindow`, red logs |
| F7 REC evidence | existing 16 real HTTP/SQLite tests retained; B2 tests load normative REC JSON expected HTTP/result/error and high-water (`highest_gen`/`last_seq`) assertions, multi-attempt REC-06/30, transaction-fault REC-15, byte-identical restart replay REC-19; B3 local-agent behavior explicitly not claimed | `b2_rec_fixture_test.go`, `b2_conformance_test.go` |

Windows harness: attempt 1 of run 45837003465 failed with the known
`PROCESS_ENUMERATION_FAILED`/winerror=5 flake; same-HEAD attempt 2 passed. Harness
unchanged; deferred as a separate issue.

Still deferred: B3 REC-17/18/27, B4 management UI/type-to-confirm purge, UM-C
ingress, UM-E full disk-pressure/200-500 node performance/backup/restore.


## Round-9 correction gate (C1–C4)

| Finding | Implementation | Evidence |
| --- | --- | --- |
| C1 mapping gate/durable purge | `createMappingVersion` now runs `EventActiveTx` inside its transaction; the false-positive purge test was replaced with public `CreateMappingVersion` future `effective_from`, asserting active success and purging/purged lifecycle rejection; one incomplete `purge_ops` per event via partial unique index under capacity lock; DELETE batch + `deleted_rows` committed atomically; resume preserves progress; final completion guarded against duplicate tombstone/audit | `TestB2PurgeBlocksIngestAndEnrollmentConcurrently`, `TestB2PurgeSingleIncompleteOperation`, `TestB2PurgeBatchProgressSurvivesRestart`, ordinary UPDATE/DELETE mapping tests |
| C2 enrollment response legality | production token creation enforces canonical UUIDv4 event id; Enroll defensively checks pre-existing token event id before consumption; invalid token test proves no consumption/partial node/key/config; SPKI static form checked before store commit | `TestB2EnrollmentEventIDUUIDv4`, red C2 log |
| C3 overlap budget | explicit `OverlapBudget`/`ComputeOverlapBudget` in bytes: 5 GiB active-only planning basis, 10 GiB 2× **active+archived total** budget; candidate moved from active to archived without double count; below/equal/above, last-active and post-archive-active tests | `TestB2OverlapBudgetFormula`, `TestB2OverlapBudgetArchiveBoundary`, red C3 compile log |
| C4 config authorization closure | effective-dated history fail-closed when no valid row; v8 migration re-anchors v7 backfill to fail-closed initial config at registration; UpdateNodeConfig rejects effective time before registration/latest history, same-second deterministic version rule; Windows selection vs active_connections independent terminal/mihomo checks; service vs singbox event kinds independent; Report uses historical config for validation and current in-transaction config version for ACK; nonce audits consistent across Report/Config/Rotate; no epoch backfill HTTP fixtures | `TestB2ConfigHistoryBoundsAndFailClosed`, `TestC4WindowsTerminalAndControllerSourcesIndependent`, `TestC4HistoricalConfigAndCurrentACKVersion`, `TestC4LinuxServicesAndSingboxApprovalIndependent` |

Round-9 red evidence: `um127-round9-evidence/b2-round9-red-store.log`,
`b2-round9-red-c3.log` (pre-fix `bc892591`: mapping during purging succeeded,
invalid event id token accepted, backdated config accepted, explicit budget
absent). Green: `full-v-green.log`.

Still deferred: B4 management UI/type-to-confirm purge, B3 REC-17/18/27 and
agent-local behavior, UM-C ingress, UM-E disk-pressure/200–500-node performance
and backup/restore.


## Final hotfix H1–H3

| Finding | Fix/evidence |
| --- | --- |
| H1 Windows default snapshot | terminal source validation now checks object existence: absent terminal object is legal (default false/false); present object with both sources false is rejected; selection/active_connections remain independently authorized. Real HTTP matrix test uses a true default enrollment (no auto-enable helper): false/false no terminal accepted, false/false with terminal rejected, true/false selection ok + controller honest unavailable, false/true inverse, true/true legal |
| H2 purge executor/progress | per-event in-process purge lock serializes execution; `updatePurgeOp` never writes `deleted_rows` and only advances state/phase forward (otherwise error/update only); final audit reads persisted deleted_rows inside final tx; completed op without graveyard is refused rather than recreated; 50,005-row two-concurrent-call test asserts exact progress, one completed op/graveyard/tombstone/event_purged audit, no incomplete ops and idempotent repeat |
| H3 overlap total | 5 GiB active-only planning basis, 2× = 10 GiB applied to projected **active+archived total**; candidate moved from active to archived (no double count); post-archive active data included in later decisions; below/equal/above, last-active and post-archive tests; planning budget not disk limit |
