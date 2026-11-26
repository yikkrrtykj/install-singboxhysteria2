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
  rotation lifecycle/abort/admin revoke, authenticated ingest transaction
  rollback, snapshot latest ordering, retention physical pruning (seq 256,
  boot 8), 30-day archive, node_boot preserved, repeatable retention, capacity
  stats, and security-ledger entries for token/config/rotation state changes.

## Retention / capacity

Implemented in `RunRetentionB2`:

- seq_dedupe: physically keep latest 256 entries of the current generation;
- boot_registry: keep latest 8 generations;
- nonce 24 h, report_dedupe 8 days, report_activity 30 days;
- active snapshots/metrics/events archived after 30 days, archive retained a
  further 30 days, latest pointers never point at deleted snapshots;
- **node_boot is never deleted**;
- each run recorded in `retention_runs`; the sweep is repeatable.

This is a bounded smoke/capacity test, **not** a 200-node performance SLA and
not real-event acceptance. Full capacity/performance gating remains UM-E.

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
