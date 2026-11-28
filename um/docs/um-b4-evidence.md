# UM-B4 evidence and verification record (Draft)

PR: #133 (Draft, Refs #127)
Branch: `codex/um-b4-management`
Base: `da8173317aa6b6395a5e002ea4a89dac3fe4fd5e` (rev-6 main)
Reviewed HEAD: the final PR head on `codex/um-b4-management`; exact CI/lab
runs and review records are on PR #133. Independent review found no P0/P1 and
approved the runtime change set for Draft PR status.

## 1. Implementation evidence

- `um/internal/management/` — service layer, local auth, RBAC, strict admin
  handler, CLI HTTP client, typed models, OpenAPI route inventory.
- `um/internal/store/b4.go`, `b4_audit.go`, `b4_purge_auth.go`, migrations
  v9/v10 — management reads,
  event/node/token/alias/audit/mapping/purge/retention store additions; B2/B3
  engines reused.
- `um/internal/center` — optional admin API mounted on the isolated admin
  listener; ingest listener unchanged.
- `um/cmd/um-center` — authenticated management CLI (`admin` subcommand) and
  serving flags (`--admin-auth-file`).
- `um/docs/um-b4-admin-api.openapi.json`; architecture/runbook/migration/scope
  and data-source investigation docs.

## 2. Real E2E tests

`um/internal/management/e2e_test.go`, `security_test.go`, `purge_test.go` and
`cmd/um-center/admin_cli_test.go` use:

- real `center.Server` HTTP listeners + real SQLite;
- real B3 `agent.Runtime` for `linux_vps` and `windows_terminal`;
- two independent events A/B;
- the real management HTTP API and real CLI command function.

Verified:

- real Linux agent enrolls with a scoped one-time token, pulls config, sends
  snapshot/metrics/events accepted by the center;
- real Windows agent enrolls, pulls class-valid config, sends snapshot/events
  with terminal/active-connection data `unavailable` where the R1 source is not
  enabled;
- node list/detail includes latest snapshot, keys and derived status; aliases
  appear on the node view;
- mapping v1/v2 created at distinct effective times; historical resolution at
  each time returns the corresponding Linux VPS target and not the current one;
- event_admin A cannot read event B (404), viewer cannot mutate token/audit;
- admin CLI event create/list/show/rename and health/capacity/retention use the
  HTTP management API and return non-zero on a missing event;
- Event B archive + purge preview + exact confirmation + durable graveyard;
  repeated purge is idempotent; Event A remains independent; purged event cannot
  be recreated or token-created; purge audit exists;
- revoked enrollment token is rejected by a real agent enrollment;
- `singbox_api:true` and `mihomo_api:true` are rejected by center config; class
  rules and token plaintext privacy checks pass.

## 3. Local verification commands

```bash
cd um
gofmt -l .
go test ./... -count=1
go vet ./...
go mod verify
GOOS=linux GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
```

Last local run: all packages PASS; vet/build/mod verify PASS.

Exact-HEAD evidence:
- Full CI run `46084342391`: 35/36 lanes pass, including native
  Linux/Windows unit/conformance/coverage and B4 management tests. The remaining
  `windows-exe` lane is the pre-existing unrelated Python frozen-EXE process
  enumeration lane; reruns after its process-identity flake
  (`QueryFullProcessImageNameW ... winerror=5`) are recorded on PR #133; it does
  not exercise `um/**` or B4 code and is not modified by B4. All B4-relevant
  lanes pass.
- UM-B3/B4 isolated lab run `46084337257` at `fe702754` is **all green**:
  `linux-systemd-agent-lab`, `windows-service-r1-lab`,
  `linux-singbox-serviceapi-lab`, `b4-management-e2e`, and both environment
  probes. The B4 labs now create event/token through the authenticated
  management API (no removed direct-store `-issue-enroll-token` flag).
- Independent review of `b4aee666` found four P1 issues (lab CLI JSON shape,
  revoked-token 503, invalid/inconsistent OpenAPI, duplicate-event 500) and
  material P2 issues. All were fixed in `fe702754`. A follow-up review of
  `fb499a5e` confirmed all P1/P2 fixes and returned **no remaining P0/P1;
  clear/approved for Draft PR status**. Its residual P2 OpenAPI field-fidelity
  findings (mapping create response, mapping entries array, config/event/node/
  token fields, request constraints) were then fixed and guarded by a
  reflection test comparing every public JSON DTO with its OpenAPI schema.
- Final lab dispatch `46088111556` at `04480ef6` is all green, including
  `b4-management-e2e`, Linux systemd agent, Windows R1 and serviceapi. The
  same HEAD adds the required audit time-range filter (`since`/`until`) and its
  OpenAPI/CLI/tests; final independent review found no P0/P1 and approved it
  for Draft PR status.

## 3.1 Final security closure (purge receipt + audit retention)

Red-first evidence: the new management tests initially failed because
`purge/preview` returned no server receipt and `RunRetentionB2PolicyB` never
deleted `admin_audit` rows. After the minimal fixes:

- Purge preview now returns a 5-minute single-use `preview_id` /
  `preview_expires_at`; `purge/confirm` requires it for a first start. The
  receipt is bound to authenticated actor, event, `event_purge`, and the preview
  lifecycle fingerprint (state/archive/purge/data/catalog update time), and is
  consumed in the same transaction that persists the durable purge operation.
- Real HTTP tests cover missing/wrong event/wrong actor receipts, viewer and
  event_admin rejection, expiry, preview-to-archived state change, concurrent
  replay, completed-idempotence after expiry, and safe resume of an
  already-persisted operation after an injected crash and receipt expiry.
- Store-level `TestB4PurgeConfirmed50kResume` exercises the challenge-aware path
  through the existing B2 engine: 50,005 rows, a batch-boundary interruption,
  restart/resume without a live receipt, exactly one purge operation, exact
  `deleted_rows=50005`, one security-ledger entry, and no remaining receipts.
- `admin_audit` is now included in the bounded policy-B sweep at the frozen
  `SecurityRetentionSeconds` (180d): strict `at < cutoff`, ≤50,000 rows per
  transaction, age-only deletion, interrupted/repeat runs idempotent,
  archived/purged event audit preserved while unexpired, and security ledger
  unaffected. Capacity output exposes `admin_audit` row count.
- v10 adds only the `purge_confirmations` table/indexes; the durable purge
  operation, graveyard, tombstone, ledger and B2 recovery semantics are
  unchanged.

## 4. Migration/privacy/security notes

- v9 is additive (event display names, token revoked_at, admin_audit, aliases,
  indexes); v10 adds only purge confirmation receipts; v1–v8 untouched; one
  transaction per migration.
- Admin auth file and CLI token file are protected files; raw tokens never in
  SQLite/logs/audit/API list.
- Mutations append audit rows inside their transaction; denied attempts are
  audited; critical security changes reuse the hash-chained ledger.
- No token/private key/controller secret/proxy name/raw user traffic in admin
  responses or audit.
- `singbox_api` remains disabled/unavailable; R1 remains local-bundle-only and
  production HOLD.

## 5. Known limitations / HOLD

- No UM-C Web UI/login/TOTP/session/CSRF/public ingress.
- Admin listener is loopback-only in this release.
- No production deployment/real VPS/SSH/tournament terminal/Cloudflare/R1.
- Linux Reality/Hysteria2 real traffic collection remains a pre-production
  functional blocker on #127 (see `um-b4-data-source-investigation.md`).
- Backup/restore, VACUUM/disk-pressure and offsite ledger acceptance remain UM-E.
- Formal Codex review ran successfully through the Codex auto-review model
  after local CLI account/model incompatibility was worked around. It found two
  P1s: archived-event alias **deletion** bypassed the event lifecycle gate, and
  the central `Authorize` matrix still let viewers through the audit-read action
  before the service's explicit denial. Fixed by applying the active-event
  transaction gate to both alias writes and restricting `audit_read` to
  platform/event admins in the central matrix, with archived-alias-delete and
  viewer-audit regression coverage. Final Codex re-review at the fixed HEAD found
  **no discrete actionable regressions** (full Go suite ok). A non-Codex
  independent review was also run; its P1/P2 findings were fixed and it cleared
  the runtime change set for Draft PR status.
