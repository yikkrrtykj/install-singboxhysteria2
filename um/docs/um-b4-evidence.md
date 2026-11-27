# UM-B4 evidence and verification record (Draft)

PR: #133 (Draft, Refs #127)
Branch: `codex/um-b4-management`
Base: `da8173317aa6b6395a5e002ea4a89dac3fe4fd5e` (rev-6 main)

## 1. Implementation evidence

- `um/internal/management/` — service layer, local auth, RBAC, strict admin
  handler, CLI HTTP client, typed models, OpenAPI route inventory.
- `um/internal/store/b4.go`, `b4_audit.go`, migration v9 — management reads,
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

Last local run: all packages PASS; vet/build/mod verify PASS. CI/race/coverage
and exact-HEAD lab evidence are recorded on PR #133 and will be bound to the
final reviewed HEAD before the final status claim.

## 4. Migration/privacy/security notes

- v9 is additive (event display names, token revoked_at, admin_audit, aliases,
  indexes); v1–v8 untouched; one transaction per migration.
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
- Formal Codex review may be quota-blocked; independent review/quota record is
  required and must not be represented as Codex completion.
