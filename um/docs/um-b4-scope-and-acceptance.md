# UM-B4 scope and acceptance matrix (Draft)

Status: **UM-B4 Draft PR** (Refs #127). No merge, public ingress, production
deployment or UM-C+ work is authorized by this document.

## 1. Module status

| Module | Scope | Implementation | Evidence/status |
| --- | --- | --- | --- |
| B4.1 | Management service layer, admin boundary/inventory, fail-closed local auth, RBAC foundation, audit foundation | `internal/management`, `internal/store/b4*.go`, `internal/center` admin hook | unit + real HTTP tests; auth/RBAC/audit tests PASS |
| B4.2 | Event create/list/detail/rename/archive/purge preview-confirm-status, counts, lifecycle gates | `management.Service` + store B4 methods + existing B2 lifecycle/purge | real HTTP lifecycle/purge tests PASS; no second engine |
| B4.3 | Node list/filter/detail, derived status, aliases display, keys/rotation metadata, revoke, enrollment token create/list/status/revoke | management + existing B2 enrollment/revocation | real Linux/Windows agent E2E PASS; revoked-token enrollment rejected |
| B4.4 | Effective-dated agent config read/history/update; source/class validation; no unauthorized source enablement | management + existing B2 config engine | positive/negative source tests PASS |
| B4.5 | Append-only route mapping list/create/resolve; same-event/class validation; historical resolution | management + existing store mapping engine | real two-event E2E historical mapping PASS; invalid target/version tests PASS |
| B4.6 | Retention/capacity/audit visibility, bounded maintenance trigger; aliases; purge safety | management + existing B2 retention/purge | real purge isolation/idempotence tests; store lifecycle tests PASS |
| B4.7 | Admin HTTP API, OpenAPI, management CLI, E2E/security/final acceptance | `management.Handler`, `cmd/um-center/admin_cli.go`, docs | spec/inventory test; CLI real HTTP test; full suite/CI/lab pending final HEAD |

## 2. API inventory

The machine-readable API is `um/docs/um-b4-admin-api.openapi.json` (OpenAPI
3.0.3, 26 paths / 32 operations). `management.AdminRouteInventory()` is checked
against the spec by `TestOpenAPISpecMatchesRouteInventory`.

| Group | Operations |
| --- | --- |
| Health | `GET /api/v1/health` |
| Events | `GET/POST /events`; `GET/PATCH /events/{id}`; `POST /archive`; `GET /purge/preview`; `POST /purge/confirm`; `GET /purge/status` |
| Nodes | `GET /events/{id}/nodes`; `GET /nodes/{node}`; `POST /revoke` |
| Enrollment | `GET/POST /events/{id}/tokens`; `GET /tokens/{token}`; `POST /tokens/{token}/revoke` |
| Config | `GET/PUT /events/{id}/nodes/{node}/config`; `GET .../config/history` |
| Aliases | `GET /events/{id}/aliases`; `PUT/DELETE /aliases/{type}/{key}` |
| Mapping | `GET/POST /events/{id}/mapping/{windows}`; `GET .../resolve` |
| Retention | `GET /retention/state|timeline|runs`; `POST /retention/run`; `GET /capacity` |
| Audit | `GET /audit`; `GET /audit/verify` |

Every `/api/v1/*` operation requires the local bearer credential. The only
anonymous admin listener route is the pre-existing `GET /api/health` probe.

## 3. RBAC acceptance

- platform_admin: global event create/rename/archive/purge, retention/run,
  config/mapping writes, audit/ledger, plus all read/event/token operations.
- event_admin: event-scoped reads, node revoke, token create/list/revoke,
  alias writes; **not** event create/rename/archive/purge, config write, mapping
  write, retention or audit-global.
- viewer: event-scoped read (events/nodes/config/aliases/mapping/token status);
  no mutation, no audit.
- machine identity/enrollment token: no admin API access.
- Unknown/out-of-scope event → 404; action forbidden on a visible event → 403.
- Every scoped query uses a server-resolved event set in SQL; all body/related
  IDs are revalidated (IDOR/cross-event tests).

## 4. Real E2E acceptance

`internal/management/e2e_test.go`, `security_test.go`, `purge_test.go` use real
`center.Server` HTTP listeners + real SQLite + real B3 `agent.Runtime` for both
`linux_vps` and `windows_terminal`, with two independent events:

1. create events A/B;
2. event_admin A creates scoped token; real Linux and Windows agents enroll;
3. platform configures legal class-specific sources; agents pull config;
4. real snapshot/metrics/events reports accepted;
5. node list/detail, latest snapshot, keys and derived status;
6. admin aliases with optimistic version;
7. mapping v1 → v2 and historical resolution at each effective time;
8. node revocation; real agent report fails;
9. viewer/event-admin scope and mutation denial; audit scope;
10. Event B archive/purge preview/type-confirm/idempotence/graveyard/audit;
11. Event A remains completely independent.

The tests call the real management HTTP API/CLI path; they do not call the store
to claim API acceptance. Real CLI test is in `cmd/um-center/admin_cli_test.go`.

## 5. Security/negative acceptance

- Missing/invalid bearer, role/event spoof headers → 401; no anonymous admin.
- Agent/enrollment identity as admin credential → 401.
- Viewer mutation, event_admin platform-only actions, cross-event reads/writes →
  403/404; no client-supplied scope widening.
- IDOR via body node IDs, mapping targets, alias targets, token/event mismatch →
  revalidated/rejected.
- Token plaintext never in list/status/audit/logs; revoked token cannot enroll.
- Config rejects `singbox_api:true` and `mihomo_api:true`; class rules enforced.
- Mapping rejects reserved tokens, cross-event/class targets, duplicate versions,
  backdating and rewrites; append-only triggers unchanged.
- Purge requires platform_admin + exact type-to-confirm; invalid/stale/cross-event
  confirmation rejected; durable op/graveyard/tombstone/ledger; repeated request
  safe; event A untouched.
- No admin path reads arbitrary files, executes commands, fetches URLs or pushes
  commands/config to agents.
- Audit and ledger failure cannot be reported as success for mutations (audit is
  written in the mutation transaction; ledger failures roll back).
- Privacy: no token/private key/controller secret/proxy name/raw user traffic
  in responses or audit; aliases bounded/no control chars.

## 6. Regression/quality gates

- Existing B1/B2/B3 and rev-6 tests remain mandatory; no frozen rev-5/rev-6 or
  B2 engine modification without explicit change control.
- `go test ./...`, `go vet`, `go mod verify`, `govulncheck`, Linux/Windows
  builds, Linux race, coverage, native CI and exact-HEAD lab workflow.
- Final exact-HEAD independent review; Codex review attempted and quota status
  recorded honestly; no claim of Codex completion/0 findings.
- Final PR Draft; no merge/main write/force-push.

## 7. Known limits / HOLD

- No UM-C Web UI/login/TOTP/session/CSRF/Cloudflare or public admin ingress.
- Admin API disabled unless local auth file configured; loopback-only.
- No production deployment, real VPS/SSH/tournament terminal/Cloudflare/R1.
- Linux `singbox_api` remains disabled/unavailable (P1-10 audit FAIL); Linux
  Reality/Hysteria2 real traffic collection is a pre-production functional
  blocker, not a B4 PASS.
- Windows R1 production enablement HOLD; center config cannot enable it.
- No backup/restore, VACUUM, disk-pressure or offsite ledger acceptance (UM-E).
- No admin-initiated node rotate/remote command; agent-initiated rotation only.
- Retention/capacity constants are displayed/enforced but not increased.
