# UM-C scope and acceptance matrix (Draft)

Status: **UM-C Draft PR Refs #127**. No merge, production deployment, real
Cloudflare/Tunnel/DNS/Access/certificate resource, real R1 or `singbox_api`
enablement is authorized by this document.

Base: merged main `6d9e12fd` (B1/B2/B3/B4, rev-6 frozen). Implementation branch:
`codex/um-c-auth-security`. This document tracks C1-C7; it is not a final
completion claim. Final exact-HEAD evidence is recorded separately in
`um-c-evidence.md` and the Draft PR.

## 1. Module status

| Module | Scope | Implementation | Evidence/status |
| --- | --- | --- | --- |
| C1 | Auth/DB design; additive v11/v12 migrations; single existing SQLite/center/management engine | `internal/store/umc_auth.go`, `schema.go` v11/v12, `um-c-architecture.md` | store migration/reopen + auth cleanup tests; B1-B4 regressions PASS |
| C2 | Local accounts; Argon2id; forced TOTP; one-time recovery codes; AES-256-GCM master key; local bootstrap/recovery; last-admin protection; TOTP failure lockout | `internal/umcauth`, `internal/web`, `cmd/um-center/auth_cli.go` | crypto unit tests; web login/TOTP/setup/recovery/lockout tests; CLI test PASS |
| C3 | Server-side sessions, `__Host-` Secure HttpOnly SameSite=Strict cookies (session + CSRF), per-session CSRF, idle/absolute/pending TTL, fixation defense, immediate revocation, bounded rate limits/KDF concurrency | `internal/web`, v11/v12 tables | login/TOTP/session replay/cookie flags/idle+absolute expiry/password/logout/browser tests PASS |
| C4 | Cloudflare Access JWT cryptographic verification: trusted JWKS issuer/audience/signature/alg allowlist/exp/nbf/sub/kid rotation/cache/timeouts/fail-closed/no jku/x5u/SSRF | `internal/umcauth/accessjwt.go`, `internal/web` middleware | 25 focused Access-JWT tests among 70 package tests; web Access-required/subject-binding tests PASS; real Cloudflare edge is HOLD |
| C5 | Account/role/event-scope administration; existing B4 RBAC/SQL scopes; platform-admin-only user admin; no public self-registration/default credentials; audit/ledger | `internal/web/user_handlers.go`, `internal/management` bridge | admin + event-scope isolation + last-admin tests PASS; browser user-admin page PASS |
| C6 | Loopback Web listener behind Tunnel/Access; independent local bearer admin CLI plane; independent machine hostname + TLS 1.3 ingest; machine/Web route and credential isolation; Vue 3/TS/Vite UI | `cmd/um-center`, `internal/web`, `internal/center` machine TLS config/test, `um/web` | machine TLS enroll/config/report, TLS1.3-only, TLS1.2-reject, untrusted-CA negative, route-isolation PASS; local-bearer bypass negative PASS; browser E2E PASS; real cert/DNS HOLD |
| C7 | Migrations, docs, OpenAPI, runbook, deployment templates, CI, negative/fault/concurrency labs, final evidence | `um/docs/um-c-*`, `.github/workflows/um-c-web.yml`, Playwright harness | independent review completed; fixes applied; **final exact-HEAD CI/lab rerun and evidence refresh pending** |

## 2. Role/permission acceptance

| Capability | platform_admin | event_admin (assigned event) | viewer (assigned event) |
| --- | --- | --- | --- |
| Browser login/TOTP/session/CSRF | yes | yes | yes |
| Own password/TOTP/recovery/sessions | yes | yes | yes |
| Event list/detail; node/config/alias/token reads | global | assigned only | assigned only |
| Event create/rename/archive/purge | yes | no | no |
| Config/mapping writes | yes | no | no |
| Node revoke, token create/revoke, alias writes | global | assigned only | no |
| Retention/run/capacity | yes | no | no |
| Audit/ledger reads | yes | assigned event only | no |
| Web account administration (create/disable/role/scope/reset/sessions) | yes | no (403) | no (403) |
| Machine enrollment/report | no browser access | no browser access | no browser access |

Roles are stored on the local account and converted to the existing
`management.Principal`; the Web bridge never trusts a client role/event header.
Event scopes are re-read from SQL on every authenticated request. Out-of-scope
event operations return the pre-existing B4 non-leaking 404/403 behavior.

## 3. Required security acceptance

- Access JWT: valid signature, allowed alg, exact issuer/audience, bounded
  exp/nbf/iat/sub, trusted JWKS only, cache/unknown-kid refresh/timeout/fail
  closed; missing/invalid JWT -> 401; Access JWT alone never grants local admin.
- Local password + mandatory TOTP required for a normal browser session; no
  public bootstrap/registration/default credentials/third-party email.
- TOTP replay after successful use (including setup code), restart and clock
  rollback fails; persistent counter and transactional consume.
- Recovery codes one-time; consumption revokes sessions and forces TOTP
  re-enrollment; local OS-controlled recovery only clears TOTP/sessions and sets
  a new password.
- Secrets only encrypted/persisted hashed; no password/TOTP/recovery/session/CSRF
  token/Access JWT/private key in logs, audit, ledger, URL or browser storage.
- Session cookie `__Host-` Secure HttpOnly SameSite=Strict; CSRF header required
  on unsafe Web/B4-bridge mutations plus Origin allowlist; password/TOTP/role/
  scope/disable changes revoke affected sessions.
- B4 local bearer cannot authenticate on Web; Web session cannot authenticate on
  machine/admin listeners; no `RemoteAddr`-only trust; privileged local CLI is a
  separate process/file-owned path.
- Last enabled platform_admin cannot be disabled/demoted. Web can create only
  event_admin/viewer accounts; additional platform_admin expansion requires a
  separate Owner decision.
- Bounded rate limits/login KDF concurrency; generic credential errors avoid
  account enumeration.
- Response CSP/frame-ancestors/no-store/nosniff/referrer policy; same-origin
  only; no broad CORS.

## 4. Non-goals / HOLD

- `PRODUCTION HOLD`; no production deployment, accounts or real secrets.
- Cloudflare Tunnel/Access/DNS/IdP/audience/team/tunnel token/certificates are
  deployment templates only; **HOLD**.
- Real machine DNS/certificate/public port: **HOLD**.
- R1 **PRODUCTION HOLD**; `singbox_api` **DISABLED**; UM-F **DEFERRED**.
- No monitoring charts/full dashboard (UM-D), no monitor-v2/sbox-cm/HA-UI
  modifications, no real R1, no remote device control, no #48 reopen, no #127
  close, no merge/main write/force-push.
- Linux Reality/Hysteria2 real traffic remains a pre-production functional
  blocker on #127; UM-C does not change frozen contracts or claim that blocker
  resolved.
- Master-key rotation and offsite key escrow backup/restore drills are not
  implemented here; operational guidance is in the runbook and remains an
  Owner/UM-E gate.

## 5. Exit criteria for this phase

- Go unit/integration tests, frontend typecheck/Vitest/build, browser E2E and
  synthetic Access/machine TLS labs green on exact HEAD.
- B1/B2/B3/B4 and frozen rev-6 conformance regressions green.
- Security negative tests for auth bypass, CSRF, session replay, TOTP/recovery
  replay, scope isolation and route/credential isolation green.
- Docs/OpenAPI/runbook/templates committed; no real external resource used.
- Independent review complete or explicitly outstanding; Draft PR remains open,
  unmerged; final status recorded only when evidence is tied to exact HEAD.
