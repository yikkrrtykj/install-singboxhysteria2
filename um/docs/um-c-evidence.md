# UM-C evidence and acceptance notes (Draft PR #134)

Status: **UM-C Draft PR, Refs #127 — pre-merge. No merge has been performed.**
This document records exact-HEAD commands/results and honestly distinguishes
verified local/CI evidence from production HOLD work. The final merge and
post-merge verification are recorded in PR #134 and Issue #127, not claimed here.

## Baseline and code verification target

- Base `origin/main`: `6d9e12fd7ad4d0866ea507209fcbe52931c4a70a`
  (tree `3cbd4bee73b49c5c047021390886c3e261bea42f`; B1/B2/B3/B4 merged).
- Branch: `codex/um-c-auth-security`; Draft PR #134 (Refs #127).
- Final code verification target: `61df67f06631ff2886fc81e938dd8ce5f2db3c6f`
  (tree `7605bf3f16f11e02a0db574eba46cfde9698b28c`).
- Earlier implementation commits: `f04c9135`, `387e11b8`, `d83b1942`,
  `395583e1`, `051952be`, `07633572`, `45b90a46`, `d46a73fe`, `5f95d096`,
  `6e3c7975`, `f144a5a9`, `61df67f0`.
- This evidence document is committed in a docs/workflow-only commit after
  `61df67f0`; it changes no production code. Exact run IDs for that final
  evidence commit are archived in the PR/Issue comments.
- UM-C uses the existing Go module/center/SQLite/management engine; no second
  database or RBAC engine.

## Final code target CI (exact `61df67f0`)

- `Unified Monitor Go` run `46148046992` (push) and `46148042788` (PR):
  **success**; Linux/Windows native, race, vet/build/tests all green.
- `UM-C Web and Browser Lab` run `46148046962` (push) and `46148042815` (PR):
  **success**, including frontend typecheck/Vitest/build, `um-c-e2e` harness
  tests, and the real Chromium 9-test lab (artifact
  `um-c-browser-evidence`).
- `UM-B3 isolated service labs` run `46148042877`: **success**. Jobs:
  `linux-systemd-environment`, `windows-service-environment`,
  `linux-systemd-agent-lab`, `windows-service-r1-lab`, `b4-management-e2e`,
  `linux-singbox-serviceapi-lab` all success.
- `quality-receiver` run `46148047010`: Linux contract/systemd jobs success;
  the unrelated Windows quality-exe environment job was still running at the
  time of writing and is rerun on the docs-only final HEAD; no UM-C code is
  exercised by it.
- `shell-tests` `46148046965`, `p6b2-foundations` `46148046970`,
  `monitor-packaging` `46148047022`, `HY2 BBR defaults` `46148046975`:
  **success** on `61df67f0`.
- Any later docs-only evidence commit is verified by the same full CI matrix on
  that exact HEAD; run IDs are archived in PR #134/Issue #127. No code diff is
  introduced by it.

## Local verification at the final code worktree

Commands (Windows host; race detector unavailable locally because cgo/gcc is
absent, so Linux race runs in CI):

```bash
cd um
go vet ./...
go test -count=1 ./...
go build ./...
gofmt -l cmd internal
govulncheck ./...   # in CI/lab; no new dependency

cd web
npm ci
npm run typecheck
npm run lint                 # static typecheck gate; no separate ESLint config in tree
npm test                     # Vitest
npm run build
npm audit --omit=dev --audit-level=high
```

Observed:

- `go vet ./...`: exit 0.
- Full `go test ./...`: all packages `ok` (agent, center, conformance, contract,
  management, store, umcauth, web, windows, wire, etc.).
- `go build ./...`: exit 0.
- Frontend `vue-tsc`: exit 0; Vitest **99/99** tests in **10** files; Vite
  production build succeeds; `npm audit --omit=dev`: 0 vulnerabilities.
- Real-browser Playwright lab **9/9 passed** locally against the real built Vue
  bundle + real Web handler/store/management bridge, with synthetic Access
  JWKS/JWT and a self-signed loopback TLS certificate only. Single worker; test
  fails closed if `UM_C_E2E_*` is absent.
- Machine TLS lab passed: real center handler over synthetic TLS 1.3 listener,
  real agent enrollment/config/snapshot report; TLS 1.2 client, untrusted CA,
  hostname mismatch and expired certificate rejected; no admin/web routes on the
  machine listener.
- Auth CLI lab passed: protected key generation, sentinel-first once-only local
  bootstrap, controlled local recovery (TOTP/session reset), explicit master-key
  key-init upgrade verification, and bootstrap refusing to create an account when
  the sentinel does not match the supplied key.

## H1-H8 final security closure evidence

- **H1 credential epoch**: v13 `umc_users.auth_epoch`/`umc_sessions.auth_epoch`;
  all session-creation paths CAS/revalidate the account epoch in SQLite after
  Argon2id outside transactions. `TestUMCCredentialEpochPasswordResetRace`
  deterministically pauses after password verification, commits a reset, then
  proves no pending/setup/active session is created for both bound and unbound
  TOTP accounts. All credential mutations bump the epoch; v12 rows map to 0.
- **H2 authorization linearization**: ordered, refcounted per-account read/write
  gates in `internal/web/gate.go` reuse the existing B4 RBAC/service. B4 mutations
  hold the principal read gate, re-authenticate, then call the existing
  transaction; account-security mutations take the write gate.
  `TestUMCManagementMutationRevocationLinearization` blocks a real B4 mutation,
  proves logout waits, releases the mutation, then proves the next B4 request is
  401. No global lock/second RBAC. CLI recovery remains the documented OS-trusted
  boundary and advances the epoch.
- **H3 failure semantics**: logout revoke+audit/ledger is one transaction; real
  SQLite write-lock fault returns bounded 503, keeps the session, retry succeeds;
  password/logout/session-list/TOTP/admin-gate auth-state failures map to 503
  `auth_state_unavailable` rather than false 401. Repeated admin session revoke is
  idempotent only after the store proves the row is already revoked; no false
  success audit. Preauth consume errors are checked; frontend displays logout
  uncertainty. Tests: `TestUMCLogoutDatabaseFaultIsNotReportedAsSuccess`,
  `TestUMCAdminSessionRevokeIsIdempotentOnlyAfterProof`.
- **H4 TOTP/recovery**: persistent high-water checked on login/counter consume and
  surviving counter cleanup/restart; new secret generation resets it; TOTP
  setup/login completion atomic; recovery-code consumption atomic with setup
  session creation and rollback-tested; recovery generation invalidates old state;
  lockout expiry/admin unlock tested. Tests in store/web suites and H8.
- **H5 master key/files**: AEAD `umc_meta` sentinel; wrong key fails Web startup;
  any existing-account DB without sentinel requires explicit local
  `auth key-init`, which verifies every encrypted TOTP secret before writing the
  sentinel; bootstrap initializes sentinel before creating the first account;
  zero-account DB may auto-init. DB/WAL/SHM/TLS-key/B4 files use closed permission
  model; existing foreign/shared directories are refused, not destructively
  chmod'ed/ACL-rewritten; dedicated missing dirs are created private on
  POSIX/Windows; service umask 0077. Tests: keycheck, master-key CLI, fileguard
  POSIX/Windows refusal/DACL, v12→v13 upgrade, private DB files.
- **H6 JWKS/machine TLS**: no production insecure-JWKS flag; HTTPS-only verifier;
  plain `-ingest` forced loopback, non-loopback machine traffic requires TLS 1.3
  machine listener; TLS1.2/untrusted CA/hostname mismatch/expired cert negatives;
  machine route isolation; Access/JWKS/Web session plane independent of machine
  listener once running. Tests: machine TLS, ingest-loopback, route isolation.
- **H7 bounds/audit**: limiter capacity oldest-eviction with tests; hashed
  untrusted usernames; global preauth bucket; per-user 32/global 10000 **usable**
  session caps (pending/setup counted only within their 10-minute TTL and purged
  before the cap, preventing abandoned-challenge lockout); unknown usernames only
  anonymous audit and 429 burst test; admin unlock; v12→v13 migration; atomic
  audit/ledger rollback; B4 180-day retention unchanged.
- **H8 browser**: 9 serial real-Chromium tests (see `web/README.md`): preserved
  single-role closure plus UI provisioning of event_admin A/B and viewer A/B with
  two events; forced TOTP setup and normal login for each role; RBAC visibility/
  viewer read-only/event_admin no-global-admin; CSRF and local B4 bearer rejection
  by the Web plane; own/admin session revocation; admin password reset; role/scope
  revocation and effective new authorization; own password change; recovery-code
  login/reuse rejection/stale authenticator; TOTP update; idle expiry; logout;
  403/404. Screenshots under ignored `web/test-results/` uploaded by CI.

## Independent review disposition

- The first H1-H8 independent review of `d46a73fe` found no P0/P1 and required
  fixes for H3 503 coverage/overclaim, stale evidence, and destructive fileguard
  path mutation, plus P3 items.
- Correction commits `5f95d096`/`6e3c7975` and `f144a5a9` implement the 503
  mapping, conservative fileguard/private-dir lab layout, session caps/idempotence
  fixes, strict sentinel/bootstrap ordering, limiter/oldest eviction, DACL object
  ACE fail-closed, docs/remediation, and B3 lab ACL fix. A fresh independent
  review of `f144a5a9`/`8d4f39df` returned **CLEAN (Draft)** with no P0/P1/P2;
  the final `61df67f0` changes only close two P3 boundary/bootstrap edges and add
  tests, and final review is archived in PR #134 before merge.
- Codex Review is unavailable in this environment. As permitted by the Owner
  instruction, the substitute is a complete independent read-only review of the
  actual final commit; no Codex zero-finding claim is made.

## Claims NOT made

- No real Cloudflare/Tunnel/DNS/Access/IdP/tunnel token, real certificate/public
  port, production account or paid resource was used.
- No merge, force-push, main write, #127 close or #48 reopen has happened at this
  evidence target; merge/post-merge status is recorded only after execution.
- No monitoring/full dashboard (UM-D), R1 production, `singbox_api` enablement,
  monitor-v2/sbox-cm/HA-UI modification, remote device control or UM-F.
- Browser E2E uses a synthetic Access header injected by Playwright and a
  self-signed loopback cert plus lab-only loopback `/__lab/*` fixtures; it is an
  isolated simulation, not proof of a real edge deployment.
- Linux Reality/Hysteria2 real traffic remains a pre-production blocker on #127.
- PRODUCTION HOLD, R1 PRODUCTION HOLD, `singbox_api` DISABLED, UM-F DEFERRED.

## Merge gate status (pre-merge)

- No P0/P1 found by independent review; final review verdict to be archived in
  PR #134.
- Full exact-code-HEAD CI/labs green as listed above; docs-only evidence commit
  is independently CI-verified.
- PR #134 remains Draft until all gates including final review/threads are green;
  merge will be an ordinary merge commit only.
- Final allowed status will be exactly one of:
  `UM-C MERGED / MAIN CI PASS / SECURITY LAB PASS / READY FOR NEXT GOAL`,
  `UM-C MERGE BLOCKED`, or
  `UM-C MERGED / POST-MERGE VERIFICATION HOLD`.
