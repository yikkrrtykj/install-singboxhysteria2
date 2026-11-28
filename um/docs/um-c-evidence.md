# UM-C evidence and acceptance notes (Draft, exact HEAD pending)

Status: **UM-C Draft PR Refs #127**. This document records commands/results and
honestly distinguishes verified local/CI evidence from production HOLD work. The
final status line is only updated after the final exact-HEAD run and commit.

## Baseline

- Base `origin/main`: `6d9e12fd7ad4d0866ea507209fcbe52931c4a70a`
  (B1/B2/B3/B4 merged; tree `3cbd4bee73b49c5c047021390886c3e261bea42f`).
- Branch: `codex/um-c-auth-security`; Draft PR #134 (Refs #127).
- First implementation commit: `f04c9135`; second: `387e11b8`; review-fix
  commit(s) are added after the findings below. Final evidence MUST be refreshed
  after the last commit; do not treat an older run as exact-HEAD evidence.
- UM-C uses the existing Go module/center/SQLite/management engine. No second
  database or RBAC engine was added.

## Local verification (development worktree)

Commands (Windows host; race detector not available locally because cgo/gcc is
absent, so Linux race runs in CI):

```bash
cd um
go vet ./...
go test -count=1 ./...
go test -count=1 -cover ./internal/umcauth ./internal/web ./internal/store ./internal/center ./cmd/um-center
go build ./...

cd web
npm ci
npm run typecheck
npm test
npm run build
```

Observed during development (before the final review-fix commit):

- `go vet ./...`: exit 0.
- Full `go test ./...`: all packages `ok` (agent, center, conformance,
  contract, management, store, umcauth, web, windows, wire, etc.).
- Coverage snapshot: `umcauth 87.0%`, `web 54.3%`, `store 64.8%`,
  `center 82.5%`, `cmd/um-center 29.9%` (coverage is informational, not the
  acceptance metric).
- Frontend `vue-tsc`: exit 0; Vitest **99/99** tests in **10** files; Vite
  production build succeeds (`dist/index.html`, hashed CSS/JS).
- Real-browser Playwright lab passed locally against the real built Vue bundle +
  real Web handler/store/management bridge, with synthetic Access JWKS/JWT and a
  self-signed loopback TLS cert only:
  `1 passed` login -> forced TOTP setup -> recovery codes/dashboard -> B4
  platform-admin user page -> logout -> TOTP login. Screenshots:
  `um/docs/um-c-browser-dashboard.png`, `um/docs/um-c-browser-users.png`.
- Machine TLS lab passed: real center handler over synthetic TLS 1.3 listener,
  real agent enrollment/config/snapshot report, TLS 1.2 client rejected,
  untrusted CA rejected with a fresh enrollment token, no admin/web routes on
  the machine listener.
- Auth CLI lab passed: protected key generation, once-only local bootstrap,
  controlled local recovery (TOTP/session reset).

## CI observed (development commits, not final evidence)

For `387e11b8`:

- `UM-C Web and Browser Lab`: **success**. The `frontend` job ran typecheck/Vitest/
  build; the `real-browser-auth-lab` job installed a hermetic Chromium, started
  `um-c-e2e`, ran Playwright, and reported **1 passed**. This is synthetic
  Access/TLS only.
- `UM-B3 isolated service labs`: success; B4/B2/foundations jobs remained green.
- `Unified Monitor Go` native Windows: passed. The Linux race job failed in the
  new `umcauth` POSIX master-key test because a mode-0000 file hit `open`
  permission-denied and the implementation classified it as `ErrMasterKeyFile`
  instead of `ErrMasterKeyPermissions`. This review-fix is in the working tree
  (`vault_unix.go`/`vault.go`), and the final run must confirm it.
- Other workflows (HY2 BBR, monitor-packaging, p6b2-foundations, shell-tests,
  quality-receiver) were green or not UM-C-specific; `Unified Monitor Go` is the
  required exact-HEAD gate.

**Final exact-HEAD CI/lab must be rerun after the review-fix commit; this file is
updated with the final run IDs/commit/tree before the goal is reported complete.**

## Independent review (completed)

An independent reviewer examined HEAD `387e11b8` read-only and returned
**NEEDS FIXES** with no remote auth bypass found. High-priority findings and
disposition:

| Finding | Disposition |
| --- | --- |
| P1 online TOTP guessing / no lockout | Fixed: persistent per-account failure count + 15-minute lockout after 5 failures, pending session revocation on lock, 10-minute pending/setup TTL, TOTP mutation rate bounded; lockout test added. |
| P2 TOTP setup non-atomic | Fixed: new `CompleteTOTPSetup` transaction consumes counter, stores sealed secret + recovery generation, revokes old sessions, inserts active session and audit/ledger; cookie written only after commit; concurrency test added. |
| P2 rate limits keyed by loopback Tunnel address | Fixed: login/TOTP/recovery buckets use verified Access subject/session/user where available; account budget checked after preauth/CSRF. |
| P2 recovery timing account enumeration | Fixed: dummy Argon2 hash path for unknown/disabled accounts. |
| P2 unbounded preauth rows | Mitigated: per-Access-subject preauth creation rate limit + bounded maintenance cleanup; documented. |
| P2 audit/ledger non-atomic login/recovery/CLI | Fixed: mutation metadata attached to TOTP login completion, recovery-code regeneration and local CLI recovery. |
| P2 CSRF cookie not HttpOnly | Fixed (working tree/commit): both `__Host-um_session` and `__Host-um_csrf` are Secure HttpOnly SameSite=Strict; cookie-attribute test added; CSRF token obtained via `/auth/context`, never `document.cookie`. |
| P2 evidence false-green / vacuous TLS / missing evidence | Fixed: Playwright hard-fails when `UM_C_E2E_*` is absent; machine TLS test uses fresh token and production TLS config with TLS1.2 rejection; this evidence file added; docs corrected. |
| P2 frontend README contract mismatch claims | Fixed: stale claims removed/corrected. |
| P3 recovery generation invalidation | Fixed: successful recovery deletes remaining codes and old TOTP counters. |
| P3 `SetAuthUserTOTP` comment/DB permissions/TLS key ACLs/startup wrong-key wording | Partially addressed by docs/comment; DB/TLS key permission hardening and startup key validation remain operational HOLD hardening, not claimed complete. |

## Claims NOT made

- No real Cloudflare/Tunnel/DNS/Access/IdP/tunnel token, real certificate/public
  port, production account or paid resource was used.
- No merge, force-push, main write, #127 close or #48 reopen.
- No monitoring/full dashboard (UM-D), R1 production, `singbox_api` enablement,
  monitor-v2/sbox-cm/HA-UI modification, remote device control or UM-F.
- Browser E2E uses a synthetic Access header injected by Playwright and a
  self-signed loopback cert; it is an isolated simulation, not proof of a real
  edge deployment.
- Linux Reality/Hysteria2 real traffic remains a pre-production blocker on #127.
- PRODUCTION HOLD, R1 PRODUCTION HOLD, `singbox_api` DISABLED, UM-F DEFERRED.

## Final status

Pending: final review-fix commit, exact HEAD tree, full local/CI reruns, updated
evidence IDs, and owner-equivalent independent rereview. The final report will
use one of the authorized stop statuses.
