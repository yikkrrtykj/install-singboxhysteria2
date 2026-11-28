# UM-C evidence and acceptance notes (Draft PR #134)

Status: **UM-C Draft PR Refs #127**. This document records commands/results and
honestly distinguishes verified local/CI evidence from production HOLD work.
Verification target for code: commit `076335720cf8c15254ffe41acab1b1dc38525b80`
(tree `a7fe98c94975af4e823248862674fa3fd6cb2beb`). A following docs-only commit
records this document; no production code changes are in that commit.

## Baseline

- Base `origin/main`: `6d9e12fd7ad4d0866ea507209fcbe52931c4a70a`
  (B1/B2/B3/B4 merged; tree `3cbd4bee73b49c5c047021390886c3e261bea42f`).
- Branch: `codex/um-c-auth-security`; Draft PR #134 (Refs #127).
- Implementation commits: `f04c9135`, `387e11b8`, `d83b1942`, `395583e1`,
  `051952be`, and code verification target `07633572` (test-only determinism fix
  after the final code re-review).
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

## CI exact verification target (`07633572`)

All required UM-C/Go/browser jobs below are on the pushed verification commit
`076335720cf8c15254ffe41acab1b1dc38525b80`:

- `Unified Monitor Go` run `46137755887`: **success**. Jobs:
  `native (ubuntu-24.04)` success, `native (windows-2022)` success,
  `linux-race` success, `coverage` success, `govulncheck` success.
- `UM-C Web and Browser Lab` run `46137755898`: **success**.
  `frontend` success (typecheck/Vitest/build); `real-browser-auth-lab` success
  (hermetic Chromium started `um-c-e2e`, synthetic Access/TLS only, Playwright
  real-browser auth closure passed).
- `UM-B3 isolated service labs` remained green on the related baseline; B1-B4
  regression tests are part of the full `go test ./...` above.
- An unrelated `quality-receiver` Windows quality-exe process-enumeration lab
  failed transiently with `winerror=5` (`PROCESS_ENUMERATION_FAILED`); it is not
  part of the UM Go/UM-C changed code and was retried. Do not cite that
  unrelated flake as UM-C evidence either way.

Local final checks (same worktree/commit family):

- `go vet ./...`: exit 0.
- Full `go test -count=1 ./...`: every package `ok`.
- `go build ./...`: exit 0.
- Frontend `npm ci`, `npm run typecheck`, `npm test` (99/99 in 10 files),
  `npm run build`: green.
- Local real-browser Playwright auth closure: `1 passed`; synthetic Access/JWKS
  and self-signed loopback TLS only. Screenshots:
  `um/docs/um-c-browser-dashboard.png`, `um/docs/um-c-browser-users.png`.
- Machine TLS lab: production `center.MachineTLSConfig`, TLS 1.2 rejection,
  untrusted CA rejection with a fresh token, real agent enrollment/config/snapshot
  report; route isolation from admin/web.
- Auth CLI lab: protected key generation, once-only local bootstrap, controlled
  local recovery; no password in argv.
- TOTP/session deterministic test suite run repeatedly successfully; no skipped
  browser lab env (Playwright exits nonzero if `UM_C_E2E_*` is missing).

An independent reviewer examined HEAD `387e11b8` read-only and returned
**NEEDS FIXES** with no remote auth bypass found. High-priority findings and
disposition:

| Finding | Disposition |
| --- | --- |
| P1 online TOTP guessing / no lockout | Fixed: persistent per-account failure count + 15-minute lockout after 5 failures, account-session revocation on lock, failure-window reset after expiry/success/password reset/enable, 10-minute pending/setup TTL, TOTP mutation rate bounded; lockout test added. |
| P2 TOTP setup non-atomic | Fixed: new `CompleteTOTPSetup` transaction consumes counter, stores sealed secret + recovery generation, revokes old sessions, inserts active session and audit/ledger; cookie written only after commit; concurrency test added. |
| P2 rate limits keyed by loopback Tunnel address | Fixed: login/TOTP/recovery buckets use verified Access subject/session/user where available; account budget checked after preauth/CSRF. |
| P2 recovery timing account enumeration | Fixed: dummy Argon2 hash path plus an identical pre-lookup rate bucket keyed by Access subject + username, so known/unknown names get the same 401/429 behavior. |
| P2 unbounded preauth rows | Mitigated: per-Access-subject preauth creation rate limit + bounded maintenance cleanup; documented. |
| P2 audit/ledger non-atomic login/recovery/CLI | Fixed: mutation metadata attached to TOTP login completion, recovery-code regeneration and local CLI recovery. |
| P2 CSRF cookie not HttpOnly | Fixed (working tree/commit): both `__Host-um_session` and `__Host-um_csrf` are Secure HttpOnly SameSite=Strict; cookie-attribute test added; CSRF token obtained via `/auth/context`, never `document.cookie`. |
| P2 evidence false-green / vacuous TLS / missing evidence | Fixed: Playwright hard-fails when `UM_C_E2E_*` is absent; machine TLS test uses fresh token and production TLS config with TLS1.2 rejection; this evidence file added; docs corrected. |
| P2 frontend README contract mismatch claims | Fixed: stale claims removed/corrected. |
| P3 recovery generation invalidation | Fixed: successful recovery deletes remaining codes and old TOTP counters. |
| P3 `SetAuthUserTOTP` comment/DB permissions/TLS key ACLs/startup wrong-key wording | Partially addressed by docs/comment; DB/TLS key permission hardening and startup key validation remain operational HOLD hardening, not claimed complete. |

### Follow-up independent review

A second read-only pass on `395583e1` confirmed the original P1/P2 fixes but found two residual P2s: the persistent TOTP failure counter did not reset after an expired lock (possible indefinite lockout DoS), and `/auth/recovery` still had a deterministic 429-vs-401 pre-lookup oracle for known vs unknown usernames. Both are fixed in the next review-fix commit: lock expiry resets the failure window; password reset/enable clears lock state; all-session revocation is documented; recovery uses one subject+username pre-lookup bucket for both cases. The follow-up also committed the setup-session conflict 401 mapping. Remaining items are P3 doc/test gaps and exact-HEAD CI/evidence refresh.

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

**UM-C GOAL COMPLETED / DRAFT PR / AWAITING FINAL INDEPENDENT REVIEW**

- Draft PR #134 remains open, Draft, unmerged; no merge/force-push/main write.
- Code verification target `07633572` has green exact-HEAD Go and browser CI as
  above.
- The independent reviewer's final read-only verdict was **CLEAN (Draft)** for
  `051952be`; the only later commit (`07633572`) is a test-only deterministic
  clock fix with no production-code change. Final reviewer sign-off on the
  docs-only evidence commit is the remaining external review step.
- Remaining accepted P3 items: inherent threshold-lockout DoS for an attacker who
  already knows the password (mitigated by admin reset/enable/recovery/local
  recovery and documented); test gaps for admin-unlock/upgrade/ledger-fault;
  generic OpenAPI 429 vs `totp_locked` code detail; DB/TLS-key ACL hardening and
  master-key startup validation remain operational HOLD hardening.
- Holds: **PRODUCTION HOLD**, **R1 PRODUCTION HOLD**, `singbox_api` **DISABLED**,
  UM-F **DEFERRED**. Real Cloudflare/Tunnel/DNS/Access/IdP/certificate and
  production accounts are untouched. Linux Reality/Hysteria2 real traffic remains
  a pre-production blocker on #127; #127 stays OPEN.
