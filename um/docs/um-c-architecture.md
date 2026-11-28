# UM-C authentication, RBAC and secure ingress architecture (Draft)

Status: UM-C implementation on `codex/um-c-auth-security`, Draft PR Refs #127.
No real Cloudflare/DNS/certificate/production resource is used. Web origin is
loopback-only; Cloudflare Tunnel/Access configuration is a deployment template
HOLD.

## 1. Baseline and single-engine rule

Base: merged main `6d9e12fd` (B1/B2/B3/B4, rev-6 frozen). UM-C adds an
authentication/ingress layer above the existing center and management service.
It does **not** create a second center, SQLite database, business API, RBAC
matrix, event/node/token/mapping/purge engine. Browser authorization resolves a
server-side local account into the existing `management.Principal` and then calls
the existing B4 `management.Service`/`Handler`.

## 2. Planes and listeners

| Plane | Listener | Routes | Identity | Browser state |
| --- | --- | --- | --- | --- |
| Machine (B2/B3) | `-ingest` HTTP, optional `-machine-tls` TLS 1.3 | `/v1/agent/*` only | frozen Ed25519 enrollment/key protocol | never accepts cookies/session/admin bearer |
| Local admin (B4) | `-admin`, loopback only | `/api/health`, `/api/v1/*` | local protected auth file + bearer; CLI-only | never routed through Cloudflare; no web session |
| Web | `-web`, loopback only | `/`, `/auth/*`, `/web/api/*`, `/api/v1/*` (session bridge) | Access JWT + local password/TOTP + server session | `__Host-` Secure HttpOnly SameSite=Strict cookie |
| Local ops | `um-center auth ...` process-local commands | bootstrap/recover/init-key | OS file/ACL ownership + local process | none |

Web and admin use different ports. The deployment template routes only the Web
origin through Cloudflare Tunnel; the admin listener must never be published.
The Web handler rejects `Authorization: Bearer` admin credentials, and the admin
handler does not mount web/session routes. Source-IP/`RemoteAddr` is never an
authorization decision.

## 3. Cloudflare Access verification

Each Web request that reaches the origin must carry a valid
`Cf-Access-Jwt-Assertion`. The verifier:

- accepts only configured issuer/audience;
- enforces compact JWT shape and a bounded size;
- allows only RS256/ES256 (never `none`/HMAC/algorithm confusion);
- verifies signature against a configured trusted JWKS URL;
- rejects `jku`, `x5u`, embedded `jwk` and arbitrary key URLs;
- validates `exp`, `nbf`, `iat`, `sub` with bounded leeway;
- caches a bounded key set with expiry, refreshes on unknown `kid` with a
  cooldown and single-flight-like suppression, and fails closed on JWKS timeout;
- never uses `Cf-Access-Authenticated-User-Email` or other edge headers as
  local identity.

Access JWT proves edge access only. Local username/password and TOTP remain
mandatory. The session stores the verified Access subject/issuer; every request
re-verifies Access JWT and requires the session subject to match. Expired/invalid
Access JWT cannot be bypassed with an old session.

## 4. Local accounts, password and TOTP

- Initial `platform_admin` is created only by the local, OS-protected
  `um-center auth bootstrap` path; atomic once-only creation, no public bootstrap
  endpoint, no default password.
- Passwords: Argon2id (memory 64 MiB, time 3, parallelism 2, 16-byte salt,
  32-byte key; versioned PHC string), min 12/max 1024 bytes, password never in
  argv/env/URL/log/audit/error. KDF concurrency is bounded.
- Every browser user requires TOTP for a normal session. First login after
  bootstrap/password reset enters a restricted TOTP setup session; only setup
  endpoints are available until confirmation. Pending/setup sessions never reach
  `/api/v1`.
- TOTP: RFC 6238 SHA1, 6 digits, 30 s, ±1 step; persistent consumed-counter
  table makes replay/restart/clock-rollback fail; transactional insert means one
  concurrent code succeeds at most once.
- TOTP secrets are AES-256-GCM sealed with a master key from a protected local
  file (not SQLite), bound to user ID/version as AAD. Missing/corrupt/wrong key
  fails closed; startup never auto-regenerates a key.
- Recovery codes: 10 high-entropy single-use codes, only hashes stored; display
  once; regeneration replaces old generation; transactional consumption;
  success revokes sessions and requires TOTP re-enrollment. Controlled local
  recovery remains available when both TOTP and codes are unavailable, bounded
  by OS-owned access to the center host.

## 5. Sessions, cookies and CSRF

- Server-side sessions: random 32-byte token, only SHA-256 hash in SQLite;
  `__Host-` cookie, Secure, HttpOnly, SameSite=Strict, Path=/, no Domain.
- Idle timeout 30 min and absolute lifetime 12 h are candidate defaults; both
  server-enforced. Login/TOTP/setup/recovery rotate session IDs (fixation
  defense). Logout and explicit revocation are immediate.
- Password/TOTP/recovery/role/scope/disable/critical changes revoke affected
  sessions. Authorization is resolved fresh on each request from persisted
  account+scope, not cached in a client token.
- Mutations from the Web plane require a per-session CSRF token plus Origin
  check; missing/wrong/cross-session token fails. B4 mutation through the Web
  bridge goes through the same CSRF gate; purge preview (a GET that creates a
  durable confirmation receipt) is included in explicit CSRF/Origin protection
  in the Web bridge. The local admin bearer plane keeps its B4 behavior and is
  not reachable through the web handler.
- CSP, frame-ancestors, nosniff, Referrer-Policy, no-store on auth responses,
  same-origin only, no broad CORS, HSTS deployment notes. Session/CSRF tokens
  are never placed in localStorage/sessionStorage.

## 6. Authorization and account administration

Roles remain `platform_admin`, `event_admin`, `viewer`; machine is not a Web
role. Web user administration is platform_admin-only and projects to the same B4
action matrix:

- config/mapping/event lifecycle/retention/user administration: platform_admin;
- event-scoped token/revoke/alias/audit: event_admin only in assigned events;
- viewer read-only, no audit;
- stale scopes are revalidated on each request and SQL scope remains mandatory.

Account lifecycle: create/query/list, enable/disable, initial and changed
password, TOTP state, recovery generation, role/event scope, session
list/revoke, controlled local recovery, audit. Last enabled platform_admin cannot
be disabled/demoted. No public self-registration. Account count/platform-admin
expansion uses the frozen least-privilege defaults and Owner policy if a limit is
later required.

## 7. Database migration

Additive v11 adds only UM-C tables: `umc_users`, `umc_user_event_scopes`,
`umc_preauth`, `umc_sessions`, `umc_recovery_codes`, `umc_totp_counters` and
indexes. Existing v1-v10 migrations, B1-B4 tables, frozen schemas and ledger are
unchanged. Auth state cleanup is bounded; TOTP/recovery/session critical
transitions are transactional. Backup/restore drills, master-key offsite backup
and real Cloudflare integration remain UM-E/HOLD.

## 8. Machine TLS

The production machine entry is an independent hostname + direct TLS 1.3
listener serving the existing `/v1/agent/*` handler with the frozen Ed25519
identity. Tests use synthetic CA/server certs and verify hostname mismatch,
untrusted CA, expired cert, no insecure fallback, agent enroll/report/rotate and
Web/Access outage independence. Agent browser sessions/cookies/Cloudflare Access
are never required for machine reports. Real certificates/DNS/public ports stay
Owner HOLD.

## 9. Frontend and deployment

Single Vue 3 + TypeScript + Vite project under `um/web`, built to static assets
served by the Web plane. Pages: login, TOTP verify/setup, recovery, session
management, account/password/TOTP/recovery, platform-admin user management,
dashboard shell and error states. No full monitoring/chart implementation (UM-D).
No secrets, test credentials or real domains in the bundle. Cloudflare Tunnel,
Access application/audience/issuer, loopback origin, firewall, master key,
bootstrap/recovery, TLS/certificate rotation and rollback are documented
templates with synthetic values; no real Cloudflare/DNS/credential operation.

## 10. Residual gates

- Real Cloudflare Access/Tunnel/DNS/certificate deployment: **HOLD**, not
  claimed by isolated tests.
- Production deployment/accounts: **PRODUCTION HOLD**.
- Linux `singbox_api` **DISABLED**; R1 **PRODUCTION HOLD**; UM-F **DEFERRED**.
- Linux Reality/Hysteria2 real traffic remains a pre-production functional
  blocker on #127; this phase does not modify monitor-v2 or frozen contracts.
