# UM-C Web authentication API (Draft)

This is the browser-plane API served by the center Web listener. Every route
except the minimal anonymous `GET /api/health` requires a valid Cloudflare Access
assertion. Browser mutations additionally require the per-session
`X-CSRF-Token` and a same-origin `Origin` when the browser sends one. The API does
not accept the B4 local bearer credential, an Access email header, a client role
header or a browser-stored token.

Machine-readable contract: `um-c-auth-api.openapi.json`. The existing B4
management API contract remains `um-b4-admin-api.openapi.json`; the Web bridge
exposes the same `/api/v1/*` paths with the same request/response shapes after
session/RBAC resolution.

## Authentication flow

1. Cloudflare Access terminates the edge session and supplies
   `Cf-Access-Jwt-Assertion` to the origin.
2. `GET /auth/context`:
   - with a valid local session returns user/role/scope/session stage/CSRF;
   - without one creates a short-lived Access-subject-bound preauth and returns
     `csrf_token`.
3. `POST /auth/login` requires the preauth cookie and CSRF. On success it returns
   either a TOTP challenge or first-time TOTP setup material. No active session is
   granted before TOTP.
4. `POST /auth/totp` consumes a valid TOTP (or completes setup), rotates the
   session and returns the authenticated context. Setup also returns the
   one-time recovery codes.
5. Mutations use the CSRF token; session/public IDs are opaque.

All responses use `Cache-Control: no-store` on auth/API routes. CSP denies
framing, inline script and external connect sources. Error messages are generic
for credential failures.

## Browser/auth endpoints

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| GET | `/api/health` | no | minimal Web health probe |
| GET | `/auth/context` | yes | session/user/CSRF/preauth context; setup material may be re-displayed for a pending setup session |
| POST | `/auth/login` | yes | username/password -> TOTP challenge or forced TOTP setup |
| POST | `/auth/totp` | yes | verify TOTP or complete setup; rotates session and returns recovery codes on setup |
| POST | `/auth/totp/confirm` | yes | compatibility alias for setup/verify confirmation |
| POST | `/auth/recovery` | yes | username/password + one recovery code -> forced TOTP setup |
| POST | `/auth/logout` | yes | revoke current active/pending session |
| POST | `/auth/abandon` | yes | revoke pending setup/challenge session |
| GET | `/auth/me` | yes | current authenticated/pending user view |
| POST | `/auth/password` | active | change own password; revokes all sessions, requires re-login |
| POST | `/auth/totp/update` | active | verify current password, start TOTP re-enrollment |
| POST | `/auth/recovery-codes` | active | regenerate one-time recovery codes (returns plaintext exactly once) |
| GET | `/auth/sessions` | active | own sessions (public IDs, times, current flag; no token hashes) |
| POST | `/auth/sessions/{session_id}/revoke` | active | revoke an owned session |

## User administration endpoints (platform_admin only)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/web/api/users` | list accounts (no hashes/secrets) |
| POST | `/web/api/users` | create `event_admin`/`viewer`; returns one-time initial password |
| GET | `/web/api/users/{user_id}` | account detail + unused recovery-code count |
| POST | `/web/api/users/{user_id}/disable` | disable account, revoke sessions, last-admin protected |
| POST | `/web/api/users/{user_id}/enable` | re-enable account (new login required) |
| POST | `/web/api/users/{user_id}/role` | replace role + event scopes, revoke sessions, last-admin protected |
| POST | `/web/api/users/{user_id}/reset-password` | set generated one-time password, revoke sessions |
| GET | `/web/api/users/{user_id}/sessions` | list another account's sessions |
| POST | `/web/api/users/{user_id}/sessions/{session_id}/revoke` | revoke another account's session |

Web cannot create or promote `platform_admin`; this requires a separate Owner
policy and the local bootstrap boundary. `event_admin`/`viewer` require at least
one existing event scope. All account admin actions are audited/ledgered.

## B4 bridge

`/api/v1/*` on the Web listener is the existing B4 management handler. The Web
wrapper authenticates Access + local session once, requires CSRF for unsafe
methods (and the B4 purge-preview GET receipt), resolves the current persistent
role/event scopes into `management.Principal`, then calls the existing service.
No second management service or permission matrix exists. The local loopback B4
bearer listener remains separate and is not tunnel-routed.

| Method | Path | Notes |
| --- | --- | --- |
| GET/POST | `/api/v1/events` | Web session bridge; role/scope checked by B4 |
| GET/PATCH | `/api/v1/events/{event_id}` | same |
| … | all other B4 routes | same OpenAPI contract, Web credentials only |

## Session and rate-limit parameters

- Session cookie: `__Host-um_session`, Secure, HttpOnly, SameSite=Strict, Path=/,
  no Domain. Server stores SHA-256(token) only.
- CSRF cookie: `__Host-um_csrf`, Secure, HttpOnly, SameSite=Strict; the SPA
  obtains the raw value from `/auth/context` (never `document.cookie`) and puts
  it in `X-CSRF-Token`; server stores only its hash.
- Idle 30 min, absolute 12 h (server-enforced). Pending TOTP challenge/setup
  sessions have a 10-minute TTL. Login/TOTP/recovery/user mutations are
  rate-limited by verified Access subject/session/user, not loopback IP;
  Argon2id concurrency is capped at 4. Five TOTP failures temporarily lock the
  account's TOTP for 15 minutes and revoke pending sessions.
- TOTP: RFC 6238 SHA-1/6 digits/30 s, ±1 step; persistent counter and atomic
  login/setup completion prevent replay. Recovery codes: 10 generated, single
  use, hashes only; successful recovery invalidates the remaining generation.

## Error model

Errors are JSON `{"error":{"code","message","retryable"}}`. Credential failures
use generic `invalid_credentials`/`invalid_recovery`; CSRF failure is
`csrf_invalid`/`login_csrf_failed`; last-admin protection is
`last_platform_admin`; rate limits use HTTP 429 and KDF saturation uses HTTP 503
`kdf_busy`. No error contains a secret or a credential value.
