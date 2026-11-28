# UM-C Web console (`um/web`)

Vue 3 + TypeScript + Vite single-page operations console for the UM-C browser
plane. It is the shared frontend foundation for UM-C and a future UM-D
dashboard; this milestone intentionally does **not** implement monitoring,
charts or alert views.

- This directory contains only the frontend; backend Go/docs/workflow changes live elsewhere in the same branch. Frozen rev-5/rev-6 files are untouched.
- Authentication/authorization is enforced by the center Web plane
  (`um/internal/web`); this UI never treats hidden buttons or routes as a
  security boundary.
- Built assets are served by the center Web listener
  (`um-center -web ... -web-static um/web/dist`).

## Commands

Requires Node.js `>= 20.19` and npm.

```bash
npm ci             # install from package-lock.json
npm run dev        # Vite dev server (127.0.0.1:5173)
npm run typecheck  # vue-tsc --noEmit
npm test           # Vitest unit/component tests
npm run build      # typecheck + production build to um/web/dist
```

Optional local proxy target for `npm run dev`:

```bash
VITE_DEV_PROXY_TARGET=https://127.0.0.1:9443 npm run dev
```

`/auth`, `/web/api` and `/api/v1` are proxied to that origin. The center Web
plane requires a valid Cloudflare Access assertion on every request, so local
development still needs an Access test path; the committed real-browser lab uses
the isolated synthetic harness in `um/cmd/um-c-e2e`. The frontend deliberately
has no authentication bypass.

## Structure

```
um/web
├── index.html            # no inline scripts; CSP meta injected at build
├── vite.config.ts        # Vue plugin, CSP injection, optional dev proxy, Vitest config
├── tsconfig.json
├── package.json / package-lock.json
├── public/favicon.svg
└── src
    ├── api/              # fetch wrapper, CSRF, auth/users/B4 clients, normalizers, tests
    ├── components/       # AppShell, QR code, recovery codes, dialogs, state blocks
    ├── composables/      # shared API-error handling (expired → /expired)
    ├── router/           # routes, /auth/context guard, safe redirects, guard tests
    ├── stores/auth.ts    # in-memory auth/session state (Pinia)
    ├── views/            # login, TOTP verify/setup, recovery, dashboard, account, admin
    ├── utils/            # formatting, clipboard, error messages
    └── assets/main.css   # compact desktop-first ops UI, responsive fallbacks
```

## Pages

| Route | Page |
| --- | --- |
| `/login` | username/password login (Cloudflare Access assumed at the edge) |
| `/totp` | TOTP challenge for a pending session |
| `/setup-totp` | first-time TOTP enrolment (QR rendered locally with `qrcode`) |
| `/recovery` | recovery-code login |
| `/` | authenticated shell + dashboard (user, role, event scopes, health placeholder) |
| `/account/sessions` | own session list / revoke |
| `/account/security` | TOTP re-enrolment, recovery-code regeneration (shown once) |
| `/account/password` | change password |
| `/admin/users` | platform-admin user list/create/disable/enable/role+event scope/sessions |
| `/expired`, `/403`, `/404` | session-expired, forbidden and not-found states |

Loading, empty, error, expired, 403 and 404 states are implemented; list pages
show retry actions, forms show inline API errors.

## Security invariants

- **No bearer token in the browser.** The Cloudflare Access JWT is checked at the
  edge and never fabricated, read or stored by JavaScript. No `Authorization`
  header is sent by this app.
- **Session cookies are HttpOnly server-set.** The client uses
  `fetch(..., { credentials: 'same-origin' })` and never reads cookies.
- **CSRF token only in memory.** It comes from `/auth/context` or auth-mutation
  responses, is held in a module-scope variable, and is sent as
  `X-CSRF-Token`. It is never written to `localStorage`, `sessionStorage`, the
  URL or logs. It is attached to protected GETs as well, because the center
  Web plane requires it for `/web/api/*` reads.
- **Tokens cannot leak into the bundle.** No credentials, secrets or Access
  material are compiled in; TOTP/recovery material is memory-only and shown
  once.
- **CSP-compatible.** No inline `<script>`, `eval`, `new Function`, external CDN,
  inline style or `v-html`. The production `dist/index.html` gets a CSP meta tag
  and the center Web plane sends the authoritative CSP header. Styling is an
  external CSS asset; the QR code is drawn on `<canvas>` by the local `qrcode`
  npm library (no external QR service).
- **Guard by `/auth/context`.** The router bootstraps the context once and
  redirects by real session state/role: protected pages, platform-admin pages
  (403), pending TOTP, TOTP setup, expired session, context outage. Every
  backend request re-authorizes independently.

## Backend contract used

The concrete backend in this repository is `um/internal/web` (center Web plane).
The frontend targets it, with narrowly-scoped fallbacks for the earlier drafted
contract.

| Request | Notes |
| --- | --- |
| `GET /auth/context` | Preauth CSRF + cookie, or `{authenticated,session_state,user,csrf_token}`; setup material may be re-displayed for a pending setup session; no `allowed_events` field (scopes are `user.event_ids`) |
| `POST /auth/login` `{username,password}` + CSRF | Returns `totp_required` or `totp_setup_required`; first-time setup includes `secret`, `otpauth_uri`, `user` |
| `POST /auth/totp` `{code}` + CSRF | Verifies a pending session or confirms a setup session; confirm returns `authenticated`, `recovery_codes` |
| `POST /auth/totp/update` `{password}` + CSRF | Re-enrolment (requires current password; rotates the session into setup state) |
| `POST /auth/recovery` `{username,password,recovery_code}` + preauth CSRF | Returns TOTP setup material (new enrolment required) |
| `POST /auth/logout` / `POST /auth/abandon` + CSRF | Revoke active or pending session; 204 |
| `GET /auth/sessions` | `{sessions:[{session_id,state,created_at,last_seen_at,idle_expires_at,absolute_expires_at,current}]}` |
| `POST /auth/sessions/{session_id}/revoke` + CSRF | Own session revoke |
| `POST /auth/password` `{current_password,new_password}` + CSRF | `{relogin_required:true}`; all cookies cleared |
| `POST /auth/recovery-codes` + CSRF | `{recovery_codes:[...]}` (display once) |
| `GET /web/api/users` (GET needs no CSRF header) | `{users:[{user_id,username,role,enabled,event_ids,totp_enrolled,last_login_at}]}` |
| `POST /web/api/users` + CSRF | `{username,role,event_ids}`; center allows only `event_admin`/`viewer`; returns `{user,initial_password}` |
| `POST /web/api/users/{id}/disable\|enable` + CSRF | `{user_id,enabled}` |
| `POST /web/api/users/{id}/reset-password` + CSRF | `{user_id,temporary_password,relogin_required}` |
| `POST /web/api/users/{id}/role` + CSRF | `{role,event_ids}`; `platform_admin` escalation is refused |
| `GET /web/api/users/{id}/sessions` | Session list for another user (GET needs no CSRF header) |
| `POST /web/api/users/{id}/sessions/{session_id}/revoke` + CSRF | Revoke another user's session |
| `GET /api/v1/events` (B4 bridge) | Event catalogue for scope assignment; B4 `{v:1,data:{events:[...]}}` envelope |
| `GET /api/v1/*` / mutations | B4 envelope `{v:1,data}`; unsafe mutations and the purge-preview GET need `X-CSRF-Token` (helpers in `src/api/http.ts`) |

Errors use `{error:{code,message,retryable}}`. Direct auth/web JSON is accepted as
well as B4 envelopes. 401/419 is treated as an expired session except for
credential-error codes (`invalid_credentials`, `invalid_totp`,
`invalid_recovery`, ...); 403 is shown inline/route-403 and never silently
ignored.

## Backend alignment notes

- First-time TOTP material is returned by `/auth/login` and `/auth/recovery`;
  confirmation is `POST /auth/totp` (the adapter also tries `/auth/totp/confirm`
  for compatibility). Re-enrolment is `POST /auth/totp/update` with the current
  password.
- `/auth/context` includes `session_state` (`totp_pending`/`totp_setup`/
  `authenticated`) and re-displays setup material for a pending setup session.
  Event scopes are `user.event_ids`; the user-admin event catalogue comes from
  B4 `GET /api/v1/events`.
- `GET /web/api/users` does not require CSRF; unsafe `/web/api/*` mutations do.
  The SPA sends `X-CSRF-Token` on every request when it holds one.
- `/auth/logout` and `/auth/abandon` revoke active or pending sessions. The UI
  currently offers no cancel button on the challenge page, which is a product
  choice, not a backend limitation.
- Platform-admin creation/escalation is refused by the Web API. Additional
  platform admins require a separate Owner policy; the UI only offers
  `event_admin`/`viewer`.
- Password change revokes all sessions and returns `{relogin_required:true}`; the
  UI redirects to `/login?reason=password_changed`.
- Access JWT is required even for static assets; local browser E2E uses the
  isolated `um-c-e2e` harness with synthetic Access/TLS, not a bypass.

## Verification

- `npm run typecheck` — clean.
- `npm test` — 99 Vitest tests across HTTP wrapper, contract adapters,
  normalizers, auth store, route guard, QR/state components and dashboard.
- `npm run build` — emits `um/web/dist` (`index.html`, hashed JS/CSS,
  favicon). `node_modules/` and `dist/` are ignored by `um/web/.gitignore`.
- `npm ci --dry-run` — lockfile is consistent.

Note: `npm ci` prints harmless `EBADENGINE` warnings for the test-only
`@vue/test-utils → js-beautify → nopt` chain on Node 24.13 (it asks for
`>=24.15`); tests and build run successfully. Node >= 24.15 removes the warning.

## Not in scope

UM-D monitoring dashboards, charts, alerting, B4 data pages and real
Cloudflare/DNS/certificate operations are intentionally not implemented here.
The dashboard shows only a system-health placeholder and scope summary.


## Real-browser E2E lab

Playwright drives the actual built Vue bundle against the real center Web handler,
real SQLite store, real management bridge and real HTTP/TLS cookies. The isolated
`um-c-e2e` harness supplies **synthetic** Cloudflare Access JWKS/JWT and a
self-signed loopback TLS certificate only; it never contacts Cloudflare/DNS and
does not prove a real edge deployment.

The harness is a lab-only command (`um/cmd/um-c-e2e`) with two same-origin lab
surfaces: `/__lab/state|advance` for deterministic forward-only clock/fixtures and
`/__lab/b4/*`, which mounts the unchanged real B4 management handler behind a
synthetic in-memory local bearer to prove that a valid local admin credential is
still rejected by the browser Web plane. None of these surfaces exist in the
production `um-center` command. The lab seeds a second platform_admin
(`e2e-owner`) only as an isolated Owner-policy stand-in.

```bash
cd um
go build -o /tmp/um-c-e2e ./cmd/um-c-e2e
(cd web && npm run build)
/tmp/um-c-e2e -listen 127.0.0.1:18443 -static web/dist
# read the E2E_READY JSON line and export:
# UM_C_E2E_URL, UM_C_E2E_TOKEN, UM_C_E2E_USER, UM_C_E2E_PASSWORD
cd web
PLAYWRIGHT_CHANNEL=chrome npm run test:e2e
```

`tests/e2e/auth.spec.ts` is the only spec and must run single-worker (the lab
clock is global). It contains **9 serial real-Chromium tests**:

1. preserved platform_admin login → forced TOTP → dashboard/users → logout →
   TOTP login closure;
2. UI provisioning of event_admin A/B and viewer A/B with two independent events;
3. forced first-login TOTP + normal TOTP login for all roles;
4. authorized/unauthorized event visibility, viewer read-only, event_admin without
   global admin;
5. CSRF rejection and synthetic B4 local bearer accepted by the isolated local
   admin plane but rejected by the Web plane;
6. own/admin session revocation and admin password reset;
7. role/scope change revoking sessions and applying new authorization;
8. own password change, recovery-code login, recovery-code reuse rejection, stale
   authenticator rejection, TOTP update;
9. idle-timeout `/expired`, logout and 404 surfaces.

Screenshots are written under ignored `um/web/test-results/` and uploaded by CI.
The test fails closed if `UM_C_E2E_*` is absent or any step fails. Real
Cloudflare/Tunnel/DNS/Access/IdP/certificate/deployment remains HOLD; see the
UM-C runbook/scope/evidence.
