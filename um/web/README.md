# UM-C Web console (`um/web`)

Vue 3 + TypeScript + Vite single-page operations console for the UM-C browser
plane. It is the shared frontend foundation for UM-C and a future UM-D
dashboard; this milestone intentionally does **not** implement monitoring,
charts or alert views.

- Frontend-only project: no Go, docs, workflow or frozen files are modified.
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
development still needs an Access test path (for example the backend's
test-only Access header hook or a local tunnel). The frontend deliberately has
no authentication bypass.

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
| `GET /auth/context` | Preauth CSRF + cookie, or `{authenticated,user,csrf_token}`; no `allowed_events` field |
| `POST /auth/login` `{username,password}` + CSRF | Returns `totp_required` or `totp_setup_required`; first-time setup includes `secret`, `otpauth_uri`, `user` |
| `POST /auth/totp` `{code}` + CSRF | Verifies a pending session or confirms a setup session; confirm returns `authenticated`, `recovery_codes` |
| `POST /auth/totp/update` `{password}` + CSRF | Re-enrolment (requires current password; rotates the session into setup state) |
| `POST /auth/recovery` `{username,password,recovery_code}` + preauth CSRF | Returns TOTP setup material (new enrolment required) |
| `POST /auth/logout` + CSRF | Active sessions only; 204 |
| `GET /auth/sessions` | `{sessions:[{session_id,state,created_at,last_seen_at,idle_expires_at,absolute_expires_at,current}]}` |
| `POST /auth/sessions/{session_id}/revoke` + CSRF | Own session revoke |
| `POST /auth/password` `{current_password,new_password}` + CSRF | `{relogin_required:true}`; all cookies cleared |
| `POST /auth/recovery-codes` + CSRF | `{recovery_codes:[...]}` (display once) |
| `GET /web/api/users` + CSRF | `{users:[{user_id,username,role,enabled,event_ids,totp_enrolled,last_login_at}]}` |
| `POST /web/api/users` + CSRF | `{username,role,event_ids}`; center allows only `event_admin`/`viewer`; returns `{user,initial_password}` |
| `POST /web/api/users/{id}/disable\|enable` + CSRF | `{user_id,enabled}` |
| `POST /web/api/users/{id}/reset-password` + CSRF | `{user_id,temporary_password,relogin_required}` |
| `POST /web/api/users/{id}/role` + CSRF | `{role,event_ids}`; `platform_admin` escalation is refused |
| `GET /web/api/users/{id}/sessions` + CSRF | Session list for another user |
| `POST /web/api/users/{id}/sessions/{session_id}/revoke` + CSRF | Revoke another user's session |
| `GET /api/v1/events` (B4 bridge) | Event catalogue for scope assignment; B4 `{v:1,data:{events:[...]}}` envelope |
| `GET /api/v1/*` / mutations | B4 envelope `{v:1,data}`; mutations need `X-CSRF-Token` (helpers in `src/api/http.ts`) |

Errors use `{error:{code,message,retryable}}`. Direct auth/web JSON is accepted as
well as B4 envelopes. 401/419 is treated as an expired session except for
credential-error codes (`invalid_credentials`, `invalid_totp`,
`invalid_recovery`, ...); 403 is shown inline/route-403 and never silently
ignored.

## Contract mismatches vs. the original task assumptions

These are the differences found between the task's written assumptions and the
implemented center Web plane, and how the frontend handles each one:

1. **TOTP setup/confirm endpoints.** Assumed `POST /auth/totp/setup` and
   `POST /auth/totp/confirm`; implemented first-time material is returned by
   `/auth/login` and `/auth/recovery`, confirmation is `POST /auth/totp`, and
   re-enrolment is `POST /auth/totp/update` requiring the current password.
   → The store keeps returned setup material in memory; the API adapter calls
   `/auth/totp/confirm` and falls back to `/auth/totp`; re-enrolment calls
   `/auth/totp/update` with the password and falls back to `/auth/totp/setup`.
2. **No `allowed_events` in `/auth/context`.** → The current user's event scopes
   come from `user.event_ids`; the user-admin event catalogue is read from B4
   `GET /api/v1/events`.
3. **No pending/setup stage in `/auth/context`.** → Inferred from
   `user.totp_enrolled` for normal flows; explicit setup material returned by a
   mutation wins. Edge case: a recovered TOTP setup session that is reloaded
   reports `totp_enrolled=true` and cannot be distinguished from a TOTP
   challenge (documented backend gap; needs a context stage field).
4. **Admin session revoke path.** Assumed `/web/api/sessions/{id}/revoke`;
   implemented `/web/api/users/{id}/sessions/{session_id}/revoke`. → Nested path
   first, flat path only when the endpoint itself is missing.
5. **CSRF on protected GETs.** Assumed mutations only; implemented
   `/web/api/*` GETs also require `X-CSRF-Token`. → Header sent on all requests
   when the in-memory token exists.
6. **Password change ends the session.** Implemented response is
   `{relogin_required:true}` after clearing cookies. → UI redirects to
   `/login?reason=password_changed` instead of showing a stale shell.
7. **Sessions lack IP/client metadata and use `session_id`.** → Normalizers read
   `session_id`; unavailable fields render as “—/未知客户端”.
8. **Pending TOTP sessions cannot be abandoned.** `/auth/logout` requires an
   active session, so the TOTP challenge page offers no “cancel/logout” action.
9. **Platform-admin creation/escalation refused by the Web API.** → Create/edit
   role controls only offer `event_admin`/`viewer` and state that platform-admin
   accounts come from the center-local Owner policy. The page itself is guarded
   by `/auth/context` and the backend still returns 403 for non-admins.
10. **B4 is the real event catalogue source.** Scope assignment validates
    against existing B4 events; the center store also requires at least one
    event for non-platform-admin accounts (enforced in the form too).
11. **Backend also sends a CSP header.** The built meta CSP mirrors it; no
    inline assets are emitted by the build.
12. **Access JWT is required even for static assets.** Local dev needs an Access
    test path; the app has no bypass.

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

```bash
cd um
go build -o /tmp/um-c-e2e ./cmd/um-c-e2e
/tmp/um-c-e2e -listen 127.0.0.1:18443 -static web/dist
# read the E2E_READY JSON line and export:
# UM_C_E2E_URL, UM_C_E2E_TOKEN, UM_C_E2E_USER, UM_C_E2E_PASSWORD
cd web
PLAYWRIGHT_CHANNEL=chrome npm run test:e2e
```

The committed test (`tests/e2e/auth.spec.ts`) covers Access-required page load,
password login, forced TOTP setup/QR page, session establishment, platform-admin
RBAC page through B4, logout and a second TOTP login. It fails closed if the
environment is missing or any authentication step fails. See the UM-C runbook and
scope docs for the production HOLD boundaries.
