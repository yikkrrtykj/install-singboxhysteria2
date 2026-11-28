# UM-C real-browser E2E lab

This directory drives the real built Vue bundle (`um/web/dist`) against the real
center Web handler, real SQLite store and real B4 management bridge over real
HTTPS cookies. The synthetic Access JWKS/JWT and the self-signed loopback TLS
certificate come only from the isolated lab harness `um/cmd/um-c-e2e`; nothing
here proves a real Cloudflare edge deployment, which remains a production HOLD.

## Run it

```bash
# terminal 1: build the frontend + isolated lab harness and start it
cd um
go build -o /tmp/um-c-e2e ./cmd/um-c-e2e
(cd web && npm run build)
/tmp/um-c-e2e -listen 127.0.0.1:18443 -static web/dist
# copy the E2E_READY JSON line and export:
#   UM_C_E2E_URL, UM_C_E2E_TOKEN, UM_C_E2E_USER, UM_C_E2E_PASSWORD
# the remaining fixtures are read by the test from GET /__lab/state

# terminal 2
cd um/web
PLAYWRIGHT_CHANNEL=chrome npm run test:e2e   # or plain `npm run test:e2e`
```

The suite fails closed if `UM_C_E2E_*` is missing; it never skips to green.

## Determinism: one worker only

`um-c-e2e` exposes a lab-only, strictly forward-only clock
(`POST /__lab/advance`, `now_unix` in `GET /__lab/state`) so the suite can step
past 30-second TOTP steps and the 30-minute idle window instead of sleeping.
That clock is global to the harness process, so **keep `auth.spec.ts` the only
`*.spec.ts` under this directory** (a single Playwright file already runs on one
worker). If another spec file is ever added, force `workers: 1` in
`um/web/playwright.config.ts`; otherwise the two files will fight over the lab
clock.

## What the lab covers

`auth.spec.ts` keeps the original single-role closure (platform admin password
login, forced TOTP enrolment, session, B4 user page, logout, TOTP login) and
adds the H8 multi-role lab:

- platform admin creates `event_admin` A/B and `viewer` A/B through the real user
  admin UI, assigning the independent events A/B as scopes;
- every account completes forced first-login TOTP setup and a later normal
  password + TOTP login;
- event A/B visibility is asserted in the dashboard and through real browser
  `fetch` calls to the B4 API: in-scope events are visible, out-of-scope events
  are `404 not_found` and absent from the list; viewers get `403` for mutations
  and cannot reach user administration; event admins get `403` for
  platform-global actions (event create/rename, retention run, user admin);
- CSRF failures (wrong/missing `X-CSRF-Token`) are rejected before RBAC, and a
  synthetic local-B4 bearer that is valid on the lab's isolated B4 admin handler
  still cannot authenticate or escalate the browser Web plane;
- own and administrator session revocation, administrator password reset,
  role/scope change invalidation followed by a login that shows the new
  authorization, disable/enable, own password change, single-use recovery-code
  login, stale-authenticator rejection, TOTP re-enrolment, idle-timeout expiry,
  logout and the 403/404/expired UI surfaces all run through the browser.

## Evidence output

Screenshots are written to `um/web/test-results/` (gitignored) as
`um-c-h8-*.png`. Key checks also print `[H8] ...` lines to the Playwright output
so CI logs carry the evidence without opening artifacts.

## Lab-only harness surfaces (never production code)

- `GET /__lab/state` — synthetic fixtures: lab clock, event ids/names, seeded
  lab platform-admin credential and the synthetic local B4 bearer.
- `POST /__lab/advance` — advance the lab clock (bounded, forward-only).
- `/__lab/b4/*` — the real B4 management handler mounted with an in-memory
  synthetic bearer authenticator (the lab stand-in for the separate local admin
  plane), so browser fetch can show the credential is real on that plane while
  the Web plane `/api/v1/*` still rejects it.

The harness refuses to listen on a non-loopback address. No real
Cloudflare/DNS/certificate/paid resource is contacted.
