# UM-C authentication and secure-ingress runbook (Draft)

Status: Draft PR Refs #127. **PRODUCTION HOLD.** This runbook is a deployment
template for an isolated lab. It uses placeholders and does not authorize real
Cloudflare/Tunnel/DNS/Access/IdP/certificate or production operations.

## 1. Trust planes

| Plane | Address | Credential | Routes |
| --- | --- | --- | --- |
| Web | loopback `-web` + optional local TLS | Cloudflare Access JWT + local session/password/TOTP | `/`, `/auth/*`, `/web/api/*`, `/api/v1/*` bridge |
| Local admin | loopback `-admin` | protected local bearer file | `/api/health`, `/api/v1/*` |
| Machine | `-machine-tls` public/DNS hostname (HOLD) | frozen Ed25519 agent identity | `/v1/agent/*` only |
| Local ops CLI | local process only | OS file/ACL ownership | bootstrap/recovery/init-key |

Only the Web origin may be routed through Cloudflare Tunnel. Never publish
`-admin` or point Tunnel ingress at it. The Web handler never accepts local B4
bearer credentials; the admin/machine handlers never mount browser/session
routes. Source IP alone is never authorization.

## 2. Prepare protected local files

Run on the center host as the service account. Never put a password or master
key in argv, environment, shell history, a browser URL or the repository.

```bash
umask 077
mkdir -p /etc/um-center
um-center auth init-key --path /etc/um-center/master.key
# Keep master.key off SQLite backups and out of source control. Back it up using
# the Owner-approved offline secret process; losing it makes TOTP secrets
# unrecoverable by design.
```

Create the B4 local admin auth file/bearer token separately only if the local
admin plane is required; see `um-b4-runbook.md`. The protected file must be
0600/owner-only on POSIX or an equivalent owner/service-account/LocalSystem/
Administrators-only DACL on Windows.

## 3. Bootstrap the first platform administrator

```bash
um-center auth bootstrap \
  --db /var/lib/um-center/center.db \
  --master-key /etc/um-center/master.key \
  --username <initial-admin>
# Password is read from the terminal (no echo); never pass it as a flag.
```

Bootstrap is local-process only, atomic and once-only. It creates one enabled
`platform_admin` with no TOTP enrollment. There is no public bootstrap endpoint
and no default credential. The first browser login forces TOTP setup and shows
one-time recovery codes.

Additional accounts: `event_admin`/`viewer` are created by a signed-in
platform_admin in the Web user administration page, with at least one existing
event scope and a generated one-time initial password. Additional
`platform_admin` creation/escalation is refused by the Web API and requires a
separate Owner policy; the last enabled platform_admin cannot be disabled or
demoted.

## 4. Start the center (isolated lab)

```bash
um-center \
  -ingest 127.0.0.1:8443 \
  -admin 127.0.0.1:8090 \
  -admin-auth-file /etc/um-center/admin-auth.json \
  -db /var/lib/um-center/center.db \
  -contracts /etc/um-center/contracts/v1 \
  -web 127.0.0.1:8092 \
  -web-static /opt/um-center/web/dist \
  -web-origin https://um-console.example.invalid \
  -master-key /etc/um-center/master.key \
  -access-issuer https://<team>.cloudflareaccess.invalid \
  -access-audience <UM-C-application-AUD-tag> \
  -access-jwks https://<team>.cloudflareaccess.invalid/cdn-cgi/access/certs
```

- The Web listener must be loopback; `-web` requires master key, Access
  issuer/audience/JWKS and at least one exact `https://` origin.
- Do not use `-access-jwks-insecure-http-for-tests` in deployment. It is only for
  hermetic labs.
- `-web-tls` plus `-web-tls-cert/-web-tls-key` is for local browser labs. In
  production Cloudflare terminates public TLS and the origin remains loopback;
  Access is still cryptographically verified at the center.
- `-machine-tls` + cert/key starts the independent machine TLS 1.3 listener. It
  serves only `/v1/agent/*`. Use a separate hostname/certificate from the Web
  origin; never route machine traffic through Cloudflare Access/browser cookies.
  Real certificate/DNS/public-port work is **HOLD**.
- Maintenance periodically removes expired preauth/sessions and old TOTP counters
  in bounded batches.

## 5. Cloudflare Tunnel and Access template

Only for an Owner-approved isolated deployment; configuration values are
placeholders. Copy `um/deploy/um-c/cloudflared.example.yml`, replace the tunnel
UUID/credentials/hostname, and keep the ingress target to the loopback Web
listener only. Add the Web hostname to an Access application restricted to the
intended operator IdP/groups. Do not expose `/auth/*`, `/web/api/*` or
`/api/v1/*` as separate bypass policies; they are the same Access-protected
origin. Do not create a service token that bypasses the local password/TOTP
policy.

The center verifies the Access assertion (`Cf-Access-Jwt-Assertion`) on every
request, binds the session to the verified subject/issuer, and requires the
local account/TOTP. `Cf-Access-Authenticated-User-Email` is never treated as
local identity. A stale Access session cannot bypass a revoked/expired local
session.

## 6. Operator login and account security

1. Navigate to the Web origin through Access; enter username/password.
2. First login: scan the local QR/manual TOTP secret in an authenticator, enter
   the current 6-digit code, and save the one-time recovery codes offline.
3. Normal login always requires TOTP. If the authenticator is lost, use one
   recovery code plus password; it revokes sessions, consumes the code and forces
   a new TOTP enrollment.
4. If both are unavailable, an operator with OS access to the center host runs:

```bash
um-center auth recover \
  --db /var/lib/um-center/center.db \
  --master-key /etc/um-center/master.key \
  --username <account>
# Reads a new password from the terminal, revokes sessions and clears TOTP.
```

5. Rotate/regenerate recovery codes from Account Security after displaying them
   once; store offline. Passwords/TOTP secrets/recovery codes are never displayed
   again after the one-time response.

## 7. Sessions, CSRF and incident response

- Idle timeout is 30 minutes, absolute lifetime 12 hours (candidate defaults;
  configurable in code/Config). Session ID rotates after login/TOTP/recovery/
  password changes; only a SHA-256 hash is stored server-side.
- Cookies are `__Host-um_session` Secure HttpOnly SameSite=Strict and
  `__Host-um_csrf` (non-HttpOnly per-session double-submit). Fetch mutations send
  `X-CSRF-Token` and same-origin `Origin`; browsers never store credentials in
  localStorage/sessionStorage.
- To respond to suspected compromise: disable the account in user
  administration (revokes sessions), revoke sessions from the account page, rotate
  the account password/TOTP/recovery codes, and if necessary stop the center and
  perform local recovery. Do not attempt to extract/decrypt secrets from SQLite.
- Login/TOTP/recovery/user-admin endpoints have bounded in-memory rate limits and
  Argon2id concurrency limits (4); sustained failure should return 429/503, not
  weaken authentication.
- Audit/ledger entries contain actor/role/action/result/target IDs and hashed
  ledger context only; never submit secrets in support requests.

## 8. Backup / key handling / rollback

- A SQLite backup contains password hashes, session hashes, encrypted TOTP
  secrets and hashed recovery codes but **not** the master key. Keep the master
  key separate and protected.
- Missing/corrupt/wrong master key or DB auth state fails closed; never
  auto-regenerate the key at startup. Restore the exact key/DB pair from an
  Owner-approved offline backup. Backup/restore drills and offsite escrow are
  UM-E/operations gates, not claimed complete here.
- Migration v11 is additive only. There is no automatic downgrade. Operational
  rollback restores a pre-upgrade DB backup; older binaries refuse newer schema.
- Stopping the center closes Web/admin/machine listeners; agents can continue to
  spool reports independently, and machine TLS does not depend on Cloudflare
  Access or browser sessions.

## 9. Verification commands

```bash
cd um
go test ./internal/umcauth ./internal/web ./internal/store ./internal/center ./cmd/um-center
cd web
npm ci && npm run typecheck && npm test && npm run build
# Browser lab: build the harness, start it, set UM_C_E2E_* from E2E_READY,
# then `npm run test:e2e`. See um/web/README.md.
```

The synthetic Access/JWKS/browser harness is an isolated simulation, not proof of
a real Cloudflare deployment. Real Tunnel/Access/DNS/certificate/production
verification remains **HOLD** and requires separate Owner authorization.
