# UM-B4 management runbook (Draft)

This runbook is for an isolated center deployment. It does **not** authorize a
public admin endpoint, production deployment, UM-C login, real R1 enablement or
`singbox_api`. The admin listener is loopback-only in this release.

## 1. Local admin credential provisioning

B4 has no UM-C login/TOTP/session. The release binary authenticates `/api/v1/*`
with a local bearer token file and a server-side auth file containing principals,
roles, event scopes and SHA-256 token hashes. Do not use an agent identity,
enrollment token or client-supplied role header as an admin credential.

Create the files with protected permissions (`0600`; Windows: a DACL whose only
allow ACEs are the file owner, the `um-center` service account, LocalSystem and
Builtin Administrators; reject arbitrary local/domain accounts). Keep the raw
token in a separate operator file and give only its SHA-256 hash to the server
auth file.

Linux example (conceptual; use the host's secret tooling for the raw token):

```bash
umask 077
token="$(openssl rand -base64 32 | tr -d '\n')"
printf '%s' "$token" > /etc/um-center/admin.token
sha="$(printf '%s' "$token" | sha256sum | awk '{print $1}')"
cat > /etc/um-center/admin-auth.json <<JSON
{
  "principals": [
    {"id":"platform-admin","role":"platform_admin","event_ids":[]},
    {"id":"event-a-admin","role":"event_admin","event_ids":["<event-a-uuid>"]}
  ],
  "tokens": [
    {"sha256":"$sha","principal_id":"platform-admin"}
  ]
}
JSON
chmod 0600 /etc/um-center/admin.token /etc/um-center/admin-auth.json
```

The auth file is strict JSON; unknown fields, invalid roles, duplicate ids/hashes,
non-UUID event scopes and non-platform_admin scopes without events are rejected at
startup. The server never logs or stores raw token values.

## 2. Start the center with the management API

```bash
um-center \
  -ingest 127.0.0.1:8443 \
  -admin 127.0.0.1:8090 \
  -db /var/lib/um-center/center.db \
  -contracts /etc/um-center/contracts/v1 \
  -admin-auth-file /etc/um-center/admin-auth.json
```

- Without `-admin-auth-file`, the admin listener exposes only `GET /api/health`
  and the management API is disabled (fail-closed).
- With it, `um-center` refuses a non-loopback admin address. Cloudflare Tunnel,
  public TLS, login and session handling belong to UM-C and are not implemented.
- Ingest remains exactly `/v1/agent/*`; the admin listener never serves those
  endpoints. Verify with a probe if changing deployment tooling.

## 3. CLI

Global flags come **before** the command:

```bash
export UM_CENTER_ADMIN_TOKEN_FILE=/etc/um-center/admin.token
um-center admin --url http://127.0.0.1:8090 --token-file "$UM_CENTER_ADMIN_TOKEN_FILE" --json health
```

The CLI always uses the management HTTP service; it never reads SQLite directly.
Exit codes: `0` success, `1` API/network error, `2` usage. JSON output is on
stdout; errors are bounded on stderr. Raw tokens are read from the protected file
and are never printed.

### Events

```bash
um-center admin ... event list [--state active|archived] [--limit N] [--offset N]
um-center admin ... event create --name "Event A" [--event-id UUID]
um-center admin ... event show EVENT_ID
um-center admin ... event rename EVENT_ID --name "New name"
um-center admin ... event archive EVENT_ID
um-center admin ... event purge preview EVENT_ID
# preview returns preview_id + preview_expires_at; first confirm requires it:
um-center admin ... event purge confirm EVENT_ID --preview-id PREVIEW_ID --confirm purge:EVENT_ID
um-center admin ... event purge status EVENT_ID
```

Purge is platform_admin-only, previews affected rows, requires the exact
`purge:<event_id>` phrase **and** the short-lived `preview_id` receipt for a
first start (bound to actor/event/action/lifecycle state, five-minute expiry,
single use). The receipt is consumed in the same transaction that persists the
durable purge operation. Repeat requests and interrupted-operation recovery are
idempotent once the operation/graveyard exists, without needing a live receipt.
There is no `--yes` shortcut.

### Nodes / config / tokens

```bash
um-center admin ... node list EVENT_ID [--class linux_vps|windows_terminal] [--state active|revoked]
um-center admin ... node show EVENT_ID NODE_ID
um-center admin ... node revoke EVENT_ID NODE_ID
um-center admin ... token create EVENT_ID --class linux_vps|windows_terminal [--ttl-seconds 60..900]
um-center admin ... token list EVENT_ID
um-center admin ... token status EVENT_ID TOKEN_ID
um-center admin ... token revoke EVENT_ID TOKEN_ID
um-center admin ... config show EVENT_ID NODE_ID
um-center admin ... config history EVENT_ID NODE_ID
um-center admin ... config update EVENT_ID NODE_ID --cadence 60 --sources '{"system":true,"services":true,"singbox_api":false,"mihomo_api":false,"terminal":false,"events":true}' --tags '[{"inbound_tag":"vless-in","kind":"reality"}]'
```

The token plaintext is returned **once** by `token create`; list/status expose
only the token hash, scopes and status. Feed it to the existing agent enrollment
stdin flow. Revoking an unused token makes B2 enrollment fail closed.

Config updates are effective-dated server-side, class-validated and audited.
`singbox_api:true` and `mihomo_api:true` are always rejected in B4: the Linux
source is disabled pending the P1-10 audit, and Windows R1 is local-bundle-only.
The CLI never sends controller secrets, proxy names, YAML, commands or URLs.

### Aliases / mapping

```bash
um-center admin ... alias list EVENT_ID [--type node|device_ref|route]
um-center admin ... alias set EVENT_ID node NODE_ID --name "primary-vps"
um-center admin ... alias set EVENT_ID node NODE_ID --name "renamed" --expected-version 1
um-center admin ... alias delete EVENT_ID node NODE_ID

um-center admin ... mapping list EVENT_ID WINDOWS_NODE_ID
um-center admin ... mapping create EVENT_ID WINDOWS_NODE_ID --version 1 \
  --effective-from EPOCH --entries '{"a_reality":"LINUX_NODE_ID"}'
um-center admin ... mapping resolve EVENT_ID WINDOWS_NODE_ID [--at EPOCH]
```

Mapping versions are append-only, next-version-only, non-backdated and
same-event/class-validated. `direct`/`unknown` never carry VPS targets. A new
version does not rewrite old historical attribution. Mapping writes are
platform_admin-only in B4.

### Retention / capacity / audit

```bash
um-center admin ... retention state
um-center admin ... retention timeline
um-center admin ... retention runs [N]
um-center admin ... retention run
um-center admin ... capacity
um-center admin ... audit list [--event EVENT_ID] [--action ACTION] [--result ok|denied|error] [--actor ID] [--since EPOCH] [--until EPOCH] [--limit N]
um-center admin ... audit verify
```

`retention run` invokes the existing bounded B2 policy-B sweep, platform_admin
only. Capacity output is a planning estimate, not a SQLite disk hard limit. Audit
is scoped for event_admin and denied to viewer; `audit verify` validates the
security-ledger hash chain but is not a backup/restore authorization.

## 4. Common failures

| Symptom | Meaning / action |
| --- | --- |
| `admin_auth_unavailable` | no auth file configured; management API intentionally disabled |
| `unauthenticated` (401) | missing/invalid bearer token; check the local token file and server auth hash |
| `forbidden` (403) | authenticated role is not allowed for this action |
| `not_found` (404) | missing resource **or** out-of-scope event; check principal scope without trying to enumerate |
| `conflict` (409) | alias optimistic version or mapping version conflict; re-read and retry with current version |
| `event_archived` / `event_purged` | lifecycle gate; no normal ingest/enrollment/config/mapping |
| `quota_exceeded` | frozen catalog/node/overlap quota; do not raise policy without Owner capacity decision |
| `invalid_request` | body/field/class/source/mapping validation; see the closed code/message, retry only after correction |
| `admin API unavailable` | CLI cannot reach the loopback listener; do not bypass by opening SQLite directly |

## 5. Operational boundaries

- Keep the admin listener loopback-only until UM-C provides authenticated public
  ingress, session/TOTP/CSRF and role administration.
- Keep `admin.token`/`admin-auth.json` owner-protected; rotate by replacing the
  token file and hash entry through an ordinary local operation (no production
  auto-rotation in B4).
- Do not use the management API to enable `singbox_api`/`mihomo_api`, modify
  Mihomo/Clash/HA, run commands, fetch arbitrary URLs or read arbitrary files.
- Do not use management API aliases as identity; stable `node_id`/`event_id`
  remain authoritative.
- Database migrations are forward-only; v10 adds only the purge confirmation receipt table. Never edit an applied migration.
  Back up the SQLite DB according to the center deployment policy before upgrade
  (B4 does not implement backup/restore itself).
- Production deployment, public ingress, real tournament terminals, R1 production
  enablement and UM-C/D/E/F/G remain HOLD/separate authorization.
