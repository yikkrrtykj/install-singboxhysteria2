# UM-C isolated deployment examples (Draft, PRODUCTION HOLD)

These examples are placeholders for an isolated lab. They use `.invalid`
hostnames and no real credentials. No real Cloudflare/Tunnel/DNS/Access/IdP/
certificate or production resource may be created under this milestone.

## Files

- `cloudflared.example.yml` — Tunnel ingress that publishes **only** the loopback
  Web listener; never the local admin listener.
- `um-center.service.example` — systemd unit template with flags and no secrets
  in the environment.

## Host layout

```text
/etc/um-center/master.key          # protected master key, outside SQLite/backups
/etc/um-center/admin-auth.json     # optional B4 local bearer auth (separate plane)
/var/lib/um-center/center.db       # single existing SQLite DB, v13 additive
/opt/um-center/web/dist            # built Vue assets (npm run build)
/etc/cloudflared/um-c-tunnel.json  # Owner-managed tunnel credential (never commit)
```

## First boot sequence (lab)

```bash
# 0. Create the dedicated private state directory as the service account. The
#    center refuses to rewrite an existing foreign/shared/symlinked directory.
install -d -m 0700 -o um-center -g um-center /var/lib/um-center
# Upgrades from a pre-v13 layout must fix the existing parent explicitly:
#   chown um-center:um-center /var/lib/um-center && chmod 0700 /var/lib/um-center

# 1. Protected master key (owner/service account only).
um-center auth init-key --path /etc/um-center/master.key

# 2. One-time local platform_admin bootstrap; password is typed, not passed in argv.
#    This initializes the DB master-key sentinel before creating the account. For
#    an upgraded database with existing accounts but no sentinel use:
#    um-center auth key-init --db ... --master-key ...
um-center auth bootstrap --db /var/lib/um-center/center.db \
  --master-key /etc/um-center/master.key --username <admin>

# 3. Start center with the Web listener behind the synthetic/local Access test edge.
#    For a real deployment this requires Owner approval (HOLD).
systemctl start um-center
```

## Required production HOLD checks

- Owner approves the Cloudflare account/tunnel/Access application/IdP policy.
- The Access issuer/audience/JWKS values are real and configured; the synthetic
  test flag is absent.
- Real TLS certificates and hostnames are provisioned through the Owner process;
  machine TLS hostname is independent from the Web Access hostname.
- Master key is backed up offline with the DB; restore drill is approved.
- No public admin listener, no browser access to `/api/v1/*` through a bypass,
  no machine traffic through Cloudflare Access/browser routes.
- Linux Reality/Hysteria2 real-traffic blocker on #127 remains open.

For the detailed operator flows see `um/docs/um-c-runbook.md`.
