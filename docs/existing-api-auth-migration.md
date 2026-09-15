# Existing-server service.api authentication migration (narrow S0 migration)

## Background: why an old server can have monitor-api without authentication

Before the Phase D upgrade path existed, some installations already ran
sing-box 1.14.x with a manually created `service.api` entry:

```json
{
  "type": "api",
  "tag": "monitor-api",
  "listen": "127.0.0.1",
  "listen_port": 9091
}
```

Because the entry predated the security baseline, it carries **no
`secret`**, and the derived anchor file `/root/sbox/monitor-api.secret`
does not exist either. A real VPS canary exhibited exactly this state.

The S0 bootstrap (`repair_existing_install_security_baseline()`) calls
`sync_api_secret_file()`, which deliberately does nothing when the live
config contains no usable monitor-api secret — the config is the secret's
authoritative source and S0 must never invent one silently. The full
Phase D upgrade path CAN inject the missing secret, but it is a binary
upgrade transaction: it may download and replace the sing-box binary and
restart it. That is too broad for an old server that already runs a
compliant 1.14.x service.api.

## What the narrow migration does

`maybe_migrate_existing_api_auth()` runs on every existing-install
startup, BEFORE the interactive menu (right after the fail-closed S0
baseline repair). It is wired WITHOUT a failure-swallowing `|| true`:
declined and not-applicable paths return 0 and never abort the installer,
while ANY approved-migration / rollback / anchor / health failure returns
nonzero and aborts the existing-install flow right there — the menu is
never entered on a failed migration. Fresh installs never reach it and are
unchanged: they already generate the secret (`generate_api_secret()`) and
write the derived anchor during install.

Classification (`existing_api_auth_classify()`):

| State        | Meaning                                                    | Action |
|--------------|------------------------------------------------------------|--------|
| `exact`      | exactly one compliant monitor-api WITH a non-empty string secret | no prompt, no restart, never rotate; converge the derived anchor from the config |
| `needed`     | exactly one compliant monitor-api whose secret KEY IS ABSENT -- nothing to overwrite | explicit `[y/N]` confirmation |
| `malformed-secret` | exactly one compliant monitor-api but the secret KEY EXISTS with an unusable value (`""`, `null`, number, boolean, object, array) | refuse: malformed values are NEVER treated as missing and never overwritten by the narrow migration; needs the normal Phase D repair/upgrade path; zero changes, no prompt |
| `absent`     | no monitor-api entry at all                                | refuse: needs the normal Phase D repair/upgrade path; zero changes |
| `structural` | monitor-api count/type/listen/port violate the contract    | refuse: needs the normal Phase D repair/upgrade path; zero changes |
| unreadable   | config missing / invalid JSON / audit error                | warn and skip; zero changes |

The same missing-vs-malformed secret rule is re-checked UNDER the lock in
`_migrate_existing_api_auth_locked()`: a concurrent change that gives the
secret key a present-but-unusable value ("", null, number, boolean, object,
array) between the prompt and the lock is refused there as well (fail-closed).

### Confirmation behavior

For `needed`, the operator sees:

```
检测到旧版 service.api 已启用但尚未配置认证。
是否执行安全迁移，为 localhost service.api 增加认证？
该操作不会修改 Reality/HY2 凭据、端口或 sing-box 版本，
但会受控重启 sing-box 一次。
[y/N]:
```

* **Default is NO** (any input other than `y/Y/yes/YES/Yes` declines).
* Interactive input is gathered OUTSIDE `/root/sbox/config.lock` (never
  hold the lock while waiting for a human).
* **Declined**: ZERO changes, no restart, no anchor; the installer
  continues to the normal menu with a warning that Monitor v2 requires
  this migration before deployment. Nothing is auto-restarted.

### Migration scope

The ONLY allowed live semantic change is adding
`"secret": "<256-bit CSPRNG hex>"` to the `.services[]` entry whose tag
is `monitor-api`. Before commit, the transaction mechanically proves:

1. canonicalized config excluding `.services` is identical;
2. all services other than monitor-api are identical;
3. monitor-api excluding `.secret` is identical;
4. exactly one monitor-api exists;
5. the secret is exactly the generated non-empty 64-hex value;
6. the candidate passes the identity audit (`candidate_problems`) and a
   real `sing-box check`.

Reality UUIDs, HY2 passwords, the Reality private key, short_id, SNI,
ports, certificates, `/root/sbox/config` (state), the binary, firewall,
MTU, port hopping and every other inbound/outbound/route/service field
are preserved. **No credential rotation, ever.**

### Lock / transaction behavior

* All mutation runs under the SAME global `/root/sbox/config.lock` via
  the existing fail-closed `with_client_lock` discipline. A missing
  flock binary, an unopenable lock file or a timeout aborts with ZERO
  mutation.
* The locked helper (`_migrate_existing_api_auth_locked`) re-reads the
  LIVE config after acquiring the lock, revalidates, and treats an
  already-migrated config as idempotent success: it converges the anchor
  and NEVER rotates or overwrites the secret. No nested lock, no second
  lock domain.
* Reuse of reviewed primitives: `phase_d_config_structure_problems`,
  `phase_d_inject_api_service`, `phase_d_api_service_exact`,
  `candidate_problems`, `generate_api_secret`, `sing-box check`,
  `restore_file_atomically`, `phase_d_health_ok`.

### Backup / commit / rollback

* Unique same-directory backup (`sbconfig_server.json.bak.*`), retained,
  mode 0600. The backup is kept even when the live replace itself fails.
* Atomic live config replace; the sing-box binary is NEVER touched
  (this migration is NOT a sing-box binary upgrade).
* Derived anchor `/root/sbox/monitor-api.secret` is written
  root:root 0600. The config remains the single source of truth.
* When the pre-state had NO anchor, rollback removes the migration's own
  derived file with a checked `rm -f --` and VERIFIES the absence; a
  failed removal is MANUAL INTERVENTION REQUIRED (nonzero) and is never
  reported as a successful rollback.
* After the live replace, ANY anchor/restart/health failure restores the
  pre-migration config atomically (`restore_file_atomically`, never a
  raw `cp` rollback), removes/restores the newly-created anchor,
  restarts sing-box to reload the old config and re-verifies runtime
  health. If disk restore succeeds but the restart cannot be confirmed,
  the installer reports MANUAL INTERVENTION REQUIRED and never falsely
  claims rollback success. Backups always remain preserved.

### Runtime health (after the single controlled restart)

`sing-box` active, valid MainPID, Reality TCP listener present, HY2 UDP
listener present, 9091 listening on 127.0.0.1 only (never wildcard), an
authenticated `sing-box api --secret <secret> connection list` call
succeeds, and an unauthenticated call is rejected. The secret never
appears in output or logs; it persists only in the authoritative config
and the derived anchor.

### Idempotency

* Run once: missing secret -> generated and committed.
* Run again: same secret preserved byte-for-byte, no rotation, no
  restart; a missing/stale anchor is repaired from the config.
* Concurrent invocations: the locked helper re-reads live state, so only
  the first migration generates a secret; the second sees an exact
  config, converges the anchor and does not restart. No lost update.

## Regression suite

`tests/test-existing-api-auth-migration.sh` (X1–X18 plus X7c and X12c)
covers all of the above, including failure injection for candidate check,
backup, live replace, anchor write, restart, health and rollback-restore
failures, the secret-shape contract (an ABSENT secret key auto-migrates when
approved; present-but-malformed values -- "", null, number, boolean, object,
array -- refuse with a Phase D pointer and are never overwritten),
anchor-removal failure during a no-anchor
rollback, lock timeout, concurrency, secret-leak sweeps and fresh-install
unchanged-ness. It runs in Linux CI (`shell-tests` workflow).

## Not in scope

* This migration does NOT upgrade or replace the sing-box binary.
* It does NOT repair/reinvent a missing or structurally broken
  monitor-api service — that remains the Phase D path.
* The frozen Canary rev2.3 contract is unchanged.
