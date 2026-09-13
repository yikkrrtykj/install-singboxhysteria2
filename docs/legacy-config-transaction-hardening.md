# Legacy Config Transaction Hardening (L1–L5)

Status: **implemented — draft, not integrated.**

- Base: `cd307abb4963a71134fcf5cac8cc0da5746d89ac`
- Branch: `feature/legacy-config-transaction-hardening` (independent parallel branch)
- Not merged with `feature/monitor-v2-integration` (Round 1.1)
- **E3: NOT IMPLEMENTED.** VPS: NOT RUN. Production: UNCHANGED.

This closes the `I0-7` PRE-E3 blocker (option **A** from
`docs/monitor-v2-integration.md`): every runtime durable sing-box management
mutation now serializes under the SAME global lock used by Phase C / Phase D.

## Single lock domain

```
                       /root/sbox/config.lock
                                 |
      +--------------------------+---------------------------+
      |                          |                           |
 Phase C clients           Phase D upgrade              legacy CLI
 (with_client_lock)       (with_client_lock)           (with_client_lock)
                                                              |
                                     ports/SNI (modify_singbox), direct-in
                                     (doko/dokoko), SS (ssko),
                                     HY2 hopping state writers
```

`with_client_lock` keeps its historical name but IS the global config/state
management lock (documented in `install.sh`). No second lock domain was created:
a separate state lock would have allowed `modify_singbox` and HY2 hopping to
rewrite `/root/sbox/config` concurrently.

## Lock discipline (L1)

Every migrated flow follows:

```
public_function()  -> gather interactive input WITHOUT the lock
                   -> with_client_lock _public_function_locked <values>

_..._locked()      -> re-read LIVE state, revalidate, mutate, commit
                   -> never re-acquire the lock, never block on user input
```

All new config/state candidates use unique `mktemp` paths
(`new_candidate_path` / `new_state_candidate_path`). The shared fixed temp files
`/root/sbox/sbconfig_server.temp` and `/root/sbox/sbconfig_server.json.temp` are
gone; `sed -i` is no longer executed against the live state file.

## L2 — JSON writers

`process_doko`, `process_dokoko`, `process_ssko` route through
`commit_server_config`, inheriting the candidate audit, `sing-box check`, 0600
backup, atomic replace, reload, health check and rollback. Locked helpers
re-read the LIVE config, revalidate structure, and:

- `process_doko`: regenerates/revalidates a UNIQUE `direct-in<suffix>` tag
  under the lock; delete re-checks the target exists under the lock.
- `process_dokoko`: revalidates the "no existing `direct-in`" decision under the
  lock, so concurrent adds cannot create a duplicate `direct-in`.
- `process_ssko`: revalidates `ss-in` non-existence under the lock; the SS
  password is generated inside the lock (candidate planning, no user input).

## L3 — `modify_singbox` two-file transaction

`modify_singbox` owns BOTH `/root/sbox/sbconfig_server.json` and
`/root/sbox/config`. `commit_server_config` + `sed -i` was deliberately NOT
used (it would still allow a split durable state). `_modify_singbox_locked`
performs: re-read LIVE → revalidate → build BOTH unique candidates → validate
JSON → `sing-box check` → hardened 0600 backups of BOTH → atomically replace
BOTH → reload → health. Any failure after either live replacement restores BOTH
artifacts and reloads the old configuration; a failed rollback reload is
reported as needing manual intervention, never as success. Only the requested
values are mutated — Reality UUIDs, HY2 passwords, the Reality private key and
`service.api.secret` are never rotated.

## L4 — state writers

`set_config_value` (live → unique candidate → atomic `mv`),
`enable_hy2hopping` / `disable_hy2hopping` (interactive input outside the lock,
state mutation inside) all participate in the same lock domain. This removes the
`modify_singbox` vs HY2-hopping `/root/sbox/config` lost-update race.

**Documented NONBLOCKING weakness.** `enable_hy2hopping` also touches the
systemd helper unit and the firewall rules. Adding the config lock does NOT make
those three effects atomic together; only the durable `/root/sbox/config`
mutation is serialized. A crash between the state write and
`systemctl enable --now sing-box-hy2-hopping.service` is handled by the existing
rollback (state reset to `FALSE`), preserving current operational rollback
semantics. This cannot corrupt E3-managed JSON or state, so it is recorded here
as non-blocking and NOT expanded into a firewall/systemd redesign.

## L5 — destructive uninstall/reinstall guard (E3 activation hook)

`rm -rf /root/sbox` is NOT converted into an E3 transaction. Instead a narrowly
scoped guard is introduced:

- `management_is_active()` — rc 0 when web/E3 management is active;
- `require_management_inactive <op>` — refuses with a clear message.

Marker interface: `SB_MANAGEMENT_ACTIVE_MARKER`
(default `/root/sbox/web-management.active`).

**E3 is not implemented, so no production code creates this signal** and current
installations keep the exact legacy behaviour (the marker does not exist).
This is the ACTIVATION HOOK that future E3 must own: while web management is
active it must publish the marker, and remove it when management is disabled /
maintenance mode is entered. `uninstall_singbox` and the reinstall branch call
`require_management_inactive` BEFORE any destructive mutation.

STATUS: this interface + its tests are delivered, but the concrete signal is
**subordinate to the final E3/Integration decision** and must be ratified there.
It does not block this branch.

## Tests

`tests/test-legacy-config-transactions.sh` (new) covers the 18 required cases:
concurrency with Phase C add/delete, duplicate `direct-in` / `ss-in` avoidance,
pre-commit failure isolation, invalid-candidate rejection, reload/health
rollback, absence of fixed temp filenames, dual-file success, forced
second-artifact failure, reload failure, rollback-reload failure reporting, the
HY2-state vs modify_singbox lost-update race, lock unavailable/timeout,
no-interactive-wait-under-lock, credential preservation, and the L5
management-active guard. Linux CI uses the real `flock(1)`.
