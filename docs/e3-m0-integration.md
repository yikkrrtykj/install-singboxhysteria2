# Monitor v2 — E3 M0 Integration Record

Status: **M0 implementation complete in repository; not deployed; E3 management remains disabled.**

## Anchors

| Item | Value |
| --- | --- |
| Repository | `yikkrrtykj/install-singboxhysteria2` |
| PR | `#20` — `e3: M0 transaction hardening and control-plane anchor` |
| Base | `main@00684d6b3538fe755ef9a155ac6b783ffda64104` |
| M0 reviewed code head before this record | `c3af65d9910b0b5a0a4252a4676845e6aac51a94` |
| Design | `docs/e3-rev5-privileged-mutation-design.md` |
| Production | **UNTOUCHED by E3 M0** |
| E3 management | **NOT ENABLED** |

## G1 — shared transaction library and transaction hardening

**PASS in the M0 implementation.**

- `lib/client-management.sh` is the single canonical source for:
  - `with_client_lock`
  - `reload_running_singbox`
  - `reload_health_ok`
  - `restore_file_atomically`
  - `new_candidate_path`
  - `new_backup_path`
  - `commit_server_config`
- `install.sh` no longer carries a second implementation of those primitives.
- `install.sh` binds itself to the reviewed shared-library bytes with an embedded SHA-256 and verifies the selected/fetched file **before** sourcing it. A future library drift therefore fails closed instead of silently importing different privileged transaction code.
- `commit_server_config` retains the historical CLI `0/1` return contract and additionally exposes a non-sensitive structured transaction result (`phase`, `changed`, `reload_performed`, `rollback_attempted`, `rollback_ok`, `health_verified`, `backup_path`).
- Generic config rollback uses `restore_file_atomically`; direct backup-to-live `cp` rollback is removed.
- `restore_file_atomically` uses a unique same-directory temp file, explicit mode hardening, atomic rename, and byte-for-byte `cmp` verification.
- Phase D paired rollback uses the same restore primitive for both config (`0600`) and executable binary (`0755`); direct backup-to-live `cp` restore is removed.
- If disk bytes are restored but runtime recovery cannot be confirmed, structured state is `rollback_manual` with `rollback_ok=false`; it never claims successful recovery.

## G2 — destructive-path lock discipline and permanent control-plane anchor

**PASS in the M0 implementation.**

- The one global lock remains `/root/sbox/config.lock`; no second management lock was introduced.
- `uninstall_singbox` now enters `with_client_lock _uninstall_singbox_locked`.
- `require_management_inactive "卸载"` is evaluated inside that locked critical section, closing the activate-vs-uninstall check/use window.
- The locked uninstall calls the locked HY2-hopping helper directly and does not nest `with_client_lock`.
- Production management marker default is formalized as `/var/lib/sbox-cm/management.active` while the existing environment override remains available to tests/root CLI.
- Uninstall no longer removes `/root/sbox/` wholesale and never unlinks `/root/sbox/config.lock`.
- Dynamic regression coverage records the `config.lock` inode before uninstall and verifies the same path/inode survives afterwards while installation-owned runtime/config artifacts are removed.

## Regression evidence

The M0 implementation was exercised repeatedly during development; the final hardening passes include:

- `bash -n install.sh`
- `bash -n lib/client-management.sh`
- `tests/e3/test-m0-static-contract.sh`
- `tests/e3/test-m0-shared-lib.sh`
- `tests/test-legacy-config-transactions.sh`
- `tests/test-phase-c.sh`
- `tests/test-phase-d.sh`
- `tests/test-existing-api-auth-migration.sh`

The final digest-binding run completed every listed step successfully, including all legacy / Phase C / Phase D / existing-api-auth regressions. Phase D rollback tests additionally verify restored config mode `0600` and binary mode `0755`.

This document commit intentionally triggers the repository's normal PR workflows again so `shell-tests` and `monitor-packaging` are evaluated on a user-authored final M0 head rather than relying on an Actions-bot follow-up commit.

## Explicit non-goals / not started

M0 does **not** implement or enable the E3 privileged management plane. The following remain later milestones:

- **M0.5 / G3+G4:** session-bound step-up authentication + revocation semantics; in-place E3 extension/hardening of the existing `singbox-monitor.service`.
- **M1:** root `sbox-cm` AF_UNIX daemon, SO_PEERCRED, framed RPC, ledger/journal/reconciliation.
- **M2:** Web management adapter/UI.
- **M3:** activation and canary runbook.
- **M4:** failure-injection and final hardening.

Per rev5 ordering, M1 must not precede M0/M0.5. No E3 code from this PR is to be deployed to the production VPS as part of M0 review.
