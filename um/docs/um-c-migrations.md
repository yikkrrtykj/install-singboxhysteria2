# UM-C database migration and backup notes (Draft)

UM-C adds one forward-only additive SQLite migration to the existing single
`um/internal/store` database:

- **v11** — local Web authentication/account/session/TOTP/recovery state.

Migrations v1-v10 and all B1-B4 tables, frozen contracts, triggers, ledger hash
formula and rev-5/rev-6 schemas are unchanged. `store.Open` still applies
migrations one transaction each in order, refuses unknown newer versions,
and is idempotent on reopen.

## v11 objects (additive only)

| Object | Purpose |
| --- | --- |
| `umc_users` | local accounts: username, Argon2id PHC hash, role, enabled, encrypted TOTP secret/version/enrollment, last consumed counter, timestamps |
| `umc_user_event_scopes` | event scope rows for `event_admin`/`viewer`; no client-supplied scope is trusted |
| `umc_preauth` | short-lived Access-subject-bound preauth token hash + CSRF hash (not a user session) |
| `umc_sessions` | hashed random session token, opaque public ID, user, state, Access subject/issuer binding, per-session CSRF hash, encrypted pending TOTP setup secret, idle/absolute/revoked times |
| `umc_recovery_codes` | per-user single-use recovery code hashes |
| `umc_totp_counters` | per-user consumed TOTP time steps for replay/restart/clock-rollback resistance |
| indexes | bounded preauth/session/recovery/TOTP lookup and expiry cleanup |

The tables use STRICT typing where appropriate and CASCADE from `umc_users`.
There are no foreign keys into frozen B1-B4 protocol tables; event scope rows are
validated against `event_catalog` and removed in the existing event-purge
transaction. The existing event/node/token/mapping/purge/audit/ledger behavior is
untouched.

## Security properties

- Only hashes of session/preauth/recovery/code values are stored. Password hashes
  are versioned Argon2id PHC strings; TOTP secrets are AES-256-GCM sealed blobs
  with user/version associated data and a master key **outside** SQLite.
- TOTP consumption is a transactional primary-key insert; concurrent/replayed
  counters fail before a session is issued.
- Session creation/rotation, TOTP completion, password/scope/disable revocation
  and recovery consumption are transactional. Auth cleanup is bounded.
- The database contains no raw session/CSRF/TOTP/recovery/Access JWT/password
  values and no machine private keys.
- Audit/ledger writes for UM-C record actor/role/action/result/targets and hashed
  context only; no secret is copied into audit detail.

## Upgrade and compatibility

- Existing v10 centers open and migrate in place; v11 is additive and needs no
  backfill. Existing B4 local bearer/admin behavior remains available when the
  Web plane is not configured.
- An older binary refuses a newer database. There is no automatic downgrade.
- Operational rollback restores a pre-upgrade DB backup; keys are not stored in
  the DB and must be restored with the matching backup. Backup/restore drills,
  offsite key escrow and production rollback are **HOLD**/UM-E gates.
- A Web-enabled center requires its master key file. Missing/corrupt/wrong
  key or DB state fails closed; startup never silently regenerates or rotates it.

## Deferred work

- Master-key rotation/re-encryption tooling is not implemented in this phase.
- Multi-instance/shared-DB locking, HA failover and real production backup
  automation are out of scope/HOLD.
- Retention of inactive auth rows follows bounded cleanup; an Owner-approved
  audit/session retention policy should be finalized before production.
