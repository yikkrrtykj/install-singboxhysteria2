# UM-B4 database migrations (v9 + final-closure v10)

B4 adds two forward-only SQLite migrations to the existing single
`um/internal/store` schema:

- **v9** — management metadata (event display names, token revocation, audit,
  aliases, indexes).
- **v10** — final-closure purge confirmation receipt table only.

Migrations v1–v8 are unchanged and remain applied in order in one transaction
each. A database with a newer unknown version is still rejected fail-closed by
`store.Open`. The frozen rev-5/rev-6 contracts, schemas, vectors and historical
RECs are untouched.

## v9 changes (additive only)

| Object | Change | Purpose |
| --- | --- | --- |
| `event_catalog.display_name` | nullable TEXT column | management display label; event_id remains immutable and primary key |
| `enroll_tokens.revoked_at` | nullable INTEGER column | revoke unconsumed enrollment tokens; hash-only storage remains |
| `admin_audit` | new STRICT table: id/at/actor/role/action/target/event_id/result/detail/request_id | scoped administrative audit query; bounded closed action/result vocabulary |
| `idx_admin_audit_at`, `idx_admin_audit_event` | indexes | bounded audit pagination/scope |
| `aliases` | new STRICT table: event_id,target_type,target_key,display_name,version,updated_at,updated_by | event-scoped display metadata; no identity fields |
| `idx_aliases_event` | index | scoped alias listing |
| `idx_nodes_event_class_state`, `idx_nodes_event_last_seen` | indexes | bounded node inventory/filter |
| `idx_enroll_tokens_event_expiry` | index | scoped token administration |

## v10 changes (final closure, additive only)

| Object | Change | Purpose |
| --- | --- | --- |
| `purge_confirmations` | new STRICT table: confirmation_id,event_id,actor,action,state_fingerprint,issued_at,expires_at,consumed_at,consumed_by_op_id | short-lived single-use receipt binding a first purge start to actor/event/action/preview lifecycle |
| `idx_purge_confirmations_lookup`, `idx_purge_confirmations_expiry` | indexes | bounded per-event/actor lookup and expiry cleanup |

The receipt is authorization metadata only. It is consumed in the same
transaction that persists the existing `purge_ops` operation; v10 does not add a
second purge engine and does not change `purge_ops`, graveyard, tombstone or
security-ledger behavior. Already-persisted incomplete operations resume and
completed operations remain idempotent without a live receipt.

No protocol table, high-water table, signature field, mapping row, B2 lifecycle
state or audit/ledger hash formula is changed. `event_catalog`, `enroll_tokens`,
`route_mapping_versions/entries`, `node_boot`, `seq_dedupe`, `nonce_dedupe`,
`security_ledger`, `purge_ops`, `purge_tombstones` and `event_graveyard` keep
their existing constraints/triggers. Alias deletion on event purge is added in
the existing purge transaction; mapping immutability triggers remain.

## Compatibility and rollback

- Existing centers open and migrate in place; reopen is idempotent.
- An older binary refuses a newer database rather than silently using unknown
  state.
- There is no automatic downgrade or destructive rollback. Any operational
  rollback restores a pre-upgrade DB backup; backup/restore drills are UM-E.
- Existing rows remain valid: `display_name` is NULL for auto-created catalog
  rows; `revoked_at` is NULL for all existing tokens; no backfill is required.
- Migration coverage includes event/node/token/alias/audit/purge/mapping
  behavior, v10 receipt/reopen behavior, and the existing migration idempotence
  test.

## Retention interaction

`admin_audit` is included in the existing bounded policy-B retention sweep at
the approved 180-day class retention. Only rows with `at < now-180d` are
eligible; deletion is ≤50,000 rows per transaction, age-based and event-isolation
preserving. The security ledger is independent and is not modified by this sweep.

## Operator procedure

1. Stop the center cleanly (or planned maintenance window).
2. Back up the SQLite DB/WAL using the deployment's normal procedure.
3. Start the new B4 binary with the same DB path; v9/v10 run in one transaction
   each before listeners serve.
4. Verify `GET /api/health` and, if management is configured, an authenticated
   `GET /api/v1/health`.
5. Do not edit `schema_migrations` or any applied migration statement.

## Audit transaction boundary

B4 mutations attach `store.AuditMeta` to the request context. Store methods that
already own the transaction append `admin_audit` and the existing security-ledger
entry inside that same transaction. If the audit/ledger insert fails, the
mutation rolls back; the HTTP layer returns a bounded error rather than claiming
success. Read-only endpoints do not write audit rows.
