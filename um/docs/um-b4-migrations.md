# UM-B4 database migration note (v9)

B4 adds one forward-only SQLite migration, **v9**, to the existing single
`um/internal/store` schema. Migrations v1–v8 are unchanged and remain applied in
order in one transaction each. A database with a newer unknown version is still
rejected fail-closed by `store.Open`.

## Changes (additive only)

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

No protocol table, high-water table, signature field, mapping row, B2 lifecycle
state or audit/ledger hash formula is changed. `event_catalog`, `enroll_tokens`,
`route_mapping_versions/entries`, `node_boot`, `seq_dedupe`, `nonce_dedupe`,
`security_ledger`, `purge_ops`, `purge_tombstones` and `event_graveyard` keep
their existing constraints/triggers. Alias deletion on event purge is added in
the existing purge transaction; mapping immutability triggers remain.

## Compatibility and rollback

- Existing centers open and migrate in place; reopen is idempotent.
- An older binary refuses a v9 database rather than silently using unknown state.
- There is no automatic downgrade or destructive rollback. Any operational
  rollback restores a pre-upgrade DB backup; backup/restore drills are UM-E.
- Existing rows remain valid: `display_name` is NULL for auto-created catalog
  rows; `revoked_at` is NULL for all existing tokens; no backfill is required.
- The migration is covered by store tests for reopen, event/node/token/alias/
  audit/purge/mapping behavior and the existing migration idempotence test.

## Operator procedure

1. Stop the center cleanly (or planned maintenance window).
2. Back up the SQLite DB/WAL using the deployment's normal procedure.
3. Start the new B4 binary with the same DB path; migration v9 runs in one
   transaction before listeners serve.
4. Verify `GET /api/health` and, if management is configured, an authenticated
   `GET /api/v1/health`.
5. Do not edit `schema_migrations` or any applied migration statement.

## Audit transaction boundary

B4 mutations attach `store.AuditMeta` to the request context. Store methods that
already own the transaction append `admin_audit` and the existing security-ledger
entry inside that same transaction. If the audit/ledger insert fails, the
mutation rolls back; the HTTP layer returns a bounded error rather than claiming
success. Read-only endpoints do not write audit rows.
