# UM-B2 contract clarification proposals (review, not frozen-contract edits)

The rev-5 frozen contract is unchanged. These are the minimal implementation
clarifications B2 needs; they are recorded for independent review and for the
owning later phases.

## 1. Quota errors and the closed wire error vocabulary

The frozen v1 error vocabulary has no `quota_exceeded` token. B2 must refuse a
new token/enrollment/event when a capacity quota is hit without inventing a new
wire code.

B2 behavior:

- store returns a typed `QuotaError` (kind/limit/current) wrapping
  `ErrQuotaExceeded`;
- the HTTP enrollment path maps this to the existing `503 storage_unavailable`
  with `retryable=true` (the operation is currently unavailable; no partial
  node/key/config is written);
- the CLI token-issuance path fails with a non-zero exit and an operator-readable
  quota message;
- no new wire error code, no special `X-UM-*` field, no schema change.

**Proposal to the contract owner:** add a distinct frozen token (for example
`quota_exceeded`, non-retryable 429) in a future revision. Until then B2 must not
claim a protocol-compliant quota code.

## 2. Archived/purged event ingest

The frozen contract has no `event_archived` wire token. B2 rejects ingest for an
archived/purged event with the existing `409 identity_mismatch` (the authenticated
node identity is no longer eligible for that event) and records no telemetry.
Enrollment for an archived event is likewise rejected before token consumption.
The B4 admin UI can present the precise operation state.

## 3. Disabled collection sources and historical spool

The frozen wire contract permits honest `unavailable`/null/empty states and does
not define what to do when a center config switch is turned off after an agent
has spooled data.

B2 behavior:

- a report whose `collected_at` is at or before the current config `updated_at`
  is treated as **historical spool** and is not rejected merely because the
  source switch is now disabled;
- current data (collected after the config update) for a disabled source must be
  honest `unavailable`/null/empty; fabricated `ok`/data is rejected as
  `invalid_request`;
- metrics follow the same historical rule; events keep generic agent/diagnostic
  kinds legal, while service/protocol/terminal-specific kinds require their
  source;
- `mihomo_api` remains false by default on Linux; Windows cannot enable
  Linux-only service/protocol collection; the center never authorizes a real
  Mihomo Controller in B2.

**Proposal:** the contract should state the spool/config-update boundary
explicitly in a future revision. B2's boundary is the config `updated_at`.

## 4. Event lifecycle ownership

B2 implements the minimal store primitive for policy-B lifecycle:
`event_catalog` (active/archived), archive at T with purge_after T+30d, data
deletion without a second archive copy, catalog retention until purge, and
purge tombstones retained 180 days (content-free).

The B4 admin API/UI and type-to-confirm purge workflow are not implemented in
B2. `ArchiveEvent`/`PurgeEvent` are store primitives used by tests; no public
management endpoint is exposed.

## 5. Security ledger retention

The contract asks for a 180-day audited security-ledger retention and capacity
boundary. B2 keeps the ledger append-only and **does not silently truncate or
delete ledger entries**; the hash chain must remain verifiable. Capacity/backup,
signed checkpoints, offsite recovery and restore validation remain UM-E. B2
records security state transitions (token/enrollment/config/rotation/revocation,
boot-generation gaps and privacy rejections) in the ledger without payload or
secret content.

## 6. Report-id type collision

`report_dedupe` is keyed by `(node_id, report_id)` across report types. Reusing a
`report_id` for a different body/type is a `report_conflict`; this is a safe
conservative reading of the frozen idempotency rule. If a future revision wants
`report_id` unique per type only, it must be an explicit contract change.


## 7. Purge authorization vs B1 immutable mappings (F1)

B1 route-mapping versions/entries remain immutable: ordinary UPDATE/DELETE is
still rejected by triggers. A purge is the only authorized deletion path and is
recorded durably in `purge_ops` before any destructive step. The trigger allows
mapping deletion only while that event's purge operation is in the
`mapping`/`finalizing` state produced by the store's explicit `PurgeEvent` call;
there is no generic "delete history" switch or trigger removal.

An incomplete purge blocks ingest, enrollment/token issuance, config/rotation
updates and ordinary mapping writes, and survives process/database restart. It
is resumable/idempotent and stays fail-closed until the final tombstone commit.

## 8. Permanent event identity isolation vs 180-day audit tombstone (F2)

`purge_tombstones` is the 180-day **audit** record and may expire. Event-id
non-reuse is enforced separately by the permanent `event_graveyard` row written
in the same final purge transaction. Expiry of the audit tombstone therefore
does not re-authorize the old event id, old nodes or old keys; the old boot
high-water remains fail-closed and old identities are revoked at purge.

## 9. Effective-dated configuration history (F4)

Reports are validated against `node_config_history` by `collected_at`, not
against a mutable current row and not by an `updated_at` bypass. A source that
was never enabled cannot authorize a historical report; an enable→collect→disable
sequence preserves the historical authorization; unrelated later config changes
do not widen the old window. The effective boundary uses the config update's
effective timestamp (collected_at <= effective_from uses the new config). The
initial enrollment config is fail-closed.

## 10. Endpoint-specific key permission and rotate ordering (F5)

Only Report is the rotation proof path for a provisional key. Config and Rotate
require an active old key; a provisional key cannot borrow the shared auth path.
Rotate follows frozen §7 order: transport/auth, boot generation, sequence, then
nonce-intent match; a failed nonce step rolls back high-water. Rotate replay uses
the persisted response bytes and does not reread config after commit. Expiry at
exactly `expires_at` remains valid; after that it is aborted/rotation_expired.

## 11. Report identity beyond the dedupe window (F6)

`report_dedupe` is an 8-day retry cache, while telemetry lives up to 30 days. As
long as any stored snapshot/metrics/events body for `(node_id, report_id)`
exists, the report id may not change type or body. Expired dedupe rows therefore
cannot be used to turn an old snapshot into metrics/events or a different body.

Rejection audit is not best-effort: if the security ledger write for
nonce_reuse/report_conflict/validation rejection fails, the request returns a
retryable storage error instead of silently claiming the audit was recorded.
