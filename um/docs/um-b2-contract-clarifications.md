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
