# UM-B2 center architecture (Draft)

This document describes the executable center delivered by UM-B2. It is not a
production deployment or a full product acceptance. Frozen protocol semantics
remain in `docs/um/um-a/04-node-protocol-v1.md`; this file only maps the
implementation to those rules.

## Process and startup

`cmd/um-center` exposes explicit startup configuration:

```text
-ingest      machine-ingest listener address (required, isolated)
-admin       admin listener address (required, isolated)
-db          SQLite database path (required)
-contracts   explicit trusted path to docs/um/contracts/v1 (required)
```

Environment equivalents: `UM_CENTER_INGEST_ADDR`, `UM_CENTER_ADMIN_ADDR`,
`UM_CENTER_DB`, `UM_CENTER_CONTRACTS`. There is **no** cwd/source-relative
contract fallback: startup loads and prevalidates all ten frozen schemas before
opening listeners.

Admin token issuance (test/operator bootstrap, not a B4 management UI):

```text
um-center -db ... -contracts ... -issue-enroll-token \
  -token-event <event-uuid> -token-class linux_vps|windows_terminal -token-ttl 30m
```

The token plaintext is printed once; only its SHA-256 hash is stored. Node/key/
rotation admin mutation methods exist in the store, but the full audited admin
API/UI is UM-B4.

## Listeners and routes

- Ingest plane: only `POST /v1/agent/{enroll,report,rotate,config}`.
- Admin plane: only `GET /api/health`; it has no `/v1/agent/*` routes.
- Unknown path → `404 endpoint_not_found`; non-POST agent route → `405
  method_not_allowed`. Both planes use the frozen header/body timeouts.
- Per-IP bounded token-bucket rate limiting returns `429 rate_limited` with
  `Retry-After`.

## HTTP boundary

`internal/center/{headers,body,ingest,response}.go` enforce, before any service
call:

- raw duplicate detection for every `X-UM-*`, `Content-Encoding`, `Authorization`
  header (not a joined value), and rejection of unknown `X-UM-*`;
- exact `Content-Type: application/json`;
- required raw header set and `wire.Fields.Validate()` grammar, including
  canonical decimal/bounds and the 300 s freshness window check in the Service;
- `X-UM-Content-Encoding`/HTTP `Content-Encoding` consistency (`identity`/`gzip`);
- compressed ≤256 KiB, decoded ≤128 KiB (enroll ≤8 KiB), bounded decompression,
  single-member gzip with trailing-data rejection;
- strict JSON (duplicate keys/trailing data) and request body schema validation
  before the Service;
- config body exactly `{}`; report envelope type/report_id/collected_at shape;
- response bodies schema-validated against the frozen ACK/enroll/rotate/config
  schemas; rotate replay is written from the persisted bytes verbatim;
- closed error vocabulary only; no decoder/validator/service error text is
  returned.

## Service and authentication

`internal/center/service_impl.go` implements:

- enrollment: one-time token hash consumption (event+class scope), Ed25519
  bootstrap signature, host.os↔class check, node+key+config committed active in
  one transaction; token replay is `token_used`; the orphan is revoked through
  the audited store action.
- report/config: node+key state re-check **inside** the ingest transaction,
  `|now−sent_at|≤300s`, `collected_at≤sent_at+60`, 7-day payload age bound,
  signature over exact decoded bytes, platform/schema/privacy checks, immutable
  node class binding, expected-inbound-tag binding, config class/source rules.
- rotation: old-key signature, persisted intent keyed by
  `(node,nonce,old_key_id,body_sha256)`, refreshed transport fields revalidated,
  high-water committed before replay, provisional key proof confirmation (new
  active/old revoked), aborted/expired paths, admin revocation priority.
- every attempt (including exact duplicate/replay paths) performs full auth;
  transport high-water, nonce/report dedupe, data and ledger state commit in one
  SQLite transaction (commit-before-ACK). Failures return a zero result/error.

## Storage

Migration v3 adds:

- `node_configs` (config version, cadence, source switches, expected inbound
  tags, device salt);
- `snapshots` + `node_latest` (history by collected_at; stale_ignored never
  replaces newer; latest pointer FK protected during retention);
- `report_metrics`; `report_event_reports` (validated events report payload
  once) plus normalized `report_events` rows (event id/at/kind/severity/detail)
  so a multi-event report does not duplicate the full body per event;
- `archive_records` and `retention_runs` for policy-B archive/retention;
- rotation persistence columns (`new_public_key`, `response_json`,
  `confirmed_at`).

`node_boot` remains the only authoritative transport high-water and is never
deleted by retention. `VerifyChain` remains diagnostic only and is not recovery
authorization.

## Event lifecycle, retention and capacity (review correction)

Policy B is implemented with a persistent `event_catalog` instead of a second
archive copy:

- active events keep a rolling 30-day window by `collected_at`;
- archive at T stops ingest and keeps remaining event data until T+30d;
- after T+30d event telemetry is deleted, the catalog survives until explicit
  purge (B4 UI), and purge writes a content-free 180-day tombstone;
- node retire never shortens event history; latest pointers are removed by the
  frozen 30-day/retire rule and before snapshot deletion (FK integrity);
- seq_dedupe keeps the current generation's latest 256 rows and deletes old
  generations (retired generations are rejected by the persistent high-water);
  boot_registry keeps 8 generations; node_boot is never deleted;
- deletions are bounded to 50,000 rows per transaction and are resumable;
  retention_runs is bounded to 100; soft failures set degraded/failure state and
  leave unprocessed data intact;
- quotas: 150 active nodes total, 100/event, 10 archived events with retained
  data, 50 event-catalog rows, checked under a capacity lock before token/
  enrollment/archive writes; DB/WAL/row-growth statistics are exposed.

Historical spool semantics and quota/error mapping are recorded in
`docs/um-b2-contract-clarifications.md`; the frozen wire contract is unchanged.
Synthetic capacity data is not a 200-node SLA; UM-E owns full capacity/performance
and backup/restore acceptance.

## Known limitations

- B2 is a single-process center with a local SQLite file; no HA, clustering or
  external queue.
- No UM-C public login/Cloudflare ingress, no Windows Service, no real Mihomo
  controller, no R1/R2 source enablement.
- Mapping management API/audit is UM-B4; B2 preserves the immutable historical
  mapping basis only.
- No signed checkpoint/offsite backup/full restore validation (UM-E).
- Synthetic load is not a production performance or security acceptance.


## Review-correction notes

- Event lifecycle/purge: `ArchiveEvent`/`PurgeEvent` are the minimal store
  primitives; no public B4 management endpoints or type-to-confirm UI.
- Enroll enforces the same ±300 s freshness as report/config/rotate; token
  consumption happens only after validation and commits atomically with node/
  key/config.
- Rotate aborts expired awaiting intents immediately (provisional key only; old
  key stays active), and nonce reuse is classified before boot/seq conflicts.
- Security ledger entries are written for token/config/rotation/revocation,
  boot_generation_gap and privacy rejections; ledger retention/capacity and
  checkpoints remain UM-E.
