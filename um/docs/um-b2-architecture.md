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
- `report_metrics` and `report_events` (validated payloads + per-event rows);
- `archive_records` and `retention_runs` for policy-B archive/retention;
- rotation persistence columns (`new_public_key`, `response_json`,
  `confirmed_at`).

`node_boot` remains the only authoritative transport high-water and is never
deleted by retention. `VerifyChain` remains diagnostic only and is not recovery
authorization.

## Retention and capacity

`RunRetentionB2` physically prunes seq_dedupe to the current generation's latest
256 entries, boot_registry to the latest 8 generations, applies nonce 24 h /
report 8 days / activity 30 days, archives active telemetry older than 30 days
for a further 30 days, keeps latest pointers valid, preserves node_boot and
records a repeatable run. Synthetic capacity tests only; real capacity/performance
gating remains UM-E.

## Known limitations

- B2 is a single-process center with a local SQLite file; no HA, clustering or
  external queue.
- No UM-C public login/Cloudflare ingress, no Windows Service, no real Mihomo
  controller, no R1/R2 source enablement.
- Mapping management API/audit is UM-B4; B2 preserves the immutable historical
  mapping basis only.
- No signed checkpoint/offsite backup/full restore validation (UM-E).
- Synthetic load is not a production performance or security acceptance.
