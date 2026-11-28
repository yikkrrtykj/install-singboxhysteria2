# UM-B4 management API/CLI architecture (Draft)

Status: **UM-B4 Draft PR only.** Not merged, not a production deployment, and not a
UM-C web/UI or public-admin-ingress authorization. The admin plane remains
loopback-only in this slice.

## 1. Scope and layer boundaries

B4 adds one management service layer over the existing B1/B2/B3 center:

```
um-center process (same OS process, separate listeners)
├─ ingest listener: /v1/agent/* only                 (unchanged B2)
└─ admin listener:  /api/health + /api/v1/*           (B4)
      └─ management.Handler (auth → RBAC → service)
           └─ management.Service (single business layer)
                └─ store.Store (same SQLite DB; no second store)
                     └─ B1/B2 engines: enrollment, keys, config history,
                        route mapping, retention, archive, purge, ledger,
                        audit transaction helpers
```

The management CLI (`um-center admin ...`) is an HTTP client of `/api/v1/*`. It
does not open SQLite, call the store, or bypass RBAC/audit. There is no second
store, signing implementation, enrollment engine, revocation engine, mapping
engine, retention engine or purge engine.

### Listener isolation

- The ingest listener registers exactly the four frozen `/v1/agent/*` POST
  endpoints. It never registers `/api/*`.
- The admin listener serves the anonymous `GET /api/health` probe and the B4
  `/api/v1/*` management API. It never registers `/v1/agent/*`.
- Agent identities, node signing keys and enrollment tokens are **not** admin
  credentials. Cross-plane credential probes remain rejected.
- The two listeners are separate `http.Server` stacks in one process. UM-B2
  explicitly does not claim process-level isolation; B4 preserves that honest
  statement. The DB is shared by the same `*store.Store`.

## 2. Fail-closed local admin authentication

B4 does not implement UM-C login/TOTP/session/CSRF/Cloudflare. It provides a
local, operator-owned, fail-closed credential boundary:

- `um-center --admin-auth-file <path>` loads a protected JSON file with
  principals (`id`, `role`, event_ids) and SHA-256 token entries. The file must
  be non-symlink regular, size-bounded, and access-protected (POSIX no
  group/world bits and POSIX owner must be the current `um-center` service
  user; Windows DACL allow-list is the file owner, current `um-center` service
  account, LocalSystem and Builtin Administrators only; arbitrary local/domain
  accounts and broad groups are rejected).
- Requests use `Authorization: Bearer <raw-token>`. The server hashes the token
  and compares in constant time. Raw tokens are never stored in SQLite, logged,
  audited or returned by an API.
- The principal is resolved **server-side only**. There is no trusted
  `X-Role`/`X-Admin`/body-role path, no event-scope widening from the request,
  no anonymous fallback, and no loopback-implies-platform-admin rule.
- If the auth file is absent, the management API is **disabled** (404) and only
  the existing `/api/health` probe remains. If it is configured, `um-center`
  requires the admin listener to be a loopback address; an unauthenticated
  public admin listener is not exposed by this build.
- Test-only principal injection is possible only by constructing a handler with
  a test `Authenticator`; it is not a release-binary bypass.

## 3. RBAC and scope

Roles: `platform_admin`, `event_admin`, `viewer`. Machine identities have no
admin role.

| Action group | platform_admin | event_admin (scope) | viewer (scope) |
| --- | --- | --- | --- |
| View event list/detail/dashboards | all | ✓ | ✓ |
| Create/rename/archive event | ✓ | — | — |
| Purge preview/confirm | ✓ | — | — |
| Node list/detail/latest status | all | ✓ | ✓ |
| Revoke node | ✓ | ✓ | — |
| Create/list/revoke enrollment tokens | ✓ | ✓ | token status only read |
| Agent config read | ✓ | ✓ | ✓ |
| Agent config write | ✓ | — | — |
| Alias read | ✓ | ✓ | ✓ |
| Alias write | ✓ | ✓ | — |
| Route mapping read | ✓ | ✓ | ✓ |
| Route mapping write | ✓ | — | — |
| Retention/capacity read/run | ✓ | — | — |
| Audit read | all | scope | — |
| Ledger verify | ✓ | — | — |

Frozen matrix does not explicitly grant route-mapping write or agent-config
write to event_admin. B4 uses **platform_admin only** for those two actions
(least privilege) until an Owner decision extends them. Aliases use the frozen
“Manage device display aliases” grant for event_admin in scope.

Every event-scoped operation resolves the trusted principal scope first and
passes that scope into the store query/mutation. An out-of-scope event is a
**404**, never a 403 that reveals existence. Route events, body node IDs, mapping
targets and alias targets are all re-validated server-side; checking only the
URL event is insufficient.

## 4. API conventions

- Prefix `/api/v1/`; isolated admin listener only.
- JSON UTF-8; strict body decode with unknown-field rejection; 1 MiB request cap.
- Method allowlists; unknown paths 404; non-allowed methods 405.
- Responses `{"v":1,"data":...}`; errors `{"v":1,"error":{code,message,retryable},request_id}` with bounded closed codes; no SQL/paths/secrets echoed.
- `X-Request-ID` and corresponding `admin_audit.request_id` support correlation.
- Bounded pagination (`limit` 1..100, `offset` 0..100000) and stable ordering.
- No arbitrary file, command, URL, script, YAML, proxy target or command
  execution endpoint.
- OpenAPI: `um/docs/um-b4-admin-api.openapi.json`.

## 5. Event lifecycle

- B4 exposes explicit create/rename/list/detail. `event_id` is immutable UUIDv4.
- `event_catalog` is the single lifecycle source; B2's lazy auto-create is
  retained only for the existing internal enlistment/ingest tests and
  compatibility, not as the formal catalog API path.
- Create checks catalog quota (`MaxEventsCatalog=50`), permanent
  `event_graveyard`, and incomplete purge; archive uses existing
  `ArchiveEvent`; archived ingest/rotation/config/mapping/enrollment stops.
- Archive keeps the B2 policy-B archive tail; no second copy.
- Purge is the existing durable `PurgeEvent` engine: platform_admin only,
  preview, exact `purge:<event_id>` type-to-confirm, authorization revalidation,
  `purge_ops` progress/resume, per-event lock, permanent graveyard, 180-day
  tombstone, security ledger, real deleted-row count. B4 adds no new purge
  engine and does not weaken mapping-delete triggers.
- **Final-closure confirmation binding (v10):** a preview returns a short-lived
  (5 min) single-use `preview_id`. The server stores a receipt bound to the
  authenticated actor, event, `event_purge` action, and the preview lifecycle
  fingerprint (state/archived/purge/data fields/catalog update time). The first
  durable purge operation is created only in the transaction that re-reads and
  consumes that receipt under the capacity/per-event serialization locks; an
  expired, replayed, actor/event-mismatched or stale receipt is rejected. The
  static phrase remains mandatory but is not sufficient alone. Once the op is
  durably persisted, resume and completed-operation idempotence do not require a
  live receipt; an expired receipt can never create a new operation.
- Purged event IDs cannot be recreated (graveyard) and old data/duplicate
  operations cannot revive them.

## 6. Nodes, enrollment and revocation

- Node list/detail joins `nodes`, `node_configs`, `node_latest`, aliases and
  key/rotation metadata. Public keys may be exposed only as metadata; private
  keys never leave the node.
- Derived status is explicit: `online`, `stale`, `unavailable`,
  `never_reported`, `revoked`; no fabricated healthy state.
- Node class, event and node identity are immutable. Cross-event moves/class
  changes require revoke + new enrollment (new node id); no in-place migration.
- Enrollment token creation reuses B2: one-time token, hash-only storage,
  immutable event+class, expiry ≤15 minutes (B4 cap), plaintext returned once,
  event lifecycle/quota checked under the capacity lock. Token list never
  returns plaintext; token revoke marks `revoked_at` and B2 enrollment rejects
  it.
- Revocation calls the existing `RevokeNode` transaction (all keys revoked,
  rotation aborted, ledger entry) and now includes the authenticated actor in
  the audit/ledger metadata. An agent cannot report after revocation, even
  after restart/new generation. Admin does not receive private keys and no
  remote rotate/command endpoint is added.

## 7. Agent configuration

- Reuses effective-dated B2 `node_configs`/`node_config_history`. Only frozen
  switches/fields are accepted: six `collect` booleans, cadence 30–300,
  expected inbound tags (Linux, closed kind vocabulary), config version.
- The API does not push configuration; agents pull the frozen
  `/v1/agent/config`.
- B4 rejects enabling `singbox_api` (P1-10 audit FAIL; disabled/unavailable)
  and `mihomo_api` (Windows R1 is local-bundle-only; center config cannot
  authorize it). Values remain false; no secret/YAML/proxy-name/route-binding
  is accepted or sent.
- Class rules are enforced both by the management layer and existing store
  validation.

## 8. Versioned route mapping

- Reuses `route_mapping_versions`/entries; append-only triggers remain.
- The API exposes version list, current-at-time resolution, and creation of the
  next version. `version` must be 1 then each immediate integer; `effective_from`
  must be now or later and strictly after the previous version. No backdating.
- Only the four A/B real protocol tokens may carry targets; `direct`/`unknown`
  are never forced onto a VPS. Windows node and every target must belong to the
  same event; targets must be active linux_vps nodes. Cross-event mapping is
  rejected.
- Historical samples resolve by `effective_from`; a later version never
  rewrites the attribution of an earlier timestamp.
- Mapping writes are platform_admin only and audited in the same transaction;
  the mapping engine also writes a security-ledger entry.
- The agent still only uploads tokens; no VPS ID/proxy name/mapping metadata is
  sent down.

## 9. Aliases

- New v9 `aliases` table keyed `(event_id,target_type,target_key)`; target
  types `node`, `device_ref`, `route`.
- Display-only, event-scoped, bounded 1..128 UTF-8, no control/newline/log
  injection; credentials are not accepted as alias content. Node targets and
  route tokens are validated; device_ref remains an opaque bounded key.
- Optimistic `expected_version`; blind/second update without the current version
  is a 409 conflict. Updates are audited and purged with the event.
- Aliases never change identity, token, device_ref or history, and are never
  sent to agents. Future Web UI must HTML-escape them like any user text.

## 10. Retention / archive / purge visibility

- Read-only retention state, timeline, capacity counters and bounded run
  history reuse B2. A B4 `POST /retention/run` invokes the existing bounded
  policy-B sweep, platform_admin only.
- Planning basis is explicitly a payload estimate, not a SQLite disk hard
  limit. No new retention policy, VACUUM or backup-restore engine is added.
- Quotas and frozen constants are unchanged: 150 active nodes on the 40 GB
  policy-B baseline, 100/event, 10 archived retained, 50 catalog, 5 GiB active
  planning basis with 2× overlap cap. These are not increased in B4.
- Purge preview counts affected rows; deleted rows are reported by the existing
  durable purge op.

## 11. Audit and security ledger

- `admin_audit` (v9) stores bounded actor/role/action/target/event/result/
  request_id. Mutations append the audit row **inside the same transaction** as
  the mutation through `AuditMeta` context; an audit insert failure rolls back
  the mutation. Final closure adds the missing policy-B retention class: the
  existing bounded sweep deletes only rows with `at < now-180d` in ≤50,000-row
  batches, strictly age-based (archived/purged event audit rows remain until
  their own 180-day boundary) and never touches the independent security ledger.
- v10 adds the `purge_confirmations` receipt table only; it is not a second purge
  engine.
- Critical security state changes continue to use the existing hash-chained
  security ledger: node revoke, key revoke, archive, purge, mapping creation,
  enroll/config events etc. B4 does not replace or weaken the ledger.
- Audit reads are filterable by event, action, result, actor and inclusive
  Unix-second time range; platform-wide for platform_admin, event-scoped for
  event_admin, denied to viewer.
- Successful mutations and authenticated permission/scope denials are audited.
  Unauthenticated failures have no trusted principal and are not attributed to
  `admin_audit`; invalid/conflict mutations fail before a success audit row is
  written. This is the actual documented boundary, not a fabricated audit of
  untrusted request fields. Responses contain no token/private key/
  controller secret, raw proxy names or raw user traffic.
- Ledger verify is platform_admin-only; it is visibility, not backup/restore
  authorization. UM-E owns full offsite/checkpoint/restore acceptance.

## 12. Known limits and non-goals

- No UM-C web login, TOTP, session, CSRF, cookie, Cloudflare Access/tunnel or
  public management ingress.
- No browser UI, no WebSocket, no remote command channel, no agent rotation
  initiation by admin.
- No production deployment, no production credentials, no real R1 enablement,
  no `singbox_api` enablement.
- The separate `um-lab` developer/CI helper is explicitly lab-only and may seed
  isolated test databases directly; it is not the production/admin management
  CLI and is not installed as an admin surface. The `um-center admin` CLI uses
  only the authenticated management HTTP API.
- No backup/restore trigger; no full capacity/disk-pressure/VACUUM/offsite
  ledger acceptance (UM-E).
- Linux Reality/Hysteria2 traffic collection remains a pre-production
  functional blocker; B4 does not turn unavailable data into zero/healthy.
- The admin listener and management CLI are loopback-only in this release;
  public/multi-admin user management is UM-C.
