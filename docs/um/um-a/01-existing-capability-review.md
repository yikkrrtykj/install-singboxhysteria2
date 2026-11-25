# UM-A 01 — Baseline, existing-capability review and forbidden duplication

Status: investigation result for UM-A review. Read-only work; no repository code
was changed outside `docs/um/`.

## 1. Baseline

| Item | Value |
| --- | --- |
| Main / UM-A base | `885171c08210ad0f4e91f0fed0243460d294b15e` (merge commit of PR #125) |
| Open issues (all) | #33 Incident Diagnostics, #67 P6 FROZEN Remote Probe; **#48 Closed/Completed** (2026-11-25) with its fault-injection evidence retained and unfinished event-level acceptance limits preserved |
| Open PRs | none |
| Recently merged, relevant | PR #125 quality-receiver Windows EXE CI hotfix (`9f770f9a`, `8986cbf1`); PR #124 HA-UI 0.2.0; PR #70 P6B2 Agent/provisioning; PR #69 P6B remote-probe ingest |
| Existing deployed systems | per-VPS `monitor-v2` Monitor (transactional deploy, loopback/SSH-tunnel only); `sbox-cm` privileged plane present in repo but management disabled / not deployed; optional office Remote Probe (#67) FROZEN; Windows HA-UI 0.2.0 local tool |

Deployment/rollout boundaries preserved by UM-A:

- `monitor-v2` remains a per-VPS read-only Monitor with its own contract,
  retention (7 days) and deployment transaction; UM does not modify it.
- `sbox-cm` remains the privileged mutation plane with management disabled by
  default (`sbox-cm/README.md`: `E3 MANAGEMENT ENABLED = NO`,
  `PRODUCTION DEPLOYED = NO`). UM-A does not enable it or call it.
- Issue #67 Remote Probe stays FROZEN; UM does not reactivate its contract or
  server route.
- Issue #33 (Incident Diagnostics) and #67 stay unchanged. Issue #48 is now
  **Closed/Completed**; its already-passed fault-injection evidence stays valid
  and its unfinished event-level acceptance limits remain recorded — UM does not
  reinterpret or reset them.
- HA-UI 0.2.0 remains a Windows-local tool; UM does not copy its root SSH
  operation path.
- Production rollout for every existing system remains manual/separate; UM-A
  performs no deployment.

## 2. `monitor-v2` audit (per-VPS read-only Monitor, v0.10.0)

### 2.1 Architecture and data path

- E1 collector consumes the official sing-box 1.14 `service.api`
  `SubscribeConnections` gRPC-web stream over loopback only
  (`monitor-v2/README.md` §data source, §security constraints). Identity model is
  immutable: `Device = API USER`, `Protocol = API INBOUND TAG`,
  `Lifecycle = API ID`; source IP is metadata, never identity. Stream failures
  are reported as `stale`, never converted to fake CLOSED/offline claims.
- E2 web is a Python-stdlib HTTP/SSE read-only dashboard
  (`monitor-v2/web/server.py` header): gate order is socket peer address →
  IP whitelist → admin session → route. `X-Forwarded-For` / `X-Real-IP` are
  never read (`monitor-v2/web/access.py`, `monitor-v2/web/server.py`).
- No database for E1; E2 keeps a separate SQLite incident-history store.

### 2.2 Storage, retention and failure discipline (directly relevant to UM)

- `monitor-v2/web/incident_history.py` + `docs/monitor-v2-incident-history-p1.md`:
  SQLite at `<state-root>/diagnostics/history.sqlite3` (0700 dir / 0600 file),
  `journal_mode=DELETE`, `synchronous=FULL`, `foreign_keys=ON`,
  `busy_timeout=2000ms`, `auto_vacuum=INCREMENTAL`; forward-only schema
  migrations behind a strict fail-closed schema gate; 7-day retention with a
  48 MiB target / 64 MiB hard cap; cross-table "global oldest epoch suffix"
  pruning; full `VACUUM` to actually shrink the file; retention failure is soft
  (degraded flag + closed error code, never a crash).
- Data projection is allowlist-only: connection IDs, source/destination IPs,
  UUIDs, HY2 passwords, private keys, API secrets, admin/session/recovery data,
  config content, raw snapshots and raw log lines are never persisted
  (`docs/monitor-v2-incident-history-p1.md` §5).
- Probe engine (`docs/monitor-v2-network-probes-p3b.md`): History schema v3
  `network_probe_samples`; DARK by default, opt-in through a reviewed targets
  file; closed result vocabulary; 7-day baseline window; strict closed-schema
  ingestion at the persistence boundary.
- Journal reader: a separate root-side narrow reader (`docs/monitor-v2-journal-reader-p2a.md`,
  `monitor-v2/journal_reader/`) delivers sanitized records through an exchange
  directory; the Monitor web user gets no journald/root access.

Measured evidence usable as input: P6B2 field reports record Agent-side
steady-state CPU ≈0.04–0.06 % of total machine and sampled private working set
≈13.7–15.8 MiB for the existing P6 Agent
(`docs/p6b2-acceptance-status.md`). These are **different products**, but they
are useful evidence that a bounded read-only Linux collector can be small.

### 2.3 Authentication/web security discipline (patterns to adapt, not copy)

From `monitor-v2/web/auth.py`, `monitor-v2/web/access.py`,
`docs/monitor-single-login.md`, `monitor-v2/README.md` §E2:

- scrypt password hashing (N=16384, r=8, p=1, 16-byte salt); hashes only.
- 256-bit session tokens, memory-only (restart logs out), per-session CSRF
  token; mutations require CSRF and same-origin when `Origin` is present.
- Cookie `HttpOnly; SameSite=Strict`, 8 h absolute / 15 min idle (Issue #67
  single-login amendment), session cleared on password change/recovery change/
  restart.
- Login rate limit 5 failures / 15 min → 15 min lock per source IP; stricter
  recovery path; CSRF is checked **before** password work and counters
  (anti-CSRF lockout-DoS).
- Loopback whitelist is for reachability only — it is *not* a login; the
  dashboard still requires the admin password. Localhost is never an
  administrator credential.
- Strict security headers, `CSP default-src 'self'`, no CDN/external fonts.

### 2.4 Deployment and rollback

`monitor-v2/deploy/install-monitor.sh` and
`monitor-v2/deploy/lib/monitor-deploy-lib.sh` implement a transactional
deployment: immutable release tree, atomic switch, pre-migration SQLite backup
with shape verification, forward-only schema gate, rollback refusal for schema
downgrades, bounded failure reporting. Production rollout remains manual and
separate (`docs/monitor-v2-vps-canary-runbook.md`,
`docs/p6b2-internal-release.md`).

## 3. `sbox-cm` privileged plane audit (must not be used by UM-A..UM-E)

`sbox-cm/README.md`, `docs/e3-m1-privileged-execution-plane-design.md`:

- One AF_UNIX socket `/run/sbox-cm/sbox-cm.sock` (root:sboxweb 0660), systemd
  socket activation; exactly one request + one response per connection;
  `e3-rpc/1` framing (4-byte big-endian length then UTF-8 JSON, 0 < L ≤ 65536),
  unknown version/fields/op refused.
- Seven fixed ops; RPC core is transport-only and never reads/writes
  `sbconfig_server.json` or credentials. Mutation semantics live in a root
  worker with one global `config.lock`, durable ledger intent, journal,
  reconciliation, bounded cancellation-after-intent semantics, exactly-once
  audit, and fail-closed `degraded` mode.
- Credentials never cross the privileged boundary except the one sanctioned
  read-only `client.export` response path.
- Current state: management plane disabled, not deployed; M2/M3 code present but
  default-disabled.

**UM consequence:** the UM center and its read-only agents must not open,
proxy, or depend on this socket; no UM endpoint may trigger privileged
operations. Operation-level authorization for any future remote write (UM-F) is
a separate design that must not reuse browser session/CSRF/Web UID.

## 4. Remote Probe (#67) audit

`monitor-v2/remote_probe/__init__.py`, `payload.py`, `delivery.py`,
`spool.py`, `docs/p6b2-production-agent.md`:

- FROZEN wire contract `p6-v1`: bounded canonical body (≤16 KiB), signed
  `p6-v1\nPOST\n/api/v1/remote-probes/ingest\n<probe_id>\n<sent_epoch>\n<run>\n<seq>\n<sha256(body)>`
  with HMAC-SHA256 per-probe secret; freshness window ±300 s; server replay
  cache; closed role/outcome/error vocabularies; GET-only Mihomo transport.
- Agent discipline: spool-before-ack, durable append+fsync, 32 MiB / 7 days
  bound, 4 rotating files, bounded quarantine, ordered delivery, durable retry
  counters, backoff 1 s → 60 s cap, fail-closed startup retention.
- Status: issue #67 remains OPEN/FROZEN; the production Agent and office probe
  have their own recorded acceptance status.

**UM consequence:** reuse the *patterns* (durable bounded spool, canonical
signing over exact body bytes, per-identity signature, freshness/dedupe, closed
vocabularies) and the discipline of "reuse never fork". Do not modify, enable,
depend on, or re-open #67; UM ships its own independent v1 contract (doc 04) and
its own server route namespace.

## 5. HA-UI 0.2.0 audit

`ha-ui/README.md`, `docs/windows-ha-ui-security.md`,
`docs/windows-ha-ui-data-path.md`, `ha-ui/ha_ui/core/remote.py`:

- Windows-local PySide6 tool for A/B VPS client creation and YAML generation;
  no listening ports; private ACL directories; credentials optional in Windows
  Credential Manager; UI/logs never show passwords/UUIDs/YAML.
- New-client creation is a **remote write** performed through the reviewed
  `install.sh` menu-10 path (`add_client` → `with_client_lock` →
  `cm_add_client_candidate_planned` → `commit_server_config`), not through
  `sbox-cm` bypass.
- Its root/SSH operation path is limited to a local, operator-initiated Windows
  tool and must not become the center's web management scheme.

**UM consequence:** no center-side SSH credential storage or root remote path;
UM-F, if ever approved, must design operation-level authorization independently.
Reusable concepts only: credential-hygiene rules, receipt/hash verification and
human confirmation patterns.

## 6. Reuse / adapt / forbid matrix

| Existing capability | Reuse | Adapt | Forbid | Reason |
| --- | --- | --- | --- | --- |
| sing-box `service.api` event semantics, identity model, honest state vocabulary | knowledge/spec | new Go agent implementation | copy Python code | semantics are validated; code is Python/stdlib-specific |
| `monitor-v2` incident-history retention lessons (global-order prune, VACUUM, schema gate, soft failure) | design lessons | new Go/SQLite implementation for 30 days | copy module | scale/retention differ; keep one owner per contract |
| `monitor-v2` auth/session/CSRF/rate-limit discipline | design patterns | new Go implementation, plus CF Access gateway layer | blind copy of loopback whitelist model | UM has a different network boundary (Cloudflare) |
| `monitor-v2` transactional deploy/rollback | design pattern | new UM installer/systemd units | modify existing installer | existing deployment is separate and must stay stable |
| journal reader / root-side sanitized ingest | no | no | yes | UM agent is read-only without root; journal evidence remains #33 scope |
| incident classifier / presenter / runtime | vocabulary reference for UM event schema | UM-D may define its own rules | copy implementation | #33 owns its contract; avoid two classifiers racing |
| network probe engine (#33) | vocabulary reference | UM v1 does not run active probes | enable/copy in v1 | #67/#33 remain frozen; avoid duplicate active probing |
| Remote Probe #67 agent/spool/#67 server | bounded spool/signature/replay patterns | UM v1 contract (own identity envelope) | modify/reactivate #67 | frozen contract; reuse patterns, never fork code |
| `sbox-cm` privileged plane | documentation reference for UM-F future | no | any access from center/agent | center must stay read-only; UID/session is not op authorization |
| HA-UI 0.2.0 root SSH path | human-confirmation/credential-hygiene patterns | no | any use in center | root SSH must not be centralized; UM-F separate design |
| Windows client/EXE signing and distribution | no | no | no | not needed for UM read-only platform |
| Komari | not in repository | no | no | remains independent product, no code/dependency coupling |

## 7. Forbidden duplication (binding on UM-B..UM-E designs)

1. Do not create a second per-VPS root collector / journal reader inside the UM
   agent. UM agent is unprivileged and read-only.
2. Do not copy `monitor-v2` Python modules into the center/agent or serve the
   same contract from two implementations.
3. Do not store VPS root SSH credentials, private keys or passwords centrally;
   do not add center-side SSH/root execution paths.
4. Do not add a second active probing engine in v1, and do not re-enable #67.
5. Do not touch the `sbox-cm` socket from the center or agent; do not add a
   Web→sbox-cm adapter.
6. Do not reuse the HA-UI remote-write path as a center web feature.
7. Do not duplicate config export/generation/client mutation logic in the
   center; UM-A..UM-E are read-only.
8. Do not modify existing issues' verdicts, deployment status, or existing CI
   workflows as part of UM-A.

## 8. Deployment-boundary facts recorded for UM

- Existing Monitor is loopback/SSH-tunnel only; no new public 80/443/9191 ports
  (`docs/p6b2-production-agent.md` line 16: "nor newly opened public
  80/443/9191. Monitor stays loopback/SSH-tunnel only.").
- Production rollout of existing components is manual, approval-based and
  recorded separately; UM-A performs none of it.
- UM center is a **new independent host/service** with its own public web entry
  and its own machine ingress; it must not modify or depend on existing VPS
  services for availability (see doc 03).

## 9. Open questions raised by this audit

1. No UM tracking issue exists in the repository (only #33 and #67 remain open;
   #48 is Closed/Completed).
   The design assumes the owner-provided brief is the source of truth; an
   owner-created UM tracking issue is recommended, not created by coding AI.
2. The existing per-VPS Monitor and the future UM agent both read the same
   loopback sing-box API. Running both on one VPS is read-only-technically
   possible but duplicates load; UM-B must document supported coexistence and
   recommend which system is installed per event VPS.
3. Existing HA-UI and Remote Probe contracts must remain untouched; any future
   interaction with them needs explicit owner authorization, not an UM-A
   assumption.
