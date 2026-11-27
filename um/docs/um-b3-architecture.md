# UM-B3 agent architecture (Draft)

- Status: **UM-B3 Draft PR only.** Not merged, not accepted, not deployed, not
  production. This document maps the B3 Draft to the frozen rev-5 contract; it
  does not define a new contract and does not grant any Owner decision.
- Base: `main` **54efc81c** (B2 merged). Frozen contract:
  `docs/um/um-a/04-node-protocol-v1.md` revision 5 + `docs/um/contracts/v1/**`.
- Sources consulted: `docs/um/um-127/02-dual-platform-contract.md`,
  `03-recovery-semantics.md`, `04-implementation-plan.md`,
  `05-owner-decisions.md`; `docs/um/um-a/03-architecture-and-trust-boundaries.md`,
  `06-threat-model-security-tests-performance.md`.
- Planned CLI/service names in §13 are **subject to the B3 code slice** and are
  not frozen (see `um-b3-scope-and-matrix.md`).

## 1. Design rule: one agent runtime, platform collectors only

The node side is a single Go binary/codebase with **one** signing/transport/
durability state machine and two thin platform collectors:

```text
um/cmd/um-agent                 planned CLI/service entrypoint (subject to code slice)
        │
        ▼
um/internal/agent               shared runtime (identity, boot/seq, spool, retry,
                                client, config, rotation, recovery, Run loop)
        │  agent.Collector interface: Snapshot/Metrics/Events → contract bodies
        ├── um/internal/linuxobs      linux_vps read-only collectors (/proc, probes)
        └── um/internal/windowsagent  windows_terminal collector (six tokens),
                                      observing via windowsobs RouteObserver
um/internal/wire                the only signing/verification implementation
um/internal/windowsobs          the only six-token route enum + loopback GET source
```

Hard rules:

1. There is **no second signing/transport state machine**, no copied signing
   string, no duplicated header set, no duplicated route-token enum. Only
   `internal/wire` signs/verifies; only `windowsobs` owns the six route tokens
   (`Role`, `Tokens()` = `a_reality`, `a_hy2`, `b_reality`, `b_hy2`, `direct`,
   `unknown`).
2. Collectors return already-contract-valid bodies. They do not sign, do not
   talk to the center, do not keep transport state and do not invent retry
   semantics.
3. The center still validates everything (signature, class binding, platform
   isolation, schema, privacy, dedupe, boot/seq, rotation). Agent-side checks
   are fail-closed convenience, **not** a replacement for server validation.
4. The frozen wire rules are consumed as-is (rev-5): 15-line node signing
   string, canonical decimals `1..MAX_NUMERIC` (`2^63−2`), `MAX_BOOT_GAP=65535`,
   ACK `next_seq`/`null`, one transaction/ACK on the center, `< 300 s`
   freshness, `collected_at ≤ sent_at+60`, 7-day payload age bound.

## 2. Runtime components

| Component | Location (Draft) | Responsibility |
| --- | --- | --- |
| Shared runtime | `um/internal/agent/{runtime,state,spool,client,errors,collector,sync_unix,sync_windows}.go` | durable state, single-instance, enrollment, attempts, spool, retry, config, rotation, Run loop |
| Platform host info | `um/internal/agent/host_{linux,windows}.go` | OS/kernel/arch for the enrollment/report `host` object |
| Wire primitives | `um/internal/wire` | signing strings, headers, canonical numeric parsing, fingerprint, Ed25519 |
| Linux collectors | `um/internal/linuxobs` (`collector.go`, `procfs.go`, `system.go`, `disk.go`, `disk_linux.go`/`disk_other.go`, `service.go`, `singbox.go`) | Linux snapshot/metrics/events from `/proc`/`/sys`; optional gated sing-box client; service probe interface |
| Windows collector | `um/internal/windowsagent` (`windowsagent.New(Options{...})` implementing `agent.Collector`) | Windows terminal snapshot/events; metrics `ErrUnsupported` (v1 deferred); injected `RouteObserver`; DPAPI CurrentUser key protection via `internal/secretstore`; R1 source path gated/off by default (OD-P7 pending) |
| Windows route observation | `um/internal/windowsobs` | the only six-token enum (`Role`, `Tokens()`); loopback-only `GET /proxies`/`/connections`; independent selection/active sampling; closed reason codes |
| CLI/service | `um/cmd/um-agent` (`main.go`, `platform_linux.go`, `service_windows.go`) | `enroll`/`run`/`rotate`/`status`/`service`/`version`; platform collector selection; Windows SCM lifecycle wrapper (account/ACL/DPAPI installation remains OD-P7-gated) |
| Deploy assets | `um/deploy/linux/**`, `um/deploy/windows/**` | isolated systemd unit, noexec drop-in, one-shot installer, Windows service installer template |

## 3. Durable state directory

State is written only under the agent state dir (default
`/var/lib/um-agent`, Windows `C:\ProgramData\UM Agent` per the credentials ADR
proposal). All durable state goes through an atomic writer: temp file with
owner-only mode → write → **file fsync** → `rename` → **directory fsync**.

| File/dir | Purpose | Notes |
| --- | --- | --- |
| `.lock` | single-instance OS advisory lock (flock / LockFileEx), random diagnostic token | held for the process lifetime; a leftover file is harmless because the OS lock, not file existence, is the authority; no PID-based stale-lock removal and no two-writer window |
| `identity.json` | node id, event id, node class, key id, public/private Ed25519 key, center URL | private key local only, never sent/logged; identity+class/center URL mismatch is fail-closed |
| `boot_state.json` | `generation`, `boot_id`, `next_seq`, `exhausted` | **authoritative local high-water basis**; missing/corrupt with identity ⇒ `boot_state_corrupt` (REC-17) |
| `config.json` | last validated center config (config version, cadence, six collect switches, device salt, expected tags) | absent/invalid ⇒ fail-closed defaults; never fabricated |
| `rotation.json` | persisted rotation intent: nonce, provisional new key id/material, state | allows restart-safe rotate retry/proof (REC-19/20) |
| `pending_control.json` | persisted in-flight config/rotate control attempt | exact replay after a crash; removed after terminal response |
| `spool/` | ordered report records (`report_id`, kind, collected_at, body, persisted transport attempt) | fsync before first send; oldest-first replay; ack-only removal |
| `quarantine/` | corrupt/terminal-rejected records moved out of the send path | never silently deleted; counted in diagnostics |

Permissions: state dir 0700 owned by `umagent`; files 0600; no symlinks in the
state path; agents reject state files that fail validation instead of
"repairing" them by resetting identity/generation.

## 4. Startup and single-instance sequence

1. Open state dir 0700 and acquire an OS advisory lock on `.lock`. A second
   process fails with `state directory is already in use`; the kernel releases
   the lock on process death, so a crashed process cannot leave two writers.
   Symlink/reparse state paths are rejected before use.
2. Load identity/boot/config/rotation/control; validate grammar/key
   consistency. Identity present without boot state, or boot state without
   identity, is **corruption** (`boot_state_corrupt` / `identity_corrupt`), not
   a reset trigger. Full state loss means operator revoke + re-enroll as a new
   node id.
3. Reconcile local high-water: if spooled/control attempts contain a seq above
   `next_seq`, persist the higher value **before** any send; never lower it
   (REC-27 crash window).
4. A **clean** process restart (same identity, clean-shutdown marker written by
   `Close`) increments `generation` by exactly 1, generates a new random 32-hex
   `boot_id`, starts `next_seq=1`, and replays pending payload records under the
   new generation with fresh transport fields. An abrupt power loss has no
   clean marker: generation/boot/persisted seq and the exact spooled attempt are
   preserved for duplicate/sequence recovery (REC-27).
5. If the process is starting for the first time with no identity, enrollment
   is required (no anonymous reporting).

## 5. Enrollment

- One-time admin token bound to `{event_id, node_class}`; node class is chosen
  by the installation (`linux_vps`/`windows_terminal`) and must match the token
  scope and `host.os` (center enforces; agent verifies the response class).
- The agent generates its own Ed25519 keypair; enrollment signs the frozen
  `um-enroll-v1` string with the new key. No body contains a signature field.
- P1-03 token handling: root-owned token file is opened by the root installer
  and piped into the unprivileged enrollment process on **stdin**
  (`enroll --token-stdin`, the frozen contract command); the agent never needs
  read access to the token file, never stores the token and never logs it. Root
  deletes the file after success; on failure it stays root:root 0600 for
  operator retry.
- Response-loss recovery follows the frozen rule: token already consumed →
  retry gives `401 token_used`; the admin revokes the unused orphan node and
  re-issues a token with a new node id (REC-24). No `pending_activation` state.
- On success: persist `identity.json` then `boot_state.json` (generation 1, new
  boot id, next seq 1); a crash between the two files is fail-closed boot
  corruption, not an auto-repair.

## 6. Boot generation, sequence, nonce and report identity

- `generation` is persistent and monotonic; each normal restart is exactly
  `+1`. Local state never "coalesces" gaps and never reuses a `boot_id`.
- Each request attempt gets a fresh `sent_at` (Unix seconds), a fresh 16-byte
  base64url nonce, and a `seq` from `pending_control.json`/`boot_state.json`.
  The attempt is **persisted before send** (seq high-water and, for reports,
  the spool record). A crash after allocation means the seq is skipped, never
  reused.
- `report_id` (UUIDv4) and `collected_at` are payload identity, created once
  when the body is spooled; transport fields are per attempt. Retries inside
  the freshness window reuse the **exact persisted attempt** (same seq/nonce/
  fingerprint); after ~240 s the runtime allocates a **new attempt** for the
  same `report_id`/body. The center dedupes `report_id`; a resend with a new
  seq is `duplicate` when already committed.
- `seq == MAX_NUMERIC`: ACK `next_seq:null` marks the generation numerically
  exhausted. The agent never wraps/reuses seq; it starts a new generation only
  on a clean restart (boot state available) or enters operator recovery
  (generation `MAX_NUMERIC` is terminal).
- Boot-state loss/restore behavior (REC-17/18): never reset in place; restored
  old state yields a lower generation and the center answers
  `409 stale_boot_generation`; operator recovery = admin revoke + re-enroll.

## 7. Durable spool and replay

- Capacity **32 MiB / 7 days**, single writer (the state lock), one JSON record
  per report (`report_id`, kind, `collected_at`, body, persisted attempt).
  Same-second records are ordered by their persisted sequence, not random UUID.
- The record is **fsynced before the first send**. Unix fsyncs the file and
  directory; Windows flushes file contents and uses
  `MoveFileEx(MOVEFILE_WRITE_THROUGH)` for replacement (the remaining Windows
  directory-entry limitation is documented, not claimed as POSIX fsync). It is
  removed only after a terminal ACK (`accepted`, `duplicate`, `stale_ignored`)
  or moved to bounded quarantine for a terminal payload rejection.
- Replay is **oldest-first** under the current generation/key with fresh
  transport fields when the persisted attempt is stale. A new-generation first
  report that is already stored (duplicate) still returns `duplicate`; the
  center commits the new-generation high-water (REC-04).
- Corrupt records are quarantined (not deleted, not sent) under an 8 MiB
  oldest-first inspection budget. Capacity is fail-closed: adding a record that
  would exceed the 32 MiB hard cap returns `ErrSpoolFull` and leaves all
  already-fsynced records untouched; it never silently evicts them. The runtime
  drains existing backlog before queueing new work, enforces 7-day retention
  during a long outage, and continues after a terminal payload is quarantined.
  At startup only records older than the 7-day retention are expired; the cap is
  not used to discard unexpired payloads.
- Spool contents are already contract-valid report bodies (privacy allowlist
  enforced by the collector/center); the spool never stores tokens,
  credentials or local proxy names.

## 8. Retry, backoff and error classification

- `1 s → 2× → … → 60 s` bounded backoff with context cancellation and
  ±20% jitter; `Retry-After`/ACK `retry_after_s` is honored up to the 60 s cap;
  reset to 1 s after a successful flush. No unbounded busy loop, no infinite
  tight retry.
- Retryable: transport/timeouts, malformed/over-limit responses, `5xx`,
  `429` (honor `Retry-After`), `401 stale_timestamp` (recalibrate clock from
  `server_time` and retry once).
- Terminal payload rejection (`invalid_request`, `platform_mismatch`, and other
  non-retryable payload errors): quarantine that record and continue with the
  next one — no silent drop, no fabricated success.
- Auth/identity/boot/sequence terminal conditions: `revoked_key`/`unknown_node`
  (stop reporting, keep bounded spool for operator decision),
  `stale_boot_generation`, `sequence_conflict` on the latest attempt,
  `rotation_expired` path, ACK exhaustion → operator recovery / documented
  abort path. A response for an already-superseded attempt is ignored (REC-10).

## 9. Center client and config pull

- One strict client in `internal/agent/client.go`: HTTPS origin required (plain
  HTTP only for loopback test endpoints); no userinfo/query/fragment/path;
  redirects disabled (`ErrUseLastResponse`); default transport without proxy
  configuration; bounded response body; strict JSON decoding with unknown
  fields rejected; closed error vocabulary only; no response text is logged.
- Endpoints are exactly the frozen four: `POST /v1/agent/enroll|report|rotate|
  config`; the config body is exactly the two bytes `{}`.
- Config pull is signed with the current active key and is the only agent
  configuration channel (no center push). Response is validated (class,
  version, cadence 30–300 s, exactly six source switches, device salt,
  expected inbound tags) and persisted only if valid.
- **Fail-closed config**: missing/invalid config means no collection and no
  widening; initial enrollment config is fail-closed. A config that enables a
  source not allowed for the node class is rejected (`platform_mismatch`) and
  not applied. `collect` switches default false; enabling a real source follows
  the authorization gates in `um-b3-adr-windows-sources.md` and `04` §11.

## 10. Rotation intent recovery

1. Generate provisional key; persist `rotation.json` (`nonce`, new key
   material, state `awaiting_proof`) **before** sending rotate.
2. Send rotate signed by the **old** key with the persisted nonce/body; persist
   `pending_control.json` for exact retry.
3. On restart: rebuild the rotate request with the same nonce/body and fresh
   transport fields (A-5); idempotent replay returns the same response, or
   `rotation_expired` moves to the abort path (delete provisional key, resume
   old-key reporting).
4. On success: keep old key active until a report signed with the new key is
   accepted (proof). A 2xx new-key response confirms; then persist the new
   identity and remove the old private key material.
5. `401 revoked_key` for the provisional key → provisional aborted, resume old
   key; if the old key is also rejected → stop and operator recovery. Admin
   revocation wins; there is no automatic reset or bypass.

## 11. Linux collectors (`linux_vps`)

Package `um/internal/linuxobs` provides a zero-value-usable `Collector` with
optional probes and roots for tests (`ProcRoot`, `SysRoot`, `DiskMountPath`,
`DiskProbe`, `ServiceProbe`, `SingBoxProbe`). It implements
`agent.Collector` (Snapshot/Metrics/Events).

- **System**: `/proc`/`/sys` read-only counters (CPU aggregate, memory, disk
  space/usage, network counters, load/uptime) — no subprocess, no shell, no
  root, no permissions changed. CPU is a since-boot aggregate; service.api
  traffic counters are probe-observed cumulative lower bounds, never
  active-only bytes presented as lifetime totals.
- **Services**: the Linux build ships a real read-only `SystemdDBusProbe`
  backed by pinned `godbus/dbus/v5`. It opens a private unprivileged system-bus
  connection and issues exactly `Manager.GetUnit("sing-box.service")` on
  `/org/freedesktop/systemd1`, then
  `org.freedesktop.DBus.Properties.Get` for
  `org.freedesktop.systemd1.Unit.ActiveState` on the validated unit path, both
  with `FlagNoAutoStart`. There is no generic call, no write/lifecycle method,
  no exec, no root, no file write and no `systemctl` fallback. Failures map to
  the closed `ErrProbeUnavailable` and render UNKNOWN, never fabricated
  `active`. The Linux wire path still awaits an isolated systemd-lab run.
- **sing-box data sources**: `singbox_api` is disabled by default.
  - The official sing-box 1.14 `service.api` client
    (`internal/linuxobs/serviceapi*.go`) uses a fixed loopback origin and one
    gRPC-Web stream
    `daemon.StartedService/SubscribeConnections`; the hand-rolled protobuf codec
    pins the v1.14 field numbers. It never calls the Clash REST API, and the
    source remains disabled until the versioned P1-10 server-side authorization
    audit. It has synthetic gRPC-Web fixtures plus isolated sing-box 1.14.5 lab
    evidence; probe-observed cumulative totals are lower bounds (active
    authoritative lifecycle totals plus finalized closed/abandoned lifecycles
    banked once), not daemon-lifetime totals. The accumulator exposes
    `TotalsExact=false`; the collector never uses active-connection bytes as a
    lifetime total and reports traffic unavailable when events were skipped or
    identity-conflicting.
  - The legacy Clash-compatible `SingBoxProbe` remains only as a compatibility
    path for tests; it exposes active-connection lower bounds and is not the
    contract source for production enablement.
  - When the source is configured but the versioned authorization proof is
    absent, the collector emits the frozen
    `agent_error code=source_authorization_unproven` event and still reports the
    source unavailable. The event is stable across retries of the same report.
- Class isolation: Linux must not emit `terminal`; `expected_inbound_tags` and
  the `linux_vps` source allowlist are enforced by `internal/contract`/center.

## 12. Windows terminal collector (`windows_terminal`)

Package `um/internal/windowsagent` implements `agent.Collector`; its
`New(Options{AgentVersion, Uptime, CounterEpoch, Observer RouteObserver})`
produces the snapshot with the frozen `terminal` object and the Windows events.
Metrics is `agent.ErrUnsupported` (Windows metrics v1 deferred).

- **Observation source is injected**: `RouteObserver` has
  `ObserveSelection`/`ObserveActive`; the default (nil) observer means "no local
  source". The default Windows collector emits honest `unavailable` data with
  `source_authorization_unproven` when the terminal source is authorized but no
  local source is configured, and emits the `terminal_source_unavailable`
  event (`source=mihomo_api`, closed reason) in that case; the `terminal`
  object is omitted only when both `terminal` and `mihomo_api` switches are
  false. `windowsobs.Observer` is the only loopback controller implementation:
  HTTP on a literal loopback IP, fixed `GET /proxies`/`GET /connections`, no
  redirects, bounded body. The operator-local route binding
  (controller/group/proxy-name→token profile) is injected by the host through
  `windowsobs.New(Profile)` and is never uploaded.
- **Six tokens only**, no A/B collapse and no duplicate enum:
  `a_reality`, `a_hy2`, `b_reality`, `b_hy2`, `direct`, `unknown`.
  `direct` is bindable only by an explicit operator-local route binding;
  unmapped/ambiguous paths are `unknown`/null, never auto-DIRECT. Local
  group/member/proxy names, destination/source IPs, URLs, connection ids,
  process names, controller secrets and private YAML never leave the host.
- **Independent sampling**: `selection` and `active_connections` are sampled by
  separate reads with their own `sampled_at`; both must lie in
  `[collected_at − 300 s, collected_at + 60 s]`; they may legitimately
  disagree after a route switch.
- **Honesty**: `ok` requires non-null route/counts and
  `total == sum(six counts)`; `partial` has at least one null/unknown;
  `unavailable` is all null plus a closed reason (`controller_unreachable`,
  `controller_auth`, `malformed_response`, `route_unbound`,
  `source_authorization_unproven`); a valid empty connection list is observed
  zero; a missing/malformed answer is UNKNOWN/UNAVAILABLE, never zero.
- **Source authorization (OD-P3)**: R2 was investigated on Clash Verge Rev
  2.5.10 / Mihomo 1.19.33. It is **INFEASIBLE on the tested surfaces**: the TCP
  controller requires a write-capable secret and the named pipe is
  unauthenticated yet exposes write methods. The loopback TCP controller is the
  R1 residual-risk shape (**write-capable credential**, strictly GET-only
  client); the CLI has an explicit R1 path gated by
  `UM_AGENT_WINDOWS_SOURCE_AUTHORIZED=1` + operator profile/secret files, and is
  disabled by default. It is never described as read-only and requires a
  separate Owner risk acceptance. Until a source is proven/authorized, terminal
  availability is `unavailable` with `source_authorization_unproven`. See
  `um-b3-adr-windows-sources.md`.
- **No HA/config writes**: the agent never modifies Mihomo/Clash Verge Rev
  configuration, never switches nodes, never closes connections and never
  changes HA-UI/P6/#67 behavior; a static/runtime no-write proof is required
  before any enablement (UM-E real-build assertion).
- Agent identity and rotation provisional private keys are protected at rest
  with DPAPI CurrentUser through the shared `internal/secretstore` package
  (machine scope is not the default and remains OD-P7-gated). The Windows
  `cmd/um-agent` SCM wrapper and event-log source are wired; the installer
  template still does not install a service account, run enrollment or approve
  an ACL. Service-account/ACL/enrollment/SCM lab validation and the final
  account decision remain **OD-P7 PENDING**.

## 13. Service and CLI model

Frozen by the contract: enrollment runs as the unprivileged `umagent` via
`um-agent enroll --token-stdin` with the token piped from the root installer;
the runtime is non-root, non-listening, no exec.

The Draft CLI (`um/cmd/um-agent`) exists in this code slice but its exact names
are **not frozen** until review; deploy assets document the intended shape:

| Command | Draft flags | Environment equivalents |
| --- | --- | --- |
| `um-agent enroll` | `--state-dir DIR`, `--center URL`, `--node-class linux_vps|windows_terminal`, exactly one of `--token-stdin` (contract flow; root-opened pipe) or `--token-file FILE` | `UM_AGENT_STATE_DIR`, `UM_AGENT_CENTER_URL`, `UM_AGENT_NODE_CLASS`, `UM_AGENT_TOKEN_FILE` |
| `um-agent run` | `--state-dir DIR`, `--center URL`, `--node-class ...`, `--once` (one snapshot then exit; lab use) | same env vars |
| `um-agent rotate` | `--state-dir ...`, `--center ...`, `--node-class ...` | same env vars |
| `um-agent status` | `--state-dir ...` (diagnostics only: enrolled/terminal/config version/generation/sequencing/pending/quarantined; no secrets) | `UM_AGENT_STATE_DIR` |
| Linux source env | no flags; D-Bus probe automatic; service.api only when configured | `UM_AGENT_SINGBOX_API_URL` (default `http://127.0.0.1:9091`), `UM_AGENT_SINGBOX_API_SECRET_FILE`, `UM_AGENT_SINGBOX_SOURCE_AUTHORIZED` (operator P1-10 assertion) |
| Windows source env | no flags; R1 observer only when both files/gate set | `UM_AGENT_WINDOWS_OBSERVE_PROFILE`, `UM_AGENT_WINDOWS_OBSERVE_SECRET_FILE`, `UM_AGENT_WINDOWS_SOURCE_AUTHORIZED` (OD-P3 Owner gate; off by default) |
| `um-agent service` (Windows SCM lifecycle wrapper) | `--state-dir`, `--center`, `--node-class` (flags passed through to the run loop); account, ACL, DPAPI scope, credential rotation and installation remain **OD-P7-gated** | same env vars |

The Windows `service` wrapper only hosts the SCM lifecycle (start/stop/shutdown)
around the shared runtime; it does not choose or install a service account, ACL
or DPAPI scope, and **no SCM lab was executed in this Draft** — Windows Service
integration is unverified. Account/ACL/DPAPI and any secret decision remain
**OD-P7 PENDING**; R1 is not provisioned or enabled by default.

Deployment assets in this Draft are templates: Linux `um-agent.service` +
`um-agent-noexec.conf` + `install-agent.sh` (uses the contract `--token-stdin`
pipe); Windows `install-agent-service.ps1` (explicit Owner confirmation for
account/secret; no R1; registers a Manual-start service and does not start it).
See `um-b3-runbook.md`.

## 14. Recovery conformance mapping (agent side)

| Case | Agent behavior / evidence in Draft |
| --- | --- |
| REC-01/02 | normal restart = generation+1, new boot id; first-contact `seq>1` allowed; seq persisted before send |
| REC-03/04/06/27 | lost ACK → exact/new attempt resend with same `report_id` → `duplicate`; committed seq resent; unsynced seq never reused; oldest-first spool replay; first new-generation duplicate still advances high-water |
| REC-10/13 | superseded delayed responses ignored; ACK `next_seq` adopted as `max(local, ack)` |
| REC-17 | boot state missing/corrupt → local fail-closed, no request, operator recovery (unit test) |
| REC-18 | restored old snapshot → `409 stale_boot_generation`; revoke + re-enroll, no in-place reset (unit + mocked center) |
| REC-19/20/21 | persisted rotation intent replay across restart; expired path aborts provisional key; revoked key stops queue and keeps bounded spool |
| REC-26 | `MAX_NUMERIC` exhaustion/`next_seq:null` → new generation on clean restart or operator recovery; never wrap |
| REC-30 | interleaved spool replay across generations remains oldest-first with no overwrite |

B2-owned REC real-HTTP halves stay B2 evidence; B3 does not re-count them.

## 15. Privacy and security boundaries

- Agent→center payload is the frozen restricted schema only: aggregate
  counters, protocol/route tokens, availability, timestamps, `device_ref`; no
  UUIDs/passwords/private keys/tokens/full YAML/client names/raw IPs/hostnames/
  URLs/command lines/journal text/connection records/local proxy names/controller
  credentials.
- Local route bindings and controller profile are operator-local on the Windows
  host; they are never uploaded or returned by the center. The center never
  sends raw proxy names/VPS ids/hostnames/URLs/credentials to an agent.
- Logs/diagnostics contain closed error codes and counts only: no headers,
  bodies, signatures, keys, tokens or payloads. The `status` view exposes
  enrolled/terminal/config version/generation/seq/pending/quarantined last
  result — no secrets or paths.
- Agent process: unprivileged, no listener, no shell, no package manager, no
  remote command channel, no `sbox-cm` access, no root; writes only its own
  state dir; contacts only the configured center origin over HTTPS; TLS server
  certificate/hostname validation with system CAs (optional recorded SPKI pin
  strict mode).
- Existing systems: no change to sing-box/Mihomo/Monitor/sbox-cm/HA-UI
  configuration, permissions, units or behavior; center/agent outage does not
  affect business traffic.

## 16. Failure isolation and coexistence

- Center/network down: bounded spool keeps up to 32 MiB/7 d and retries with
  backoff; business services are unaffected; after recovery spool replays
  oldest-first and `report_id` dedupe prevents double storage.
- Existing per-VPS Monitor: both it and the UM agent may read the same loopback
  sing-box API; this is read-only coexistence with duplicate local load. The UM
  install changes no Monitor file/service/credential and opens no port; the
  operator chooses which systems run per VPS (Q-COEXIST direction).
- Agent crash/power loss: fsynced state survives; a clean restart increments
  generation and an abrupt loss preserves the exact persisted attempt for
  REC-27 duplicate recovery. The frozen-contract power-loss/generation wording
  still needs Owner/contract-owner clarification; it is not claimed as a fully
  resolved durability proof. Windows directory-entry durability is a documented
  platform limitation (write-through replacement, no POSIX dir fsync).
- Center storage failure: `503 storage_unavailable` is retried; no ACK before
  commit (center side, B2 evidence).

## 17. Known limitations (do not read as PASS)

- R2 is INFEASIBLE on the tested Clash Verge Rev 2.5.10/Mihomo 1.19.33
  surfaces; full target matrix UNVERIFIED. R1 remains not authorized/BLOCKED.
- Windows final service account/ACL/enrollment is OD-P7 PENDING. Node-key
  DPAPI CurrentUser is implemented and tested at current-user scope; virtual
  service-account/session-0 and SCM lab validation remain pending.
- Linux D-Bus client is implemented with exact-call/security tests; a live
  systemd/D-Bus lab proof is still pending. The installer noexec gate is
  corrected to systemd >=248, but a target-version lab is pending.
- The sing-box service.api client is implemented/tested against fixtures and an
  isolated 1.14.5 instance; the P1-10 server-side authorization audit is absent
  and the source remains disabled.
- No live **production** sing-box `service.api` authorization audit; source disabled. The isolated synthetic 1.14.5 lab and synthetic gRPC-Web fixtures are not the P1-10 audit.
- No real systemd service install/start, no real Windows service, no real
  Clash Verge Rev/Mihomo read-only/HA proof, no production deployment, no UM-E
  load/backup/security acceptance.
- Planned CLI/service names are not frozen; the final code slice must update
  the deploy assets and runbook if they differ.

## 13. Dependencies

B3 adds the pinned `github.com/godbus/dbus/v5 v5.2.4` direct dependency
(BSD-2-Clause, pure Go on Linux, no new transitive module; OSV clean) for the
read-only systemd probe. `golang.org/x/sys v0.34.0` was already present and is
direct for Windows SCM/DPAPI primitives. The DPAPI path uses stdlib syscall +
`crypt32.dll`; no R1/Mihomo SDK, cloud SDK or scheduler dependency was added.
