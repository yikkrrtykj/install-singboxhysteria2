# UM-B3 agent operator runbook (Draft)

- Status: **UM-B3 Draft PR only.** Not a production procedure, not an
  installation authorization, not merged. Do not run against production until
  the gates in §1 and `um-b3-scope-and-matrix.md` are satisfied.
- Audience: the Owner/operator who will install a `linux_vps` or
  `windows_terminal` agent for a Draft/lab review.
- Related: `um-b3-architecture.md` (design), `um-b3-adr-credentials.md`
  (OD-P7 PENDING), `um-b3-adr-windows-sources.md` (OD-P3; R1 isolated-lab authorized, production HOLD),
  frozen contract `docs/um/um-a/04-node-protocol-v1.md` rev-5.
- Assumption: the planned CLI/service names below are **subject to the B3 code
  slice** (not frozen): `um-agent enroll|run|rotate|status` with
  `--state-dir`/`--center`/`--node-class` (env equivalents
  `UM_AGENT_STATE_DIR`, `UM_AGENT_CENTER_URL`, `UM_AGENT_NODE_CLASS`) and the
  planned Windows entrypoint `um-agent service` (SCM wrapper; account/ACL/DPAPI
  installation remains OD-P7 PENDING). The only frozen command is
  the enrollment token path: `um-agent enroll --token-stdin` as the
  unprivileged user with the token fed over a root-opened stdin pipe.

## 1. Preconditions (do not skip)

- [ ] Independent review of the B3 Draft PR completed/PASS or explicitly
      scoped; Owner merge authorization is a separate gate.
- [ ] Owner decisions needed for the target platform are recorded:
      **OD-P3** (Windows source R2/R1) and **OD-P7** (Windows account/secret)
      are **PENDING** in `docs/um/um-127/05-owner-decisions.md`. Do not install
      a Windows source, do not enable `mihomo_api`/`terminal`, and do not
      provision any R1/controller secret before they are decided.
- [ ] A reviewed build receipt exists for the agent binary: source commit,
      Go/toolchain versions, `-trimpath` build, SHA-256.
- [ ] The target host is authorized and is not production; no real event
      credentials, tokens, private keys or Clash Verge Rev controller secrets
      are used in a lab.
- [ ] The center is reachable from the host over HTTPS (or loopback HTTP for a
      local test center only); the bootstrap token is admin-created with
      `{event_id, node_class}` scope and is one-time.
- [ ] Existing systems checked first: sing-box, per-VPS Monitor
      (`singbox-monitor.service`), `sbox-cm.*`, HA-UI/P6/#67 are running and
      must not be changed by this install (see §5).

Never run steps 2–9 of this runbook against production. All commands below are
templates to be executed by the operator after review; this Draft itself
executes none of them.

## 2. Linux install — `linux_vps`

Distribution matrix: Debian 12 / Ubuntu 22.04 / 24.04 (systemd). The frozen
contract requires a non-root runtime user, a root-only one-time bootstrap token
and a one-shot root installation/orchestration.

### 2.1 Prepare

1. Build/obtain the reviewed `um-agent` binary; verify its SHA-256 against the
   build receipt.
2. Review the deploy assets: `um/deploy/linux/um-agent.service`,
   `um-agent-noexec.conf`, `install-agent.sh`.
3. Confirm the target center ingest URL (deployment choice Q-INGRESS PENDING;
   example `https://ingest.<domain>`).
4. Ask the admin to create a one-time enrollment token **after** the install
   preconditions pass; place it at `/etc/um-agent/bootstrap.token` as
   `root:root 0600` (never in an agent-readable location, never in shell
   history/CI logs). Token content is never printed by these procedures.

### 2.2 Preview (dry-run; default, no changes)

```bash
cd um/deploy/linux
./install-agent.sh \
  --binary /path/to/um-agent --sha256 <64-hex> \
  --center https://ingest.example.xyz
```

Review the PLAN lines. The script creates: `umagent` system user, state dir
`/var/lib/um-agent` 0700, `/etc/um-agent` 0700 root, binary
`/usr/local/libexec/um-agent` root 0755, unit `/etc/systemd/system/um-agent.service`
0644, `agent.env` 0640 root:root (center URL only, no secrets), and on
systemd ≥248 the `10-noexec.conf` drop-in. It does **not** enable/start the
service unless `--start-service` is given.

### 2.3 Install + one-time enrollment

```bash
sudo ./install-agent.sh --apply \
  --binary /path/to/um-agent --sha256 <64-hex> \
  --center https://ingest.example.xyz \
  --token-file /etc/um-agent/bootstrap.token
```

The enrollment step runs the agent **as `umagent`** with the token on stdin
from the root-opened pipe (`um-agent enroll --token-stdin`, the frozen contract
flow). The agent never needs read access to the token file; the CLI also accepts
`--token-file` for an explicitly reviewed alternative, but this installer uses
only the stdin pipe. The agent generates its Ed25519 key and writes
`identity.json`/`boot_state.json` in `/var/lib/um-agent` (0600). On success the
installer deletes the token file; on failure it leaves it root:root 0600 for
operator retry and exits non-zero.

### 2.4 Start and verify

```bash
sudo systemctl start um-agent.service      # or: sudo systemctl enable --now um-agent.service
systemctl status um-agent.service --no-pager
journalctl -u um-agent.service -n 50 --no-pager   # closed codes only, no payloads
```

Verification checklist (record results in the PR/lab notes; not claimed as
already passed by this Draft):

- [ ] unit active, no restart loop; process runs as `umagent`, no root process.
- [ ] `/var/lib/um-agent` 0700 `umagent:umagent`; key/state files 0600.
- [ ] `systemctl show um-agent.service -p NoNewPrivileges,ProtectSystem,PrivateTmp,...`
      reflects the unit; `systemd-analyze verify` clean.
- [ ] on systemd ≥248 the noexec drop-in is loaded (check
      `systemctl show um-agent.service -p NoExecPaths`); on older systemd it is
      absent and the gap is recorded (no fake no-exec claim).
- [ ] agent has no listening socket (`ss -lntp`), no child processes.
- [ ] a signed report reaches the center and is accepted (`200 accepted`);
      `um-agent status --state-dir /var/lib/um-agent` shows enrolled,
      generation/seq advancing, pending/quarantine counts only.
- [ ] no token/private key/headers/body in journal, shell history or files.
- [ ] existing Monitor/sing-box units are unchanged and still active.

## 3. Linux run and source behavior

- The service is single-writer: a second `um-agent` on the same state dir
  fails (`state directory is already in use`) — do not "fix" it by deleting
  `.lock` or state files; check for a stray process first.
- Boot generation increments by exactly 1 on **every** enrolled runtime start,
  including `systemctl restart` and an unclean/power-loss restart; a new boot
  id and fresh transport attempts are used, while report_id/body identity is
  preserved for dedupe. This implements published/frozen rev-6 (merge
  `a5ee4d8b`, fixture `power-loss-generation.rev6.json`). Same-process transport
  retry is the only exact same-generation duplicate path.
- Data sources are **fail-closed and off by default**: `/proc`-based system
  metrics may be collected per center config; systemd unit state is read through
  the shipped read-only D-Bus probe and is UNKNOWN on unavailable/denied.
  `singbox_api` stays **disabled/unavailable** and has **no supported
  enablement path in this release**: the v1.14.5 P1-10 server-side
  authorization audit failed (the single service.api secret is write-capable),
  and no environment variable, LoadCredential path, center switch or local
  credential path authorizes it. Lab tests construct a probe in-process only.
  The required G7 diagnostic event is emitted and the projection stays
  `unavailable`/`unknown` with closed reason codes — never fabricated data.
- Availability honesty: missing data is null/UNKNOWN; no fake zeroes, no "up"
  without evidence, no traffic absence reported as down.
- Clock: if the center returns `stale_timestamp`, the agent recalibrates from
  `server_time` and retries once; persistent skew is an operator fix (NTP),
  not something to bypass.
- Logs: journald carries closed error codes/counts; the agent never logs
  headers, bodies, signatures, keys, tokens, local proxy names or payloads.
  Do not add debug logging that prints state files or request bodies.

## 4. Linux upgrade / uninstall / rollback

### 4.1 Upgrade

1. Verify the new binary build receipt/SHA-256.
2. Preview: `./install-agent.sh --upgrade --binary ... --sha256 ... --center ...`
   (dry-run).
3. `sudo systemctl stop um-agent.service`.
4. `sudo ./install-agent.sh --apply --upgrade --binary ... --sha256 ... --center ...`
   (the script stops the service if still active; it does not start it unless
   `--start-service`).
5. `sudo systemctl start um-agent.service`; verify accepted report and the
   expected normal generation increment; state dir is preserved (no re-enroll,
   no token).
6. Keep the previous binary/SHA for rollback: stop, reinstall the previous
   verified binary with `--upgrade`, start, verify. Never roll back by editing
   or deleting `identity.json`/`boot_state.json`/`spool`.

### 4.2 Uninstall

1. `sudo systemctl stop um-agent.service && sudo systemctl disable um-agent.service`.
2. Admin revoke the node identity in the center (audited); record the spool
   disposition before deleting anything (bounded spool may contain unsent
   telemetry; never delete silently).
3. Remove service assets: unit, drop-in, `/usr/local/libexec/um-agent`, and
   `/etc/um-agent/agent.env`; verify no token file remains.
4. Remove the state dir only with explicit confirmation after data disposition:
   `/var/lib/um-agent` contains the node private key, boot/config/rotation
   state and spool. Delete the runtime user/group only after the dir is gone.
5. Existing sing-box/Monitor/`sbox-cm`/HA-UI are not touched by install,
   upgrade or uninstall; no permissions changed.
6. Rollback means reinstall the previous verified binary and restart (same
   identity); a decommissioned identity cannot be restored in place — re-enroll
   creates a new node id.

## 5. Coexistence with the existing per-VPS Monitor

- The existing Monitor (`singbox-monitor.service` and its `/opt`/`/etc`
  installation) keeps its own contract, credentials and deployment; UM does
  **not** modify, duplicate or replace it.
- The UM agent is a separate unit under a separate non-login user with its own
  state dir; it opens **no port** and shares **no socket** with the Monitor.
- Both may read the same loopback sing-box API; this is read-only technical
  coexistence with duplicate local load. Do not change sing-box/Monitor
  permissions or secrets to make the UM agent work; if a read-only API
  credential is needed, it is a new `LoadCredential` source under the P1-10
  authorization path, not a change to Monitor's files.
- Recommendation for events: install the per-VPS Monitor **or** the UM agent
  per Q-COEXIST direction; if both are required, document the duplicate load
  and keep them independent. Never let the UM agent participate in client
  failover or business traffic decisions.
- Center/agent outages stop only telemetry: agents spool locally and retry;
  sing-box, Mihomo and HA remain unaffected.

## 6. Windows install — `windows_terminal`

> OD-P7 final account/secret decisions are **PENDING**; R1 is Owner-authorized
> for isolated lab only (production HOLD). R2 was
> investigated on Clash Verge Rev 2.5.10 / Mihomo 1.19.33 and is **INFEASIBLE**
> on the tested surfaces (TCP needs a write-capable secret; the named pipe is
> unauthenticated yet write-capable). The Owner has authorized R1 **only for
> isolated lab verification** (see `um-b3-r1-isolated-lab-acceptance.md`);
> production enablement remains HOLD. Do not install a production terminal
> source or use a real controller secret. R1 activation requires a protected
> local bundle under `<state>/r1` written by `um-agent r1-provision` under the
> service account; there is no environment-variable authorization/secret path.
> The bundle is disabled unless present and valid, and production scope is
> rejected.

### 6.1 Prepare

1. Review `um/deploy/windows/install-agent-service.ps1` and
   `um-b3-adr-credentials.md`.
2. Obtain the reviewed `um-agent.exe` build receipt/SHA-256.
3. Decide/record the Owner-approved service account (OD-P7). The template's
   default `NT AUTHORITY\LocalService` is a minimum placeholder; `LocalSystem`
   is refused by the script; a dedicated non-admin account or a virtual service
   account is the proposed direction (PENDING).
4. No secret is needed for R2-style sources. R1 is isolated-lab-only and is
   not provisioned by the Windows service installer; an Owner-approved lab may
   run `um-agent r1-provision` under the service account after enrollment.
   Production enablement is HOLD.

### 6.2 Preview / plan

```powershell
# Plan only, no changes (no elevation required for -WhatIf):
.\install-agent-service.ps1 `
  -BinaryPath 'C:\build\um-agent.exe' `
  -CenterUrl 'https://ingest.example.xyz' -WhatIf
```

The plan shows: state dir `C:\ProgramData\UM Agent`, ACL (SYSTEM+Administrators+
service account, no Users), service `um-agent` (Manual start, session 0),
command line
`um-agent.exe service --state-dir ... --center ... --node-class windows_terminal`
(the SCM wrapper parses the flags; there is no literal `run` word).

### 6.3 Install (only after the Owner approval and OD-P7 decision are recorded)

```powershell
# Elevated PowerShell, after OD-P7/OD-P3 records exist:
.\install-agent-service.ps1 `
  -BinaryPath 'C:\build\um-agent.exe' -BinarySha256 <64-hex> `
  -CenterUrl 'https://ingest.example.xyz' `
  -ServiceAccount 'NT SERVICE\um-agent' `
  -ConfirmOwnerApproval
# then start explicitly when ready:
Start-Service um-agent
```

For a dedicated local user account pass `-ServiceCredential (Get-Credential)`
at install time (the password is never written to disk or logs by the script).
The script creates no controller credential and no scheduled task. The agent
itself protects its Ed25519 identity and rotation provisional private keys with
DPAPI CurrentUser; enrollment must therefore run under the same Windows account
as the service. The script does not run enrollment and does not create an
account/ACL/DPAPI decision; that remains OD-P7 PENDING. It does not create a
schedule task and
does not change Clash Verge Rev/Mihomo/HA-UI configuration.

**Windows SCM lifecycle wrapper exists in this Draft** (`um-agent service
--state-dir ... --center ... --node-class windows_terminal`; it runs the shared
runtime under SCM stop/shutdown). The service account, ACL, DPAPI scope and
installation decision remain **OD-P7 PENDING**. A dedicated isolated SCM lab
workflow (`um-b3-lab.yml`) exercises virtual-service-account creation,
enrollment, DPAPI, R1 provisioning and session-0 service execution on a
disposable GitHub Windows runner; its exact result is recorded on the PR. The
installer registers the service
as Manual-start and does not start it; do not start/enable it until the Owner
decision and the code-slice installation path are reviewed. For a lab smoke test
before that, run the collector manually (no service):
`& 'C:\build\um-agent.exe' run --once --state-dir 'C:\ProgramData\UM Agent' --center https://... --node-class windows_terminal`
and expect honest `unavailable` terminal data + acceptance/rejection evidence
from the center; this is not a Windows-service proof.

**R1 isolated-lab source path (disabled by default; production HOLD):** the
binary loads a protected bundle from `<state>/r1/acceptance.json`,
`profile.json` and `controller.secret.dpapi`. The bundle must be created by
`um-agent r1-provision` under the same service account; the secret is sealed
with DPAPI CurrentUser and the directory/files receive a private DACL. A
missing bundle means disabled; a malformed, hash-mismatched, non-isolated-lab
or unsealable bundle fails closed. There is no environment-variable secret or
authorization switch. R1 is the write-capable controller shape, not R2; never
call it read-only. The current Clash Verge Rev default may expose only the
unauthenticated named pipe (not used); the `windowsobs` client uses literal
loopback TCP only. Do not use a real controller secret.

Enrollment: the Windows agent also needs a one-time admin token. Use the
authorized process for the target environment; never store the token in the
repo, script, service command line or logs. The Windows CLI enrollment path
uses the same token contract as Linux (`--token-stdin` root-opened pipe or a
reviewed `--token-file`). Because identity private keys are DPAPI CurrentUser,
enrollment must execute under the final service account; enrolling as an
interactive/admin user and then switching the service account would make the
state unreadable (fail closed, not auto-recover). The final account/enrollment
flow remains OD-P7 PENDING; do not invent a production path from this template.

### 6.4 Verify (lab)

- [ ] service exists, Manual start, runs in session 0 under the approved
      non-admin account.
- [ ] state dir ACL: SYSTEM/Administrators/service account only; no `Users`.
- [ ] no controller credential was created; R1 remains disabled. (The agent's
      own identity/rotation private keys are DPAPI-protected at rest; this is
      not a controller secret.)
- [ ] terminal telemetry is honestly `unavailable` with
      `source_authorization_unproven` unless an authorized R2 source is proven.
- [ ] no write to Clash Verge Rev/Mihomo config, no node switch, no connection
      close, no HA-UI/P6/#67 change (UM-E real-build assertion).
- [ ] six tokens only; no local proxy names/URLs/IPs/connection ids in any
      report, log or backup.
- [ ] signed report accepted by the center; status is diagnostics-only.

## 7. Windows upgrade / uninstall

- **Upgrade**: stop service; verify new EXE SHA-256; replace the binary path
  used by the service; `Start-Service`; verify accepted report. State dir and
  (if any) protected storage are preserved; no re-enroll, no credential
  re-creation. Keep the previous EXE/SHA for rollback.
- **Uninstall**: `Stop-Service um-agent; sc.exe delete um-agent`; admin revoke
  the node; record spool disposition; remove the data dir only after explicit
  confirmation; remove ACLs/service SID as needed; remove any Owner-approved
  protected secret only through the approved procedure. Do not touch Clash
  Verge Rev/Mihomo/HA-UI.
- **Rollback**: reinstall the previous verified EXE and start; identity is
  preserved. A decommissioned/revoked identity cannot be reset in place —
  re-enroll creates a new node id.

## 8. Recovery and operator procedures (REC-17/18/27 and common cases)

General rule: **never edit, delete or "reset" `identity.json`,
`boot_state.json`, `config.json`, `rotation.json`, `pending_control.json` or the
spool to make an error go away.** These states are fail-closed by contract;
in-place generation reset is always rejected by the center
(`stale_boot_generation`) and deleting a key destroys recoverability.

| Symptom (closed code) | Meaning | Operator action |
| --- | --- | --- |
| `boot_state_corrupt` / `identity_corrupt` (REC-17) | local durable boot/identity state missing or invalid while the other exists; agent refuses to report (fail-closed) | Do **not** regenerate or edit state. Collect diagnostics (closed code only), stop the service, admin revoke the node, issue a new token and re-enroll as a **new node id**; discard the old local state only after revoke. This is the intended REC-17 path. |
| `409 stale_boot_generation` (REC-18) | the agent was restored from an old snapshot/state, or a retired generation was replayed; the center never re-activates an old generation | Stop; do not reset in place. Admin revoke + new token + re-enroll (new node id). Restore only from a state snapshot known to be current; old snapshots are not usable. |
| `409 sequence_conflict` on the **latest** attempt | local sequence state is inconsistent with the center high-water (e.g. unsynced tail/restore) | Stop; do not reuse seq or delete spool blindly; follow operator recovery (revoke + re-enroll) after collecting closed-code diagnostics. A conflict on an already-superseded delayed attempt is expected and ignored (REC-10). |
| `409 boot_identity_conflict` | same generation with a different boot id, or generation gap > 65535 | Do not fabricate a generation; operator recovery (revoke + re-enroll). Check for a second agent instance or copied state dir. |
| no ACK / retries pending after a power loss (REC-27) | committed seq may be resent (→ `duplicate`) or the unsynced tail may be lost | Let the agent retry normally; verify a `duplicate`/accepted ACK and spool drain. Never reuse an unsynced seq; if `sequence_conflict` persists on the latest attempt, operator recovery. |
| `401 revoked_key` / `unknown_node` | admin revoked the identity; reports rejected | Agent stops the queue and keeps the bounded spool. Confirm the revoke/decision with the admin; discard the spool only under explicit data-disposition decision; re-enroll as a new node id if telemetry should resume (REC-21). |
| `409 rotation_expired` | provisional rotation key expired while offline | Agent deletes the provisional key and resumes old-key reporting (old key stays active); no center change needed. If the old key is also rejected → operator recovery. Rotation intent replay/restart is REC-19. |
| `nonce_reuse` / `report_conflict` | replay/fingerprint anomaly (should be handled/ignored per contract) | Stop, collect closed-code diagnostics and timestamps; do not edit state; escalate to the center admin/reviewer. |
| `503 storage_unavailable` / `429 rate_limited` | center transient/backpressure | Retryable; let bounded backoff/spool work; check center health (admin plane) rather than changing the agent. |
| `stale_timestamp` | host clock skew | Recalibrate NTP from `server_time`; the agent retries once; persistent skew is an NTP/operator issue, not a reason to loosen validation. |
| spool quarantine grows | terminal payload rejections or corrupt records | Quarantine is bounded (8 MiB, oldest-first) for operator inspection; inspect only closed reasons/metadata (not payload content in logs). Fix the collector/config cause; decide disposition with the admin. |
| spool full | bounded 32 MiB/7 d reached | Fail-closed/observable; the runtime drains existing backlog before queueing new work, so restore center connectivity and let it ACK; do not raise the cap or drop records silently. |
| enrollment returns `401 token_used` (REC-24) | the enrollment response was lost after commit; the node may be an active orphan | Admin identifies the unused orphan (recent creation, no reports), revokes it and issues a new token; agent enrolls as a new node. Do not revoke a node that has already reported. |
| agent cannot start: `state directory is already in use` | another agent instance holds the OS advisory lock | Confirm no other process uses the state dir. A leftover `.lock` **file** after a crash is harmless; the OS lock is released on process death. Do not delete it while a process may be running. |

Center outage / long offline: the spool is durable/bounded (32 MiB / 7 d) and
retries 1→60 s; business services are unaffected. Do not delete the spool to
"clear" backlog; after recovery it replays oldest-first and dedupe prevents
double storage.

## 9. Backup and no-secrets rules

- **Center** backup/restore is UM-E scope; agent state is **not** backed up
  centrally. Node private keys must never be copied to the center, a repo, a
  ticket or a shared drive.
- If an operator keeps a local encrypted backup of agent state for disaster
  recovery, treat it as a private key and record that a revoked/old copy cannot
  be used in place (REC-18). Prefer re-enrollment over restoring old state.
- The bounded spool contains telemetry payloads, not secrets; it is not backed
  up off-host by UM-B3 and should follow data-retention policy (never copied to
  logs/tickets).
- Never log or paste: tokens, private keys, request headers/bodies, DPAPI
  blobs, controller secrets, local proxy names/YAML, raw IPs/URLs, connection
  ids. Closed error codes/counts only.
- Windows: protect the state dir by ACL. The agent's identity and rotation
  private keys are DPAPI CurrentUser-protected at rest; enrollment must run
  under the same service account. Controller/R1 secrets (if ever approved) are
  separate and remain disabled. Linux: 0700/0600 as in §2; no permission
  loosening of existing systems.

## 10. Rollback / production gate

- Rollback = previous verified binary + restart (identity preserved); uninstall
  = service/assets/dir removal after revoke and data disposition; neither
  touches existing Monitor/sing-box/HA systems.
- Do not enable R1, do not install a Windows source, do not deploy to
  production, and do not create real credentials while OD-P3/OD-P7 and the
  merge/production gates are open.
- Production remains **HOLD** until UM-E acceptance (load/capacity, backup/
  restore, independent review, real read-only/HA assertions) and separate Owner
  authorization; this runbook does not grant it.

## 11. Optional revision-7 read-only traffic export (UM-LT)

Status: OPTIONAL, default DISABLED, additive to the rev-5 agent protocol. It is
not a production authorization, does not change `singbox_api`, and creates no
credential or listening socket.

- **Agent local input only.** The non-root agent reads one operator-local,
  fixed absolute path supplied by `--monitor-export-file` or
  `UM_AGENT_MONITOR_EXPORT_FILE` (for example
  `/run/singbox-monitor-export/traffic.json`), produced by the separately
  deployed non-root monitor-v2. The path is never accepted from center config, a
  URL or a command. The file is read read-only under a 64 KiB cap; symlinks,
  non-regular files and oversized documents are rejected and degrade to an
  honest `unavailable` observation (never zero, never a previous value reused as
  fresh). No new group/capability/secret is required by the agent: OS read
  permission is enough (the monitor packaging notes describe a dedicated
  `sboxmon-export` read group). No writing, no listener, no service.api secret.
- **Center source switch.** `collect.monitor_export` (optional boolean, absence =
  false) is stored by the center and enabled by an admin config update. While it
  is disabled, the agent reads nothing and its snapshot remains byte-identical to
  the frozen rev-5 body. When enabled and a valid fresh export exists, the agent
  emits `contract_revision: 7` plus a per-inbound `traffic_observation` of
  OBSERVED LOWER-BOUND bytes/rates; the rev-5 `traffic` array stays empty and
  `availability.traffic` stays `unavailable` because lower bounds are not
  contract totals.
- **OD-LT-14 agent-version gate.** Agent releases before 1.1.0 have a strict
  six-key `collect` decoder, so the center only emits `monitor_export` to a node
  whose latest **authenticated snapshot** `agent.version` is `>= 1.1.0` (the
  agent release version is 1.1.0 from that build on; the center tracks it in the
  v14 `nodes.last_agent_version` metadata and never trusts a header). Bootstrap
  ordering is deliberate: the old/unknown agent keeps receiving the frozen
  six-key config and its rev-5 snapshots stay accepted; after it reports 1.1.0,
  the next config pull (bounded refresh ≤5 min, or the next `run`/`-once` start)
  carries the switch. Enabling the center source before upgrading is safe: the
  stored switch persists and takes effect only for a capable agent.
- **Expected tags.** The agent only reports center-authorized
  `expected_inbound_tags`; export tags not in that allowlist, kind mismatches,
  duplicate/unknown tags, malformed JSON, unsupported schema version, stale or
  future observations, sequence regressions and source-epoch changes are handled
  as documented in `docs/monitor-v2-traffic-export.md` and the rev-7
  `traffic_observation` contract: freshness `fresh|stale|unavailable`,
  availability `ok|partial|unavailable`, null counters when unobserved.
- **Normalization.** The center stores only allowlisted normalized fields
  (migration v14 `traffic_observation_reports` / `traffic_observations`), never
  the raw export JSON, in the same snapshot ingest transaction; dedupe/replay of
  a report never duplicates traffic rows. Retention/purge/archive delete the
  rows with the snapshot/event.
- **Read API.** The bounded browser-plane endpoints
  `GET /web/api/traffic/latest` and `GET /web/api/traffic/history` require
  Cloudflare Access plus an active UM-C session; viewer/event_admin are limited
  to assigned events (out-of-scope event => 403), platform_admin is global; rows
  are ordered by `observed_at` (never `received_at`), ranges are capped at 30
  days and 2000 rows, and history reports `gap_before_seconds`/`truncated`.
- **Explicit non-goals.** This does not expose raw Monitor state, sing-box
  service.api, connection/user data, IPs/URLs, or a write path; it does not
  change monitor-v2's default-disabled packaging and does not enable
  `singbox_api`.
