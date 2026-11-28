# UM-LT — Operator runbook (install, enable, disable, upgrade, rollback)

Status: **CANDIDATE runbook for the rev-7 contract package — docs-only, pending
independent review/CI and the Owner's conditional merge authorization. NOT
published/frozen, NOT merged, NOT implemented. NO PRODUCTION EXECUTION is
authorized by this file.** Commands below are reference procedures to be aligned
with the implementation PR's exact installer/unit/paths; they were not executed
against real infrastructure for this contract PR. No Cloudflare/DNS/certificate/
VPS/SSH/paid resource is used.

Reference identities/paths: center `um-center.service` (`umcenter`), agent
`um-agent.service` (`umagent`), monitor `singbox-monitor.service` (`sboxweb`),
export group `sboxmon-export`, export directory `/run/singbox-monitor-export/`,
export file `traffic.json`, agent state `/var/lib/um-agent/`. The implementation
PR fixes the exact names; the operator setup must assert them. The directory is
on `/run` tmpfs, so it is operator-created and must be recreated after a reboot
(systemd-tmpfiles or the install script); the exporter is disabled while it is
absent.

## 0. Preconditions

- A rev-7-capable center build is deployed (or ready) and its source-authorization
  audit version matches `UM-LT-SOURCE-AUDIT-v1`.
- The monitor package includes the audited export writer; the agent package
  includes rev-7 support (A7).
- `CFG-REV7` version gate: the center emits `collect.monitor_export` only after
  the node's latest signed snapshot reports `agent.version >= 1.1.0`
  (`MIN_REV7_AGENT_VERSION`; the rev-5 agent is `1.0.0`). Until then the center
  tracks the version and omits the key entirely; a stored source-enable flag is
  not effective yet. The implementation PR must provide the exact read-only way
  to inspect the latest signed `agent.version` and config emission state.
- A pre-change backup/rollback point exists for the center database and the
  affected node state (frozen rev-5 backup rules).
- Operator has read the compatibility matrix
  ([`um-lt-compatibility.md`](um-lt-compatibility.md)) and the source audit
  ([`um-lt-source-authorization-audit.md`](um-lt-source-authorization-audit.md)).
- `singbox_api` remains `false`/DISABLED before, during and after every step;
  P1-10 remains FAIL.

## 1. Rollout order (normative for this runbook)

| Step | Action | Why this order |
| --- | --- | --- |
| 1 | Upgrade the center to the rev-7-capable build with the source disabled (no node has `monitor_export`) | C7 must be able to receive/validate rev-5/6 bodies first; no behavior change for old agents |
| 2 | Install the monitor package with the export writer; the operator creates the `sboxmon-export` group and `/run/singbox-monitor-export/` directory | the file may exist before any center enables the source; nothing consumes it until enabled; the writer's operator path is validated at startup |
| 3 | Upgrade agents to the rev-7 build (source disabled) | A7 emits only rev-5 bodies until a config advertises the switch; its signed snapshots must report `agent.version >= 1.1.0` before the center can emit the key |
| 4 | Enable the source for one canary `linux_vps` node in the center | validates config/gating per node; if the stored flag is enabled before the version gate is satisfied, the center withholds the key and applies it on the next pull after a signed `>=1.1.0` snapshot |
| 5 | Verify export file, agent report, ingest, storage and query (see §5) | catches ACL/schema/semantics issues before fleet |
| 6 | Expand node by node / event by event; keep an explicit disable path | bounded blast radius |
| 7 | Record evidence (versions, audit version, queries, rollback point) | required before any production approval |

Monitor and agent start order is not security-sensitive: the agent can start
before the monitor (it reports unavailable until a fresh export exists) and the
monitor can start before the agent. For a clean first observation, start the
monitor first and wait for one successful export.

## 2. Install (reference commands; verify in the implementation PR)

### 2.1 Export group and directory (one-time per node, operator step)

```bash
# explicit operator step; the installer and the monitor never create these
getent group sboxmon-export || groupadd --system sboxmon-export
# the group contains ONLY the non-root local agent service user; never root,
# never interactive users, and the monitor user is not a member (owner write)
usermod -aG sboxmon-export umagent
install -d -m 2750 -o sboxweb -g sboxmon-export /run/singbox-monitor-export
```

Verify (must match; a wrong result aborts the rollout):

```bash
stat -c '%U:%G %a %F %n' /run/singbox-monitor-export
getent group sboxmon-export          # exactly one member: the agent user
# agent must be able to traverse/read, not write:
sudo -u umagent test -r /run/singbox-monitor-export && echo readable-ok
sudo -u umagent test -w /run/singbox-monitor-export && echo "FAIL writable" || echo "read-only-ok"
getfacl -p /run/singbox-monitor-export 2>/dev/null || true   # must have no extended ACL entries
```

The monitor unit must gain exactly one optional writable path:
`ReadWritePaths=-/run/singbox-monitor-export` (the packaged equivalent; the
leading `-` keeps a default install without the directory working). No
sing-box/`sbox-cm`/data-root permission changes. Diff and record the unit
change. Because `/run` is tmpfs, recreate the directory after a reboot
(systemd-tmpfiles/install script); an absent directory means no export and the
agent reports honest unavailable.

### 2.2 Monitor package

```bash
# use the reviewed package/installer for this node; do not hand-edit units
systemctl daemon-reload
systemctl restart singbox-monitor.service
systemctl is-active singbox-monitor.service
```

The export file must appear after one collection interval:

```bash
stat -c '%U:%G %a %s %y %n' /run/singbox-monitor-export/traffic.json
python3 - <<'PY'
import json
p="/run/singbox-monitor-export/traffic.json"
d=json.load(open(p))
print(d["schema"], d["schema_version"], d["source"], d["source_epoch"], d["sequence"], d["monitor_stale"], len(d["inbounds"]))
PY
```

The reader-side checks are strict: `schema=singbox-monitor-traffic-export`,
`schema_version=1`, `source=monitor-v2`, 32-hex epoch, boolean stale flag, ≤8
inbounds, no unknown fields.

### 2.3 Agent package

```bash
systemctl daemon-reload
systemctl restart um-agent.service
systemctl is-active um-agent.service
um-agent status    # existing read-only status; must not mutate state
```

The agent must show the source disabled until the center advertises it; the
rev-5 snapshot/metrics/events flow must remain healthy.

## 3. Enable the source (per node)

1. Confirm the node is `linux_vps`, the agent is rev-7 capable, the latest
   signed snapshot reports `agent.version >= 1.1.0` (`CFG-REV7`), and the
   source-authorization audit version is recorded in the center rollout gate.
   If the version is unknown/older, upgrade the agent first; enabling the stored
   flag early is safe but the center MUST keep the key absent until a signed
   `>=1.1.0` snapshot arrives.
2. Enable `monitor_export` for the node in the center (management action per the
   implementation UI/CLI; the value is a boolean, never a path/URL/token).
3. Wait for the agent config refresh (bound: 300 s in the frozen runtime) and a
   config version bump; confirm the applied config has
   `collect.monitor_export=true` via `um-agent status` (the existing read-only
   status output). If the key never appears, re-check the latest signed
   `agent.version`; a stored flag alone is not enough (`CFG-REV7-02`).
4. Confirm the node's next snapshot contains `contract_revision: 7` and a
   `traffic_observation` with `source=monitor_readonly_export`,
   `exactness=lower_bound`, `counter_scope=observation_epoch` (center diagnostics
   or a signed test report; never log raw payloads).
5. Confirm center ingest stored it (`latest observation` row / query endpoint)
   and the query surface labels it as an observed lower bound with freshness/
   availability/age — never "total".
6. Confirm no Windows node and no non-enabled Linux node receives the switch.

## 4. Disable the source

1. Set `monitor_export=false` (or remove it) for the affected nodes/fleet.
2. Within the config refresh bound the agents stop creating rev-7 records; they
   emit rev-5 bodies with `traffic: []` and `availability.traffic: unavailable`.
3. Already-spooled rev-7 records may still drain to a rev-7-capable center
   (effective-dated authorization); if the center is being downgraded, follow
   §6 drain rules instead.
4. The last observation ages to `stale`, then the no-observation sentinel; verify
   the query shows STALE/UNAVAILABLE rather than zero.
5. `singbox_api` stays false; the monitor's existing credential is untouched.

## 5. Verification checklist (canary)

| Check | Expected |
| --- | --- |
| export file owner/group/mode | `sboxweb:sboxmon-export 0640`, regular file, size ≤64 KiB; directory owner `sboxweb` / `2750` / no ACL |
| export epoch/sequence | 32-hex epoch; sequence increases; change of epoch only on monitor restart |
| export privacy scan | no IP/hostname/user/device/connection-id/UUID/proxy/URL/YAML/secret tokens |
| agent reads only export | no monitor data-root/secret access; no new listener; no export write |
| `CFG-REV7` version gate | center tracks the latest signed `agent.version`; key absent entirely for unknown/older; present only after a signed `>=1.1.0` snapshot + next pull; absent again if a later older version is reported |
| signed report | rev-5 transport unchanged; body has `contract_revision=7`; signature verifies at center |
| center validation | accepted once, deduped on retry; invalid/unknown tag rejected; Windows rev-7 rejected |
| query | lower-bound label + freshness/availability/age + epoch boundary; no totals, no fabricated zero |
| rev-5 regression | system/services/protocols/clients and metrics/events unchanged; Windows nodes unchanged |
| no credential expansion | `singbox_api=false`; no `service.api` credential on agent/center; P1-10 FAIL unchanged |

## 6. Rollback and drain

Follow [`um-lt-compatibility.md`](um-lt-compatibility.md) §5–§6.

1. Disable the source in the center and confirm the switch is off fleet-wide.
2. Wait for the config refresh bound and drain the normal rev-5 spool; rev-7
   records still in the send path must be quarantined (preserved byte-identical,
   never rewritten) when the target center cannot accept them.
3. Record `um-agent status` quarantine counts and the spool/quarantine size.
4. Roll back the center only with a known-good pre-upgrade database backup (an
   old binary refuses a newer schema; do not force it). Roll back agents at the
   same time or before the center if the state schema changed.
5. After rollback verify: rev-5 payload flow healthy; no rev-7 body in the send
   path; no rev-7 data rendered; `singbox_api=false`; monitor export writer
   disabled or its file unused; no lingering group/permission change beyond the
   documented export directory (remove it only if the writer is gone).
6. Restore point and evidence are recorded; no production claim is made until a
   later authorized deployment.

## 7. Uninstall

1. Disable the source and drain/quarantine as in §6.
2. Stop and remove the agent/monitor rev-7 packages using the reviewed uninstall
   path; do not hand-delete state directories that the uninstaller manages.
3. Remove `umagent` from `sboxmon-export`; remove
   `/run/singbox-monitor-export/` only after the monitor writer is removed and the
   uninstall evidence confirms no remaining writer.
4. Do not change sing-box/`sbox-cm` permissions or remove unrelated monitor data.
5. `singbox_api` stays false; P1-10 FAIL is retained regardless of uninstall.

## 8. Diagnose

| Symptom | First checks | Likely action |
| --- | --- | --- |
| node shows no rev-7 data | center rollout gate, audit version, node class, latest signed `agent.version` (`>=1.1.0`), applied config switch, monitor mode | enable/upgrade only through the documented gate; never bypass; if the monitor runs only the legacy compatibility collector-loop mode it never publishes the export — run the production web mode with the explicit export flags |
| source flag enabled in center but key absent from agent config | `CFG-REV7` gate not satisfied: version unknown/older, no signed snapshot yet, or class/audit mismatch | upgrade agent and wait for a signed `>=1.1.0` snapshot + next config pull; center MUST omit the key, not emit `false` (`CFG-REV7-01/02/04`) |
| key appears then disappears without a config disable | later signed snapshot reported an older version (agent rollback) or class/audit state changed | treat as compatibility downgrade; drain per §6; do not force-enable |
| `traffic_observation.availability=unavailable` | monitor running, export file exists/fresh, owner/group/mode, `monitor_stale`, symlink/FIFO, size | fix monitor/ACL; do not fake data |
| `freshness=stale` | export age vs `max(2×cadence,120)`; monitor stopped? stream gap? | restore monitor/stream; stale is honest |
| missing inbound tags | `expected_inbound_tags` vs export tags/kinds; monitor sees a different inbound set | correct center config; the agent drops unknown tags by design |
| `400 invalid_request` on report | center build rev-7 capable? `contract_revision`/field tokens, lexical ints, duplicate tags, base traffic non-empty, availability coherence | fix the payload/center version; never strip/rewrite to bypass |
| `400 platform_mismatch` | node class / terminal object | class-bound; re-enroll if the class is wrong (never self-assert) |
| quarantine growth | old center after rollback, disabled source, unauthorized tags | expected on downgrade; drain/quarantine per §6; inspect, do not delete blindly |
| permission denied on export | group membership, directory mode, file mode/owner, symlink | restore documented model; do not broaden to world/other groups |
| capacity/alarm | bucket rows, base payload, disk free, retention | capacity tuning/UM-E; never silently drop data |

Closed local diagnostics are counters/codes only; raw export content must never
be pasted into tickets or logs.

## 9. Evidence to record per rollout

- center/monitor/agent versions and config versions; export audit version
  `UM-LT-SOURCE-AUDIT-v1`;
- export file metadata (owner/group/mode/size/epoch/sequence counts) and a
  privacy scan result;
- center ingest/query results for the canary (accepted/duplicate, lower-bound
  labels, freshness);
- negative checks (Windows untouched, non-enabled Linux untouched,
  `singbox_api=false`, unauthorized tag rejected);
- rollback point, drain/quarantine counts, and revocation/rollback record.

**No production execution is claimed by this runbook. Production deployment,
R1 production enablement, Cloudflare/DNS/TLS/certificates, VPS/SSH access and
paid resources remain unauthorized and out of scope for UM-LT.**
