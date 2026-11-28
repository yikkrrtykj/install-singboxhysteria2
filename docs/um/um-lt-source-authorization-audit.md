# UM-LT — Source authorization and audit (version 1, candidate)

Status: **CANDIDATE versioned source-authorization audit for the rev-7 contract
package — docs-only, pending independent review/CI and the Owner's conditional
merge authorization. NOT published/frozen, NOT merged, NOT implemented, NOT a
production authorization.** Implementation evidence is **NOT RUN** at contract-PR
time (see §8). Normative protocol text:
[`um-a/04-node-protocol-v1.rev7.md`](um-a/04-node-protocol-v1.rev7.md).
Architecture: [`um-lt-architecture.md`](um-lt-architecture.md).

Audit ID: **UM-LT-SOURCE-AUDIT-v1** (record/compare this version everywhere: the
center rollout gate, the implementation PR, the lab evidence and the runbook).

## 1. Scope and inherited facts

This audit covers exactly one new data source: the **Linux read-only local
monitor-v2 JSON export** consumed by the unprivileged UM Linux agent and reported
as `traffic_observation.source = monitor_readonly_export`.

Inherited, unchanged facts that this audit does **not** overturn:

| Fact | Status carried forward |
| --- | --- |
| sing-box `1.14 service.api` credential is write-capable | P1-10 authorization audit **FAIL / cannot be proven** (`um/docs/um-b3-singbox-serviceapi-audit.md`); remains FAIL |
| `collect.singbox_api` | **DISABLED / false** in every scope; must stay disabled; no environment/center/local credential path may enable it in this goal |
| Monitor `sboxweb` process | already holds the existing write-capable `service.api` secret internally; that does not change and is not duplicated anywhere by UM-LT |
| Linux Reality/Hysteria2 real traffic | remains the pre-production functional blocker on Issue #127 until the implementation and real lab prove this source; this audit alone proves nothing at runtime |
| `sbox-cm`, journal reader, conntrack/`ss`, packet capture | out of scope and forbidden as sources |

## 2. Principals, capabilities and invariants

| Principal | May | Must not |
| --- | --- | --- |
| sing-box daemon | serve its loopback `service.api` (unchanged) | be reconfigured, restarted or given new permissions by UM-LT |
| `monitor-v2` (`sboxweb`) | read its existing configuration/secret, consume `SubscribeConnections`, write **only** the new export file in the dedicated export directory, keep existing data root | write any secret/raw data into the export; change sing-box/`sbox-cm` permissions; gain new memberships except the export group |
| `um-agent` (`umagent`) | read the fixed export path (read-only), read `/proc`, its own state, the signed center transport | read `service.api` secret, monitor config/state DB/raw snapshot/session, `sbox-cm`, sing-box config or any other monitor data; write/replace/delete the export; accept a center-supplied path/URL/command |
| `um-center` | validate/store/query the signed observation, emit the boolean config switch | read monitor/agent local files, send paths/URLs/commands, change node permissions, enable `service.api`, or present lower bounds as totals |
| operators | install/disable per runbook, run audits/labs | enable the source without this audit version + implementation evidence + deployment authorization |

Invariants to prove (implementation PR tests):

1. **No new write-capable credential holder.** The export path is writable only
   by the existing monitor user; the agent has no new credential at all; the
   `service.api` secret stays inside the monitor and is never exported,
   delivered, logged or accepted by the agent/center.
2. **Agent cannot read the service.api secret or raw monitor data.** The agent's
   only new readable path is the export file; it is not in any monitor/sing-box/
   `sbox-cm` group and its unit keeps no exec/listener.
3. **Agent cannot write the export.** The directory is owned by the non-root
   monitor user with group `r-x` only, and the file mode grants read-only to the
   reader group; the agent opens `O_RDONLY|O_NOFOLLOW`, verifies regular
   file/owner/group/mode/size, and never deletes/renames/cleans anything.
4. **Minimal group/ACL.** One system group `sboxmon-export` containing exactly
   the non-root agent user (never root, never interactive users; the monitor user
   writes as directory owner and is not a group member); operator-created setgid
   directory `/run/singbox-monitor-export/` owned by the non-root monitor user
   (`2750`), file `traffic.json` (`0640`), no world access, **no POSIX ACL
   entries at all**, no existing mode/owner changed, no new root
   process/setuid/capability/sudoers rule. The directory lives on root-controlled
   `/run` tmpfs and is created by an operator step, not by the installer or the
   monitor.
5. **Symlink/path handling.** Fixed build-time path; no center/agent-config input
   can change it; the monitor's validated operator path must be absolute, the
   parent must be an existing non-symlink directory, and an existing final path
   must be a regular non-symlink file; the writer replaces atomically via a
   same-directory create-exclusive temp file with no symlink following; the
   reader refuses symlinks, non-regular files, wrong ownership/mode and
   trailing/oversized data. `/run` is root-controlled, so an unrelated local user
   cannot pre-create the path before the operator; after a reboot the directory
   must be recreated and an absent path is unavailable, never a stale trusted
   file.
6. **No URL/command/path from the center.** The only rev-7 wire addition is the
   boolean `collect.monitor_export`; it carries no string at all. There is no
   center→agent command channel; the agent's source path and format are fixed.
7. **No public listener.** No new listening socket/port/UNIX socket/named pipe is
   created by monitor, agent or center. The export is a one-way file; the
   machine and web entry points are unchanged.
8. **Privacy allow-list enforced at the export boundary.** Aggregate per-inbound
   counters only; raw source/destination addresses, device/API user names,
   connection IDs, proxy names, URLs, YAML, paths, journal/free text and secrets
   are never serialized; a privacy sentinel hit rejects the document/report.
9. **Authorization is not inferred from the switch.** Recording this audit
   version, the `CFG-REV7` agent-version evidence (minimum signed
   `agent.version` `1.1.0`; key omitted entirely for unknown/older) and the
   implementation evidence is required before a center may emit
   `monitor_export=true`; the boolean itself is only a source switch.
10. **`singbox_api` isolation.** The rev-7 path never reads/delivers/proves the
    `service.api` credential; P1-10 remains FAIL and `collect.singbox_api` stays
    false. No security gate is weakened by rev-7.

## 3. Capability analysis: monitor export writer

| Question | Answer |
| --- | --- |
| Does the monitor gain a new credential? | No. It reuses only its existing loopback `service.api` stream internally; no token/password/path is added to its unit or configuration. |
| Does the monitor gain a new network surface? | No. The export is written to a local file; its existing loopback listeners are unchanged. |
| Does the monitor gain write access outside the export dir? | No. Its unit's writable path set gains only `/run/singbox-monitor-export` (`ReadWritePaths=-…`, optional so a default install without the directory is untouched); sing-box/`sbox-cm`/data-root permissions are unchanged. |
| Can the export leak the secret or raw data? | Only if the writer serializes forbidden fields; the format is closed and the implementation must prove a privacy scan over the writer output (sentinel tests), including "no field for raw data exists"; `kind` is the operator allow-list attestation `TAG:KIND`, never a heuristic over raw daemon data. |
| Can a compromised agent use the export to write anywhere? | No. The file is read-only to the agent and contains no credential, URL, path or command. |
| Can a malicious local user pre-create the path/symlink? | `/run` is root-controlled and the export directory is operator-created/owned by the non-root monitor user, so an unrelated local user cannot create entries before or inside it; the writer validates the operator-supplied absolute path (no relative path, no symlinked parent/final path, regular-file only) and replaces via a same-directory temp+rename; the agent refuses symlinks/wrong owner/mode. The implementation PR must include the symlink/FIFO/wrong-owner negative tests. |
| Residual capability of the monitor itself | The monitor already holds a write-capable `service.api` secret; UM-LT does not reduce or expand that. This is the pre-existing accepted-in-monitor risk, not a new UM agent/center capability. |

## 4. Capability analysis: agent reader

| Question | Answer |
| --- | --- |
| New credential on the agent? | None. The only new access is group-read on one aggregate file. |
| New network surface? | None; still no listening socket; only the configured center origin is contacted. |
| Can the agent read raw monitor data? | No. It has no read access to the monitor data root/config/state DB/session/snapshot/socket and no `service.api` secret. Its unit keeps `ProtectHome`/`ProtectSystem`/no-exec/no-listener rules; the implementation PR asserts the readable-path delta is exactly the export file. |
| Can the agent write the export? | No. Read-only group/mode; no directory write; no delete/rename; `O_NOFOLLOW` regular-file checks; failure → unavailable. |
| Can the agent be redirected by the center? | No. No path/URL/command field exists in the config; the path is compiled/package-fixed. |
| Can the agent be tricked by a crafted file? | Bounded 64 KiB strict parse, closed schema, numeric/coherence rules, allow-list filter; failure → no-observation sentinel and a closed local counter; raw content never logged. |

## 5. Data minimization and privacy

Export/report content is restricted to the frozen allow-list: per-inbound tag
(from the center-configured set), kind (`reality|hysteria2|other`), observed
lower-bound bytes per direction, observed rates and window, active connection
counts, observation timestamps, `source_epoch`, `sequence`, freshness/
availability/quality tokens, `counter_epoch` and the frozen rev-5 base snapshot
fields. The export additionally carries monitor-owned observability
(`generated_at`, `monitor_stale`, `monitor_last_success_at`, file
`schema`/`schema_version`/`source`) which stays monitor-side and is never
forwarded into the report. Forbidden: source/destination IPs or hostnames, raw
connection IDs,
device/API user names, node/event/key IDs or any UUID, proxy/outbound/rule
names, SNI, URLs, YAML, journal/log text, filesystem paths, command lines, free
text, error text, credentials/secrets/tokens/private keys, passwords and
per-client rows.

Implementation must run sentinel tests proving these values never appear in the
export file, the agent log, the signed body, center storage rows, query
responses, retrievals and backups (SEC-14 extension). Any hit rejects the
document/report and is audited; the value itself is never logged.

## 6. Explicitly not used / not enabled

| Surface | Status |
| --- | --- |
| sing-box `service.api` credential (agent) | **NOT used, NOT delivered, DISABLED**; P1-10 remains FAIL |
| monitor admin password/session, loopback snapshot/SSE | not used |
| monitor data root `state/snapshot.json`, diagnostics DB | not read/not permission-widened |
| `sbox-cm` privileged socket | not used |
| journal reader | not used (no bytes) |
| conntrack/`ss`/packet capture | not used |
| new listener/token/HTTP endpoint on monitor | not added |
| center-supplied path/URL/token/command | impossible by contract |
| cloudflared/DNS/TLS/certificate change | none |

## 7. Threat scenarios and dispositions

| # | Scenario | Disposition |
| --- | --- | --- |
| SA-1 | Compromised agent tries to read monitor secret/raw data | no access path; export-only group read; unit hardening; test asserts EACCES/nonexistent |
| SA-2 | Compromised agent tries to forge/replace export or symlink the path | no directory/file write permission (directory group is `r-x`, file `r`); monitor replaces atomically; reader refuses symlinks/ownership mismatch; an unrelated local user cannot create entries because `/run` is root-controlled and the operator-owned directory has no other writers |
| SA-3 | Local user pre-creates a malicious file/path | `/run` is root-controlled and the directory is operator-created with the non-root monitor user as owner; an unrelated user cannot pre-create the path; the monitor validates the operator-supplied absolute path (no relative/symlinked parent or final path, regular file only), creates the temp with O_EXCL and renames; the reader verifies owner/group/mode; path fixed |
| SA-4 | Malicious center sends a path/URL/command to read elsewhere | no such field exists; config is a closed schema; boolean only |
| SA-5 | Compromised monitor writes raw secrets into export | closed writer format + privacy allow-list + implementation sentinel tests; no field for raw data; monitor compromise already implies its own data, but the export must not widen it |
| SA-6 | Replay of an old export to fake freshness | `source_epoch`+`sequence`+`observed_at` must be coherent; monitor deletes stale file at startup; agent/center age-check; old-epoch values never diffed or resurrected |
| SA-7 | Denial via giant/malformed file | 64 KiB cap, strict parse, bounded arrays; failure → unavailable; no unbounded work/memory |
| SA-8 | Center stores/renders a lower bound as a total | schema exactness/counter_scope consts + semantic vectors + center query labelling tests; UI must render lower-bound label |
| SA-9 | `service.api` gets enabled "because traffic now works" | prohibited: P1-10 FAIL retained, switch stays DISABLED, separately audited source; tests assert no enablement path/credential wiring |
| SA-10 | Windows node receives/uses the source | class-gated in config and ingest; `platform_mismatch`; Windows code unchanged |
| SA-11 | Export/agent file is read by an unrelated process | 0640 group, no world access; only the non-root agent user is in `sboxmon-export`; the monitor user writes as owner and is not a group member; no ACL entries |
| SA-12 | Center downgrade/rollback reintroduces old agent surface | compatibility/rollback rules in [`um-lt-compatibility.md`](um-lt-compatibility.md); old center rejects rev-7; queued rev-7 quarantined byte-identically, not rewritten |

## 8. Evidence status and what the implementation PR must prove

| Evidence | Contract PR | Implementation PR |
| --- | --- | --- |
| Versioned audit text (this file) | **PROVIDED (docs)** | must stay current and be referenced by the implementation/runbook |
| `$id`/schema/base-shape/negative-vector consistency | **PROVIDED, executed**: `cd um && go test ./internal/schema -run 'TestRev7' -v` compiles the rev-7 overlay schemas (report/config/traffic-export), validates the positive fixtures, executes all `json_schema`-stage vectors and the two raw-body lexical cases; reviewed HEAD `1aa71abe` Unified Monitor Go run `46156909313` all five jobs success | full runner also executes implementation-semantic/platform/config-generation vectors and real ingest/storage/query behavior |
| real file-ACL/group/symlink/atomicity tests on Linux | **NOT RUN** | required (installer + reader/writer negative matrix) |
| real writer privacy sentinel tests (no raw fields) | **NOT RUN** | required |
| real agent EACCES/no-read of monitor secret/data root | **NOT RUN** | required (Linux systemd lab) |
| real center rev-7 ingest/validate/store/query tests | **NOT RUN** | required |
| real monitor→export→agent→center end-to-end with synthetic traffic | **NOT RUN** | required lab |
| real Reality/Hysteria2 inbound acceptance | **NOT RUN** | required before any production claim (Issue #127 blocker) |
| independent review of this audit | pending with the contract PR | re-review of any implementation change |

## 9. Conclusion and conditions

- The rev-7 source is a **read-only, aggregate, local-file** source; it does not
  add a write-capable credential holder, does not enable `service.api`, and does
  not widen existing monitor/sing-box permissions. Its authorization basis is
  this versioned audit plus the implementation evidence above — not the boolean
  switch, not an unauthenticated claim, not a config URL.
- **At contract-PR time the source is NOT authorized for runtime use.** It may be
  implemented and tested; any environment that enables it requires the
  implementation PR's evidence, this audit version recorded in the rollout gate,
  and the normal deployment authorization. Production, R1 production, Cloudflare/
  DNS/certificates/VPS/SSH and paid resources remain out of scope.
- **P1-10 remains FAIL; `singbox_api` remains DISABLED.** Nothing here may be
  used to claim otherwise; a future attempt to enable `service.api` needs its own
  authorization proof and owner decision.
- Residual risks are recorded, not waived: the monitor already holds a
  write-capable secret; bounded replay/dedupe guards make the observed value an
  approximation/lower bound rather than exact; the monitor is a separately
  deployed product whose release must carry the audited writer; real
  Reality/Hysteria2 acceptance remains an implementation/lab gate.
